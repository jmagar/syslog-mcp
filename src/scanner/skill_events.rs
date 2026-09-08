//! Skill-event extraction from AI transcript records.
//!
//! Two independent extractors feed the same [`ExtractedSkillEvent`] shape:
//! - Claude: structured `attributionSkill` / `attributionPlugin` JSON fields
//!   (top-level or `message.*` nesting — a third `payload.*` candidate was
//!   deliberately NOT added: no observed transcript sample confirms that
//!   shape, so it would be speculative).
//! - Codex: `<skill><name>...</name></skill>` tags embedded in transcript
//!   message text (see `CODEX_SKILL_TAG` in this module).
//!
//! Both extractors short-circuit on a cheap substring check before doing any
//! real parsing/regex work (eng review Fix 1), so the common no-skill-event
//! case costs a single `str::contains` call.
//!
//! Callers normalize with [`ExtractedSkillEvent::normalized`] before
//! inserting, which trims/clamps/derives the `plugin:skill` combined form
//! and rejects control characters (eng review Fix 8 — an adversarial
//! transcript could otherwise embed ANSI escapes that the CLI printer
//! would echo verbatim via `println!`).

use std::sync::LazyLock;

use regex::Regex;

const MAX_SKILL_FIELD_CHARS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkillEventKind {
    ClaudeAttribution,
    CodexSkillBlock,
    CodexSkillRead,
}

impl SkillEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClaudeAttribution => "claude_attribution",
            Self::CodexSkillBlock => "codex_skill_block",
            Self::CodexSkillRead => "codex_skill_read",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkillEvidenceKind {
    StructuredJsonField,
    TranscriptContent,
}

impl SkillEvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StructuredJsonField => "structured_json_field",
            Self::TranscriptContent => "transcript_content",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedSkillEvent {
    pub skill_name: String,
    pub skill_plugin: Option<String>,
    pub event_kind: SkillEventKind,
    pub evidence_kind: SkillEvidenceKind,
}

impl ExtractedSkillEvent {
    /// Trim, reject-if-empty, reject-if-contains-control-characters, and
    /// clamp `skill_name`/`skill_plugin` to `MAX_SKILL_FIELD_CHARS`. Returns
    /// `None` when the resulting skill_name would be empty OR contains any
    /// `char::is_control()` character (eng review Fix 8 — closes a terminal
    /// output spoofing vector: ANSI escapes or embedded newlines/CRs in a
    /// skill name would otherwise be echoed verbatim by the CLI's
    /// `println!`-based printer). Never panics or bubbles an error —
    /// callers skip the event and keep parsing the rest of the transcript.
    fn normalized(mut self) -> Option<Self> {
        let trimmed_name = self.skill_name.trim();
        if trimmed_name.is_empty() || trimmed_name.chars().any(char::is_control) {
            return None;
        }
        if self
            .skill_plugin
            .as_deref()
            .is_some_and(|plugin| plugin.chars().any(char::is_control))
        {
            return None;
        }
        // If the source already used "plugin:skill" combined form, split it
        // out for skill_plugin while keeping skill_name as the full combined
        // string (locked behavior — do not fabricate this split when
        // plugin/skill came from separate source fields, e.g. Claude's
        // attributionSkill/attributionPlugin).
        if self.skill_plugin.is_none()
            && let Some((plugin, _rest)) = trimmed_name.split_once(':')
            && !plugin.is_empty()
        {
            self.skill_plugin = Some(plugin.to_string());
        }
        self.skill_name = clamp_chars(trimmed_name, MAX_SKILL_FIELD_CHARS);
        self.skill_plugin = self.skill_plugin.and_then(|plugin| {
            let trimmed = plugin.trim();
            (!trimmed.is_empty()).then(|| clamp_chars(trimmed, MAX_SKILL_FIELD_CHARS))
        });
        Some(self)
    }
}

fn clamp_chars(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        value.to_string()
    } else {
        value.chars().take(max_chars).collect()
    }
}

/// Extract Claude skill-attribution events from a raw transcript JSON value.
/// Checks top-level and `message.*` nesting for `attributionSkill` /
/// `attributionPlugin` string fields (Claude transcripts use flat top-level
/// fields on user-facing records and nested `message.*` fields on some
/// tool-result records). Returns one event per candidate location that has a
/// non-empty `attributionSkill`; at most one event in practice since a single
/// transcript line only has one of the two shapes.
///
/// Eng review Fix 1: callers should already have skipped calling this
/// function at all when the source text doesn't contain `"attributionSkill"`
/// as a substring — this function itself has nothing further to
/// short-circuit on since it operates on an already-parsed `Value`, not raw
/// text.
pub fn extract_claude_skill_events(value: &serde_json::Value) -> Vec<ExtractedSkillEvent> {
    let candidates = [
        value,
        value.get("message").unwrap_or(&serde_json::Value::Null),
    ];
    for candidate in candidates {
        let Some(skill) = candidate
            .get("attributionSkill")
            .and_then(serde_json::Value::as_str)
        else {
            continue;
        };
        let plugin = candidate
            .get("attributionPlugin")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string);
        let event = ExtractedSkillEvent {
            skill_name: skill.to_string(),
            skill_plugin: plugin,
            event_kind: SkillEventKind::ClaudeAttribution,
            evidence_kind: SkillEvidenceKind::StructuredJsonField,
        };
        if let Some(normalized) = event.normalized() {
            return vec![normalized];
        }
        return Vec::new();
    }
    Vec::new()
}

/// Matches `<skill> <name> ... </name> </skill>` with optional whitespace
/// around every tag boundary. `(?s)` lets `.` cross newlines (skill names are
/// short but transcripts can wrap). Non-greedy `.*?` keeps each match scoped
/// to one tag pair even when multiple `<skill>` blocks appear in one message.
static CODEX_SKILL_TAG: LazyLock<Regex> = LazyLock::new(|| {
    // Current Codex emits a path and the entire skill body after the name.
    // The forwarding byte budget can truncate that body, so require the
    // complete structured header, not the closing tag beyond the budget.
    // Keep the historical name-only form and reject ordinary catalog paths.
    Regex::new(r"(?s)<skill>\s*<name>\s*([^<]*?)\s*</name>\s*(?:</skill>|<path>[^<>\r\n]+/SKILL\.md</path>)")
        .expect("static regex")
});

/// Extract Codex skill-invocation events from transcript message text. Scans
/// for ALL `<skill><name>...</name></skill>` occurrences (a single row can
/// invoke multiple skills), de-duplicating identical skill names within the
/// row. Deliberately narrow — matches only the literal tag pair, never prose
/// like "use the rust skill".
///
/// Eng review Fix 1: short-circuits on a cheap substring check before
/// touching the regex engine at all — the overwhelming majority of
/// transcript rows contain no skill tag, so this bounds the common case to
/// one `str::contains` call instead of a full regex scan.
pub fn extract_codex_skill_events(text: &str) -> Vec<ExtractedSkillEvent> {
    if text.starts_with("{\"cortex_skill_read\":") {
        let name = serde_json::from_str::<serde_json::Value>(text)
            .ok()
            .and_then(|value| {
                value
                    .get("cortex_skill_read")
                    .and_then(|name| name.as_str())
                    .map(str::to_owned)
            });
        return name
            .and_then(|skill_name| {
                ExtractedSkillEvent {
                    skill_name,
                    skill_plugin: None,
                    event_kind: SkillEventKind::CodexSkillRead,
                    evidence_kind: SkillEvidenceKind::StructuredJsonField,
                }
                .normalized()
            })
            .into_iter()
            .collect();
    }
    if !text.contains("<skill>") {
        return Vec::new();
    }
    let mut seen = std::collections::HashSet::new();
    let mut events = Vec::new();
    for capture in CODEX_SKILL_TAG.captures_iter(text) {
        let raw_name = capture.get(1).map_or("", |m| m.as_str());
        let event = ExtractedSkillEvent {
            skill_name: raw_name.to_string(),
            skill_plugin: None,
            event_kind: SkillEventKind::CodexSkillBlock,
            evidence_kind: SkillEvidenceKind::TranscriptContent,
        };
        let Some(normalized) = event.normalized() else {
            continue;
        };
        if seen.insert(normalized.skill_name.clone()) {
            events.push(normalized);
        }
    }
    events
}

/// Native Codex command-completion evidence, not a path guessed from shell
/// text. Restrict this to a single parsed read with a successful completion:
/// a multi-command shell's final exit code cannot prove each read succeeded.
pub(crate) fn codex_skill_read_summary(value: &serde_json::Value) -> Option<String> {
    if value.get("type")?.as_str()? != "event_msg"
        || value.pointer("/payload/type")?.as_str()? != "item_completed"
    {
        return None;
    }
    let item = value.pointer("/payload/item")?;
    if item.get("type")?.as_str()? != "CommandExecution"
        || item.get("status")?.as_str()? != "completed"
        || item.get("exit_code")?.as_i64()? != 0
        || item.get("aggregated_output")?.as_str()?.trim().is_empty()
    {
        return None;
    }
    let commands = item.get("parsed_cmd")?.as_array()?;
    if commands.len() != 1 || commands[0].get("type")?.as_str()? != "read" {
        return None;
    }
    let path = commands[0].get("path")?.as_str()?;
    let directory = path.strip_suffix("/SKILL.md")?;
    let name = directory.rsplit('/').next()?;
    if name.is_empty()
        || name.len() > MAX_SKILL_FIELD_CHARS
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-.:".contains(&byte))
    {
        return None;
    }
    Some(serde_json::json!({"cortex_skill_read": name}).to_string())
}

#[cfg(test)]
#[path = "skill_events_tests.rs"]
mod tests;
