//! Hook-event extraction from AI transcript records.
//!
//! Claude transcripts carry first-class hook *runtime execution* evidence:
//! attachment rows whose `attachment.type` begins with `hook_` (e.g.
//! `hook_success`) plus the observed `async_hook_response` shape, carrying
//! `hookName`, `hookEvent`, `command`, `exitCode`,
//! `durationMs`, `stdout`, `stderr`, `content`, and an optional persisted
//! output path pointer when the captured output is too large to inline.
//!
//! Codex transcripts (per the original research for GH #105) did NOT show an
//! equivalent structured runtime hook attachment shape in sampled logs, so
//! this module intentionally ships **no Codex runtime-hook parser**. Codex
//! hook evidence is config/trust-state only and is produced by the separate
//! config-inventory collectors (see `crate::scanner::hook_config`), never here.
//!
//! Every extracted event carries an `evidence_kind` so downstream callers can
//! distinguish runtime-proven facts (`runtime_transcript`) from
//! configuration-inventory facts (`config_inventory`, `trusted_hash_state`).
//! This module only ever produces `runtime_transcript` evidence.
//!
//! The extractor short-circuits on a cheap substring check before doing any
//! real JSON walking, mirroring the skill-event extractor: the common
//! no-hook-attachment case costs a single `str::contains` call.
//!
//! Bounded preview fields (`stdout_preview`/`stderr_preview`/`hook_command`)
//! are redacted via [`bounded_redact`] and clamped before they leave this
//! module — an adversarial transcript could otherwise embed ANSI escapes or
//! secrets that the CLI printer would echo verbatim.

use crate::assessment::{redact_json_value_strings, redact_secrets};

/// Redact `value`, tree-walking it first if it parses as a JSON object or
/// array. `redact_secrets` tokenizes on whitespace, so a secret carried as
/// a JSON value (e.g. `{"api_key":"sk-..."}`, a common shape for hook
/// stdout/stderr that echoes a config blob or API response) serializes to
/// a single whitespace-free token that doesn't start with a known prefix
/// and is never caught. When `value` parses as an object/array, redact
/// each string leaf individually before re-serializing instead, so secret
/// boundaries are visible to `looks_secretish`. Scalar JSON values and
/// non-JSON text fall back to whole-string redaction unchanged.
fn bounded_redact(value: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(value) {
        Ok(mut parsed @ (serde_json::Value::Object(_) | serde_json::Value::Array(_))) => {
            redact_json_value_strings(&mut parsed);
            parsed.to_string()
        }
        // A bare JSON string (e.g. `value` is `"sk-realsecret"`, quotes
        // included) parses successfully but isn't an Object/Array, so it
        // fell through to `redact_secrets(value)` below on the STILL-
        // QUOTED text — the leading `"` breaks every `looks_secretish`
        // prefix check (`"sk-...` doesn't start with `sk-`), silently
        // letting the secret through. Redact the unquoted inner string
        // directly instead.
        Ok(serde_json::Value::String(s)) => redact_secrets(&s),
        _ => redact_secrets(value),
    }
}

/// Char cap for every bounded free-text field on an extracted hook event.
/// Mirrors the `MAX_SKILL_FIELD_CHARS` convention from `skill_events.rs`; the
/// preview fields get a larger budget because stdout/stderr are inherently
/// longer than a skill name while still needing a hard bound before storage.
const MAX_HOOK_FIELD_CHARS: usize = 256;
const MAX_HOOK_PREVIEW_CHARS: usize = 2048;
const MAX_HOOK_COMMAND_CHARS: usize = 1024;

/// Runtime status of a hook execution, derived from the attachment `type`
/// suffix. Unknown/unrecognized `hook_*` variants map to [`HookStatus::Unknown`]
/// rather than panicking — we have no live sample of every failure variant, so
/// the parser is deliberately defensive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookStatus {
    Success,
    Failed,
    Blocked,
    Error,
    Unknown,
    /// Not a runtime status: marks a config-inventory / trusted-hash-state row
    /// produced by `crate::hook_config`. A `Configured` row is proof only that
    /// a hook is *configured*/*trusted*, never that it executed. Kept in this
    /// enum (rather than a bare string) so the DB `status` column has a single
    /// authoritative source and config rows are excluded from runtime failure
    /// anchors (`hook_signal_detectors::is_hook_failure_status`).
    Configured,
}

impl HookStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failed => "failed",
            Self::Blocked => "blocked",
            Self::Error => "error",
            Self::Unknown => "unknown",
            Self::Configured => "configured",
        }
    }

    /// Map a Claude attachment `type` (e.g. `hook_success`, `hook_failure`,
    /// `hook_blocked`, `hook_error`) to a status. Best-effort: matches on the
    /// suffix after the `hook_` prefix, tolerating unseen variants.
    fn from_attachment_type(attachment_type: &str) -> Self {
        let suffix = attachment_type
            .strip_prefix("hook_")
            .unwrap_or(attachment_type);
        match suffix {
            "success" | "ok" | "completed" | "complete" => Self::Success,
            "failure" | "failed" | "fail" | "nonzero" => Self::Failed,
            "blocked" | "block" | "denied" | "deny" => Self::Blocked,
            "error" | "errored" | "timeout" | "timed_out" | "parse_error"
            | "non_blocking_error" => Self::Error,
            _ => Self::Unknown,
        }
    }
}

/// Provenance of a hook event. Only `RuntimeTranscript` is produced by this
/// module; the config/trust-state variants are produced by the config
/// inventory collectors. The `LogCorrelation`/`SideEffectInference` variants
/// are reserved conceptually per GH #105 — no extractor emits them yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookEvidenceKind {
    RuntimeTranscript,
    ConfigInventory,
    TrustedHashState,
    /// Reserved (GH #105): a hook event inferred by correlating hook activity
    /// with surrounding syslog. No extractor emits this yet; kept so the
    /// `evidence_kind` taxonomy is stable and callers can already branch on it.
    #[allow(dead_code)]
    LogCorrelation,
    /// Reserved (GH #105): a hook event inferred from an observed side effect
    /// (e.g. a config/file mutation) rather than a direct execution record. No
    /// extractor emits this yet.
    #[allow(dead_code)]
    SideEffectInference,
}

impl HookEvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeTranscript => "runtime_transcript",
            Self::ConfigInventory => "config_inventory",
            Self::TrustedHashState => "trusted_hash_state",
            Self::LogCorrelation => "log_correlation",
            Self::SideEffectInference => "side_effect_inference",
        }
    }
}

/// A single extracted hook event, in the shape shared by the runtime-transcript
/// extractor and the config-inventory collectors. Callers thread the
/// already-known session/host/timestamp context around this struct (mirroring
/// `ExtractedSkillEvent`); this struct holds only the hook-specific fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedHookEvent {
    pub hook_event: String,
    pub hook_name: Option<String>,
    pub hook_source: Option<String>,
    pub hook_command: Option<String>,
    pub status: HookStatus,
    pub exit_code: Option<i64>,
    pub duration_ms: Option<i64>,
    pub stdout_preview: Option<String>,
    pub stderr_preview: Option<String>,
    pub persisted_output_path: Option<String>,
    pub trusted_hash: Option<String>,
    pub evidence_kind: HookEvidenceKind,
    pub metadata_json: Option<String>,
}

impl ExtractedHookEvent {
    /// Trim, reject-if-control-chars, and clamp every free-text field. Returns
    /// `None` when the resulting `hook_event` would be empty OR any retained
    /// text field contains a `char::is_control()` character (closes the same
    /// terminal-spoofing vector the skill extractor's `normalized()` closes).
    /// Preview fields are redacted here as a final guard even though the
    /// runtime extractor already redacts them — the config collectors reuse
    /// this path and must also be safe. Never panics.
    pub fn normalized(mut self) -> Option<Self> {
        let trimmed_event = self.hook_event.trim();
        if trimmed_event.is_empty() || trimmed_event.chars().any(char::is_control) {
            return None;
        }
        self.hook_event = clamp_chars(trimmed_event, MAX_HOOK_FIELD_CHARS);

        self.hook_name = normalize_field(self.hook_name, MAX_HOOK_FIELD_CHARS)?;
        self.hook_source = normalize_field(self.hook_source, MAX_HOOK_FIELD_CHARS)?;
        // Unlike hook_name/hook_source (opaque identifiers), hook_command is
        // free text a human wrote and may embed a credential (e.g. `curl -H
        // "Authorization: Bearer sk-..."`) — redact it too, but AFTER the
        // control-char rejection, not before. Eng review fix (adversarial
        // re-verify): `bounded_redact`'s fallback path
        // (`redact_secrets`) does `split_whitespace().join(" ")`, which
        // treats tab/`\v`/`\f` as splitters and re-emits plain spaces —
        // redacting first silently laundered whitespace-class control
        // characters out of the string before `normalize_field`'s
        // `char::is_control()` check ever saw them, letting a
        // control-char-laden command through instead of rejecting the
        // event. Redact only after the reject-on-control-char check has
        // already run on the raw text, and re-clamp afterward since
        // `[REDACTED]` can be longer than the token it replaces.
        self.hook_command = normalize_field(self.hook_command, MAX_HOOK_COMMAND_CHARS)?;
        self.hook_command = self
            .hook_command
            .map(|s| clamp_chars(&bounded_redact(&s), MAX_HOOK_COMMAND_CHARS));
        self.persisted_output_path =
            normalize_field(self.persisted_output_path, MAX_HOOK_FIELD_CHARS)?;
        self.trusted_hash = normalize_field(self.trusted_hash, MAX_HOOK_FIELD_CHARS)?;

        self.stdout_preview = normalize_preview(self.stdout_preview);
        self.stderr_preview = normalize_preview(self.stderr_preview);

        Some(self)
    }
}

/// Trim + clamp an optional short field. Rejects the whole event (returns the
/// outer `None` via `?`) when the field carries control characters; drops the
/// field to `None` when it trims to empty.
fn normalize_field(value: Option<String>, max_chars: usize) -> Option<Option<String>> {
    match value {
        None => Some(None),
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.chars().any(char::is_control) {
                return None;
            }
            if trimmed.is_empty() {
                Some(None)
            } else {
                Some(Some(clamp_chars(trimmed, max_chars)))
            }
        }
    }
}

/// Redact secrets, strip control characters, and clamp a preview blob. Unlike
/// [`normalize_field`], control characters here are stripped (not rejected) —
/// stdout/stderr legitimately contain newlines, so we sanitize them into
/// spaces rather than dropping the whole event.
fn normalize_preview(value: Option<String>) -> Option<String> {
    let raw = value?;
    let redacted = bounded_redact(&raw);
    let sanitized: String = redacted
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let trimmed = sanitized.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(clamp_chars(trimmed, MAX_HOOK_PREVIEW_CHARS))
    }
}

fn clamp_chars(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        value.to_string()
    } else {
        value.chars().take(max_chars).collect()
    }
}

/// Extract Claude hook *runtime* events from a raw transcript JSON value.
///
/// Claude transcript lines carry hook execution evidence in an `attachment`
/// object (or an `attachments` array of them) whose `type` begins with
/// `hook_`, or the explicit `async_hook_response` type. This walks both the
/// top-level record and the `message.*` nesting
/// (the same two candidate locations the skill extractor checks), collecting
/// one event per hook attachment found.
///
/// Callers should already have skipped this function when the source text
/// doesn't contain the `"hook_"` substring — this function operates on an
/// already-parsed `Value`, so it can only short-circuit on structural absence.
pub fn extract_claude_hook_events(value: &serde_json::Value) -> Vec<ExtractedHookEvent> {
    let mut events = Vec::new();
    let candidates = [
        value,
        value.get("message").unwrap_or(&serde_json::Value::Null),
    ];
    for candidate in candidates {
        // A single record may carry a single `attachment` object or an
        // `attachments` array; support both.
        if let Some(attachment) = candidate.get("attachment") {
            collect_hook_attachment(attachment, &mut events);
        }
        if let Some(array) = candidate.get("attachments").and_then(|v| v.as_array()) {
            for attachment in array {
                collect_hook_attachment(attachment, &mut events);
            }
        }
    }
    events
}

/// Parse a single attachment object into a hook event if its `type` is one of
/// the observed hook shapes. Non-hook attachments are ignored.
fn collect_hook_attachment(attachment: &serde_json::Value, out: &mut Vec<ExtractedHookEvent>) {
    let Some(attachment_type) = attachment.get("type").and_then(serde_json::Value::as_str) else {
        return;
    };
    if !attachment_type.starts_with("hook_") && attachment_type != "async_hook_response" {
        return;
    }

    let status = if attachment_type == "async_hook_response" {
        match int_field(attachment, "exitCode").or_else(|| int_field(attachment, "exit_code")) {
            Some(0) => HookStatus::Success,
            Some(_) => HookStatus::Failed,
            None => HookStatus::Unknown,
        }
    } else {
        HookStatus::from_attachment_type(attachment_type)
    };
    let hook_event = str_field(attachment, "hookEvent")
        .or_else(|| str_field(attachment, "hook_event"))
        // Fall back to the attachment type suffix so an event with a missing
        // hookEvent still lands somewhere meaningful rather than being dropped.
        .unwrap_or_else(|| {
            attachment_type
                .strip_prefix("hook_")
                .unwrap_or(attachment_type)
                .to_string()
        });

    let hook_name =
        str_field(attachment, "hookName").or_else(|| str_field(attachment, "hook_name"));
    let hook_command =
        str_field(attachment, "command").or_else(|| str_field(attachment, "hookCommand"));
    let exit_code =
        int_field(attachment, "exitCode").or_else(|| int_field(attachment, "exit_code"));
    let duration_ms =
        int_field(attachment, "durationMs").or_else(|| int_field(attachment, "duration_ms"));
    // `content` is a secondary source for stdout when `stdout` is absent.
    let stdout_preview = str_field(attachment, "stdout")
        .or_else(|| str_field(attachment, "content"))
        .or_else(|| str_field(attachment, "response"))
        .map(|s| bounded_redact(&s));
    let stderr_preview = str_field(attachment, "stderr").map(|s| bounded_redact(&s));
    let persisted_output_path = str_field(attachment, "persistedOutputPath")
        .or_else(|| str_field(attachment, "persisted_output_path"))
        .or_else(|| str_field(attachment, "outputPath"));

    let event = ExtractedHookEvent {
        hook_event,
        hook_name,
        hook_source: None,
        hook_command,
        status,
        exit_code,
        duration_ms,
        stdout_preview,
        stderr_preview,
        persisted_output_path,
        trusted_hash: None,
        evidence_kind: HookEvidenceKind::RuntimeTranscript,
        metadata_json: None,
    };
    if let Some(normalized) = event.normalized() {
        out.push(normalized);
    }
}

fn str_field(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string)
}

fn int_field(value: &serde_json::Value, key: &str) -> Option<i64> {
    value.get(key).and_then(serde_json::Value::as_i64)
}

#[cfg(test)]
#[path = "hook_events_tests.rs"]
mod tests;
