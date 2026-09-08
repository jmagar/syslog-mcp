use super::*;

#[test]
fn codex_completed_skill_read_preserves_typed_evidence_without_paths_or_content() {
    let value = serde_json::json!({"type":"event_msg","payload":{"type":"item_completed","item":{
        "type":"CommandExecution","status":"completed","exit_code":0,
        "aggregated_output":"---\nname: limetech-ai-review\n---\nPrivate skill content",
        "parsed_cmd":[{"type":"read","path":"/Users/private/.codex/skills/limetech-ai-review/SKILL.md"}]
    }}});
    let summary = codex_skill_read_summary(&value).unwrap();
    assert!(!summary.contains("private"));
    assert!(!summary.contains("Private skill content"));
    let events = extract_codex_skill_events(&summary);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].skill_name, "limetech-ai-review");
    assert_eq!(events[0].event_kind, SkillEventKind::CodexSkillRead);
    for (field, replacement) in [
        ("exit_code", serde_json::json!(1)),
        ("status", serde_json::json!("in_progress")),
        ("aggregated_output", serde_json::json!("")),
        (
            "parsed_cmd",
            serde_json::json!([{"type":"search","path":"/skills/review/SKILL.md"}]),
        ),
        (
            "parsed_cmd",
            serde_json::json!([{"type":"read","path":"/skills/review/README.md"}]),
        ),
        (
            "parsed_cmd",
            serde_json::json!([{"type":"read","path":"/skills/review/SKILL.md"},{"type":"unknown","cmd":"true"}]),
        ),
    ] {
        let mut invalid = value.clone();
        invalid["payload"]["item"][field] = replacement;
        assert!(codex_skill_read_summary(&invalid).is_none(), "{field}");
    }
}
use serde_json::json;

#[test]
fn extracts_top_level_attribution_skill_and_plugin() {
    let value = json!({
        "sessionId": "sess-1",
        "attributionSkill": "cortex-troubleshoot",
        "attributionPlugin": "cortex",
        "content": "ran the troubleshoot skill"
    });
    let events = extract_claude_skill_events(&value);
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event.skill_name, "cortex-troubleshoot");
    assert_eq!(event.skill_plugin.as_deref(), Some("cortex"));
    assert_eq!(event.event_kind, SkillEventKind::ClaudeAttribution);
    assert_eq!(event.evidence_kind, SkillEvidenceKind::StructuredJsonField);
}

#[test]
fn extracts_nested_message_attribution_fields() {
    let value = json!({
        "message": {
            "attributionSkill": "web-app-testing",
            "attributionPlugin": "testing",
            "content": "tested the app"
        }
    });
    let events = extract_claude_skill_events(&value);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].skill_name, "web-app-testing");
    assert_eq!(events[0].skill_plugin.as_deref(), Some("testing"));
}

#[test]
fn emits_nothing_when_attribution_fields_absent() {
    let value = json!({"sessionId": "sess-1", "content": "just chatting"});
    assert!(extract_claude_skill_events(&value).is_empty());
}

#[test]
fn emits_nothing_for_empty_or_whitespace_skill_name() {
    let value = json!({"attributionSkill": "   "});
    assert!(extract_claude_skill_events(&value).is_empty());
}

#[test]
fn does_not_fabricate_plugin_skill_combined_string() {
    // Claude gives plugin and skill as SEPARATE fields — the combined
    // "plugin:skill" form must only appear when the source field itself
    // already used that format (see codex tests for that case).
    let value = json!({
        "attributionSkill": "sonnar",
        "attributionPlugin": "arrs"
    });
    let events = extract_claude_skill_events(&value);
    assert_eq!(events[0].skill_name, "sonnar");
    assert_eq!(events[0].skill_plugin.as_deref(), Some("arrs"));
}

#[test]
fn rejects_skill_name_containing_control_characters() {
    // Eng review Fix 8: a crafted attributionSkill value embedding an ANSI
    // escape sequence must be rejected, not silently stored — the CLI
    // printer (Task 9) uses println! directly on skill_name, so control
    // characters would let a malicious transcript spoof terminal output.
    let value = json!({
        "attributionSkill": "\u{1b}[2J\u{1b}[31mFAKE",
    });
    assert!(extract_claude_skill_events(&value).is_empty());
}

#[test]
fn rejects_skill_name_containing_embedded_newline() {
    let value = json!({
        "attributionSkill": "cortex-troubleshoot\nFAKE APPROVED LINE",
    });
    assert!(extract_claude_skill_events(&value).is_empty());
}

#[test]
fn extracts_single_codex_skill_tag() {
    let text = "Running <skill><name>rustarr</name></skill> now.";
    let events = extract_codex_skill_events(text);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].skill_name, "rustarr");
    assert_eq!(events[0].event_kind, SkillEventKind::CodexSkillBlock);
    assert_eq!(
        events[0].evidence_kind,
        SkillEvidenceKind::TranscriptContent
    );
}

#[test]
fn extracts_current_codex_skill_content_even_when_forwarded_body_is_truncated() {
    let prefix = "<skill>\n<name>limetech-ai-review</name>\n<path>/Users/example/.codex/skills/limetech-ai-review/SKILL.md</path>\n---\nname: limetech-ai-review\n---\n";
    for body in [
        format!("{prefix}Review instructions\n</skill>"),
        format!("{prefix}{}", "x".repeat(3000)),
    ] {
        let events = extract_codex_skill_events(&body);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].skill_name, "limetech-ai-review");
    }
}

#[test]
fn rejects_catalog_paths_and_incomplete_skill_headers() {
    for text in [
        "- limetech-ai-review: (file: /skills/limetech-ai-review/SKILL.md)",
        "<skill><name>limetech-ai-review</name>",
        "<skill><name>limetech-ai-review</name><path>/tmp/notes.md</path>",
    ] {
        assert!(extract_codex_skill_events(text).is_empty());
    }
}

#[test]
fn extracts_multiple_distinct_codex_skill_tags() {
    let text = "<skill><name>sonarr</name></skill> then <skill><name>radarr</name></skill>";
    let mut events = extract_codex_skill_events(text);
    events.sort_by(|a, b| a.skill_name.cmp(&b.skill_name));
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].skill_name, "radarr");
    assert_eq!(events[1].skill_name, "sonarr");
}

#[test]
fn dedupes_identical_skill_names_within_one_row() {
    let text = "<skill><name>cortex</name></skill> ... <skill><name>cortex</name></skill>";
    let events = extract_codex_skill_events(text);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].skill_name, "cortex");
}

#[test]
fn accepts_optional_whitespace_around_tags() {
    let text = "<skill> <name> tailscale </name> </skill>";
    let events = extract_codex_skill_events(text);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].skill_name, "tailscale");
}

#[test]
fn does_not_match_prose_mentioning_a_skill() {
    let text = "You should use the rust skill for this task, not a literal tag.";
    assert!(extract_codex_skill_events(text).is_empty());
}

#[test]
fn skips_empty_skill_name_tag_without_erroring() {
    let text = "<skill><name></name></skill> <skill><name>real-skill</name></skill>";
    let events = extract_codex_skill_events(text);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].skill_name, "real-skill");
}

#[test]
fn derives_plugin_skill_split_from_combined_form() {
    let text = "<skill><name>cortex:cortex-troubleshoot</name></skill>";
    let events = extract_codex_skill_events(text);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].skill_name, "cortex:cortex-troubleshoot");
    assert_eq!(events[0].skill_plugin.as_deref(), Some("cortex"));
}

#[test]
fn clamps_oversized_skill_name_to_256_chars() {
    let long_name = "a".repeat(300);
    let text = format!("<skill><name>{long_name}</name></skill>");
    let events = extract_codex_skill_events(&text);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].skill_name.chars().count(), 256);
}

#[test]
fn rejects_codex_skill_name_containing_ansi_escape() {
    // Eng review Fix 8 — same adversarial-input rejection as Task 2's
    // Claude test, but through the Codex tag-scanning path.
    let text = "<skill><name>\u{1b}[2J\u{1b}[31mFAKE</name></skill>";
    assert!(extract_codex_skill_events(text).is_empty());
}

#[test]
fn rejects_codex_skill_name_containing_embedded_newline() {
    let text = "<skill><name>real-skill\nFAKE APPROVED LINE</name></skill>";
    assert!(extract_codex_skill_events(text).is_empty());
}

#[test]
fn short_circuits_when_text_has_no_skill_tag_substring() {
    // Eng review Fix 1 — cheap bound on the common (no-skill-event) case:
    // text without a literal "<skill>" substring never reaches the regex
    // engine. This is a behavioral assertion (empty result), not a proof of
    // the short-circuit itself — see Task 6/7 for where the caller-side
    // substring check actually lives.
    let text = "just a normal transcript line with no tags at all";
    assert!(extract_codex_skill_events(text).is_empty());
}
