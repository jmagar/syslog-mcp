use super::{
    IdentityError, MAX_EVENT_KEY_BYTES, actor_key, canonical_tool, event_key, repository_key,
    run_key, worktree_key,
};

#[test]
fn canonical_tool_normalizes_known_unknown_and_explicit_unknown_values() {
    assert_eq!(canonical_tool(" Claude ").unwrap(), "claude");
    assert_eq!(canonical_tool("CoDeX").unwrap(), "codex");
    assert_eq!(canonical_tool("GEMINI").unwrap(), "gemini");
    assert_eq!(canonical_tool("claude-code").unwrap(), "claude");
    assert_eq!(canonical_tool("openai-codex").unwrap(), "codex");
    assert_eq!(canonical_tool("gemini-transcript").unwrap(), "gemini");
    assert_eq!(
        canonical_tool(" OpenAI DevTools ").unwrap(),
        "unknown:openai devtools"
    );
    assert_eq!(canonical_tool(" UNKNOWN:ΔΕΛΤΑ ").unwrap(), "unknown:δελτα");
}

#[test]
fn run_key_matches_contract_and_trims_identity_components() {
    assert_eq!(
        run_key(
            " devhost ",
            " Claude ",
            " 00112233-4455-6677-8899-aabbccddeeff "
        )
        .unwrap(),
        "v1|7:devhost|6:claude|36:00112233-4455-6677-8899-aabbccddeeff"
    );
}

#[test]
fn unicode_lengths_are_counted_in_utf8_bytes() {
    assert_eq!(
        run_key("猫", "Claude", "会話").unwrap(),
        "v1|3:猫|6:claude|6:会話"
    );
    assert_eq!(
        repository_key("猫", "/srv/会話/.git").unwrap(),
        "v1|3:猫|16:/srv/会話/.git"
    );
}

#[test]
fn length_prefixes_make_delimiter_characters_unambiguous() {
    assert_eq!(
        repository_key("do|ok:ie", "/srv/repo|main:.git").unwrap(),
        "v1|8:do|ok:ie|19:/srv/repo|main:.git"
    );
    assert_eq!(
        worktree_key("do|ok:ie", "/srv/repo|main:wt").unwrap(),
        "v1|8:do|ok:ie|17:/srv/repo|main:wt"
    );
}

#[test]
fn actor_key_nests_the_complete_run_key_without_ambiguity() {
    let run = run_key("devhost", "Claude", "session-1").unwrap();
    assert_eq!(
        actor_key(&run, "agent:1").unwrap(),
        format!("v1|{}:{run}|7:agent:1", run.len())
    );
}

#[test]
fn event_key_is_deterministic_and_allows_delimiters_in_source_identity() {
    assert_eq!(
        event_key("otel_spans", "trace:span|1", "primary").unwrap(),
        "v1:otel_spans:trace:span|1:primary"
    );
    assert_eq!(
        event_key("repository_observations", "42", "git_head").unwrap(),
        "v1:repository_observations:42:git_head"
    );
}

#[test]
fn event_key_rejects_non_lower_snake_components() {
    for invalid in ["OTEL_SPANS", "otel-spans", "_otel", "otel_", "otel__spans"] {
        assert_eq!(
            event_key(invalid, "1", "primary"),
            Err(IdentityError::InvalidLowerSnake("source_kind"))
        );
    }
    assert_eq!(
        event_key("logs", "1", "Primary"),
        Err(IdentityError::InvalidLowerSnake("projection_variant"))
    );
}

#[test]
fn event_key_enforces_1024_byte_contract_limit() {
    let exact = "x".repeat(MAX_EVENT_KEY_BYTES - "v1:logs::primary".len());
    let key = event_key("logs", &exact, "primary").unwrap();
    assert_eq!(key.len(), MAX_EVENT_KEY_BYTES);

    let oversized = format!("{exact}x");
    assert_eq!(
        event_key("logs", &oversized, "primary"),
        Err(IdentityError::EventKeyTooLong {
            actual: MAX_EVENT_KEY_BYTES + 1,
            max: MAX_EVENT_KEY_BYTES,
        })
    );
}

#[test]
fn every_identity_rejects_empty_trimmed_components() {
    assert_eq!(canonical_tool("  "), Err(IdentityError::Empty("tool")));
    assert_eq!(
        run_key("", "claude", "session"),
        Err(IdentityError::Empty("host"))
    );
    assert_eq!(
        run_key("host", "", "session"),
        Err(IdentityError::Empty("tool"))
    );
    assert_eq!(
        run_key("host", "claude", ""),
        Err(IdentityError::Empty("session"))
    );
    assert_eq!(
        repository_key("host", "  "),
        Err(IdentityError::Empty("common_git_dir"))
    );
    assert_eq!(
        worktree_key("host", "  "),
        Err(IdentityError::Empty("worktree_path"))
    );
    assert_eq!(
        actor_key("  ", "actor"),
        Err(IdentityError::Empty("run_key"))
    );
    assert_eq!(
        actor_key("run", "  "),
        Err(IdentityError::Empty("actor_id"))
    );
    assert_eq!(
        event_key("logs", "  ", "primary"),
        Err(IdentityError::Empty("source_primary_key"))
    );
}

#[test]
fn property_style_vectors_are_stable_across_repeated_calls() {
    let vectors = [
        ("devhost", "claude", "abc"),
        (" host:one ", "Custom Tool", "session|two"),
        ("δοκιμή", "Gemini", "会話:三"),
    ];

    for (host, tool, session) in vectors {
        let first = run_key(host, tool, session).unwrap();
        for _ in 0..32 {
            assert_eq!(run_key(host, tool, session).unwrap(), first);
        }
    }
}
