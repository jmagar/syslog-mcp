use super::*;
use serial_test::serial;

struct EnvGuard {
    name: &'static str,
    previous: Option<String>,
}

impl EnvGuard {
    fn set(name: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
        let previous = crate::env::var(name).ok();
        crate::env::set_test_var(name, value);
        Self { name, previous }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => {
                crate::env::set_test_var(self.name, value);
            }
            None => {
                crate::env::remove_test_var(self.name);
            }
        }
    }
}

#[cfg(unix)]
fn executable_file(path: &std::path::Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;

    std::fs::write(path, body).unwrap();
    let mut perms = std::fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).unwrap();
}

#[test]
fn ensure_env_file_preserves_existing_token_and_adds_compose_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join(".env");
    let data_dir = dir.path().join("data");
    std::fs::write(&env_path, "CORTEX_TOKEN=keep-me\n").unwrap();

    let result = ensure_env_file(&env_path, &data_dir).unwrap();
    let raw = std::fs::read_to_string(&env_path).unwrap();

    assert_eq!(
        result.values.get("CORTEX_TOKEN").map(String::as_str),
        Some("keep-me")
    );
    assert!(raw.contains("CORTEX_TOKEN=keep-me"));
    assert!(raw.contains("CORTEX_DATA_VOLUME="));
    assert!(raw.contains("CORTEX_DB_PATH="));
    assert!(raw.contains("COMPOSE_PROJECT_NAME="));
}

/// `CORTEX_API_TOKEN` is always provisioned (API is unconditionally mounted).
/// First run on a clean .env generates a 64-char hex token (32 bytes hex-encoded).
#[test]
fn ensure_env_file_generates_api_token_when_missing() {
    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join(".env");
    let data_dir = dir.path().join("data");

    let result = ensure_env_file(&env_path, &data_dir).unwrap();

    let token = result
        .values
        .get("CORTEX_API_TOKEN")
        .expect("CORTEX_API_TOKEN must be present after ensure_env_file");
    // The implementation generates 32 random bytes encoded as hex → exactly
    // 64 ASCII chars. Lock down the precise length so future refactors that
    // shorten the token (and weaken brute-force resistance) fail this test.
    assert_eq!(
        token.len(),
        64,
        "generated CORTEX_API_TOKEN must be 64 hex chars (32 random bytes), got {} chars",
        token.len()
    );
    assert!(
        token.chars().all(|c| c.is_ascii_hexdigit()),
        "generated CORTEX_API_TOKEN must be hex"
    );
    let raw = std::fs::read_to_string(&env_path).unwrap();
    assert!(raw.contains(&format!("CORTEX_API_TOKEN={token}")));
}

/// Re-running `ensure_env_file` against a .env that already has a
/// CORTEX_API_TOKEN must preserve it byte-for-byte — mirrors the
/// CORTEX_TOKEN contract that operators depend on for token rotation.
#[test]
fn ensure_env_file_preserves_existing_api_token_byte_for_byte() {
    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join(".env");
    let data_dir = dir.path().join("data");
    std::fs::write(
        &env_path,
        "CORTEX_TOKEN=mcp-keep\nCORTEX_API_TOKEN=api-keep-me-exactly\n",
    )
    .unwrap();

    let result = ensure_env_file(&env_path, &data_dir).unwrap();

    assert_eq!(
        result.values.get("CORTEX_API_TOKEN").map(String::as_str),
        Some("api-keep-me-exactly")
    );
    let raw = std::fs::read_to_string(&env_path).unwrap();
    assert!(raw.contains("CORTEX_API_TOKEN=api-keep-me-exactly"));
}

/// Cutover (bead 0p8r.10): on first install, `ensure_env_file` writes
/// `CORTEX_USE_HTTP=true` so the CLI defaults to HTTP transport via the
/// container REST API.
#[test]
fn ensure_env_file_sets_use_http_true_when_missing() {
    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join(".env");
    let data_dir = dir.path().join("data");

    let result = ensure_env_file(&env_path, &data_dir).unwrap();

    assert_eq!(
        result.values.get("CORTEX_USE_HTTP").map(String::as_str),
        Some("true"),
        "first install must default CORTEX_USE_HTTP=true"
    );
    let raw = std::fs::read_to_string(&env_path).unwrap();
    assert!(
        raw.contains("CORTEX_USE_HTTP=true"),
        "rendered .env must contain CORTEX_USE_HTTP=true literally"
    );
}

/// Operator opt-out (`CORTEX_USE_HTTP=false`) must survive `setup repair`
/// byte-for-byte — unlike CORTEX_API_TOKEN, this is a behaviour toggle the
/// operator may legitimately disable.
#[test]
fn ensure_env_file_preserves_use_http_false_byte_for_byte() {
    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join(".env");
    let data_dir = dir.path().join("data");
    std::fs::write(&env_path, "CORTEX_USE_HTTP=false\n").unwrap();

    let result = ensure_env_file(&env_path, &data_dir).unwrap();

    assert_eq!(
        result.values.get("CORTEX_USE_HTTP").map(String::as_str),
        Some("false"),
        "operator override CORTEX_USE_HTTP=false must be preserved exactly"
    );
    let raw = std::fs::read_to_string(&env_path).unwrap();
    assert!(raw.contains("CORTEX_USE_HTTP=false"));
    assert!(!raw.contains("CORTEX_USE_HTTP=true"));
}

/// Idempotent re-run: when `CORTEX_USE_HTTP=true` already exists, repair
/// leaves it untouched (no double-write, no value rewrite).
#[test]
fn ensure_env_file_preserves_use_http_true_on_rerun() {
    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join(".env");
    let data_dir = dir.path().join("data");
    std::fs::write(&env_path, "CORTEX_USE_HTTP=true\n").unwrap();

    let result = ensure_env_file(&env_path, &data_dir).unwrap();

    assert_eq!(
        result.values.get("CORTEX_USE_HTTP").map(String::as_str),
        Some("true")
    );
    let raw = std::fs::read_to_string(&env_path).unwrap();
    // Exactly one occurrence — write_env must not duplicate the key.
    assert_eq!(
        raw.matches("CORTEX_USE_HTTP=").count(),
        1,
        "CORTEX_USE_HTTP must appear exactly once after re-run"
    );
}

/// Empty value (`CORTEX_USE_HTTP=`) is treated as an explicit operator
/// choice and preserved. The CLI falls through to its compiled default in
/// that case; we do NOT silently rewrite to `true` because doing so would
/// override an operator who wrote the line intentionally blank to "let the
/// binary decide". Mirrors the wider design: operator intent always wins
/// for behaviour toggles.
#[test]
fn ensure_env_file_preserves_empty_use_http_value() {
    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join(".env");
    let data_dir = dir.path().join("data");
    std::fs::write(&env_path, "CORTEX_USE_HTTP=\n").unwrap();

    let result = ensure_env_file(&env_path, &data_dir).unwrap();

    assert_eq!(
        result.values.get("CORTEX_USE_HTTP").map(String::as_str),
        Some(""),
        "empty CORTEX_USE_HTTP must be preserved (operator intent wins)"
    );
}

/// Blank API token must be replaced (an empty value would still fail the
/// runtime `api.rs` token check and brick container startup).
#[test]
fn ensure_env_file_replaces_blank_api_token() {
    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join(".env");
    let data_dir = dir.path().join("data");
    std::fs::write(&env_path, "CORTEX_API_TOKEN=\n").unwrap();

    let result = ensure_env_file(&env_path, &data_dir).unwrap();

    let token = result.values.get("CORTEX_API_TOKEN").unwrap();
    assert!(!token.trim().is_empty());
    assert!(token.len() >= 32);
}

/// Atomic `write_env`: the live target file is either fully written or
/// unchanged. Crucial because a corrupt .env bricks container startup
/// (api.rs bails on empty CORTEX_API_TOKEN).
#[test]
fn write_env_replaces_file_atomically() {
    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join(".env");
    std::fs::write(&env_path, "OLD=value\n").unwrap();

    let mut env = std::collections::BTreeMap::new();
    env.insert("NEW".to_string(), "fresh".to_string());
    env.insert("SECRET".to_string(), "shhh".to_string());
    write_env(&env_path, &env).unwrap();

    let raw = std::fs::read_to_string(&env_path).unwrap();
    assert!(raw.contains("NEW=fresh"));
    assert!(raw.contains("SECRET=shhh"));
    assert!(!raw.contains("OLD=value"));

    // No orphaned tempfiles in the directory after a successful write.
    for entry in std::fs::read_dir(dir.path()).unwrap().flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // write_env names its tempfile `.{file_name}.tmp.{pid}.{nanos}`.
        // For `.env` that's `..env.tmp.*`. Match the actual prefix so the
        // assertion catches real orphans instead of silently passing.
        assert!(
            !name.starts_with("..env.tmp."),
            "orphaned tempfile after write_env: {name}"
        );
    }
}

/// Permission check (Unix only): atomic write must still produce a 0o600 file.
#[cfg(unix)]
#[test]
fn write_env_sets_0600_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join(".env");
    let mut env = std::collections::BTreeMap::new();
    env.insert("K".to_string(), "v".to_string());
    write_env(&env_path, &env).unwrap();

    let mode = std::fs::metadata(&env_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "expected 0o600 perms, got {mode:o}");
}

#[test]
fn parse_env_ignores_comments_and_blank_lines() {
    let parsed = parse_env("\n# comment\nA=1\nB = two\n");
    assert_eq!(parsed.get("A").map(String::as_str), Some("1"));
    assert_eq!(parsed.get("B").map(String::as_str), Some("two"));
}

#[test]
fn parse_env_preserves_equals_inside_values_and_trims_outer_whitespace() {
    let parsed = parse_env(" URL = https://example.test/path?a=1&b=2 \nBROKEN\nEMPTY=\n");

    assert_eq!(
        parsed.get("URL").map(String::as_str),
        Some("https://example.test/path?a=1&b=2")
    );
    assert_eq!(parsed.get("EMPTY").map(String::as_str), Some(""));
    assert!(
        !parsed.contains_key("BROKEN"),
        "lines without '=' are ignored"
    );
}

#[test]
fn default_env_for_data_dir_uses_agent_docker_defaults_and_required_tokens() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");

    let env = default_env_for_data_dir(&data_dir).unwrap();

    assert_eq!(
        env.get("CORTEX_DOCKER_INGEST_ENABLED").map(String::as_str),
        Some("false"),
        "fresh setup must keep legacy central Docker ingest disabled"
    );
    assert!(
        !env.contains_key("CORTEX_DOCKER_HOSTS"),
        "remote Docker Engine hosts are opt-in compatibility config only"
    );
    assert_eq!(
        env.get("CORTEX_DATA_VOLUME").map(String::as_str),
        Some(data_dir.to_string_lossy().as_ref())
    );
    for key in ["CORTEX_TOKEN", "CORTEX_API_TOKEN"] {
        let token = env.get(key).expect("token default must be generated");
        assert_eq!(token.len(), 64, "{key} must be 64 hex chars");
        assert!(
            token.chars().all(|c| c.is_ascii_hexdigit()),
            "{key} must be hex"
        );
    }
}

#[test]
fn filesystem_phase_check_warns_when_setup_dirs_are_missing() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join(".cortex");
    let data_dir = home.join("data");
    let compose_dir = home.join("compose");

    let phase = filesystem_phase(SetupMode::Check, &home, &data_dir, &compose_dir).unwrap();

    assert_eq!(phase.name, "filesystem");
    assert_eq!(phase.status, SetupStatus::Warn);
    assert!(phase.detail.contains("missing setup dirs"));
}

#[test]
fn filesystem_phase_repair_creates_private_runtime_directories() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join(".cortex");
    let data_dir = home.join("data");
    let backup_dir = home.join("backups");
    let compose_dir = home.join("compose");

    let phase = filesystem_phase(SetupMode::Repair, &home, &data_dir, &compose_dir).unwrap();

    assert_eq!(phase.status, SetupStatus::Ok);
    assert!(home.is_dir());
    assert!(data_dir.is_dir());
    assert!(backup_dir.is_dir());
    assert!(compose_dir.is_dir());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let home_mode = std::fs::metadata(&home).unwrap().permissions().mode() & 0o777;
        let data_mode = std::fs::metadata(&data_dir).unwrap().permissions().mode() & 0o777;
        let backup_mode = std::fs::metadata(&backup_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(home_mode, 0o700);
        assert_eq!(data_mode, 0o700);
        assert_eq!(backup_mode, 0o700);
    }
}

#[test]
fn write_compose_assets_writes_installed_compose_and_dockerfile() {
    let dir = tempfile::tempdir().unwrap();
    let compose_dir = dir.path().join("compose");

    let phase = write_compose_assets(&compose_dir).unwrap();

    assert_eq!(phase.status, SetupStatus::Ok);
    let compose = std::fs::read_to_string(compose_dir.join("docker-compose.yml")).unwrap();
    let dockerfile = std::fs::read_to_string(compose_dir.join("config/Dockerfile")).unwrap();
    assert_eq!(compose, installed_compose_asset());
    assert_eq!(dockerfile, dockerfile_asset());
    assert!(compose.contains("      - path: ../.env\n"));
}

#[test]
fn installed_compose_asset_uses_published_image_only() {
    // COMPOSE_ASSET is now docker-compose.prod.yml — the publishable template.
    assert!(COMPOSE_ASSET.contains("image: ghcr.io/dinglebear-ai/cortex:"));
    assert!(!COMPOSE_ASSET.contains("syslog-setup-build-stanza"));
    assert!(!COMPOSE_ASSET.contains("\n    build:\n"));

    let compose = installed_compose_asset();
    assert_ne!(compose, COMPOSE_ASSET);
    assert!(compose.contains("image: ghcr.io/dinglebear-ai/cortex:"));
    assert!(compose.contains("      - path: ../.env\n"));
    // env_file path is rewritten — source pattern must not survive.
    assert!(!compose.contains("      - path: .env\n"));
}

#[test]
fn installed_compose_asset_memory_limit_is_configurable_with_2g_default() {
    // Issue 3: the memory limit must default to 2G (was 512M, which OOM'd on
    // heavy stats queries) and be overridable via CORTEX_MEMORY_LIMIT so a
    // fresh deploy picks up the safer default and operators can tune it.
    assert!(
        COMPOSE_ASSET.contains("memory: ${CORTEX_MEMORY_LIMIT:-2G}"),
        "compose asset must use a configurable 2G memory limit"
    );
    assert!(
        !COMPOSE_ASSET.contains("memory: 512M"),
        "compose asset must not hardcode the old 512M limit"
    );
    // The installed transform must preserve the configurable limit.
    let compose = installed_compose_asset();
    assert!(compose.contains("memory: ${CORTEX_MEMORY_LIMIT:-2G}"));
}

#[test]
fn installed_compose_asset_keeps_graph_projection_current() {
    assert!(COMPOSE_ASSET.contains(
        "CORTEX_GRAPH_REFRESH_INTERVAL_SECS: \"${CORTEX_GRAPH_REFRESH_INTERVAL_SECS:-300}\""
    ));
    assert!(COMPOSE_ASSET.contains(
        "CORTEX_INVENTORY_GRAPH_PROJECTION_ENABLED: \"${CORTEX_INVENTORY_GRAPH_PROJECTION_ENABLED:-true}\""
    ));
}

#[test]
fn ai_index_timer_script_uses_host_cortex_and_disables_docker_ingest() {
    let script = ai_index_script();
    assert!(script.contains("command -v cortex"));
    assert!(script.contains("cortex --version"));
    assert!(script.contains("cortex sessions index --json"));
    assert!(script.contains("CORTEX_DOCKER_INGEST_ENABLED"));
    assert!(script.contains(".claude/plugins/data/syslog-jmagar-lab/cortex.db"));
}

#[test]
fn ai_index_timer_units_are_host_user_units() {
    let unit = ai_index_service_unit(std::path::Path::new(
        "/home/me/.local/bin/cortex-sessions-index",
    ));
    let timer = ai_index_timer_unit();

    assert!(unit.contains("Description=cortex local AI transcript index"));
    assert!(unit.contains("ExecStart=/home/me/.local/bin/cortex-sessions-index"));
    assert!(timer.contains("OnUnitActiveSec=30min"));
    assert!(timer.contains("WantedBy=timers.target"));
}

#[test]
fn ai_watch_env_file_pins_db_and_disables_docker_ingest() {
    let env = ai_watch_env_file(std::path::Path::new("/home/me/cortex.db"));
    assert!(env.contains("CORTEX_DB_PATH=/home/me/cortex.db"));
    assert!(env.contains("CORTEX_DOCKER_INGEST_ENABLED=false"));
    assert!(env.contains("RUST_LOG=warn"));
}

#[test]
fn ai_watch_service_unit_is_hardened_and_uses_absolute_exec() {
    let unit = ai_watch_service_unit(
        std::path::Path::new("/home/me/.local/bin/cortex"),
        std::path::Path::new("/home/me/.config/cortex/ai-watch.env"),
        std::path::Path::new("/home/me/.cortex/data/cortex.db"),
        std::path::Path::new("/home/me/.local/state/cortex"),
        std::path::Path::new("/home/me"),
    );

    assert!(unit.contains("Type=simple"));
    assert!(unit.contains("EnvironmentFile=/home/me/.config/cortex/ai-watch.env"));
    assert!(unit.contains(
        "Environment=PATH=/home/me/.local/bin:/home/me/.cargo/bin:/usr/local/bin:/usr/bin:/bin"
    ));
    assert!(
        unit.contains("Environment=CARGO_TARGET_DIR=/home/me/.local/state/cortex/cargo-target")
    );
    assert!(unit.contains("WorkingDirectory=/"));
    assert!(
        unit.contains(
            "ExecStart=/home/me/.local/bin/cortex sessions watch --no-initial-scan --json"
        )
    );
    assert!(unit.contains("Restart=on-failure"));
    assert!(unit.contains("StartLimitBurst=20"));
    assert!(unit.contains("UMask=0077"));
    assert!(unit.contains("NoNewPrivileges=true"));
    assert!(unit.contains("PrivateTmp=true"));
    assert!(unit.contains("ProtectSystem=strict"));
    assert!(unit.contains("ProtectHome=read-only"));
    assert!(
        unit.contains("BindReadOnlyPaths=-/home/me/.claude/projects -/home/me/.codex/sessions")
    );
    assert!(unit.contains("-/home/me/.gemini/tmp"));
    assert!(unit.contains("-/home/me/.gemini/antigravity/brain"));
    assert!(unit.contains("-/home/me/.gemini/antigravity-cli/brain"));
    assert!(unit.contains("BindPaths=/home/me/.cortex/data /home/me/.local/state/cortex"));
    assert!(unit.contains("ReadWritePaths=/home/me/.cortex/data /home/me/.local/state/cortex"));
    assert!(unit.contains("WantedBy=default.target"));
}

#[test]
fn setup_path_value_rejects_unit_breaking_characters() {
    assert!(setup_path_value(std::path::Path::new("/home/me/cortex.db")).is_ok());
    assert!(setup_path_value(std::path::Path::new("/home/me/bad path/cortex.db")).is_err());
    assert!(setup_path_value(std::path::Path::new("/home/me/%n/cortex.db")).is_err());
}

#[test]
fn ai_watch_service_content_phase_detects_stale_unit() {
    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join("ai-watch.env");
    let service_path = dir.path().join("cortex-sessions-watch.service");
    let state_dir = dir.path().join("state");
    let db_path = dir.path().join("data/cortex.db");
    let user_home = dir.path().join("home");
    let bin = dir.path().join("bin/cortex");
    std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
    std::fs::write(&bin, "#!/bin/sh\n").unwrap();
    std::fs::write(&env_path, ai_watch_env_file(&db_path)).unwrap();
    std::fs::write(&service_path, "stale unit").unwrap();

    let phase = check_ai_watch_service_content_phase(
        &env_path,
        &service_path,
        &state_dir,
        &bin,
        &db_path,
        &user_home,
    );

    assert!(matches!(phase.status, SetupStatus::Error));
    assert!(
        phase
            .detail
            .contains("does not match generated AI watch unit")
    );
}

#[test]
fn ai_watch_service_content_phase_accepts_generated_files() {
    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join("ai-watch.env");
    let service_path = dir.path().join("cortex-sessions-watch.service");
    let state_dir = dir.path().join("state");
    let db_path = dir.path().join("data/cortex.db");
    let user_home = dir.path().join("home");
    let bin = dir.path().join("bin/cortex");
    std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
    std::fs::write(&bin, "#!/bin/sh\n").unwrap();
    std::fs::write(&env_path, ai_watch_env_file(&db_path)).unwrap();
    std::fs::write(
        &service_path,
        ai_watch_service_unit(&bin, &env_path, &db_path, &state_dir, &user_home),
    )
    .unwrap();

    let phase = check_ai_watch_service_content_phase(
        &env_path,
        &service_path,
        &state_dir,
        &bin,
        &db_path,
        &user_home,
    );

    assert_eq!(phase.status, SetupStatus::Ok);
    assert_eq!(
        phase.detail,
        "AI watch service files match generated content"
    );
}

#[test]
fn debug_wrapper_script_builds_current_repo_debug_binary() {
    let script = debug_wrapper_script(std::path::Path::new("/home/me/workspace/cortex"));

    assert!(script.contains(r#"repo="${CORTEX_REPO:-/home/me/workspace/cortex}""#));
    assert!(script.contains(r#"repo="${HOME}/workspace/cortex""#));
    assert!(script.contains(r#"export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-.cache/cargo}""#));
    assert!(script.contains("CORTEX_DOCKER_INGEST_ENABLED"));
    assert!(script.contains("CORTEX_AUTH_MODE"));
    assert!(script.contains("cargo build --quiet --bin cortex"));
    assert!(script.contains(r#"exec "${CARGO_TARGET_DIR}/debug/cortex" "$@""#));
}

#[test]
fn debug_wrapper_content_phase_detects_stale_wrapper() {
    let dir = tempfile::tempdir().unwrap();
    let wrapper = dir.path().join("cortex");
    std::fs::write(&wrapper, "#!/bin/sh\nexec old\n").unwrap();

    let phase = check_debug_wrapper_content_phase(&wrapper, dir.path());

    assert!(matches!(phase.status, SetupStatus::Error));
    assert!(
        phase
            .detail
            .contains("does not match generated debug wrapper")
    );
}

#[test]
fn debug_compose_override_builds_local_debug_image_from_repo() {
    let override_yaml = debug_compose_override(std::path::Path::new("/home/me/workspace/cortex"));

    assert!(override_yaml.contains("image: cortex:local-debug"));
    assert!(override_yaml.contains("context: /home/me/workspace/cortex"));
    assert!(override_yaml.contains("dockerfile: config/Dockerfile"));
    assert!(override_yaml.contains("CORTEX_BUILD_PROFILE: debug"));
}

#[test]
fn debug_compose_content_phase_detects_stale_override() {
    let dir = tempfile::tempdir().unwrap();
    let override_path = dir.path().join("docker-compose.override.yml");
    std::fs::write(&override_path, "services: {}\n").unwrap();

    let phase = check_debug_compose_content_phase(&override_path, dir.path());

    assert!(matches!(phase.status, SetupStatus::Error));
    assert!(
        phase
            .detail
            .contains("does not match generated debug Compose override")
    );
}

#[test]
fn transcript_root_permissions_phase_reports_missing_roots() {
    let dir = tempfile::tempdir().unwrap();

    let phase = transcript_root_permissions_phase(dir.path());

    assert!(matches!(phase.status, SetupStatus::Error));
    assert!(phase.detail.contains(".claude/projects"));
    assert!(phase.detail.contains(".codex/sessions"));
    assert!(phase.detail.contains(".gemini/tmp"));
    assert!(phase.detail.contains(".gemini/antigravity/brain"));
    assert!(phase.detail.contains(".gemini/antigravity-cli/brain"));
}

#[test]
fn transcript_root_permissions_phase_accepts_owned_writable_roots() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(".claude/projects")).unwrap();
    std::fs::create_dir_all(dir.path().join(".codex/sessions")).unwrap();
    std::fs::create_dir_all(dir.path().join(".gemini/tmp")).unwrap();
    std::fs::create_dir_all(dir.path().join(".gemini/antigravity/brain")).unwrap();
    std::fs::create_dir_all(dir.path().join(".gemini/antigravity-cli/brain")).unwrap();

    let phase = transcript_root_permissions_phase(dir.path());

    assert_eq!(phase.status, SetupStatus::Ok);
    assert_eq!(
        phase.detail,
        "AI transcript roots are owned/readable/writable"
    );
}

#[test]
fn summarize_ai_index_output_reports_key_counts() {
    let summary = summarize_ai_index_output(
        r#"{
  "discovered_files": 3,
  "ingested": 2,
  "skipped_dupes": 1,
  "parse_errors": 4,
  "storage_blocked_chunks": 0,
  "file_errors": ["bad"]
}"#,
    );

    assert_eq!(
        summary,
        "indexed files=3 ingested=2 duplicates=1 parse_errors=4 storage_blocked=0 dropped_metadata_fields=0 file_errors=1; inspect with `cortex sessions errors --limit 20`, `cortex sessions checkpoints --errors`, then rerun `cortex sessions index --json` after fixes"
    );
}

#[test]
fn summarize_ai_index_output_reports_invalid_json() {
    assert_eq!(
        summarize_ai_index_output("not json"),
        "invalid ai index JSON output"
    );
}

#[test]
fn ai_index_output_status_classifies_blocking_and_recoverable_failures() {
    assert_eq!(
        ai_index_output_status(r#"{"parse_errors":0,"storage_blocked_chunks":0,"file_errors":[]}"#),
        (SetupStatus::Ok, None)
    );
    assert_eq!(
        ai_index_output_status(r#"{"parse_errors":1,"storage_blocked_chunks":0,"file_errors":[]}"#),
        (SetupStatus::Warn, Some(SetupIssueKind::DataQualityWarning))
    );
    assert_eq!(
        ai_index_output_status(r#"{"parse_errors":0,"storage_blocked_chunks":1,"file_errors":[]}"#),
        (SetupStatus::Error, Some(SetupIssueKind::BlockingError))
    );
    assert_eq!(
        ai_index_output_status(
            r#"{"parse_errors":0,"storage_blocked_chunks":0,"file_errors":["bad"]}"#
        ),
        (SetupStatus::Warn, Some(SetupIssueKind::DataQualityWarning))
    );
    assert_eq!(
        ai_index_output_status(
            r#"{"parse_errors":0,"storage_blocked_chunks":0,"dropped_metadata_fields":1,"file_errors":[]}"#
        ),
        (SetupStatus::Warn, Some(SetupIssueKind::DataQualityWarning))
    );
    assert_eq!(
        ai_index_output_status("not json"),
        (SetupStatus::Error, Some(SetupIssueKind::BlockingError))
    );
}

#[test]
fn ai_watch_systemd_enable_gate_allows_data_quality_warnings() {
    let phases = vec![
        PhaseTimer::start("sessions-watch-service-files").finish(SetupStatus::Ok, "ok"),
        PhaseTimer::start("ai-watch-initial-index").finish_with_issue(
            SetupStatus::Warn,
            Some(SetupIssueKind::DataQualityWarning),
            "parse_errors=1",
        ),
    ];
    assert!(!should_skip_ai_watch_systemd_enable(&phases));

    let mut phases_with_error = phases;
    phases_with_error.push(PhaseTimer::start("systemd").finish_with_issue(
        SetupStatus::Error,
        Some(SetupIssueKind::BlockingError),
        "systemctl failed",
    ));
    assert!(should_skip_ai_watch_systemd_enable(&phases_with_error));
}

#[test]
fn setup_report_exposes_ai_watch_summary_fields() {
    let phases = vec![
        PhaseTimer::start("ai-watch-initial-index").finish_with_issue(
            SetupStatus::Warn,
            Some(SetupIssueKind::DataQualityWarning),
            "parse_errors=1",
        ),
        PhaseTimer::start(AI_WATCH_SERVICE_ENABLED_PHASE).finish(SetupStatus::Ok, "enabled"),
        PhaseTimer::start(AI_WATCH_SERVICE_ACTIVE_PHASE).finish(SetupStatus::Error, "inactive"),
    ];
    let report = setup_report(
        SetupReportInput {
            mode: "sessions-watch-service-check",
            elapsed_ms: 0,
            home: PathBuf::from("/tmp/home"),
            env_path: PathBuf::from("/tmp/home/.env"),
            compose_dir: PathBuf::from("/tmp/home/compose"),
            data_dir: PathBuf::from("/tmp/home/data"),
            health_url: "host-local helper".to_string(),
            mcp_url: "host-local helper".to_string(),
        },
        phases,
    );

    assert!(report.has_errors);
    assert_eq!(report.blocking_errors, 1);
    assert_eq!(report.data_quality_warnings, 1);
    assert_eq!(report.service_enabled, Some(true));
    assert_eq!(report.watcher_healthy, Some(false));
}

#[test]
fn inferred_user_bus_env_uses_runtime_bus_when_present() {
    let Some((runtime_dir, bus_address)) = inferred_user_bus_env() else {
        return;
    };

    assert!(runtime_dir.is_absolute());
    assert!(bus_address.starts_with("unix:path="));
    assert!(bus_address.ends_with("/bus"));
}

#[cfg(unix)]
#[test]
#[serial]
fn systemctl_user_phases_use_mocked_systemctl_status_and_output() {
    let dir = tempfile::tempdir().unwrap();
    let bin_dir = dir.path().join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    executable_file(
        &bin_dir.join("systemctl"),
        r#"#!/bin/sh
case "$*" in
  "--user ok") printf 'done\n'; exit 0 ;;
  "--user fail") printf 'inactive\n'; printf 'ignored stderr\n' >&2; exit 4 ;;
  "--user is-active cortex.service") printf 'active\n'; exit 3 ;;
  *) printf 'unexpected args: %s\n' "$*" >&2; exit 9 ;;
esac
"#,
    );
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        crate::env::var("PATH").unwrap_or_default()
    );
    let _path_guard = EnvGuard::set("PATH", path);

    let ok = systemctl_user_named_phase("mock-systemctl", &["ok"]);
    let optional = systemctl_user_named_phase("mock-systemctl", &["fail"]);
    let required = systemctl_user_required_named_phase("mock-systemctl", &["fail"]);
    let state = systemctl_user_state("is-active", "cortex.service");

    assert_eq!(ok.status, SetupStatus::Ok);
    assert_eq!(ok.detail, "done");
    assert_eq!(optional.status, SetupStatus::Warn);
    assert_eq!(optional.detail, "inactive");
    assert_eq!(required.status, SetupStatus::Error);
    assert_eq!(required.detail, "inactive");
    assert_eq!(state.as_deref(), Some("active"));
}

#[cfg(unix)]
#[test]
#[serial]
fn command_phase_reports_success_failure_and_missing_binary() {
    let dir = tempfile::tempdir().unwrap();
    let bin_dir = dir.path().join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    executable_file(
        &bin_dir.join("docker"),
        r#"#!/bin/sh
case "$*" in
  "--version") printf 'Docker version 99\n'; exit 0 ;;
  "compose version") printf 'Docker Compose version 88\n'; exit 0 ;;
  "bad") printf 'docker failed\n' >&2; exit 7 ;;
  *) printf 'unexpected args: %s\n' "$*" >&2; exit 9 ;;
esac
"#,
    );
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        crate::env::var("PATH").unwrap_or_default()
    );
    let _path_guard = EnvGuard::set("PATH", path);

    let docker = command_phase("docker", ["--version"]);
    let compose = command_phase("docker compose", ["compose", "version"]);
    let failed = command_phase("docker", ["bad"]);
    let missing = command_phase("missing-cortex-test-bin", ["--version"]);

    assert_eq!(docker.status, SetupStatus::Ok);
    assert_eq!(docker.detail, "Docker version 99");
    assert_eq!(compose.status, SetupStatus::Ok);
    assert_eq!(compose.detail, "Docker Compose version 88");
    assert_eq!(failed.status, SetupStatus::Error);
    assert_eq!(failed.detail, "docker failed");
    assert_eq!(missing.status, SetupStatus::Error);
    assert_eq!(missing.detail, "not found on PATH");
}

#[cfg(unix)]
#[test]
#[serial]
fn cleanup_legacy_systemd_removes_stale_units_and_dropins() {
    let dir = tempfile::tempdir().unwrap();
    let bin_dir = dir.path().join("bin");
    let home = dir.path().join("home");
    let systemd_dir = home.join(".config/systemd/user");
    let dropin_dir = systemd_dir.join("cortex.service.d");
    std::fs::create_dir_all(&bin_dir).unwrap();
    std::fs::create_dir_all(&dropin_dir).unwrap();
    std::fs::write(systemd_dir.join("cortex.service"), "stale\n").unwrap();
    std::fs::write(dropin_dir.join("override.conf"), "stale\n").unwrap();
    executable_file(
        &bin_dir.join("systemctl"),
        r#"#!/bin/sh
case "$*" in
  "--user disable --now cortex.service") exit 0 ;;
  "--user disable --now mnemo-index.service") exit 0 ;;
  "--user disable --now mnemo-index.timer") exit 0 ;;
  "--user daemon-reload") exit 0 ;;
  *) printf 'unexpected args: %s\n' "$*" >&2; exit 9 ;;
esac
"#,
    );
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        crate::env::var("PATH").unwrap_or_default()
    );
    let _path_guard = EnvGuard::set("PATH", path);
    let _home_guard = EnvGuard::set("HOME", &home);

    let phase = cleanup_legacy_systemd();

    assert_eq!(phase.status, SetupStatus::Ok);
    assert!(!systemd_dir.join("cortex.service").exists());
    assert!(!dropin_dir.exists());
}

#[test]
fn repair_rewrites_stale_commands_in_managed_systemd_units() {
    let dir = tempfile::tempdir().unwrap();
    let systemd_dir = dir.path().join("systemd");
    std::fs::create_dir_all(&systemd_dir).unwrap();
    let stale = systemd_dir.join("cortex-sessions-watch-doctor.service");
    std::fs::write(
        &stale,
        "[Service]\nExecStart=/usr/bin/cortex setup sessions-watch-health-check --json\n",
    )
    .unwrap();
    let unrelated = systemd_dir.join("unrelated.service");
    std::fs::write(
        &unrelated,
        "[Service]\nExecStart=/usr/bin/cortex setup sessions-watch-health-check --json\n",
    )
    .unwrap();

    let phase = rewrite_stale_managed_unit_commands(&systemd_dir).unwrap();

    assert_eq!(phase.status, SetupStatus::Ok);
    assert!(phase.detail.contains("rewrote 1 managed unit"));
    let repaired = std::fs::read_to_string(stale).unwrap();
    assert!(repaired.contains("setup sessionshealth --json"));
    assert!(!repaired.contains("sessions-watch-health-check"));
    assert!(
        std::fs::read_to_string(unrelated)
            .unwrap()
            .contains("sessions-watch-health-check")
    );
}

#[cfg(unix)]
#[test]
#[serial]
fn ensure_network_phase_inspects_before_creating_network() {
    let dir = tempfile::tempdir().unwrap();
    let bin_dir = dir.path().join("bin");
    let log = dir.path().join("docker.log");
    std::fs::create_dir_all(&bin_dir).unwrap();
    executable_file(
        &bin_dir.join("docker"),
        r#"#!/bin/sh
printf '%s\n' "$*" >> "$CORTEX_TEST_DOCKER_LOG"
case "$*" in
  "network inspect exists") exit 0 ;;
  "network inspect needs-create") exit 1 ;;
  "network create needs-create") printf 'made\n'; exit 0 ;;
  *) printf 'unexpected args: %s\n' "$*" >&2; exit 9 ;;
esac
"#,
    );
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        crate::env::var("PATH").unwrap_or_default()
    );
    let _path_guard = EnvGuard::set("PATH", path);
    let _log_guard = EnvGuard::set("CORTEX_TEST_DOCKER_LOG", &log);

    let mut phases = Vec::new();
    let mut env = std::collections::BTreeMap::new();
    env.insert("DOCKER_NETWORK".to_string(), "exists".to_string());
    ensure_network_phase(&mut phases, Some(&env));
    env.insert("DOCKER_NETWORK".to_string(), "needs-create".to_string());
    ensure_network_phase(&mut phases, Some(&env));

    assert_eq!(phases[0].status, SetupStatus::Ok);
    assert_eq!(phases[0].detail, "exists exists");
    assert_eq!(phases[1].status, SetupStatus::Ok);
    assert_eq!(phases[1].detail, "created needs-create");
    assert_eq!(
        std::fs::read_to_string(log).unwrap(),
        "network inspect exists\nnetwork inspect needs-create\nnetwork create needs-create\n"
    );
}

#[cfg(unix)]
#[test]
#[serial]
fn run_compose_phase_includes_env_compose_and_override_files() {
    let dir = tempfile::tempdir().unwrap();
    let bin_dir = dir.path().join("bin");
    let compose_dir = dir.path().join("compose");
    let env_path = dir.path().join(".env");
    let log = dir.path().join("docker.log");
    std::fs::create_dir_all(&bin_dir).unwrap();
    std::fs::create_dir_all(&compose_dir).unwrap();
    std::fs::write(compose_dir.join("docker-compose.yml"), "services: {}\n").unwrap();
    std::fs::write(
        compose_dir.join("docker-compose.override.yml"),
        "services: {}\n",
    )
    .unwrap();
    std::fs::write(&env_path, "CORTEX_PORT=3100\n").unwrap();
    executable_file(
        &bin_dir.join("docker"),
        r#"#!/bin/sh
printf 'cwd=%s args=%s\n' "$PWD" "$*" >> "$CORTEX_TEST_DOCKER_LOG"
printf 'compose ok\n'
exit 0
"#,
    );
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        crate::env::var("PATH").unwrap_or_default()
    );
    let _path_guard = EnvGuard::set("PATH", path);
    let _log_guard = EnvGuard::set("CORTEX_TEST_DOCKER_LOG", &log);

    let phase = run_compose_phase(&compose_dir, &env_path, &["up", "-d", "--build"]);

    assert_eq!(phase.status, SetupStatus::Ok);
    assert_eq!(phase.name, "compose-up");
    assert_eq!(phase.detail, "compose ok");
    let logged = std::fs::read_to_string(log).unwrap();
    assert!(logged.contains(&format!("cwd={}", compose_dir.display())));
    assert!(logged.contains(&format!("--env-file {}", env_path.display())));
    assert!(logged.contains(&format!(
        "-f {}",
        compose_dir.join("docker-compose.yml").display()
    )));
    assert!(logged.contains(&format!(
        "-f {}",
        compose_dir.join("docker-compose.override.yml").display()
    )));
    assert!(logged.contains("up -d --build"));
}

#[cfg(unix)]
#[test]
#[serial]
fn health_phase_uses_configured_port_and_reports_curl_errors() {
    let dir = tempfile::tempdir().unwrap();
    let bin_dir = dir.path().join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    executable_file(
        &bin_dir.join("curl"),
        r#"#!/bin/sh
case "$*" in
  *"http://127.0.0.1:3999/health"*) printf 'ok\n'; exit 0 ;;
  *) printf 'connection refused\n' >&2; exit 7 ;;
esac
"#,
    );
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        crate::env::var("PATH").unwrap_or_default()
    );
    let _path_guard = EnvGuard::set("PATH", path);
    let mut env = std::collections::BTreeMap::new();
    env.insert("CORTEX_PORT".to_string(), "3999".to_string());

    let ok = health_phase(&Some(env));
    let failed = health_phase(&None);

    assert_eq!(ok.status, SetupStatus::Ok);
    assert_eq!(ok.detail, "http://127.0.0.1:3999/health ready");
    assert_eq!(failed.status, SetupStatus::Error);
    assert_eq!(failed.detail, "connection refused");
}

#[cfg(unix)]
#[test]
#[serial]
fn ai_watch_initial_index_phase_maps_success_warning_and_failures() {
    let dir = tempfile::tempdir().unwrap();
    let cortex = dir.path().join("cortex");
    let env_path = dir.path().join("ai-watch.env");
    std::fs::write(
        &env_path,
        "CORTEX_DB_PATH=/tmp/cortex.db\nCORTEX_TEST_MODE=warn\n",
    )
    .unwrap();
    executable_file(
        &cortex,
        r#"#!/bin/sh
case "$CORTEX_TEST_MODE" in
  warn) printf '{"discovered_files":1,"ingested":0,"skipped_dupes":0,"parse_errors":1,"storage_blocked_chunks":0,"file_errors":[]}\n'; exit 0 ;;
  fail) printf 'boom\n' >&2; exit 2 ;;
  *) printf '{"discovered_files":1,"ingested":1,"skipped_dupes":0,"parse_errors":0,"storage_blocked_chunks":0,"file_errors":[]}\n'; exit 0 ;;
esac
"#,
    );

    let warn = run_ai_watch_initial_index_phase(&cortex, &env_path);
    std::fs::write(&env_path, "CORTEX_TEST_MODE=fail\n").unwrap();
    let failed = run_ai_watch_initial_index_phase(&cortex, &env_path);
    let missing_env = run_ai_watch_initial_index_phase(&cortex, &dir.path().join("missing.env"));

    assert_eq!(warn.status, SetupStatus::Warn);
    assert_eq!(warn.issue_kind, Some(SetupIssueKind::DataQualityWarning));
    assert!(warn.detail.contains("parse_errors=1"));
    assert_eq!(failed.status, SetupStatus::Error);
    assert_eq!(failed.issue_kind, Some(SetupIssueKind::BlockingError));
    assert_eq!(failed.detail, "boom");
    assert_eq!(missing_env.status, SetupStatus::Error);
    assert!(missing_env.detail.contains("missing.env"));
}
