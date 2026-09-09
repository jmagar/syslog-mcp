const CURRENT_DOCKER_DOCS: &[(&str, &str)] = &[
    ("CLAUDE.md", include_str!("../CLAUDE.md")),
    ("README.md", include_str!("../README.md")),
    ("docs/CONFIG.md", include_str!("../docs/CONFIG.md")),
    ("docs/SETUP.md", include_str!("../docs/SETUP.md")),
    (
        "docs/architecture.md",
        include_str!("../docs/architecture.md"),
    ),
    (
        "docs/runbooks/deploy.md",
        include_str!("../docs/runbooks/deploy.md"),
    ),
    ("docs/mcp/ENV.md", include_str!("../docs/mcp/ENV.md")),
    ("docs/SECURITY.md", include_str!("../docs/SECURITY.md")),
];

#[test]
fn current_docker_ingest_docs_prefer_agent_path_over_socket_proxy() {
    for (path, text) in CURRENT_DOCKER_DOCS {
        assert!(
            text.contains("host-local cortex agent")
                || text.contains("host-local agent")
                || text.contains("deployed agent"),
            "{path} should describe the current host-local agent Docker log path"
        );
        assert!(
            text.contains("legacy central pull")
                || text.contains("legacy pull")
                || text.contains("compatibility mode"),
            "{path} should label CORTEX_DOCKER_* as legacy/compatibility coverage"
        );
        assert!(
            !text.contains("Docker socket-proxy ingest"),
            "{path} still presents socket-proxy ingest as a current section heading"
        );
    }
}

#[test]
fn coverage_docs_use_cortex_names_and_current_smoke_scope() {
    let coverage = include_str!("../tests/TEST_COVERAGE.md");
    assert!(
        !coverage.contains("syslog help") && !coverage.contains("syslog status"),
        "tests/TEST_COVERAGE.md should use cortex command/action names after the rebrand"
    );
    for required in [
        "UDP",
        "TCP",
        "file-tail",
        "CLI surfaces",
        "REST",
        "host-local agent",
        "cargo llvm-cov",
    ] {
        assert!(
            coverage.contains(required),
            "tests/TEST_COVERAGE.md should mention {required}"
        );
    }
}

#[test]
fn coverage_tooling_is_documented_and_scripted() {
    let justfile = include_str!("../Justfile");
    assert!(
        justfile.contains("\ncoverage:") && justfile.contains("cargo llvm-cov nextest"),
        "Justfile should expose a coverage recipe using cargo-llvm-cov + nextest"
    );

    let mcp_tests = include_str!("../docs/mcp/TESTS.md");
    assert!(
        mcp_tests.contains("just coverage") && mcp_tests.contains("cargo llvm-cov"),
        "docs/mcp/TESTS.md should document the coverage workflow"
    );
}

#[test]
fn published_package_readme_tracks_the_current_schema_version() {
    let package_readme = include_str!("../packages/cortex-rmcp/README.md");
    let current = format!(
        "{} sequential schema migrations",
        crate::db::KNOWN_SCHEMA_VERSION
    );
    assert!(
        package_readme.contains(&current),
        "packages/cortex-rmcp/README.md should report {current}"
    );
}

#[test]
fn live_smoke_uses_the_fail_closed_registry_runner() {
    let live = include_str!("../tests/live/runner.sh");
    let surfaces = include_str!("../tests/live/phases/surfaces/run.sh");
    assert!(
        live.contains("live_ledger_validate")
            && live.contains("live_summary_accepts_profile")
            && surfaces.contains("rest_sweep.py")
            && surfaces.contains("cli_sweep.py"),
        "live smoke should use registry-derived, fail-closed REST and CLI qualification"
    );
    assert!(
        include_str!("../tests/test_live.sh").contains("tests/live/run-profile.sh"),
        "the historical live entry point should be a thin compatibility wrapper"
    );
}

#[test]
fn live_smoke_keeps_deterministic_admin_rest_coverage() {
    let live = include_str!("../tests/live/phases/surfaces/rest_sweep.py");
    assert!(
        live.contains("ADMIN_TOKEN"),
        "live smoke should expose a deterministic admin REST gate in its run-owned topology"
    );
    assert!(
        live.contains("POST /api/file-tails")
            && live.contains("authorization")
            && live.contains("validation-negative"),
        "live smoke should cover semantic, validation, and authorization cases for admin routes"
    );
}
