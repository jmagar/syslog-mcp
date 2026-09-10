#[test]
fn ci_uses_changed_path_classifier_and_stable_gate() {
    let workflow = include_str!("../.github/workflows/ci.yml");

    assert!(
        workflow.contains("scripts/ci/changed_paths.py"),
        "CI must run the changed-path classifier"
    );
    assert!(
        workflow.contains("git show \"${{ github.event.pull_request.base.sha }}:$classifier\""),
        "PRs must use the base-branch classifier when available"
    );

    for job in [
        "version-sync",
        "identity",
        "fmt",
        "clippy",
        "test",
        "docs-contract",
        "coverage",
        "deny",
        "mcp-integration",
        "deployment-contract",
    ] {
        let block = workflow_job_block(workflow, job);
        assert!(
            block.contains("needs: [changes"),
            "{job} must depend on the changes job"
        );
        assert!(
            block.contains("needs.changes.outputs."),
            "{job} must be gated by changed-path outputs"
        );
    }

    let docs_contract = workflow_job_block(workflow, "docs-contract");
    assert!(
        docs_contract.contains("needs.changes.outputs.docs == 'true'")
            && docs_contract.contains("cargo test --lib --locked docs_tests::"),
        "docs-contract must run focused embedded-document tests for docs changes"
    );

    let identity = workflow_job_block(workflow, "identity");
    assert!(
        identity.contains("bash scripts/check-public-identity.sh")
            && identity.contains("needs.changes.outputs.docs == 'true'"),
        "identity must validate public strings across documentation and release surfaces"
    );

    let gate = workflow_job_block(workflow, "ci-gate");
    for job in [
        "changes",
        "version-sync",
        "identity",
        "fmt",
        "clippy",
        "test",
        "docs-contract",
        "coverage",
        "deny",
        "mcp-integration",
        "deployment-contract",
    ] {
        assert!(
            gate.contains(&format!("require_success_or_skipped {job}")),
            "ci-gate must cover {job}"
        );
    }

    // The dedicated gitleaks job was retired in favour of the CodeQL/secret
    // scanning already running on the repository; assert it stays gone rather
    // than leaving a stale contract for a job that no longer exists.
    assert!(
        !workflow.contains("gitleaks"),
        "the redundant gitleaks job was retired — re-adding it needs a deliberate contract update"
    );

    let deployment = workflow_job_block(workflow, "deployment-contract");
    for required in [
        "docker build -f config/Dockerfile -t cortex:ci-release-smoke .",
        "bash scripts/container-release-smoke.sh cortex:ci-release-smoke",
        "bash scripts/test-backup-contract.sh cortex:ci-release-smoke",
        "bash scripts/test-compose-provisioning.sh cortex:ci-release-smoke",
        "bash scripts/test-agent-env-file.sh cortex:ci-release-smoke",
    ] {
        assert!(
            deployment.contains(required),
            "deployment-contract must execute {required:?}"
        );
    }
}

/// Workflows that legitimately need a writable `GITHUB_TOKEN` at the top level.
/// Everything else must declare read-only `contents`. Keeping this as an
/// allowlist means a newly added workflow fails the test until it is either
/// made read-only or consciously added here.
const WRITE_SCOPED_WORKFLOWS: &[&str] = &["release.yml", "openwiki-update.yml"];

#[test]
fn workflows_default_to_read_only_github_token_permissions() {
    // Read the directory at test time rather than `include_str!`ing a fixed
    // list, so a new workflow with no top-level `permissions:` block is caught.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows");
    let mut checked = 0;

    for entry in std::fs::read_dir(&dir).expect("workflows directory must exist") {
        let path = entry.expect("readable workflow entry").path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        if !name.ends_with(".yml") && !name.ends_with(".yaml") {
            continue;
        }
        checked += 1;

        let workflow = std::fs::read_to_string(&path).expect("readable workflow");
        let permissions = workflow
            .lines()
            .position(|line| matches!(line.trim_end(), "permissions:" | "permissions: {}"))
            .map(|idx| {
                workflow
                    .lines()
                    .skip(idx + 1)
                    .take_while(|line| line.starts_with("  ") || line.trim().is_empty())
                    .collect::<Vec<_>>()
                    .join("\n")
            });

        let permissions = permissions.unwrap_or_else(|| {
            panic!("{name} must declare an explicit top-level permissions block")
        });

        if WRITE_SCOPED_WORKFLOWS.contains(&name.as_str()) {
            continue;
        }
        assert!(
            workflow
                .lines()
                .any(|line| line.trim_end() == "permissions: {}")
                || permissions.contains("contents: read"),
            "{name} must deny all GITHUB_TOKEN permissions or default contents access to read-only"
        );
    }

    assert!(
        checked > 0,
        "no workflows were checked — is the path right?"
    );

    let docker = include_str!("../.github/workflows/docker-publish.yml");
    let registry = include_str!("../.github/workflows/mcp-registry.yml");
    let container = workflow_job_block(docker, "container");
    assert!(
        container.contains("hosted-container-release.yml"),
        "the container job must remain delegated to the hardened reusable release workflow"
    );
    assert!(
        docker.contains("packages: write")
            && docker.contains("attestations: write")
            && docker.contains("id-token: write"),
        "the container release workflow must retain package, provenance, and OIDC scopes"
    );
    assert!(
        docker.contains("workflow_dispatch:") && docker.contains("release_tag:"),
        "the container release workflow must support controlled recovery for an existing release tag"
    );
    assert!(
        docker.contains(r#"smoke-command: bash scripts/container-release-smoke.sh "$IMAGE_REF""#),
        "container publication must run the exact-image live smoke harness"
    );
    assert!(
        !docker.contains("mcp-publisher")
            && !docker.contains("registry.modelcontextprotocol.io")
            && !docker.contains("MCP_PRIVATE_KEY"),
        "container publication must not duplicate the shared MCP Registry publisher"
    );
    assert!(
        registry.contains("mcp-registry-publish.yml@befa67c7b7f976235bf3fbced6ede93293a7f405")
            && registry.contains("workflow_dispatch:")
            && registry.contains("expected-version:")
            && registry.contains("manifest-path: server.json")
            && registry.contains("MCP_PRIVATE_KEY")
            && !registry.contains("auth-method:"),
        "MCP Registry publication must use the pinned DNS-only workflow source of truth"
    );

    let manifest: serde_json::Value =
        serde_json::from_str(include_str!("../server.json")).expect("server.json must parse");
    let description = manifest["description"]
        .as_str()
        .expect("server.json description must be a string");
    assert!(
        description.chars().count() <= 100,
        "MCP Registry description must stay within the 100-character schema limit"
    );
    assert!(
        registry.contains("version-prefix: v"),
        "Cortex Registry recovery must normalize v-prefixed release tags"
    );
}

#[test]
fn release_please_opens_prs_and_fixes_up_regex_carriers() {
    let release_please = include_str!("../.github/workflows/release-please.yml");
    let release = include_str!("../.github/workflows/release.yml");

    assert!(
        release_please.contains("googleapis/release-please-action"),
        "release-please.yml must run the googleapis release-please-action"
    );
    assert!(
        release_please.contains("config-file: release-please-config.json")
            && release_please.contains("manifest-file: .release-please-manifest.json"),
        "release-please.yml must point at the repo's config/manifest files"
    );
    assert!(
        release_please.contains("RELEASE_PLEASE_TOKEN"),
        "release-please must require a non-default token so it can trigger downstream workflows"
    );
    assert!(
        release_please.contains("cargo xtask sync-version")
            && release_please.contains("cargo xtask check-release-versions"),
        "the release-pr-fixup job must sync regex-based version carriers and re-verify them"
    );

    assert!(
        release.contains("tags: [\"v*\"]"),
        "release.yml must still trigger on the vX.Y.Z tags release-please creates"
    );
    assert!(
        release.contains("publish:") && release.contains("type: boolean"),
        "release workflow must expose an explicit publish input for workflow_dispatch"
    );
    assert!(
        release.contains("github.event.inputs.publish == 'true'"),
        "release publish job must run for tagged workflow_dispatch when publish=true"
    );
    assert!(
        !release.contains("generate_release_notes: true"),
        "release.yml must not overwrite the changelog-derived notes release-please already wrote"
    );
}

#[test]
fn release_please_config_and_manifest_agree_with_components_toml() {
    let config = include_str!("../release-please-config.json");
    let manifest = include_str!("../.release-please-manifest.json");
    let components = include_str!("../release/components.toml");

    assert!(
        config.contains("\"release-type\": \"rust\""),
        "cortex is a single-crate Rust package"
    );
    for extra_file in ["server.json", "mcpb/manifest.json"] {
        assert!(
            config.contains(extra_file),
            "release-please-config.json must declare an extra-files entry for {extra_file}"
        );
    }
    let config_json: serde_json::Value =
        serde_json::from_str(config).expect("release-please config must be valid JSON");
    let extra_files = config_json["packages"]["."]["extra-files"]
        .as_array()
        .expect("root package must declare extra-files");
    for jsonpath in ["$.version", "$.binaryVersion"] {
        assert!(
            extra_files.iter().any(|entry| {
                entry["type"] == "json"
                    && entry["path"] == "packages/cortex-rmcp/package.json"
                    && entry["jsonpath"] == jsonpath
            }),
            "npm launcher {jsonpath} must use an explicit JSON updater"
        );
    }
    assert!(
        !extra_files
            .iter()
            .any(|entry| entry.as_str() == Some("packages/cortex-rmcp/package.json")),
        "package.json must not use the implicit extra-file updater"
    );

    assert!(
        manifest.contains("\".\""),
        ".release-please-manifest.json must track the root package"
    );

    // The two regex_version carriers release-please's extra-files schema
    // can't express must stay declared in components.toml so the
    // release-pr-fixup job's `cargo xtask sync-version` step covers them.
    for regex_carrier in ["server.json", "docker-compose.prod.yml"] {
        assert!(
            components.contains(&format!("regex_version\", path = \"{regex_carrier}\"")),
            "release/components.toml must keep a regex_version carrier for {regex_carrier}"
        );
    }
}

#[test]
fn release_please_rust_workspace_uses_scalar_package_versions() {
    let root_manifest = include_str!("../Cargo.toml");
    let xtask_manifest = include_str!("../xtask/Cargo.toml");
    let components = include_str!("../release/components.toml");

    let root: toml::Value = toml::from_str(root_manifest).expect("root Cargo.toml must parse");
    let xtask: toml::Value = toml::from_str(xtask_manifest).expect("xtask Cargo.toml must parse");
    let root_version = root
        .get("package")
        .and_then(|value| value.get("version"))
        .and_then(toml::Value::as_str)
        .expect("root package.version must be a scalar string");
    let xtask_version = xtask
        .get("package")
        .and_then(|value| value.get("version"))
        .and_then(toml::Value::as_str)
        .expect("xtask package.version must be a scalar string");

    assert_eq!(root_version, xtask_version);
    assert!(
        root.get("workspace")
            .and_then(|value| value.get("package"))
            .and_then(|value| value.get("version"))
            .is_none(),
        "workspace.package.version must stay absent because release-please cannot replace inherited package versions"
    );
    for required in [
        r#"cargo_package", path = "xtask/Cargo.toml", package = "xtask""#,
        r#"cargo_lock_package", path = "Cargo.lock", package = "xtask""#,
    ] {
        assert!(
            components.contains(required),
            "release/components.toml must track {required}"
        );
    }
}

#[test]
fn local_cortex_server_has_auto_deploy_timer_contract() {
    let service = include_str!("../config/systemd/cortex-auto-deploy.service");
    let timer = include_str!("../config/systemd/cortex-auto-deploy.timer");
    let script = include_str!("../scripts/auto-deploy.sh");

    assert!(
        service.contains("ExecStart=") && service.contains("scripts/auto-deploy.sh"),
        "auto-deploy service must execute the repo-owned deploy script"
    );
    assert!(
        timer.contains("OnCalendar=") && timer.contains("cortex-auto-deploy.service"),
        "auto-deploy timer must schedule the service"
    );
    for required in [
        "git fetch --no-tags origin main",
        "git pull --ff-only",
        "docker compose build cortex",
        "docker compose up -d --no-deps --force-recreate cortex",
        "curl -fsS",
        "docker exec cortex cortex --version",
    ] {
        assert!(
            script.contains(required),
            "auto-deploy script must contain {required:?}"
        );
    }
    assert!(
        !script.contains("--tags"),
        "auto-deploy must not fetch tags; stale local tag conflicts must not block deploy"
    );
}

fn workflow_job_block<'a>(workflow: &'a str, job_name: &str) -> &'a str {
    let marker = format!("  {job_name}:");
    let start = workflow
        .find(&marker)
        .unwrap_or_else(|| panic!("job {job_name} exists"));
    let rest = &workflow[start + marker.len()..];
    let end = rest
        .lines()
        .enumerate()
        .skip(1)
        .find_map(|(line_index, line)| {
            let trimmed = line.trim_end();
            if line.starts_with("  ") && !line.starts_with("    ") && trimmed.ends_with(':') {
                let byte_offset = rest
                    .lines()
                    .take(line_index)
                    .map(|line| line.len() + 1)
                    .sum();
                Some(byte_offset)
            } else {
                None
            }
        })
        .unwrap_or(rest.len());
    &rest[..end]
}
