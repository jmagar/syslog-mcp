use super::*;
use crate::mcp;

const CURRENT_API_ROUTES: &[&str] = &[
    "/api/search",
    "/api/filter",
    "/api/feed",
    "/api/tail",
    "/api/errors",
    "/api/hosts",
    "/api/correlate",
    "/api/stats",
    "/api/version",
    "/api/v1/investigation/version",
    "/api/v1/investigations/ask",
    "/api/v1/graph/entity",
    "/api/v1/graph/around",
    "/api/v1/graph/explain",
    "/api/v1/graph/evidence",
    "/api/source-ips",
    "/api/timeline",
    "/api/patterns",
    "/api/ingest-rate",
    "/api/get",
    "/api/host-state",
    "/api/context",
    "/api/fleet-state",
    "/api/correlate-state",
    "/api/topic-correlate",
    "/api/errors/unaddressed",
    "/api/errors/ack",
    "/api/errors/unack",
    "/api/notifications/recent",
    "/api/notifications/test",
    "/api/file-tails",
    "/api/silent-hosts",
    "/api/clock-skew",
    "/api/anomalies",
    "/api/compare",
    "/api/apps",
    "/api/artifact-evidence",
    "/api/similar-incidents",
    "/api/incident-context",
    "/api/graph/entity",
    "/api/graph/around",
    "/api/graph/explain",
    "/api/graph/evidence",
    "/api/sessions/incidents",
    "/api/sessions/investigate",
    "/api/sessions/llm-invocations",
    "/api/sessions/skills",
    "/api/sessions/skill-incidents",
    "/api/sessions/skill-investigate",
    "/api/sessions/mcp-events",
    "/api/sessions/mcp-incidents",
    "/api/sessions/mcp-investigate",
    "/api/sessions/hooks",
    "/api/sessions/hook-incidents",
    "/api/sessions/hook-investigate",
    "/api/compose/status",
    "/api/compose/doctor",
    "/api/sessions",
    "/api/sessions/search",
    "/api/sessions/abuse",
    "/api/sessions/correlate",
    "/api/sessions/blocks",
    "/api/sessions/context",
    "/api/sessions/tools",
    "/api/sessions/projects",
    "/api/sessions/checkpoints",
    "/api/sessions/errors",
    "/api/sessions/prune-checkpoints",
    "/api/db/status",
    "/api/db/integrity",
    "/api/db/integrity/background",
    "/api/db/integrity/jobs/{id}",
    "/api/db/checkpoint",
    "/api/db/vacuum",
    "/api/db/backup",
];

#[test]
fn qualification_contract_is_versioned_deterministic_and_unique() {
    let first = export_json().expect("contract serializes");
    let second = export_json().expect("contract serializes repeatedly");
    assert_eq!(first, second);
    assert!(first.contains(&format!(r#""version": {}"#, SURFACE_CONTRACT_VERSION)));

    let contract = contract();
    let mut ids: Vec<_> = contract
        .entries
        .iter()
        .map(|entry| entry.id.as_str())
        .collect();
    let before = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), before, "surface IDs must be globally unique");
    for entry in contract.entries {
        assert!(
            entry.scenario_id.is_some()
                || entry
                    .allowed_dispositions
                    .contains(&ProfileDisposition::PendingScenario),
            "{} must bind a scenario or explicitly remain pending",
            entry.id
        );
        assert!(
            entry
                .required_cases
                .contains(&RequiredCaseKind::SemanticPositive)
                || entry
                    .required_cases
                    .contains(&RequiredCaseKind::ExecutedRefusalSemantic)
        );
        assert!(
            entry
                .required_cases
                .contains(&RequiredCaseKind::ValidationNegative)
        );
        if matches!(entry.auth, "read" | "admin") {
            assert!(
                entry
                    .required_cases
                    .contains(&RequiredCaseKind::Authorization),
                "{} lacks auth case",
                entry.id
            );
        }
        if entry.mutation != MutationClass::None {
            assert!(
                entry.cleanup.is_some(),
                "{} mutates without cleanup",
                entry.id
            );
        }
    }
}

#[test]
fn ingest_surfaces_have_executable_profile_owners() {
    let exported = contract::contract();
    let ingest: Vec<_> = exported
        .entries
        .iter()
        .filter(|entry| entry.kind == "ingest")
        .collect();
    assert!(!ingest.is_empty());
    assert!(ingest.iter().all(|entry| !entry.profiles.is_empty()));
    assert_eq!(
        ingest
            .iter()
            .find(|entry| entry.spelling == "agent-docker")
            .unwrap()
            .profiles,
        ["agent"]
    );
    assert_eq!(
        ingest
            .iter()
            .find(|entry| entry.spelling == "POST /token")
            .unwrap()
            .profiles,
        ["auth"]
    );
    assert_eq!(
        ingest
            .iter()
            .find(|entry| entry.spelling == "POST /v1/logs")
            .unwrap()
            .profiles,
        ["isolated"]
    );
    assert_eq!(
        ingest
            .iter()
            .find(|entry| entry.spelling == "GET /app")
            .unwrap()
            .profiles,
        ["security"]
    );
}

#[test]
fn every_surface_has_one_aggregate_owner() {
    let exported = contract::contract();
    assert!(
        exported
            .entries
            .iter()
            .all(|entry| entry.profiles.len() == 1),
        "aggregate ownership must be unambiguous"
    );
}

#[test]
fn every_api_method_path_binding_has_exactly_one_contract_entry() {
    let entries = contract().entries;
    for binding in api_bindings() {
        let count = entries
            .iter()
            .filter(|entry| {
                entry.kind == "rest"
                    && entry.spelling == binding.path
                    && entry.method == Some(binding.method)
            })
            .count();
        assert_eq!(
            count, 1,
            "{:?} {} must have exactly one entry",
            binding.method, binding.path
        );
    }
}

#[test]
fn every_cli_child_has_exactly_one_contract_entry() {
    let entries = contract().entries;
    for (parent, children) in CLI_CHILDREN {
        for child in *children {
            let path = format!("{parent} {child}");
            assert_eq!(
                entries
                    .iter()
                    .filter(|entry| entry.kind == "cli" && entry.spelling == path)
                    .count(),
                1,
                "{path}"
            );
        }
    }
}

#[test]
fn mounted_route_audit_rejects_unregistered_routes() {
    assert_mounted_routes(&["POST /v1/logs", "GET /health/full", "GET /app/{*path}"]);
    assert!(
        std::panic::catch_unwind(|| assert_mounted_routes(&["POST /v1/not-registered"])).is_err()
    );
}

#[test]
fn real_cli_aliases_are_explicit_not_duplicate_surfaces() {
    let entries = contract().entries;
    for (canonical, alias) in [
        ("config list", "config ls"),
        ("update clients", "update agents"),
        ("update config clients", "update config agents"),
    ] {
        let entry = entries
            .iter()
            .find(|entry| entry.kind == "cli" && entry.spelling == canonical)
            .expect("canonical alias owner");
        assert!(
            entry.aliases.iter().any(|candidate| candidate == alias),
            "{alias} missing from {canonical}"
        );
        assert!(
            !entries
                .iter()
                .any(|entry| entry.kind == "cli" && entry.spelling == alias),
            "alias must not be a duplicate surface"
        );
    }
}

#[test]
fn metadata_distinguishes_read_mutating_platform_and_cleanup_classes() {
    let entries = contract().entries;
    let get = |id: &str| {
        entries
            .iter()
            .find(|entry| entry.id == id)
            .unwrap_or_else(|| panic!("missing {id}"))
    };
    assert_eq!(get("cli.search").mutation, MutationClass::None);
    assert_eq!(get("mcp.llm-invocations").mutation, MutationClass::None);
    assert_eq!(
        get("mcp.ack-error").cleanup,
        Some("restore-error-acknowledgement-state")
    );
    assert_eq!(
        get("rest.post-api-db-vacuum").mutation,
        MutationClass::Destructive
    );
    assert!(get("cli.compose-up").platforms.contains(&Platform::Unix));
    assert!(get("rest.get-api-search").profiles.contains(&"full"));
    assert_eq!(
        get("ingest.post-v1-logs").cleanup,
        Some("purge-or-discard-run-owned-ingest-store")
    );
}

#[test]
fn every_current_mcp_action_is_classified() {
    for name in mcp::action_names() {
        assert!(
            find(SurfaceKind::McpAction, name).is_some(),
            "MCP action {name} is missing from surfaces catalog"
        );
    }
}

#[test]
fn mcp_access_metadata_matches_scope_gate() {
    for spec in specs_for(SurfaceKind::McpAction) {
        let expected_access = match mcp::required_scope_for(spec.spelling) {
            Some("cortex:read") => SurfaceAccess::Read,
            Some("cortex:admin") => SurfaceAccess::Admin,
            None => SurfaceAccess::Info,
            other => panic!("unexpected MCP scope for {}: {other:?}", spec.spelling),
        };
        assert_eq!(
            spec.access, expected_access,
            "{} registry access must match ACTION_SPECS scope gate",
            spec.spelling
        );
    }
}

#[test]
fn every_current_api_route_is_classified() {
    for route in CURRENT_API_ROUTES {
        assert!(
            find(SurfaceKind::ApiRoute, route).is_some(),
            "API route {route} is missing from surfaces catalog"
        );
    }
}

#[test]
fn retained_operational_roots_are_not_grouped_domains() {
    for root in ["db", "compose", "setup", "config", "doctor", "serve", "mcp"] {
        let spec = find(SurfaceKind::Cli, root).expect("operational root classified");
        assert_eq!(
            spec.disposition,
            SurfaceDisposition::RetainedTopLevelOperational,
            "{root} must stay an operational top-level command"
        );
        assert!(spec.transports.contains(SurfaceTransport::LOCAL_ONLY));
    }
}

#[test]
fn every_removed_cli_spelling_has_one_replacement() {
    let removed: Vec<_> = specs_for(SurfaceKind::Cli)
        .filter(|spec| spec.disposition == SurfaceDisposition::RemovedCleanBreak)
        .collect();
    assert!(!removed.is_empty());
    for spec in removed {
        assert!(
            spec.replacement.is_some(),
            "{} needs a replacement",
            spec.spelling
        );
        assert!(spec.reason.is_some(), "{} needs a reason", spec.spelling);
    }
}

#[test]
fn api_ai_routes_are_intentional_clean_breaks() {
    for route in [
        "/api/ai",
        "/api/ai/search",
        "/api/ai/abuse",
        "/api/ai/correlate",
        "/api/ai/blocks",
        "/api/ai/context",
        "/api/ai/tools",
        "/api/ai/projects",
    ] {
        let spec = find(SurfaceKind::ApiRoute, route).expect("removed /api/ai route");
        assert_eq!(spec.disposition, SurfaceDisposition::RemovedCleanBreak);
        assert!(
            spec.replacement
                .expect("replacement")
                .starts_with("/api/sessions")
        );
    }
}

#[test]
fn all_entries_record_transport_and_access() {
    for kind in [
        SurfaceKind::Cli,
        SurfaceKind::McpAction,
        SurfaceKind::ApiRoute,
    ] {
        for spec in specs_for(kind) {
            match spec.kind {
                SurfaceKind::Cli => assert!(
                    spec.transports.contains(SurfaceTransport::LOCAL_CLI),
                    "{} CLI row lacks local CLI transport",
                    spec.spelling
                ),
                SurfaceKind::McpAction => assert!(
                    spec.transports.contains(SurfaceTransport::MCP),
                    "{} MCP row lacks MCP transport",
                    spec.spelling
                ),
                SurfaceKind::ApiRoute => assert!(
                    spec.transports.contains(SurfaceTransport::REST),
                    "{} API row lacks REST transport",
                    spec.spelling
                ),
            }
            let _ = spec.access;
        }
    }
}

#[test]
fn parity_groups_join_equivalent_transports_only() {
    let export = contract::contract();
    let expected_kinds = std::collections::BTreeSet::from(["cli", "mcp", "rest"]);
    for capability in [
        "search",
        "host-state",
        "source-ips",
        "silent-hosts",
        "patterns",
        "anomalies",
        "compare",
        "correlate-state",
        "topic-correlate",
        "ingest-rate",
        "unaddressed-errors",
        "notifications-recent",
        "skill-incidents",
        "mcp-incidents",
        "hook-incidents",
    ] {
        let kinds = export
            .entries
            .iter()
            .filter(|entry| {
                entry.parity_group.as_deref() == Some(&format!("capability.{capability}"))
            })
            .map(|entry| entry.kind)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            kinds, expected_kinds,
            "{capability} must retain CLI, MCP, and REST parity members"
        );
    }

    let mut groups = std::collections::BTreeMap::<&str, std::collections::BTreeSet<&str>>::new();
    for entry in &export.entries {
        if let Some(group) = entry.parity_group.as_deref() {
            groups.entry(group).or_default().insert(entry.kind);
        }
    }
    assert!(groups.values().all(|kinds| kinds.len() >= 2));

    let artifact_read = export
        .entries
        .iter()
        .filter(|entry| entry.parity_group.as_deref() == Some("capability.artifact-evidence"))
        .collect::<Vec<_>>();
    assert!(
        artifact_read
            .iter()
            .all(|entry| entry.mutation == MutationClass::None)
    );
    let artifact_record = export
        .entries
        .iter()
        .filter(|entry| {
            entry.parity_group.as_deref() == Some("capability.artifact-evidence-record")
        })
        .collect::<Vec<_>>();
    assert_eq!(artifact_record.len(), 2);
    assert!(
        artifact_record
            .iter()
            .all(|entry| entry.mutation == MutationClass::AppendOnly)
    );
}

#[test]
fn every_rest_binding_records_an_authorization_case() {
    for entry in contract::contract()
        .entries
        .iter()
        .filter(|entry| entry.kind == "rest")
    {
        assert!(
            entry
                .required_cases
                .contains(&RequiredCaseKind::Authorization),
            "REST binding {} is mounted behind forced authentication",
            entry.spelling
        );
    }
}
