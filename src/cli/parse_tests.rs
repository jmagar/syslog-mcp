use super::super::{
    FileTailAddArgs, FileTailCommand, FileTailListArgs, HeartbeatAgentArgs, HeartbeatCommand,
    IngestCommand, InventoryArgs, InventoryCommand, OutputArgs, SessionsCommand, StateCommand,
    StatsCommand,
};
use super::*;

#[test]
fn every_parser_root_is_in_the_compiled_surface_contract() {
    let contract = cortex::surfaces::contract();
    for command in TOP_LEVEL_COMMANDS {
        assert!(
            contract
                .entries
                .iter()
                .any(|entry| entry.kind == "cli" && entry.spelling == *command),
            "parser root {command} is missing from SurfaceContract"
        );
    }
}

#[test]
fn catalog_children_reach_parser_dispatch_in_both_directions() {
    for domain in ["analysis", "correlate", "stats", "heartbeat", "sessions"] {
        for child in cortex::surfaces::cli_children(domain) {
            let result = parse_command(vec![domain.into(), (*child).into(), "--help".into()]);
            if let Err(error) = result {
                assert!(
                    !error
                        .to_string()
                        .contains(&format!("unknown {domain} subcommand")),
                    "catalog child {domain} {child} lacks a parser arm: {error}"
                );
            }
        }
    }
    for (domain, bogus) in [
        ("analysis", "bogus-analysis"),
        ("correlate", "bogus-correlate"),
        ("sessions", "bogus-session"),
    ] {
        let error = parse_command(vec![domain.into(), bogus.into()])
            .expect_err("uncataloged child must be rejected");
        assert!(
            error
                .to_string()
                .contains(&format!("unknown {domain} subcommand"))
        );
    }
}

#[test]
fn parser_top_level_commands_are_classified_in_surfaces() {
    for command in TOP_LEVEL_COMMANDS {
        let spec = cortex::surfaces::find(cortex::surfaces::SurfaceKind::Cli, command)
            .unwrap_or_else(|| panic!("{command} missing from surfaces registry"));
        assert_ne!(
            spec.disposition,
            cortex::surfaces::SurfaceDisposition::RemovedCleanBreak,
            "{command} is still accepted by the parser and cannot be marked removed"
        );
    }
}

#[test]
fn parse_routes_stats() {
    assert_eq!(
        parse_command(vec!["stats".to_string()]).unwrap(),
        CliCommand::Stats(StatsCommand::Summary(OutputArgs::default()))
    );
}

#[test]
fn canonical_command_tokens_are_single_words() {
    let commands = [
        vec!["state", "clockskew"],
        vec!["stats", "ingestrate"],
        vec!["ingest", "filetail", "list"],
        vec!["setup", "pluginhook"],
        vec!["sessions", "prunecheckpoints"],
        vec!["sessions", "watchstatus"],
        vec!["sessions", "smokewatch"],
        vec!["sessions", "incidentcontext"],
        vec!["sessions", "llminvocations"],
        vec!["sessions", "skillincidents"],
        vec!["sessions", "skillinvestigate", "superpowers:test"],
        vec!["sessions", "skillassess", "superpowers:test", "--no-llm"],
        vec!["sessions", "mcpevents"],
        vec!["sessions", "mcpincidents"],
        vec!["sessions", "mcpinvestigate", "labby.search"],
        vec!["sessions", "mcpassess", "labby.search", "--no-llm"],
        vec!["sessions", "hookevents"],
        vec!["sessions", "hooksbackfill"],
    ];

    for command in commands {
        assert!(
            command.iter().take(2).all(|token| !token.contains('-')),
            "test fixture contains a hyphenated command token: {command:?}"
        );
        let args = command.iter().map(|value| (*value).to_string()).collect();
        parse_command(args).unwrap_or_else(|err| panic!("{command:?} did not parse: {err}"));
    }
}

#[test]
fn filetail_add_needs_only_a_path() {
    let command = parse_command(vec![
        "ingest".into(),
        "filetail".into(),
        "add".into(),
        "/var/log/cortex/access.log".into(),
    ]);

    assert!(command.is_ok(), "minimal filetail add failed: {command:?}");
}

#[test]
fn parses_file_tail_add() {
    let command = parse_command(vec![
        "ingest".into(),
        "filetail".into(),
        "add".into(),
        "--id".into(),
        "swag-access".into(),
        "--path".into(),
        "/mnt/appdata/swag/log/nginx/access.log".into(),
        "--tag".into(),
        "swag-access".into(),
        "--host".into(),
        "edgehost".into(),
        "--facility".into(),
        "local4".into(),
        "--severity".into(),
        "info".into(),
        "--from-start".into(),
        "--json".into(),
    ])
    .unwrap();

    assert_eq!(
        command,
        CliCommand::Ingest(IngestCommand::FileTail(FileTailCommand::Add(
            FileTailAddArgs {
                id: Some("swag-access".into()),
                path: "/mnt/appdata/swag/log/nginx/access.log".into(),
                tag: Some("swag-access".into()),
                host: Some("edgehost".into()),
                facility: Some("local4".into()),
                severity: Some("info".into()),
                start_at_end: false,
                json: true,
            }
        )))
    );
}

#[test]
fn filetail_add_accepts_missing_hostname() {
    let command = parse_command(vec![
        "ingest".into(),
        "filetail".into(),
        "add".into(),
        "--id".into(),
        "swag-access".into(),
        "--path".into(),
        "/mnt/appdata/swag/log/nginx/access.log".into(),
        "--tag".into(),
        "swag-access".into(),
    ])
    .unwrap();

    assert!(matches!(
        command,
        CliCommand::Ingest(IngestCommand::FileTail(FileTailCommand::Add(_)))
    ));
}

#[test]
fn parses_file_tail_list() {
    let command = parse_command(vec![
        "ingest".into(),
        "filetail".into(),
        "list".into(),
        "--json".into(),
    ])
    .unwrap();
    assert_eq!(
        command,
        CliCommand::Ingest(IngestCommand::FileTail(FileTailCommand::List(
            FileTailListArgs { json: true }
        )))
    );
}

#[test]
fn parse_routes_heartbeat_agent_defaults() {
    assert_eq!(
        parse_command(vec!["heartbeat".to_string(), "agent".to_string()]).unwrap(),
        CliCommand::Heartbeat(HeartbeatCommand::Agent(HeartbeatAgentArgs {
            env_file: None,
            target: None,
            token: None,
            interval_secs: 30,
            probe_deadline_ms: 2000,
            collection_deadline_ms: 5000,
            retry_buffer: 32,
            once: false,
            emit: false,
            json: false,
            host_id_path: None,
            docker: false,
            docker_url: None,
            journald: false,
            syslog_target: None,
            ai_transcripts: false,
            agent_command_forward: false,
            shell_history_forward: false,
        }))
    );
}

#[test]
fn parse_routes_heartbeat_agent_flags() {
    assert_eq!(
        parse_command(vec![
            "heartbeat".to_string(),
            "agent".to_string(),
            "--target".to_string(),
            "http://127.0.0.1:3100".to_string(),
            "--token".to_string(),
            "secret".to_string(),
            "--interval-secs".to_string(),
            "15".to_string(),
            "--probe-deadline-ms".to_string(),
            "100".to_string(),
            "--collection-deadline-ms".to_string(),
            "300".to_string(),
            "--retry-buffer".to_string(),
            "4".to_string(),
            "--host-id-path".to_string(),
            "/tmp/host-id".to_string(),
            "--once".to_string(),
            "--json".to_string(),
        ])
        .unwrap(),
        CliCommand::Heartbeat(HeartbeatCommand::Agent(HeartbeatAgentArgs {
            env_file: None,
            target: Some("http://127.0.0.1:3100".to_string()),
            token: Some("secret".to_string()),
            interval_secs: 15,
            probe_deadline_ms: 100,
            collection_deadline_ms: 300,
            retry_buffer: 4,
            once: true,
            emit: false,
            json: true,
            host_id_path: Some("/tmp/host-id".to_string()),
            docker: false,
            docker_url: None,
            journald: false,
            syslog_target: None,
            ai_transcripts: false,
            agent_command_forward: false,
            shell_history_forward: false,
        }))
    );
}

#[test]
fn parse_rejects_missing_command() {
    let err = parse_command(Vec::new()).unwrap_err().to_string();

    assert!(err.contains("CLI command is required"));
}

#[test]
fn parse_rejects_unknown_command() {
    let err = parse_command(vec!["wat".to_string()])
        .unwrap_err()
        .to_string();

    assert!(err.contains("unknown CLI command: wat"));
}

#[test]
fn parse_routes_inventory_refresh_json() {
    assert_eq!(
        parse_command(vec![
            "ingest".to_string(),
            "inventory".to_string(),
            "refresh".to_string(),
            "--json".to_string(),
        ])
        .unwrap(),
        CliCommand::Ingest(IngestCommand::Inventory(InventoryCommand::Refresh(
            InventoryArgs { json: true }
        )))
    );
}

#[test]
fn parse_inventory_requires_subcommand() {
    let err = parse_command(vec!["ingest".to_string(), "inventory".to_string()])
        .unwrap_err()
        .to_string();

    assert!(
        err.contains("inventory subcommand is required"),
        "got: {err}"
    );
}

#[test]
fn parse_inventory_unknown_subcommand_suggests() {
    let err = parse_command(vec![
        "ingest".to_string(),
        "inventory".to_string(),
        "stats".to_string(),
    ])
    .unwrap_err()
    .to_string();

    assert!(
        err.contains("unknown ingest inventory subcommand: stats"),
        "got: {err}"
    );
    assert!(
        err.contains("refresh") || err.contains("status"),
        "got: {err}"
    );
}

#[test]
fn parse_inventory_rejects_unknown_flag() {
    let err = parse_command(vec![
        "ingest".to_string(),
        "inventory".to_string(),
        "refresh".to_string(),
        "--wat".to_string(),
    ])
    .unwrap_err()
    .to_string();

    assert!(
        err.contains("unknown ingest inventory option: --wat"),
        "got: {err}"
    );
}

#[test]
fn parse_inventory_help_does_not_execute_subcommand() {
    let err = parse_command(vec![
        "ingest".to_string(),
        "inventory".to_string(),
        "--help".to_string(),
    ])
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("Usage: cortex ingest inventory refresh"),
        "got: {err}"
    );

    let err = parse_command(vec![
        "ingest".to_string(),
        "inventory".to_string(),
        "refresh".to_string(),
        "--help".to_string(),
    ])
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("Usage: cortex ingest inventory refresh"),
        "got: {err}"
    );
}

#[test]
fn parse_unknown_command_suggests_close_match() {
    let err = parse_command(vec!["serach".to_string()])
        .unwrap_err()
        .to_string();

    assert!(err.contains("Did you mean `search`?"), "got: {err}");
}

#[test]
fn removed_top_level_commands_fail_with_replacement_guidance() {
    let cases = [
        ("ai", "cortex sessions"),
        ("source-ips", "cortex hosts sources"),
        ("silent-hosts", "cortex hosts silent"),
        ("service", "cortex compose logs SERVICE"),
        ("deploy", "cortex setup deploy"),
        ("host-state", "cortex state host"),
        ("fleet-state", "cortex state fleet"),
        ("clock-skew", "cortex state clockskew"),
        ("ingest-rate", "cortex stats ingestrate"),
        ("sig", "cortex alerts signatures"),
        ("notify", "cortex alerts notifications"),
        ("file-tail", "cortex ingest filetail"),
        ("shell", "cortex ingest shell"),
        ("agent-command", "cortex ingest shell agent"),
        ("inventory", "cortex ingest inventory"),
        ("errors", "cortex analysis errors"),
        ("incident", "cortex analysis incident"),
        ("patterns", "cortex analysis patterns"),
        ("anomalies", "cortex analysis anomalies"),
        ("compare", "cortex analysis compare"),
        ("correlate-state", "cortex correlate state"),
        ("topic-correlate", "cortex correlate topic"),
    ];

    for (old, replacement) in cases {
        let err = parse_command(vec![old.to_string()])
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            format!("removed CLI command: {old}\n\nUse `{replacement}`.")
        );
    }
}

#[test]
fn removed_command_replacements_parse() {
    let replacements = [
        vec!["sessions"],
        vec!["hosts", "sources"],
        vec!["hosts", "silent"],
        vec!["compose", "logs", "cortex.service"],
        vec!["state", "host", "devhost"],
        vec!["state", "fleet"],
        vec!["state", "clockskew"],
        vec!["stats", "ingestrate"],
        vec!["alerts", "signatures"],
        vec!["alerts", "notifications"],
        vec!["ingest", "filetail", "list"],
        vec!["ingest", "shell", "user", "index", "--path", "/tmp/history"],
        vec!["ingest", "shell", "agent", "index", "--path", "/tmp/spool"],
        vec!["ingest", "shell", "agent", "index", "--path", "/tmp/spool"],
        vec!["ingest", "inventory", "status"],
        vec!["analysis", "errors"],
        vec!["analysis", "incident", "--around", "1h"],
        vec!["analysis", "patterns"],
        vec!["analysis", "anomalies"],
        vec![
            "analysis", "compare", "--a-from", "2h", "--a-to", "1h", "--b-from", "1h", "--b-to",
            "now",
        ],
        vec!["correlate", "state", "--reference-time", "1h"],
        vec!["correlate", "topic", "devhost"],
    ];

    for replacement in replacements {
        let args = replacement.into_iter().map(str::to_string).collect();
        parse_command(args).unwrap();
    }
}

// ─── Heartbeat fleet state parity (cxih.4) ──────────────────────────────────

#[test]
fn parse_routes_host_state() {
    assert!(matches!(
        parse_command(vec![
            "state".to_string(),
            "host".to_string(),
            "--host".to_string(),
            "nashost".to_string(),
            "--json".to_string(),
        ])
        .unwrap(),
        CliCommand::State(StateCommand::Host(_))
    ));
}

#[test]
fn parse_host_state_binds_bare_positional_to_host() {
    let cmd = parse_command(vec![
        "state".to_string(),
        "host".to_string(),
        "devhost".to_string(),
    ])
    .unwrap();
    let CliCommand::State(StateCommand::Host(args)) = cmd else {
        panic!("expected HostState")
    };
    assert_eq!(args.host.as_deref(), Some("devhost"));
}

#[test]
fn parse_host_state_positional_and_host_flag_are_mutually_exclusive() {
    let err = parse_command(vec![
        "state".to_string(),
        "host".to_string(),
        "devhost".to_string(),
        "--host".to_string(),
        "nashost".to_string(),
    ])
    .unwrap_err()
    .to_string();
    assert!(err.contains("mutually exclusive"), "{err}");
}

#[test]
fn parse_host_state_allows_freshest_host_default() {
    let command = parse_command(vec!["state".to_string(), "host".to_string()]).unwrap();
    let CliCommand::State(StateCommand::Host(args)) = command else {
        panic!("expected host state")
    };
    assert!(args.host.is_none());
    assert!(args.host_id.is_none());
}

#[test]
fn parse_routes_fleet_state() {
    assert!(matches!(
        parse_command(vec![
            "state".to_string(),
            "fleet".to_string(),
            "--exclude-ok".to_string()
        ])
        .unwrap(),
        CliCommand::State(StateCommand::Fleet(_))
    ));
}

#[test]
fn parse_fleet_state_rejects_bad_sort() {
    let err = parse_command(vec![
        "state".to_string(),
        "fleet".to_string(),
        "--sort".to_string(),
        "bogus".to_string(),
    ])
    .unwrap_err()
    .to_string();
    assert!(err.contains("--sort must be"), "got: {err}");
}

#[test]
fn parse_routes_entity_lookup() {
    let command = parse_command(vec![
        "entity".to_string(),
        "host".to_string(),
        "nashost".to_string(),
        "--limit=5".to_string(),
        "--json".to_string(),
    ])
    .unwrap();
    match command {
        CliCommand::Entity(args) => {
            assert_eq!(args.entity_type.as_deref(), Some("host"));
            assert_eq!(args.key.as_deref(), Some("nashost"));
            assert_eq!(args.limit, Some(5));
            assert!(args.json);
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn parse_routes_entity_alias_lookup() {
    let command = parse_command(vec![
        "entity".to_string(),
        "--alias-type".to_string(),
        "hostname".to_string(),
        "--alias-key".to_string(),
        "nashost".to_string(),
    ])
    .unwrap();
    match command {
        CliCommand::Entity(args) => {
            assert_eq!(args.alias_type.as_deref(), Some("hostname"));
            assert_eq!(args.alias_key.as_deref(), Some("nashost"));
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn parse_routes_graph_around_type_key() {
    let command = parse_command(vec![
        "graph".to_string(),
        "around".to_string(),
        "host:nashost".to_string(),
        "--depth".to_string(),
        "1".to_string(),
        "--evidence-sample-limit=2".to_string(),
        "--payload-budget".to_string(),
        "8192".to_string(),
        "--json".to_string(),
    ])
    .unwrap();
    match command {
        CliCommand::Graph(crate::cli::GraphCommand::Around(args)) => {
            assert_eq!(args.entity_type.as_deref(), Some("host"));
            assert_eq!(args.key.as_deref(), Some("nashost"));
            assert_eq!(args.depth, Some(1));
            assert_eq!(args.evidence_sample_limit, Some(2));
            assert_eq!(args.payload_budget, Some(8192));
            assert!(args.json);
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn parse_routes_graph_explain_type_key() {
    let command = parse_command(vec![
        "graph".to_string(),
        "explain".to_string(),
        "host:nashost".to_string(),
        "--depth".to_string(),
        "3".to_string(),
        "--beam-width=12".to_string(),
        "--max-chains".to_string(),
        "50".to_string(),
        "--evidence-sample-limit=2".to_string(),
        "--payload-budget".to_string(),
        "8192".to_string(),
        "--json".to_string(),
    ])
    .unwrap();
    match command {
        CliCommand::Graph(crate::cli::GraphCommand::Explain(args)) => {
            assert_eq!(args.entity_type.as_deref(), Some("host"));
            assert_eq!(args.key.as_deref(), Some("nashost"));
            assert_eq!(args.depth, Some(3));
            assert_eq!(args.beam_width, Some(12));
            assert_eq!(args.max_chains, Some(50));
            assert_eq!(args.evidence_sample_limit, Some(2));
            assert_eq!(args.payload_budget, Some(8192));
            assert!(args.json);
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn parse_routes_graph_evidence() {
    let command = parse_command(vec![
        "graph".to_string(),
        "evidence".to_string(),
        "123".to_string(),
        "--payload-budget=8192".to_string(),
        "--json".to_string(),
    ])
    .unwrap();
    match command {
        CliCommand::Graph(crate::cli::GraphCommand::Evidence(args)) => {
            assert_eq!(args.evidence_id, 123);
            assert_eq!(args.payload_budget, Some(8192));
            assert!(args.json);
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn parse_graph_evidence_rejects_missing_non_integer_and_extra_args() {
    let missing = parse_command(vec!["graph".to_string(), "evidence".to_string()])
        .unwrap_err()
        .to_string();
    assert!(missing.contains("requires <evidence-id>"), "got: {missing}");

    let non_integer = parse_command(vec![
        "graph".to_string(),
        "evidence".to_string(),
        "nope".to_string(),
    ])
    .unwrap_err()
    .to_string();
    assert!(
        non_integer.contains("must be an integer"),
        "got: {non_integer}"
    );

    let extra = parse_command(vec![
        "graph".to_string(),
        "evidence".to_string(),
        "123".to_string(),
        "extra".to_string(),
    ])
    .unwrap_err()
    .to_string();
    assert!(extra.contains("exactly one"), "got: {extra}");
}

#[test]
fn parse_routes_graph_status_and_rebuild() {
    assert!(matches!(
        parse_command(vec!["graph".to_string(), "status".to_string()]).unwrap(),
        CliCommand::Graph(crate::cli::GraphCommand::Status(_))
    ));
    assert!(matches!(
        parse_command(vec![
            "graph".to_string(),
            "rebuild".to_string(),
            "--json".to_string()
        ])
        .unwrap(),
        CliCommand::Graph(crate::cli::GraphCommand::Rebuild(_))
    ));
}

#[test]
fn parse_graph_explain_rejects_bad_depth() {
    let err = parse_command(vec![
        "graph".to_string(),
        "explain".to_string(),
        "host".to_string(),
        "nashost".to_string(),
        "--depth".to_string(),
        "nope".to_string(),
    ])
    .unwrap_err()
    .to_string();
    assert!(err.contains("--depth must be"), "got: {err}");
}

#[test]
fn parse_graph_around_rejects_bad_entity_type() {
    let err = parse_command(vec![
        "graph".to_string(),
        "around".to_string(),
        "bogus".to_string(),
        "nashost".to_string(),
    ])
    .unwrap_err()
    .to_string();
    assert!(err.contains("unsupported graph entity type"), "got: {err}");
}

#[test]
fn parse_graph_around_rejects_bad_depth() {
    let err = parse_command(vec![
        "graph".to_string(),
        "around".to_string(),
        "host".to_string(),
        "nashost".to_string(),
        "--depth".to_string(),
        "nope".to_string(),
    ])
    .unwrap_err()
    .to_string();
    assert!(err.contains("--depth must be"), "got: {err}");
}

#[test]
fn parse_routes_correlate_state() {
    assert!(matches!(
        parse_command(vec![
            "correlate".to_string(),
            "state".to_string(),
            "--reference-time".to_string(),
            "2026-05-25T00:00:00Z".to_string(),
        ])
        .unwrap(),
        CliCommand::CorrelateState(_)
    ));
}

#[test]
fn parse_correlate_state_rejects_unknown_flag() {
    let err = parse_command(vec![
        "correlate".to_string(),
        "state".to_string(),
        "--bogus".to_string(),
    ])
    .unwrap_err()
    .to_string();
    assert!(err.contains("unknown correlate state option"), "got: {err}");
}

#[test]
fn parse_correlate_nontime_positional_points_to_topic_correlate() {
    // `correlate edgehost dockersocket` fed `edgehost` into the time parser and
    // produced a cryptic "unrecognized time value". The error must now explain
    // that the positional is a reference time and point at topic-correlate.
    let err = parse_command(vec![
        "correlate".to_string(),
        "events".to_string(),
        "edgehost".to_string(),
        "dockersocket".to_string(),
    ])
    .unwrap_err()
    .to_string();
    assert!(err.contains("reference time"), "got: {err}");
    assert!(err.contains("correlate topic edgehost"), "got: {err}");
}

// Regression: every CLI flag whose value is bound into a SQL timestamp
// comparison must route through the shared time parser, so relative/keyword
// input is normalized to RFC3339 (and non-time input is rejected) rather than
// stored raw and compared lexically — a silent-failure source. parse_logs's
// search/filter/tail/errors/timeline/patterns/incident/correlate are covered
// elsewhere; this pins the previously-unnormalized commands.
#[test]
fn time_flags_normalize_relative_across_state_admin_and_ai_commands() {
    // apps --since/--until
    let CliCommand::Apps(a) =
        parse_command(vec!["apps".into(), "--since".into(), "1h".into()]).unwrap()
    else {
        panic!("expected Apps")
    };
    let s = a.since.expect("apps since");
    assert!(s.ends_with("+00:00"), "apps --since not normalized: {s}");

    // clock-skew --since
    let CliCommand::State(StateCommand::ClockSkew(c)) = parse_command(vec![
        "state".into(),
        "clockskew".into(),
        "--since".into(),
        "2d".into(),
    ])
    .unwrap() else {
        panic!("expected ClockSkew")
    };
    assert!(c.since.unwrap().ends_with("+00:00"));

    // compare: each of the four window flags normalizes independently.
    for flag in ["--a-from", "--a-to", "--b-from", "--b-to"] {
        let CliCommand::Compare(cmp) = parse_command(vec![
            "analysis".into(),
            "compare".into(),
            flag.into(),
            "1h".into(),
        ])
        .unwrap() else {
            panic!("expected Compare")
        };
        let v = match flag {
            "--a-from" => cmp.a_from,
            "--a-to" => cmp.a_to,
            "--b-from" => cmp.b_from,
            _ => cmp.b_to,
        };
        assert!(
            v.unwrap().ends_with("+00:00"),
            "compare {flag} should normalize"
        );
    }

    // correlate-state --reference-time
    let CliCommand::CorrelateState(cs) = parse_command(vec![
        "correlate".into(),
        "state".into(),
        "--reference-time".into(),
        "1h".into(),
    ])
    .unwrap() else {
        panic!("expected CorrelateState")
    };
    assert!(cs.reference_time.unwrap().ends_with("+00:00"));

    // host-state (bare positional host) --since
    let CliCommand::State(StateCommand::Host(hs)) = parse_command(vec![
        "state".into(),
        "host".into(),
        "devhost".into(),
        "--since".into(),
        "30m".into(),
    ])
    .unwrap() else {
        panic!("expected HostState")
    };
    assert!(hs.since.unwrap().ends_with("+00:00"));

    // ai search --since
    let CliCommand::Sessions(SessionsCommand::Search(ai)) = parse_command(vec![
        "sessions".into(),
        "search".into(),
        "boom".into(),
        "--since".into(),
        "1h".into(),
    ])
    .unwrap() else {
        panic!("expected Ai Search")
    };
    assert!(ai.since.unwrap().ends_with("+00:00"));
}

#[test]
fn time_flags_reject_non_time_values() {
    for cmd in [
        vec!["apps".to_string(), "--since".into(), "notatime".into()],
        vec![
            "state".to_string(),
            "clockskew".into(),
            "--since".into(),
            "notatime".into(),
        ],
        vec![
            "analysis".to_string(),
            "compare".into(),
            "--a-from".into(),
            "notatime".into(),
        ],
        vec![
            "correlate".to_string(),
            "state".into(),
            "--reference-time".into(),
            "notatime".into(),
        ],
        vec![
            "state".to_string(),
            "host".into(),
            "devhost".into(),
            "--since".into(),
            "notatime".into(),
        ],
        vec![
            "sessions".to_string(),
            "search".into(),
            "q".into(),
            "--since".into(),
            "notatime".into(),
        ],
    ] {
        assert!(
            parse_command(cmd.clone()).is_err(),
            "expected error for {cmd:?}"
        );
    }
}
