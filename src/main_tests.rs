use super::{Mode, ShellAgentIndexDispatch, cli, resolve_shell_agent_index_dispatch};

#[test]
fn mode_parse_accepts_single_binary_transport_commands() {
    assert_eq!(Mode::parse(vec![]).unwrap(), Mode::ServeMcp);
    assert_eq!(
        Mode::parse(vec!["serve".into(), "mcp".into()]).unwrap(),
        Mode::ServeMcp
    );
    assert_eq!(Mode::parse(vec!["mcp".into()]).unwrap(), Mode::StdioMcp);
    assert_eq!(Mode::parse(vec!["--help".into()]).unwrap(), Mode::Help);
    assert_eq!(
        Mode::parse(vec!["--version".into()]).unwrap(),
        Mode::Version
    );
    assert!(matches!(
        Mode::parse(vec!["stats".into(), "--json".into()]).unwrap(),
        Mode::Cli(_)
    ));
}

#[test]
fn main_owned_operational_commands_are_in_surface_contract() {
    let contract = cortex::surfaces::contract();
    for command in ["serve", "mcp", "setup", "update", "doctor"] {
        assert!(
            contract
                .entries
                .iter()
                .any(|entry| entry.kind == "cli" && entry.spelling == command),
            "main-owned command {command} is missing from SurfaceContract"
        );
    }
    for command in ["setup deploy", "doctor binary", "update config"] {
        assert!(
            contract
                .entries
                .iter()
                .any(|entry| entry.kind == "cli" && entry.spelling == command),
            "main-owned command path {command} is missing from SurfaceContract"
        );
    }
}

#[test]
fn mode_parse_accepts_heartbeat_state_commands() {
    // Regression: state/correlate state are routed in
    // parse.rs + run.rs, but were missing from Mode::parse's top-level command
    // gate, so they fell through to print_usage()+exit 1 (bd syslog-mcp-8fww).
    assert!(matches!(
        Mode::parse(vec![
            "state".into(),
            "host".into(),
            "--host".into(),
            "nashost".into(),
            "--json".into()
        ])
        .unwrap(),
        Mode::Cli(_)
    ));
    assert!(matches!(
        Mode::parse(vec!["state".into(), "fleet".into(), "--json".into()]).unwrap(),
        Mode::Cli(_)
    ));
    assert!(matches!(
        Mode::parse(vec![
            "correlate".into(),
            "state".into(),
            "--reference-time".into(),
            "2026-01-01T00:00:00Z".into(),
            "--json".into(),
        ])
        .unwrap(),
        Mode::Cli(_)
    ));
}

#[test]
fn mode_parse_accepts_topic_correlate() {
    // Regression: correlate topic is in TOP_LEVEL_COMMANDS + parse_command but was
    // missing from Mode::parse's top-level command gate, so `cortex correlate topic
    // <topic>` parsed successfully and then hit the `unreachable!()` fallthrough →
    // panic. Both the single-term and the multi-term (screenshot) forms must route
    // cleanly to a CLI invocation.
    assert!(matches!(
        Mode::parse(vec!["correlate".into(), "topic".into(), "axon".into()]).unwrap(),
        Mode::Cli(_)
    ));
    assert!(matches!(
        Mode::parse(vec![
            "correlate".into(),
            "topic".into(),
            "edgehost".into(),
            "dockersocket".into(),
        ])
        .unwrap(),
        Mode::Cli(_)
    ));
}

#[test]
fn mode_parse_rejects_unknown_commands() {
    let err = Mode::parse(vec!["serve".into(), "http".into()]).unwrap_err();
    assert!(err.to_string().contains("unknown CLI command"));

    let err = Mode::parse(vec!["serach".into()]).unwrap_err();
    assert!(err.to_string().contains("Did you mean `search`?"));
}

#[test]
fn mode_parse_accepts_local_status_command() {
    // `cortex status` is a real local-mode CLI command (see cli::parse_admin);
    // only HTTP mode declines it in favor of the MCP status action.
    assert!(matches!(
        Mode::parse(vec!["status".into()]).unwrap(),
        Mode::Cli(_)
    ));
}

#[test]
fn mode_parse_accepts_graph_cli_commands() {
    assert!(matches!(
        Mode::parse(vec![
            "entity".into(),
            "host".into(),
            "nashost".into(),
            "--json".into(),
        ])
        .unwrap(),
        Mode::Cli(_)
    ));
    assert!(matches!(
        Mode::parse(vec![
            "graph".into(),
            "around".into(),
            "host:nashost".into(),
            "--limit".into(),
            "1".into(),
            "--json".into(),
        ])
        .unwrap(),
        Mode::Cli(_)
    ));
}

#[test]
fn mode_parse_accepts_compose_namespace() {
    assert!(matches!(
        Mode::parse(vec!["compose".into(), "status".into(), "--json".into()]).unwrap(),
        Mode::Cli(_)
    ));
}

#[test]
fn mode_parse_accepts_db_namespace() {
    assert!(matches!(
        Mode::parse(vec!["db".into(), "status".into(), "--json".into()]).unwrap(),
        Mode::Cli(_)
    ));
}

#[test]
fn mode_parse_accepts_setup_namespace() {
    assert!(matches!(
        Mode::parse(vec![
            "setup".into(),
            "pluginhook".into(),
            "--no-repair".into(),
            "--json".into()
        ])
        .unwrap(),
        Mode::Cli(_)
    ));
    assert!(matches!(
        Mode::parse(vec!["setup".into(), "check".into(), "--json".into()]).unwrap(),
        Mode::Setup(_)
    ));
}

#[test]
fn mode_parse_accepts_one_word_setup_commands() {
    for name in [
        "sessionstimer",
        "sessionswatch",
        "heartbeatagent",
        "debugwrapper",
        "debugcompose",
    ] {
        assert!(
            Mode::parse(vec!["setup".into(), name.into(), "check".into()]).is_ok(),
            "setup {name} should parse"
        );
    }
    assert!(Mode::parse(vec!["setup".into(), "sessionshealth".into()]).is_ok());
}

#[test]
fn mode_parse_accepts_sessions_index_timer_setup_namespace() {
    assert!(matches!(
        Mode::parse(vec![
            "setup".into(),
            "sessionstimer".into(),
            "install".into(),
            "--json".into()
        ])
        .unwrap(),
        Mode::Setup(_)
    ));
}

#[test]
fn mode_parse_accepts_sessions_watch_service_setup_namespace() {
    assert!(matches!(
        Mode::parse(vec![
            "setup".into(),
            "sessionswatch".into(),
            "install".into(),
            "--json".into()
        ])
        .unwrap(),
        Mode::Setup(_)
    ));
}

#[test]
fn mode_parse_rejects_old_ai_setup_namespaces() {
    for old_name in ["ai-index-timer", "ai-watch-service"] {
        let err = Mode::parse(vec!["setup".into(), old_name.into(), "check".into()]).unwrap_err();
        assert!(
            err.to_string().contains("unknown setup argument"),
            "expected {old_name} to be rejected, got: {err}"
        );
    }
}

#[test]
fn mode_parse_accepts_shell_agent_setup_namespace() {
    assert!(matches!(
        Mode::parse(vec![
            "setup".into(),
            "shell".into(),
            "agent".into(),
            "install".into(),
            "--json".into()
        ])
        .unwrap(),
        Mode::Setup(_)
    ));
}

#[test]
fn mode_parse_accepts_shell_completions_setup_namespace() {
    assert!(matches!(
        Mode::parse(vec![
            "setup".into(),
            "shell".into(),
            "completions".into(),
            "install".into(),
            "--json".into()
        ])
        .unwrap(),
        Mode::Setup(_)
    ));
}

#[test]
fn mode_parse_rejects_unknown_setup_shell_subcommand() {
    let error = Mode::parse(vec!["setup".into(), "shell".into(), "bogus".into()])
        .unwrap_err()
        .to_string();
    assert!(error.contains("agent|completions"), "got: {error}");
}

#[test]
fn mode_parse_accepts_heartbeat_agent_setup_namespace() {
    assert!(matches!(
        Mode::parse(vec![
            "setup".into(),
            "heartbeatagent".into(),
            "install".into(),
            "--json".into()
        ])
        .unwrap(),
        Mode::Setup(_)
    ));
}

#[test]
fn mode_parse_accepts_command_ingest_namespace() {
    assert!(matches!(
        Mode::parse(vec![
            "ingest".into(),
            "shell".into(),
            "user".into(),
            "index".into(),
            "--path".into(),
            "/tmp/history".into(),
            "--json".into()
        ])
        .unwrap(),
        Mode::Cli(_)
    ));
    assert!(matches!(
        Mode::parse(vec![
            "heartbeat".into(),
            "agent".into(),
            "--server".into(),
            "http://127.0.0.1:3100".into(),
            "--token".into(),
            "secret".into(),
            "--emit".into(),
            "--json".into()
        ])
        .unwrap(),
        Mode::Cli(_)
    ));
    assert!(matches!(
        Mode::parse(vec![
            "ingest".into(),
            "shell".into(),
            "agent".into(),
            "index".into(),
            "--path".into(),
            "/tmp/spool.jsonl".into(),
            "--json".into()
        ])
        .unwrap(),
        Mode::Cli(_)
    ));
    assert!(matches!(
        Mode::parse(vec![
            "ingest".into(),
            "shell".into(),
            "agent".into(),
            "wrap".into(),
            "--spool".into(),
            "/tmp/spool.jsonl".into(),
            "--".into(),
            "true".into()
        ])
        .unwrap(),
        Mode::Cli(_)
    ));
    assert!(Mode::parse(vec!["ingest".into(), "agent-command".into()]).is_err());
}

#[test]
fn mode_parse_preserves_wrapped_command_http_like_flags() {
    let mode = Mode::parse(vec![
        "ingest".into(),
        "shell".into(),
        "agent".into(),
        "wrap".into(),
        "--spool".into(),
        "/tmp/spool.jsonl".into(),
        "--".into(),
        "curl".into(),
        "--http".into(),
        "--server".into(),
        "https://example.test".into(),
        "--token=literal".into(),
    ])
    .unwrap();

    let Mode::Cli(invocation) = mode else {
        panic!("expected CLI mode");
    };
    assert_eq!(invocation.flags, cli::GlobalFlags::default());
    let cli::CliCommand::Ingest(cli::IngestCommand::Shell(cli::ShellCommand::Agent(
        cli::ShellAgentCommand::Wrap(args),
    ))) = invocation.command
    else {
        panic!("expected shell agent wrap");
    };
    assert_eq!(
        args.command,
        vec![
            "curl".to_string(),
            "--http".to_string(),
            "--server".to_string(),
            "https://example.test".to_string(),
            "--token=literal".to_string(),
        ]
    );
}

#[test]
fn mode_parse_accepts_debug_wrapper_setup_namespace() {
    assert!(matches!(
        Mode::parse(vec![
            "setup".into(),
            "debugwrapper".into(),
            "check".into(),
            "--json".into()
        ])
        .unwrap(),
        Mode::Setup(_)
    ));
}

#[test]
fn mode_parse_accepts_debug_compose_setup_namespace() {
    assert!(matches!(
        Mode::parse(vec![
            "setup".into(),
            "debugcompose".into(),
            "check".into(),
            "--json".into()
        ])
        .unwrap(),
        Mode::Setup(_)
    ));
}

#[test]
fn mode_parse_accepts_setup_doctor_namespace() {
    assert!(matches!(
        Mode::parse(vec!["setup".into(), "doctor".into(), "--json".into()]).unwrap(),
        Mode::Setup(_)
    ));
}

#[test]
fn mode_parse_accepts_setup_deploy_namespace() {
    let token_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(token_file.path(), "secret\n").unwrap();
    assert!(matches!(
        Mode::parse(vec![
            "setup".into(),
            "deploy".into(),
            "preflight".into(),
            "--json".into()
        ])
        .unwrap(),
        Mode::Deploy(_)
    ));
    assert!(matches!(
        Mode::parse(vec![
            "setup".into(),
            "deploy".into(),
            "local".into(),
            "--dry-run".into(),
            "--json".into()
        ])
        .unwrap(),
        Mode::Deploy(_)
    ));
    assert!(matches!(
        Mode::parse(vec![
            "setup".into(),
            "deploy".into(),
            "remote".into(),
            "nashost".into(),
            "--dry-run".into(),
            "--json".into()
        ])
        .unwrap(),
        Mode::Deploy(_)
    ));
    assert!(matches!(
        Mode::parse(vec![
            "setup".into(),
            "deploy".into(),
            "agent".into(),
            "--hosts".into(),
            "nashost,devhost".into(),
            "--target".into(),
            "https://cortex.example.test".into(),
            "--heartbeat-token-file".into(),
            token_file.path().to_string_lossy().into_owned(),
            "--binary".into(),
            "/tmp/cortex".into(),
            "--docker".into(),
            "--journald".into(),
            "--json".into(),
        ])
        .unwrap(),
        Mode::Deploy(_)
    ));
}

#[test]
fn mode_parse_rejects_top_level_deploy_namespace() {
    let err = Mode::parse(vec!["deploy".into(), "preflight".into()]).unwrap_err();
    assert!(
        err.to_string()
            .contains("removed CLI command: deploy\n\nUse `cortex setup deploy`.")
    );
}

#[test]
fn mode_parse_rejects_unknown_deploy_subcommand() {
    let err = Mode::parse(vec!["setup".into(), "deploy".into(), "bogus".into()]).unwrap_err();
    assert!(err.to_string().contains("unknown deploy subcommand: bogus"));
}

#[test]
fn mode_parse_rejects_remote_deploy_without_host() {
    let err = Mode::parse(vec!["setup".into(), "deploy".into(), "remote".into()]).unwrap_err();
    assert!(err.to_string().contains("deploy remote requires a host"));
}

#[test]
fn mode_parse_rejects_remote_deploy_with_multiple_hosts() {
    let err = Mode::parse(vec![
        "setup".into(),
        "deploy".into(),
        "remote".into(),
        "host-a".into(),
        "host-b".into(),
    ])
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("deploy remote accepts exactly one host")
    );
}

#[test]
fn parse_deploy_remote_accepts_home_override() {
    let command = super::parse_deploy_command(&[
        "remote".into(),
        "--home".into(),
        "/mnt/cache/appdata/cortex".into(),
        "nashost".into(),
        "--dry-run".into(),
    ])
    .unwrap();

    let super::DeployCommandKind::Remote {
        host,
        dry_run,
        home,
    } = command.kind
    else {
        panic!("expected deploy remote");
    };
    assert_eq!(host, "nashost");
    assert!(dry_run);
    assert_eq!(home.as_deref(), Some("/mnt/cache/appdata/cortex"));
}

#[test]
fn parse_deploy_remote_home_defaults_to_live_profile_seed_shape() {
    let command = super::parse_deploy_command(&[
        "remote".into(),
        "--home".into(),
        "/mnt/cache/appdata/cortex".into(),
        "nashost".into(),
    ])
    .unwrap();

    assert!(matches!(
        command.kind,
        super::DeployCommandKind::Remote {
            ref host,
            dry_run: false,
            home: Some(ref home),
        } if host == "nashost" && home == "/mnt/cache/appdata/cortex"
    ));
}

#[test]
fn parse_deploy_agent_trims_and_drops_empty_hosts() {
    let command = super::parse_deploy_command(&[
        "agent".into(),
        "--hosts".into(),
        " nashost, ,devhost, ".into(),
    ])
    .unwrap();

    let super::DeployCommandKind::Agent { hosts, .. } = command.kind else {
        panic!("expected deploy agent");
    };
    assert_eq!(hosts, vec!["nashost".to_string(), "devhost".to_string()]);
}

#[test]
fn parse_deploy_agent_preserves_all_options() {
    let token_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(token_file.path(), "secret\n").unwrap();
    let token_path = token_file.path().to_string_lossy().into_owned();
    let command = super::parse_deploy_command(&[
        "agent".into(),
        "--hosts".into(),
        "nashost,devhost".into(),
        "--target".into(),
        "https://cortex.example.test".into(),
        "--heartbeat-token-file".into(),
        token_path,
        "--binary".into(),
        "/tmp/cortex".into(),
        "--docker".into(),
        "--journald".into(),
        "--json".into(),
    ])
    .unwrap();

    assert!(command.json);
    let super::DeployCommandKind::Agent {
        hosts,
        target,
        token,
        docker,
        journald,
        binary,
    } = command.kind
    else {
        panic!("expected deploy agent");
    };
    assert_eq!(hosts, vec!["nashost".to_string(), "devhost".to_string()]);
    assert_eq!(target.as_deref(), Some("https://cortex.example.test"));
    assert_eq!(token.as_deref(), Some("secret"));
    assert_eq!(docker, Some(true));
    assert_eq!(journald, Some(true));
    assert_eq!(binary.as_deref(), Some("/tmp/cortex"));
}

#[test]
fn parse_deploy_agent_reports_missing_option_values() {
    for flag in ["--hosts", "--target", "--heartbeat-token-file", "--binary"] {
        let err = super::parse_deploy_command(&["agent".into(), flag.into()]).unwrap_err();
        assert!(
            err.to_string().contains("requires a value"),
            "expected missing-value error for {flag}, got: {err}"
        );
    }
}

#[test]
fn mode_parse_accepts_update_defaults_to_all() {
    let mode = super::Mode::parse(vec!["update".into()]).unwrap();

    assert!(matches!(
        mode,
        super::Mode::Update(super::UpdateCommand {
            kind: super::UpdateCommandKind::Run {
                scope: cortex::update::UpdateScope::All,
                dry_run: false,
                profile: None,
                binary: None,
            },
            json: false,
        })
    ));
}

#[test]
fn mode_parse_accepts_update_server_dry_run_json_profile() {
    let mode = super::Mode::parse(vec![
        "update".into(),
        "server".into(),
        "--dry-run".into(),
        "--json".into(),
        "--profile".into(),
        "/tmp/deployments.toml".into(),
    ])
    .unwrap();

    assert!(matches!(
        mode,
        super::Mode::Update(super::UpdateCommand {
            kind: super::UpdateCommandKind::Run {
                scope: cortex::update::UpdateScope::Server,
                dry_run: true,
                profile: Some(ref profile),
                binary: None,
            },
            json: true,
        }) if profile == "/tmp/deployments.toml"
    ));
}

#[test]
fn mode_parse_accepts_update_clients_aliases() {
    for scope_name in ["clients", "agents"] {
        let mode = super::Mode::parse(vec!["update".into(), scope_name.into()]).unwrap();
        assert!(matches!(
            mode,
            super::Mode::Update(super::UpdateCommand {
                kind: super::UpdateCommandKind::Run {
                    scope: cortex::update::UpdateScope::Clients,
                    ..
                },
                ..
            })
        ));
    }
}

#[test]
fn mode_parse_accepts_update_config_server() {
    let mode = super::Mode::parse(vec![
        "update".into(),
        "config".into(),
        "server".into(),
        "--host".into(),
        "nashost".into(),
        "--home".into(),
        "/mnt/cache/appdata/cortex".into(),
        "--profile".into(),
        "/tmp/deployments.toml".into(),
        "--json".into(),
    ])
    .unwrap();

    assert!(matches!(
        mode,
        super::Mode::Update(super::UpdateCommand {
            kind: super::UpdateCommandKind::ConfigServer {
                ref host,
                ref home,
                profile: Some(ref profile),
            },
            json: true,
        }) if host == "nashost" && home == "/mnt/cache/appdata/cortex" && profile == "/tmp/deployments.toml"
    ));
}

#[test]
fn mode_parse_accepts_update_config_clients() {
    let mode = super::Mode::parse(vec![
        "update".into(),
        "config".into(),
        "clients".into(),
        "--hosts".into(),
        "devhost,backuphost".into(),
        "--target".into(),
        "https://cortex.example.invalid".into(),
        "--docker".into(),
    ])
    .unwrap();

    assert!(matches!(
        mode,
        super::Mode::Update(super::UpdateCommand {
            kind: super::UpdateCommandKind::ConfigClients {
                ref hosts,
                target: Some(ref target),
                docker: Some(true),
                journald: None,
                profile: None,
            },
            json: false,
        }) if hosts == &vec!["devhost".to_string(), "backuphost".to_string()]
             && target == "https://cortex.example.invalid"
    ));
}

#[test]
fn mode_parse_rejects_update_config_run_only_flags() {
    let dry_run = super::Mode::parse(vec![
        "update".into(),
        "config".into(),
        "server".into(),
        "--host".into(),
        "nashost".into(),
        "--home".into(),
        "/mnt/cache/appdata/cortex".into(),
        "--dry-run".into(),
    ])
    .unwrap_err();
    assert!(
        dry_run.to_string().contains("--dry-run is only valid"),
        "got: {dry_run}"
    );

    let binary = super::Mode::parse(vec![
        "update".into(),
        "config".into(),
        "clients".into(),
        "--hosts".into(),
        "devhost".into(),
        "--binary".into(),
        "/tmp/cortex".into(),
    ])
    .unwrap_err();
    assert!(
        binary.to_string().contains("--binary is only valid"),
        "got: {binary}"
    );
}

#[test]
fn mode_parse_rejects_update_server_binary_flag() {
    let err = super::Mode::parse(vec![
        "update".into(),
        "server".into(),
        "--binary".into(),
        "/tmp/cortex".into(),
    ])
    .unwrap_err();

    assert!(
        err.to_string().contains("--binary is only valid"),
        "got: {err}"
    );
}

#[test]
fn mode_parse_setup_subcommands_default_to_check_and_parse_remove() {
    let cases = [
        (
            vec!["setup", "sessionstimer", "--json"],
            "sessionstimer check",
        ),
        (
            vec!["setup", "sessionswatch", "remove", "--json"],
            "sessionswatch remove",
        ),
        (
            vec!["setup", "shell", "agent", "remove", "--json"],
            "shell agent remove",
        ),
        (
            vec!["setup", "heartbeatagent", "remove", "--json"],
            "heartbeatagent remove",
        ),
        (
            vec!["setup", "debugwrapper", "remove", "--json"],
            "debugwrapper remove",
        ),
        (
            vec!["setup", "debugcompose", "remove", "--json"],
            "debugcompose remove",
        ),
    ];

    for (args, label) in cases {
        let mode = Mode::parse(args.into_iter().map(str::to_string).collect()).unwrap();
        let Mode::Setup(command) = mode else {
            panic!("{label}: expected setup mode");
        };
        assert!(command.json, "{label}: --json should be preserved");
    }
}

#[test]
fn mode_parse_rejects_duplicate_sessions_watch_service_actions() {
    let err = Mode::parse(vec![
        "setup".into(),
        "sessionswatch".into(),
        "install".into(),
        "remove".into(),
    ])
    .unwrap_err();

    assert!(
        err.to_string()
            .contains("sessionswatch action specified more than once")
    );
}

#[test]
fn mode_parse_accepts_binary_doctor() {
    assert!(matches!(
        Mode::parse(vec!["doctor".into(), "binary".into(), "--json".into()]).unwrap(),
        Mode::DoctorBinary(_)
    ));
}

#[test]
fn mode_default_log_filter_matches_operational_noise_profile() {
    assert_eq!(Mode::ServeMcp.default_log_filter(), "info");
    assert_eq!(Mode::StdioMcp.default_log_filter(), "warn");
    assert_eq!(Mode::Help.default_log_filter(), "info");
    assert_eq!(Mode::Version.default_log_filter(), "info");
    assert_eq!(
        Mode::Setup(super::SetupCommand {
            kind: super::SetupCommandKind::Main(cortex::setup::SetupMode::Check),
            json: false,
        })
        .default_log_filter(),
        "warn"
    );
    assert_eq!(
        Mode::Deploy(super::DeployCommand {
            kind: super::DeployCommandKind::Preflight,
            json: false,
        })
        .default_log_filter(),
        "warn"
    );
    assert_eq!(
        Mode::DoctorBinary(super::DoctorBinaryCommand { json: false }).default_log_filter(),
        "warn"
    );
    assert_eq!(
        Mode::DoctorFull(super::DoctorFullCommand {
            json: false,
            fix: false,
            yes: false
        })
        .default_log_filter(),
        "warn"
    );
    assert_eq!(
        Mode::parse(vec!["search".into(), "foo".into()])
            .unwrap()
            .default_log_filter(),
        "error"
    );
}

#[test]
fn parse_doctor_commands_accept_json_and_reject_bad_shapes() {
    assert!(
        super::parse_doctor_full_command(&["--json".into()])
            .unwrap()
            .json
    );
    assert!(
        super::parse_doctor_command(&["binary".into(), "--json".into()])
            .unwrap()
            .json
    );

    let err = super::parse_doctor_command(&["--json".into()])
        .unwrap_err()
        .to_string();
    assert!(err.contains("doctor requires `binary`"));

    let err = super::parse_doctor_full_command(&["bogus".into()])
        .unwrap_err()
        .to_string();
    assert!(err.contains("unknown doctor argument"));
}

#[test]
fn parse_setup_command_accepts_main_modes_and_rejects_bad_args() {
    let check = super::parse_setup_command(&["check".into(), "--json".into()]).unwrap();
    assert!(matches!(
        check.kind,
        super::SetupCommandKind::Main(cortex::setup::SetupMode::Check)
    ));
    assert!(check.json);

    let repair = super::parse_setup_command(&["repair".into()]).unwrap();
    assert!(matches!(
        repair.kind,
        super::SetupCommandKind::Main(cortex::setup::SetupMode::Repair)
    ));

    let default = super::parse_setup_command(&[]).unwrap();
    assert!(matches!(
        default.kind,
        super::SetupCommandKind::Main(cortex::setup::SetupMode::FirstRun)
    ));

    let err = super::parse_setup_command(&["bogus".into()])
        .unwrap_err()
        .to_string();
    assert!(err.contains("unknown setup argument"));

    let err =
        super::parse_setup_command(&["debugwrapper".into(), "install".into(), "remove".into()])
            .unwrap_err()
            .to_string();
    assert!(err.contains("debugwrapper action specified more than once"));

    let err = super::parse_setup_command(&["debugcompose".into(), "--bad".into()])
        .unwrap_err()
        .to_string();
    assert!(err.contains("unknown debugcompose argument"));
}

#[test]
fn setup_install_rejects_unknown_options_before_side_effects() {
    let error =
        super::parse_setup_command(&["install".into(), "--cortex-live-invalid-option".into()])
            .unwrap_err();
    assert!(error.to_string().contains("unknown setup install argument"));
}

#[test]
fn update_rejects_unknown_options_before_dispatch() {
    let error = super::parse_update_command(&["--cortex-live-invalid-option".into()]).unwrap_err();
    assert!(error.to_string().contains("unknown update scope"));
}

#[test]
fn parse_deploy_command_covers_modes_and_rejects_contextual_flags() {
    let preflight = super::parse_deploy_command(&["preflight".into(), "--json".into()]).unwrap();
    assert!(matches!(
        preflight.kind,
        super::DeployCommandKind::Preflight
    ));
    assert!(preflight.json);

    let local = super::parse_deploy_command(&["local".into()]).unwrap();
    assert!(matches!(
        local.kind,
        super::DeployCommandKind::Local { dry_run: false }
    ));

    let remote =
        super::parse_deploy_command(&["remote".into(), "nashost".into(), "--dry-run".into()])
            .unwrap();
    assert!(matches!(
        remote.kind,
        super::DeployCommandKind::Remote {
            ref host,
            dry_run: true,
            home: None
        } if host == "nashost"
    ));

    for (args, expected) in [
        (
            vec!["local", "--hosts", "nashost"],
            "unknown deploy local argument",
        ),
        (vec!["remote", "--docker"], "unknown deploy remote argument"),
        (vec!["agent", "--dry-run"], "unknown deploy agent argument"),
    ] {
        let err =
            super::parse_deploy_command(&args.into_iter().map(str::to_string).collect::<Vec<_>>())
                .unwrap_err()
                .to_string();
        assert!(err.contains(expected), "expected {expected:?}, got {err:?}");
    }
}

// ─── Bead 0p8r.6: global HTTP flag plumbing ─────────────────────────────────

use serial_test::serial;

/// Restores CORTEX_API_TOKEN / CORTEX_USE_HTTP on drop. Tests below use this
/// to assert `--help` / `--version` work without any token in the env.
struct EnvVarGuard {
    name: &'static str,
    previous: Option<String>,
}

impl EnvVarGuard {
    fn unset(name: &'static str) -> Self {
        let previous = crate::env::var(name).ok();
        crate::env::remove_test_var(name);
        Self { name, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        match &self.previous {
            Some(v) => crate::env::set_test_var(self.name, v),
            None => crate::env::remove_test_var(self.name),
        }
    }
}

#[test]
#[serial]
fn help_and_version_bypass_mode_resolution_without_token() {
    // Bead .6 contract: --help and --version must NOT touch env / discovery /
    // services. Without CORTEX_API_TOKEN and CORTEX_USE_HTTP set, they should
    // still resolve to Help/Version without erroring.
    let _g1 = EnvVarGuard::unset("CORTEX_API_TOKEN");
    let _g2 = EnvVarGuard::unset("CORTEX_USE_HTTP");

    assert_eq!(Mode::parse(vec!["--help".into()]).unwrap(), Mode::Help);
    assert_eq!(Mode::parse(vec!["-h".into()]).unwrap(), Mode::Help);
    assert_eq!(Mode::parse(vec!["help".into()]).unwrap(), Mode::Help);
    assert_eq!(
        Mode::parse(vec!["--version".into()]).unwrap(),
        Mode::Version
    );
    assert_eq!(Mode::parse(vec!["-V".into()]).unwrap(), Mode::Version);
    assert_eq!(Mode::parse(vec!["version".into()]).unwrap(), Mode::Version);
}

#[test]
fn mode_parse_strips_http_flag_before_subcommand_dispatch() {
    // `--http` before the subcommand keyword must not break dispatch.
    let mode = Mode::parse(vec!["--http".into(), "search".into(), "foo".into()]).unwrap();
    let invocation = match mode {
        Mode::Cli(b) => *b,
        other => panic!("expected Cli, got {other:?}"),
    };
    assert!(invocation.flags.force_http);
}

#[test]
fn mode_parse_strips_http_flag_after_subcommand_dispatch() {
    // `--http` after the subcommand keyword also works.
    let mode = Mode::parse(vec!["search".into(), "--http".into(), "foo".into()]).unwrap();
    let invocation = match mode {
        Mode::Cli(b) => *b,
        other => panic!("expected Cli, got {other:?}"),
    };
    assert!(invocation.flags.force_http);
}

#[test]
fn mode_parse_server_flag_implies_http_path() {
    let mode = Mode::parse(vec![
        "--server".into(),
        "http://other:3100".into(),
        "search".into(),
        "foo".into(),
    ])
    .unwrap();
    let invocation = match mode {
        Mode::Cli(b) => *b,
        other => panic!("expected Cli, got {other:?}"),
    };
    assert_eq!(
        invocation.flags.server.as_deref(),
        Some("http://other:3100")
    );
    // --server alone does NOT set force_http; http_trigger() decides.
    assert!(!invocation.flags.force_http);
    assert_eq!(invocation.flags.http_trigger(), Some("--server"));
}

#[test]
fn mode_parse_token_flag_implies_http_path() {
    let mode = Mode::parse(vec!["search".into(), "--token=sekret".into(), "foo".into()]).unwrap();
    let invocation = match mode {
        Mode::Cli(b) => *b,
        other => panic!("expected Cli, got {other:?}"),
    };
    assert_eq!(invocation.flags.token.as_deref(), Some("sekret"));
    assert_eq!(invocation.flags.http_trigger(), Some("--token"));
}

#[test]
fn mode_parse_routes_http_setup_to_cli_arm() {
    // `setup` is recognised both by the dedicated Mode::Setup arm AND by the
    // CLI dispatcher. With global flags present, the dedicated arm is skipped
    // (because it requires `global == default`) and dispatch falls through
    // to the CLI arm — run_cli is then responsible for rejecting it.
    // This test pins that routing so a future refactor doesn't silently
    // swallow --http on `setup`.
    let mode = Mode::parse(vec!["--http".into(), "setup".into(), "check".into()]).expect("parses");
    let invocation = match mode {
        Mode::Cli(b) => *b,
        other => panic!("expected Cli (routed to run_cli for the reject), got {other:?}"),
    };
    assert!(invocation.flags.force_http);
    assert!(matches!(
        invocation.command,
        super::cli::CliCommand::Setup(_)
    ));
}

#[test]
fn mode_parse_rejects_http_flag_on_serve_mcp() {
    let err = Mode::parse(vec!["--http".into(), "serve".into(), "mcp".into()]).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("HTTP flags") && msg.contains("query CLI"),
        "expected guard message, got: {msg}"
    );
}

#[test]
fn mode_parse_rejects_http_flag_on_deploy() {
    let err = Mode::parse(vec!["--http".into(), "deploy".into(), "local".into()]).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("HTTP flags") && msg.contains("query CLI"),
        "expected HTTP flag guard message, got: {msg}"
    );
}

#[test]
fn mode_parse_accepts_new_surface_parity_subcommands() {
    // All five surface-parity subcommands parse at the top level with no
    // flags — `compare`'s required-flag validation lives in
    // `CompareArgs::into_request()`, not the top-level parser, so a bare
    // `compare` is accepted by `Mode::parse` even though running it would
    // later bail.
    let cases: &[&[&str]] = &[
        &["hosts", "silent"],
        &["state", "clockskew"],
        &["analysis", "anomalies"],
        &["analysis", "compare"],
        &["apps"],
    ];
    for args in cases {
        let result = Mode::parse(args.iter().map(|arg| (*arg).to_string()).collect());
        assert!(
            result.is_ok(),
            "Mode::parse rejected '{args:?}': {result:?}"
        );
    }
}

fn cli_invocation(args: &[&str]) -> super::CliInvocation {
    let mode = Mode::parse(args.iter().map(|arg| (*arg).to_string()).collect()).unwrap();
    let Mode::Cli(invocation) = mode else {
        panic!("expected CLI mode");
    };
    *invocation
}

#[tokio::test]
async fn run_cli_rejects_http_flags_for_local_only_compose_setup_and_inventory() {
    for (args, expected) in [
        (
            &["--http", "compose", "status"][..],
            "`compose` (local-only command)",
        ),
        (
            &["--server", "http://127.0.0.1:3100", "setup", "check"][..],
            "`setup` (local-only command)",
        ),
        (
            &["ingest", "inventory", "--token", "secret", "refresh"][..],
            "`ingest inventory` (local-only command)",
        ),
    ] {
        let err = super::run_cli(cli_invocation(args)).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(expected),
            "expected {expected:?} in {msg:?} for args {args:?}"
        );
    }
}

#[tokio::test]
async fn run_cli_rejects_http_flags_for_agent_local_surfaces() {
    for (args, expected) in [
        (
            &["--http", "heartbeat", "agent"][..],
            "--http has no effect on `heartbeat agent`",
        ),
        (
            &[
                "ingest",
                "shell",
                "agent",
                "wrap",
                "--server",
                "http://127.0.0.1:3100",
                "--spool",
                "/tmp/spool.jsonl",
                "--",
                "true",
            ][..],
            "`ingest shell agent wrap` (wrapper command)",
        ),
        (
            &[
                "ingest",
                "shell",
                "user",
                "index",
                "--path",
                "/tmp/history",
                "--token",
                "secret",
            ][..],
            "local shell commands",
        ),
    ] {
        let err = super::run_cli(cli_invocation(args)).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(expected),
            "expected {expected:?} in {msg:?} for args {args:?}"
        );
    }
}

#[test]
fn colorize_setup_status_renders_all_status_variants() {
    use cortex::setup::SetupStatus;

    assert!(super::colorize_setup_status(&SetupStatus::Ok).contains("Ok"));
    assert!(super::colorize_setup_status(&SetupStatus::Warn).contains("Warn"));
    assert!(super::colorize_setup_status(&SetupStatus::Error).contains("Error"));
    assert!(super::colorize_setup_status(&SetupStatus::Skipped).contains("Skipped"));
}

// Top-level help banner content + per-command drift coverage now live in
// `src/cli/help_tests.rs` (the `CATALOG` is the source of truth, not a flat
// USAGE const).

#[test]
fn install_color_from_args_parses_and_strips() {
    use cli::color::install_color_from_args;

    let mut a = vec!["--no-color".to_string(), "stats".to_string()];
    install_color_from_args(&mut a).unwrap();
    assert_eq!(a, vec!["stats".to_string()], "--no-color must be stripped");

    let mut b = vec!["--color=never".to_string(), "tail".to_string()];
    install_color_from_args(&mut b).unwrap();
    assert_eq!(
        b,
        vec!["tail".to_string()],
        "--color=VALUE must be stripped"
    );

    let mut c = vec![
        "--color".to_string(),
        "always".to_string(),
        "tail".to_string(),
    ];
    install_color_from_args(&mut c).unwrap();
    assert_eq!(
        c,
        vec!["tail".to_string()],
        "--color VALUE must be stripped"
    );

    let mut d = vec!["--color".to_string(), "search".to_string()];
    install_color_from_args(&mut d).unwrap();
    assert_eq!(
        d,
        vec!["search".to_string()],
        "bare --color (no value word) must be stripped, treating `search` as the command"
    );

    // `--` sentinel: nothing past it is touched.
    let mut e = vec![
        "wrap".to_string(),
        "--".to_string(),
        "--color".to_string(),
        "never".to_string(),
    ];
    install_color_from_args(&mut e).unwrap();
    assert_eq!(
        e,
        vec![
            "wrap".to_string(),
            "--".to_string(),
            "--color".to_string(),
            "never".to_string()
        ],
        "args after `--` must be left untouched"
    );

    // Bad value errors.
    let mut f = vec!["--color=technicolor".to_string()];
    assert!(install_color_from_args(&mut f).is_err());
}

fn shell_agent_index_args(server: Option<&str>, token: Option<&str>) -> cli::ShellAgentIndexArgs {
    cli::ShellAgentIndexArgs {
        path: "/tmp/spool.jsonl".to_string(),
        json: false,
        server: server.map(str::to_string),
        token: token.map(str::to_string),
    }
}

#[test]
fn resolve_shell_agent_index_dispatch_prefers_resolved_server_for_remote() {
    // By the time this function runs, the caller has already folded any
    // global `--server` into `args.server` — this only asserts that once
    // `args.server` is `Some`, the dispatch is Remote regardless of --http.
    let args = shell_agent_index_args(Some("https://cortex.example.test"), None);
    let flags = cli::GlobalFlags::default();
    assert_eq!(
        resolve_shell_agent_index_dispatch(&args, &flags).unwrap(),
        ShellAgentIndexDispatch::Remote("https://cortex.example.test".to_string())
    );
}

#[test]
fn resolve_shell_agent_index_dispatch_local_when_no_server_or_token() {
    let args = shell_agent_index_args(None, None);
    let flags = cli::GlobalFlags::default();
    assert_eq!(
        resolve_shell_agent_index_dispatch(&args, &flags).unwrap(),
        ShellAgentIndexDispatch::Local
    );
}

#[test]
fn resolve_shell_agent_index_dispatch_bails_on_http_without_resolvable_server() {
    let args = shell_agent_index_args(None, None);
    let flags = cli::GlobalFlags {
        force_http: true,
        ..cli::GlobalFlags::default()
    };
    let error = resolve_shell_agent_index_dispatch(&args, &flags)
        .unwrap_err()
        .to_string();
    assert!(error.contains("--http requires --server"), "got: {error}");
}

#[test]
fn resolve_shell_agent_index_dispatch_bails_on_token_without_resolvable_server() {
    // Code-review finding this test guards: a `--token` with no `--server`
    // anywhere used to silently fall through to the local path, which never
    // reads `args.token` — the token was accepted and quietly discarded.
    let args = shell_agent_index_args(None, Some("secret"));
    let flags = cli::GlobalFlags::default();
    let error = resolve_shell_agent_index_dispatch(&args, &flags)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("--token has no effect without --server"),
        "got: {error}"
    );
}

#[test]
fn resolve_shell_agent_index_dispatch_server_and_token_together_is_remote() {
    let args = shell_agent_index_args(Some("https://cortex.example.test"), Some("secret"));
    let flags = cli::GlobalFlags::default();
    assert_eq!(
        resolve_shell_agent_index_dispatch(&args, &flags).unwrap(),
        ShellAgentIndexDispatch::Remote("https://cortex.example.test".to_string())
    );
}
