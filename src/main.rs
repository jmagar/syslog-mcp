use anyhow::{Context, Result};

use axum::Router;
pub(crate) use cortex::env;
use cortex::{api, doctor, logging, mcp, runtime::RuntimeCore, web_app};
use rmcp::{ServiceExt, transport::stdio};
use tracing::info;

mod cli;

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        // Aurora rose-red `error:` prefix on stderr (gated by --color / TTY).
        cli::color::report_error(&format!("{e:#}"));
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    // Parse + strip `--color` / `--no-color` before anything prints, so the
    // help banner, errors, query output, doctor, setup, and tracing all honor
    // the same switch.
    let mut raw: Vec<String> = std::env::args().skip(1).collect();
    cli::color::install_color_from_args(&mut raw)?;

    // Explicit help (`cortex [--help|help]`, `cortex <cmd> --help`) prints the
    // Aurora grouped banner / per-command flags to stdout and exits 0.
    if cli::help::maybe_handle_help(&raw) {
        return Ok(());
    }

    let mode = Mode::parse(raw)?;
    if mode == Mode::Help {
        print_usage();
        return Ok(());
    }
    if mode == Mode::Version {
        println!("cortex {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    logging::init(mode.default_log_filter());

    info!("cortex v{}", env!("CARGO_PKG_VERSION"));

    match mode {
        Mode::ServeMcp => serve_mcp().await,
        Mode::StdioMcp => serve_stdio_mcp().await,
        Mode::Cli(invocation) => run_cli(*invocation).await,
        Mode::Setup(command) => run_setup(command).await,
        Mode::Deploy(command) => run_deploy(command).await,
        Mode::Update(command) => run_update(command).await,
        Mode::DoctorBinary(command) => doctor::run_binary_doctor(command.json).await,
        Mode::DoctorFull(command) => {
            doctor::run_full_doctor(command.json, command.fix, command.yes).await
        }
        Mode::Help => unreachable!("handled before logging initialization"),
        Mode::Version => unreachable!("handled before logging initialization"),
    }
}

async fn serve_stdio_mcp() -> Result<()> {
    let runtime = RuntimeCore::load_query_only().await?;
    let service = mcp::rmcp_server(runtime.mcp_state()).serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}

async fn run_cli(invocation: CliInvocation) -> Result<()> {
    let CliInvocation { command, flags } = invocation;

    // `compose` and `setup` stay on the local-only path: they
    // manage local host state (systemd units, Docker compose stacks, on-disk
    // config, user journal logs) that has no HTTP analogue. Reject explicit
    // HTTP-mode FLAGS up front, but
    // silently ignore the `CORTEX_USE_HTTP` env trigger — `setup repair`
    // writes that into `~/.cortex/.env` as the post-cutover default, and
    // bailing on it would break the very command operators run to repair.
    if matches!(
        command,
        cli::CliCommand::Compose(_) | cli::CliCommand::Setup(_)
    ) {
        if let Some(trigger) = flags.http_flag_trigger() {
            let command_name = match command {
                cli::CliCommand::Compose(_) => "compose",
                cli::CliCommand::Setup(_) => "setup",
                _ => unreachable!("guarded by matches! above"),
            };
            anyhow::bail!(
                "{} has no effect on `{}` (local-only command); remove --http / --server / --token",
                trigger,
                command_name,
            );
        }
        return match command {
            cli::CliCommand::Compose(_) => cli::run_compose(command).await,
            cli::CliCommand::Setup(cmd) => cli::run_setup(cmd),
            _ => unreachable!("guarded by matches! above"),
        };
    }

    if let cli::CliCommand::Config(command) = command {
        return cli::run_config(command);
    }

    if let cli::CliCommand::Completions(args) = command {
        return cli::run_completions(&args);
    }

    if let cli::CliCommand::Complete(args) = command {
        return cli::run_complete(&args);
    }

    if let cli::CliCommand::Ingest(cli::IngestCommand::Inventory(command)) = command {
        if let Some(trigger) = flags.http_flag_trigger() {
            anyhow::bail!(
                "{} has no effect on `ingest inventory` (local-only command); remove --http / --server / --token",
                trigger
            );
        }
        return cli::run_inventory(command).await;
    }

    if let cli::CliCommand::Ingest(cli::IngestCommand::Shell(cli::ShellCommand::Agent(
        cli::ShellAgentCommand::Wrap(args),
    ))) = command
    {
        // Liveness probe from the generated wrapper: succeed fast, run nothing.
        // Keep this ahead of the http-flag check so a probe never errors.
        if args.probe {
            std::process::exit(0);
        }
        if let Some(trigger) = flags.http_flag_trigger() {
            anyhow::bail!(
                "{} has no effect on `ingest shell agent wrap` (wrapper command); remove --http / --server / --token",
                trigger
            );
        }
        let code = cli::run_shell_agent_wrap(args)?;
        std::process::exit(code);
    }

    if let cli::CliCommand::Ingest(cli::IngestCommand::Shell(cli::ShellCommand::Agent(
        cli::ShellAgentCommand::Index(mut args),
    ))) = command
    {
        if args.server.is_none() {
            args.server = flags.server.clone();
        }
        if args.token.is_none() {
            args.token = flags.token.clone();
        }
        match resolve_shell_agent_index_dispatch(&args, &flags)? {
            ShellAgentIndexDispatch::Remote(server) => {
                return cli::run_shell_agent_index_remote(args, server).await;
            }
            ShellAgentIndexDispatch::Local => {
                let runtime = RuntimeCore::load_query_only().await?;
                return cli::run_shell_agent_index_local(
                    &cli::CliMode::Local(runtime.service()),
                    args,
                )
                .await;
            }
        }
    }

    if let cli::CliCommand::Heartbeat(mut command) = command {
        if flags.force_http {
            anyhow::bail!(
                "--http has no effect on `heartbeat agent`; use --target/--server and --token"
            );
        }
        match &mut command {
            cli::HeartbeatCommand::Agent(args) => {
                if args.target.is_none() {
                    args.target = flags.server;
                }
                if args.token.is_none() {
                    args.token = flags.token;
                }
            }
        }
        return cli::run_heartbeat_no_db(command).await;
    }

    if matches!(
        command,
        cli::CliCommand::Ingest(cli::IngestCommand::Shell(cli::ShellCommand::User(_)))
    ) {
        if let Some(trigger) = flags.http_flag_trigger() {
            anyhow::bail!(
                "{} has no effect on local shell commands; remove --http / --server / --token",
                trigger
            );
        }
        let runtime = RuntimeCore::load_query_only().await?;
        return cli::run(cli::CliMode::Local(runtime.service()), command).await;
    }

    // Build CliMode ONCE per invocation, matching the per-invocation reqwest
    // Client rule from bead .5. For Local mode we lazily load the runtime so
    // HTTP-mode invocations don't pay the SQLite-open cost.
    let mode = match flags.http_trigger() {
        Some(trigger) => cli::CliMode::Http(flags.build_http_client(trigger)?),
        None => {
            let runtime = RuntimeCore::load_query_only().await?;
            cli::CliMode::Local(runtime.service())
        }
    };
    cli::run(mode, command).await
}

async fn run_deploy(command: DeployCommand) -> Result<()> {
    let (mode, label) = match command.kind {
        DeployCommandKind::Preflight => (cortex::setup::SetupMode::Check, "preflight"),
        DeployCommandKind::Local { dry_run: true } => {
            (cortex::setup::SetupMode::Check, "local dry-run")
        }
        DeployCommandKind::Local { dry_run: false } => (cortex::setup::SetupMode::Repair, "local"),
        DeployCommandKind::Remote {
            host,
            dry_run,
            home,
        } => {
            let report = cortex::deploy::run_remote_deploy(
                &host,
                cortex::deploy::RemoteDeployOptions { dry_run, home },
            )?;
            if command.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("cortex setup deploy remote {host}");
                println!("mode: {}", report.mode);
                println!("host: {}", report.host);
                println!("home: {}", report.home);
                println!("env: {}", report.env_path);
                println!("compose: {}", report.compose_dir);
                println!("data: {}", report.data_dir);
                println!("health: {}", report.health_url);
                println!("mcp: {}", report.mcp_url);
                for phase in &report.phases {
                    println!(
                        "{:?}\t{}\t{}ms\t{}",
                        phase.status, phase.name, phase.elapsed_ms, phase.detail
                    );
                }
            }
            if report.has_errors {
                anyhow::bail!("cortex setup deploy remote {host} completed with failed phases");
            }
            if !dry_run {
                cortex::update::configure_server_profile(None, &host, &report.home)?;
            }
            return Ok(());
        }
        DeployCommandKind::Agent {
            hosts,
            target,
            token,
            docker,
            journald,
            binary,
        } => {
            run_deploy_agent(hosts, target, token, docker, journald, binary)?;
            return Ok(());
        }
    };
    let report = cortex::setup::run_setup(mode).await?;
    if command.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("cortex setup deploy {label}");
        println!("mode: {}", report.mode);
        println!("home: {}", report.home.display());
        println!("env: {}", report.env_path.display());
        println!("compose: {}", report.compose_dir.display());
        println!("data: {}", report.data_dir.display());
        println!("health: {}", report.health_url);
        println!("mcp: {}", report.mcp_url);
        for phase in &report.phases {
            println!(
                "{:?}\t{}\t{}ms\t{}",
                phase.status, phase.name, phase.elapsed_ms, phase.detail
            );
        }
    }
    if report.has_errors {
        anyhow::bail!("cortex setup deploy {label} completed with failed phases");
    }
    Ok(())
}

fn run_deploy_agent(
    explicit_hosts: Vec<String>,
    target: Option<String>,
    token: Option<String>,
    docker: Option<bool>,
    journald: Option<bool>,
    binary: Option<String>,
) -> Result<()> {
    use cortex::agent_deploy::{
        AgentDeployConfig, deploy_agent_to_host, find_local_binary, probe_hosts,
        select_hosts_interactive, ssh_config_hosts,
    };

    // Resolve the binary to deploy.
    let local_binary = match binary.as_deref() {
        Some(p) => std::path::PathBuf::from(p),
        None => find_local_binary()
            .ok_or_else(|| anyhow::anyhow!("could not find cortex binary; use --binary"))?,
    };
    eprintln!("  binary  {}", local_binary.display());

    // Determine target hosts (explicit list or discover + interactive select).
    let selected = if !explicit_hosts.is_empty() {
        explicit_hosts
    } else {
        let all_hosts = ssh_config_hosts();
        if all_hosts.is_empty() {
            anyhow::bail!("no hosts found in ~/.ssh/config");
        }
        eprintln!(
            "  discovering {} host(s) from ~/.ssh/config …",
            all_hosts.len()
        );
        let probes = probe_hosts(all_hosts);
        select_hosts_interactive(&probes)?
    };

    if selected.is_empty() {
        eprintln!("  no hosts selected");
        return Ok(());
    }

    let config = AgentDeployConfig {
        target,
        token,
        require_token: false,
        docker,
        journald,
    };
    let mut failed = false;
    for host in &selected {
        eprint!("  deploying → {host} … ");
        let _ = std::io::Write::flush(&mut std::io::stderr());
        let result = deploy_agent_to_host(host, &local_binary, &config);
        if result.ok {
            eprintln!("✓  ({}ms)", result.elapsed_ms);
        } else {
            eprintln!("✗  {}", result.detail);
            failed = true;
        }
    }
    if failed {
        anyhow::bail!("one or more agent deployments failed");
    }
    Ok(())
}

async fn run_update(command: UpdateCommand) -> Result<()> {
    match command.kind {
        UpdateCommandKind::Run {
            scope,
            dry_run,
            profile,
            binary,
        } => {
            let report = cortex::update::run_update(
                scope,
                cortex::update::UpdateOptions {
                    dry_run,
                    profile_path: profile.map(std::path::PathBuf::from),
                    binary: binary.map(std::path::PathBuf::from),
                },
            )?;
            if command.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_update_report(&report);
            }
            if report.has_errors {
                anyhow::bail!("cortex update {} completed with failed phases", report.mode);
            }
        }
        UpdateCommandKind::ConfigServer {
            host,
            home,
            profile,
        } => {
            let profile = cortex::update::configure_server_profile(
                profile.as_deref().map(std::path::Path::new),
                &host,
                &home,
            )?;
            if command.json {
                println!("{}", serde_json::to_string_pretty(&profile)?);
            } else {
                println!("cortex update config server");
                println!("host: {host}");
                println!("home: {home}");
            }
        }
        UpdateCommandKind::ConfigClients {
            hosts,
            target,
            docker,
            journald,
            profile,
        } => {
            let hosts_label = hosts.join(",");
            let profile = cortex::update::configure_clients_profile(
                profile.as_deref().map(std::path::Path::new),
                hosts,
                target,
                docker,
                journald,
            )?;
            if command.json {
                println!("{}", serde_json::to_string_pretty(&profile)?);
            } else {
                println!("cortex update config clients");
                println!("hosts: {hosts_label}");
            }
        }
    }
    Ok(())
}

fn print_update_report(report: &cortex::update::UpdateReport) {
    println!("cortex update {}", report.mode);
    println!("profile: {}", report.profile_path.display());
    if let Some(server) = &report.server {
        println!("server: {} {}", server.host, server.home);
        for phase in &server.phases {
            println!(
                "server\t{:?}\t{}\t{}ms\t{}",
                phase.status, phase.name, phase.elapsed_ms, phase.detail
            );
        }
    }
    for client in &report.clients {
        println!(
            "client\t{}\t{}\t{}ms\t{}",
            if client.ok { "ok" } else { "error" },
            client.host,
            client.elapsed_ms,
            client.detail
        );
    }
    for phase in &report.skipped {
        println!(
            "skip\t{:?}\t{}\t{}ms\t{}",
            phase.status, phase.name, phase.elapsed_ms, phase.detail
        );
    }
}

async fn run_setup(command: SetupCommand) -> Result<()> {
    let report = match command.kind {
        SetupCommandKind::Main(mode) => cortex::setup::run_setup(mode).await?,
        SetupCommandKind::SessionsIndexTimer(action) => {
            cortex::setup::run_sessions_index_timer_setup(action).await?
        }
        SetupCommandKind::SessionsWatchService(action) => {
            cortex::setup::run_sessions_watch_service_setup(action).await?
        }
        SetupCommandKind::Shell(ShellSetupCommand::Agent(action)) => {
            cortex::setup::run_shell_agent_setup(action).await?
        }
        SetupCommandKind::Shell(ShellSetupCommand::Completions(action)) => {
            cortex::setup::run_shell_completions_setup(action).await?
        }
        SetupCommandKind::HeartbeatAgent(action) => {
            cortex::setup::run_heartbeat_agent_setup(action).await?
        }
        SetupCommandKind::DebugWrapper(action) => {
            cortex::setup::run_debug_wrapper_setup(action).await?
        }
        SetupCommandKind::DebugCompose(action) => {
            cortex::setup::run_debug_compose_setup(action).await?
        }
        // `cortex setup doctor` has no `--fix`/`--yes` flags of its own — the
        // stale-agent-command-grammar fix path is exposed only via the
        // top-level `cortex doctor --fix --yes`.
        SetupCommandKind::Doctor => cortex::setup::run_setup_doctor(false, false).await?,
    };
    if command.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("cortex setup mode: {}", report.mode);
        println!("home: {}", report.home.display());
        println!("env: {}", report.env_path.display());
        println!("compose: {}", report.compose_dir.display());
        println!("data: {}", report.data_dir.display());
        println!("health: {}", report.health_url);
        println!("mcp: {}", report.mcp_url);
        for phase in &report.phases {
            println!(
                "{}\t{}\t{}ms\t{}",
                colorize_setup_status(&phase.status),
                phase.name,
                phase.elapsed_ms,
                phase.detail
            );
        }
    }
    if report.has_errors {
        anyhow::bail!("cortex setup completed with failed phases");
    }
    Ok(())
}

/// `{:?}` of a setup phase status, tinted with the Aurora palette (gated by the
/// unified `--color` policy / stdout TTY).
fn colorize_setup_status(status: &cortex::setup::SetupStatus) -> String {
    use cortex::setup::SetupStatus;
    let text = format!("{status:?}");
    match status {
        SetupStatus::Ok => cli::color::success(&text),
        SetupStatus::Warn => cli::color::warn(&text),
        SetupStatus::Error => cli::color::error(&text),
        SetupStatus::Skipped => cli::color::muted(&text),
    }
}

fn parse_doctor_full_command(args: &[String]) -> Result<DoctorFullCommand> {
    let mut json = false;
    let mut fix = false;
    let mut yes = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "--fix" => fix = true,
            "--yes" => yes = true,
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => anyhow::bail!("unknown doctor argument: {other}"),
        }
    }
    Ok(DoctorFullCommand { json, fix, yes })
}

async fn serve_mcp() -> Result<()> {
    let runtime = RuntimeCore::load().await?;
    info!(
        syslog_bind = %runtime.config.receiver.bind_addr(),
        mcp_bind = %runtime.config.mcp.bind_addr(),
        db_path = %runtime.config.storage.db_path.display(),
        retention_days = runtime.config.storage.retention_days,
        max_db_size_mb = runtime.config.storage.max_db_size_mb,
        recovery_db_size_mb = runtime.config.storage.recovery_db_size_mb,
        min_free_disk_mb = runtime.config.storage.min_free_disk_mb,
        recovery_free_disk_mb = runtime.config.storage.recovery_free_disk_mb,
        cleanup_interval_secs = runtime.config.storage.cleanup_interval_secs,
        pool_size = runtime.config.storage.pool_size,
        // The split, not just the total: a post-deploy comparison of pool
        // pressure is uninterpretable without knowing how many of these
        // connections the read semaphore was allowed to take.
        pool_read_permits = runtime.config.storage.pool_budget().read_permits(),
        pool_reserved_connections = runtime.config.storage.pool_budget().reserved(),
        wal_mode = runtime.config.storage.wal_mode,
        mcp_auth_enabled = runtime.config.mcp.api_token.is_some(),
        docker_ingest_enabled = runtime.config.docker_ingest.enabled,
        docker_ingest_hosts = runtime.config.docker_ingest.hosts.len(),
        "Configuration loaded"
    );

    let mut maintenance = runtime.spawn_maintenance_tasks();
    runtime.start_syslog(&mut maintenance).await?;

    let mut app: Router = mcp::router(runtime.mcp_state());
    // /api/* is always-on. The container fails to start without
    // CORTEX_API_TOKEN — `api::router` enforces that explicitly with a
    // recovery hint pointing at `cortex setup repair`.
    {
        let api_state = api::ApiState::new(
            runtime.service(),
            runtime.config.api.clone(),
            runtime.config.mcp.port,
            cortex::config::mcp_bind_is_loopback(&runtime.config),
            runtime.config.mcp.allowed_origins.clone(),
            runtime.auth_policy().clone(),
            runtime.config.mcp.static_token_is_admin,
            runtime.config.notifications.clone(),
            cortex::stream::CursorKeys::resolved(
                runtime.config.cursor_signing_key.as_deref(),
                &runtime.config.cursor_previous_keys,
                cortex::config::mcp_bind_is_loopback(&runtime.config),
            )
            .map_err(|error| anyhow::anyhow!("invalid stream cursor configuration: {error:?}"))?,
            api::resolved_integration_profile(&runtime.config)?,
        )?;
        app = app.merge(api::router(api_state)?);
        info!("Non-MCP API mounted under /api");
    }
    if cortex::config::api_token_plaintext_exposure(&runtime.config) {
        tracing::warn!(
            bind = %runtime.config.mcp.bind_addr(),
            public_url = ?runtime.config.mcp.auth.public_url,
            "CORTEX_API_TOKEN will traverse the wire in plaintext: non-loopback bind with no \
             https:// public URL configured. Front the listener with a TLS-terminating reverse \
             proxy (e.g. SWAG) and set CORTEX_PUBLIC_URL=https://..."
        );
    }
    app = app.merge(runtime.otlp_router());
    info!("OTLP receiver mounted at /v1/logs, /v1/metrics, and /v1/traces");
    app = app.merge(runtime.heartbeat_router());
    info!("Heartbeat receiver mounted at /v1/heartbeats");
    app = app.merge(runtime.agent_command_router());
    info!("Agent-command forward receiver mounted at /v1/agent-commands");
    app = app.merge(runtime.ai_transcript_router());
    info!("AI-transcript forward receiver mounted at /v1/ai-transcripts");
    app = app.merge(runtime.syslog_forward_router());
    info!("Receipt-backed syslog forward receiver mounted at /v1/syslog-forward");
    app = app.merge(runtime.shell_history_router());
    info!("Shell-history forward receiver mounted at /v1/shell-history");
    app = app.merge(web_app::router());
    info!("Investigation workspace mounted under /app");
    if runtime.config.mcp.api_token.is_none() && !runtime.config.mcp.host.starts_with("127.") {
        tracing::warn!(
            bind = %runtime.config.mcp.bind_addr(),
            "OTLP /v1/logs, heartbeat /v1/heartbeats, and agent-command forwarding \
             /v1/agent-commands are mounted WITHOUT authentication on a non-loopback bind. \
             Anyone reachable on this address can write telemetry. \
             Set CORTEX_TOKEN to require Bearer auth."
        );
    }
    app = app.layer(tower_http::trace::TraceLayer::new_for_http());

    let mcp_bind = runtime.config.mcp.bind_addr();
    let listener = tokio::net::TcpListener::bind(&mcp_bind).await?;
    info!(bind = %mcp_bind, "MCP server listening");
    let fatal_shutdown = runtime.fatal_shutdown_token();
    let graceful_shutdown = fatal_shutdown.clone();

    // OTLP handler needs ConnectInfo<SocketAddr> for source_ip provenance.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        tokio::select! {
            _ = shutdown_signal() => {},
            _ = graceful_shutdown.cancelled() => {
                tracing::error!("Fatal runtime condition requested shutdown");
            }
        }
    })
    .await?;

    // HTTP connections are drained. Now drain in order:
    // 1. Cooperatively cancel maintenance background tasks (purge, storage,
    //    error_scan); wait up to 10 s for them to exit cleanly.
    // 2. Drain the ingest pipeline (batch writer flush) then checkpoint WAL.
    info!("HTTP server stopped; shutting down maintenance tasks");
    let maintenance_clean = maintenance
        .shutdown(std::time::Duration::from_secs(10))
        .await;
    info!("Maintenance tasks done; draining ingest pipeline");
    let runtime_clean = runtime.shutdown(std::time::Duration::from_secs(5)).await;

    if fatal_shutdown.is_cancelled() {
        anyhow::bail!("fatal syslog listener failure");
    }
    if !maintenance_clean || !runtime_clean {
        anyhow::bail!("unclean runtime shutdown");
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Mode {
    ServeMcp,
    StdioMcp,
    Cli(Box<CliInvocation>),
    Setup(SetupCommand),
    Deploy(DeployCommand),
    Update(UpdateCommand),
    DoctorBinary(DoctorBinaryCommand),
    DoctorFull(DoctorFullCommand),
    Help,
    Version,
}

/// Pairs a parsed [`cli::CliCommand`] with the [`cli::GlobalFlags`] that came
/// alongside it on the command line. Built by [`Mode::parse`] so `run_cli`
/// can construct the [`cli::CliMode`] (Local vs Http) exactly once per
/// invocation — matching the per-invocation `reqwest::Client` rule from
/// bead .5.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CliInvocation {
    command: cli::CliCommand,
    flags: cli::GlobalFlags,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DoctorFullCommand {
    json: bool,
    fix: bool,
    yes: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SetupCommand {
    kind: SetupCommandKind,
    json: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DeployCommand {
    kind: DeployCommandKind,
    json: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UpdateCommand {
    kind: UpdateCommandKind,
    json: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum UpdateCommandKind {
    Run {
        scope: cortex::update::UpdateScope,
        dry_run: bool,
        profile: Option<String>,
        binary: Option<String>,
    },
    ConfigServer {
        host: String,
        home: String,
        profile: Option<String>,
    },
    ConfigClients {
        hosts: Vec<String>,
        target: Option<String>,
        docker: Option<bool>,
        journald: Option<bool>,
        profile: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DeployCommandKind {
    Preflight,
    Local {
        dry_run: bool,
    },
    Remote {
        host: String,
        dry_run: bool,
        home: Option<String>,
    },
    Agent {
        /// Explicit host list; if empty, run interactive discovery.
        hosts: Vec<String>,
        target: Option<String>,
        token: Option<String>,
        /// `None` = flag not passed → preserve the host's existing value.
        docker: Option<bool>,
        journald: Option<bool>,
        binary: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SetupCommandKind {
    Main(cortex::setup::SetupMode),
    SessionsIndexTimer(cortex::setup::SessionsIndexTimerAction),
    SessionsWatchService(cortex::setup::SessionsWatchServiceAction),
    Shell(ShellSetupCommand),
    HeartbeatAgent(cortex::setup::HeartbeatAgentAction),
    DebugWrapper(cortex::setup::DebugWrapperAction),
    DebugCompose(cortex::setup::DebugComposeAction),
    Doctor,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ShellSetupCommand {
    Agent(cortex::setup::ShellAgentAction),
    Completions(cortex::setup::ShellCompletionsAction),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DoctorBinaryCommand {
    json: bool,
}

impl Mode {
    fn parse(args: Vec<String>) -> Result<Self> {
        // `--help` / `--version` MUST bypass everything else: no global flag
        // extraction, no env reads, no service construction. Per bead .6
        // contract these work even with `CORTEX_API_TOKEN` unset.
        if let Some(first) = args.first() {
            if first == "--help" || first == "-h" || first == "help" {
                return Ok(Self::Help);
            }
            if first == "--version" || first == "-V" || first == "version" {
                return Ok(Self::Version);
            }
        }

        // Strip CLI-only global flags (`--http`, `--server`, `--token`) from
        // the arg list before subcommand dispatch so they work in any
        // position: `cortex --http search foo` AND `cortex search --http foo`.
        // Non-CLI modes (serve/mcp/setup/doctor) reject them below — the
        // flags imply HTTP transport, which only applies to the query CLI.
        let mut remaining = args.clone();
        let global = cli::GlobalFlags::extract(&mut remaining)?;

        match remaining.as_slice() {
            [] if global == cli::GlobalFlags::default() => Ok(Self::ServeMcp),
            [command] if command == "mcp" && global == cli::GlobalFlags::default() => {
                Ok(Self::StdioMcp)
            }
            [serve, service]
                if serve == "serve"
                    && service == "mcp"
                    && global == cli::GlobalFlags::default() =>
            {
                Ok(Self::ServeMcp)
            }
            [command, deploy, rest @ ..]
                if command == "setup"
                    && deploy == "deploy"
                    && global == cli::GlobalFlags::default() =>
            {
                Ok(Self::Deploy(parse_deploy_command(rest)?))
            }
            [command, rest @ ..]
                if command == "update" && global == cli::GlobalFlags::default() =>
            {
                Ok(Self::Update(parse_update_command(rest)?))
            }
            [command, rest @ ..]
                if command == "setup"
                    && rest.first().map(String::as_str) != Some("pluginhook")
                    && global == cli::GlobalFlags::default() =>
            {
                Ok(Self::Setup(parse_setup_command(rest)?))
            }
            [command, rest @ ..]
                if command == "doctor" && global == cli::GlobalFlags::default() =>
            {
                if rest.first().map(String::as_str) == Some("binary") {
                    Ok(Self::DoctorBinary(parse_doctor_command(rest)?))
                } else {
                    Ok(Self::DoctorFull(parse_doctor_full_command(rest)?))
                }
            }
            [command, rest @ ..] if cortex::surfaces::is_cli_mode_command(command) => {
                let mut cli_args = Vec::with_capacity(rest.len() + 1);
                cli_args.push(command.clone());
                cli_args.extend(rest.iter().cloned());
                let command = cli::CliCommand::parse(cli_args)?;
                Ok(Self::Cli(Box::new(CliInvocation {
                    command,
                    flags: global,
                })))
            }
            _ if global != cli::GlobalFlags::default() => {
                // Global HTTP flags were given but what's left isn't a recognized
                // query command. Rather than enumerate commands (a list that
                // silently drifts — it once omitted topic-correlate and a dozen
                // others), name the offending args and point at the most common
                // mistake: a bare `--http` followed by a URL that should be
                // `--server <url>` (or `--http=<url>`).
                let leftover = remaining.join(" ");
                anyhow::bail!(
                    "global HTTP flags (--http, --server <url>, --token <token>) apply only to the query CLI, \
                     but `{leftover}` is not a recognized query command. \
                     To point at a server use `--server <url>` or `--http=<url>` (bare `--http` takes no value). \
                     Local-only commands (compose, setup, inventory) reject HTTP flags."
                );
            }
            _ => match cli::CliCommand::parse(args.clone()) {
                Ok(_) => unreachable!("known CLI commands are handled above"),
                Err(err) => anyhow::bail!("{err}"),
            },
        }
    }

    fn default_log_filter(&self) -> &'static str {
        match self {
            Self::ServeMcp => "info",
            Self::StdioMcp => "warn",
            Self::Cli(_) => "error",
            Self::Setup(_) => "warn",
            Self::Deploy(_) => "warn",
            Self::Update(_) => "warn",
            Self::DoctorBinary(_) => "warn",
            Self::DoctorFull(_) => "warn",
            Self::Help => "info",
            Self::Version => "info",
        }
    }
}

fn parse_setup_command(args: &[String]) -> Result<SetupCommand> {
    let mut mode = cortex::setup::SetupMode::FirstRun;
    let mut json = false;
    let mut iter = args.iter();
    if matches!(iter.clone().next().map(String::as_str), Some("install")) {
        // Validate the complete command line before the first filesystem
        // mutation. Historically this branch installed immediately after
        // seeing `install`, so an unknown flag (and even `--help`) could
        // overwrite ~/.local/bin/cortex before parsing rejected anything.
        let _ = iter.next();
        for arg in iter {
            match arg.as_str() {
                "--json" => {}
                "--help" | "-h" => {
                    print_usage();
                    std::process::exit(0);
                }
                other => anyhow::bail!("unknown setup install argument: {other}"),
            }
        }
        let dest = cli::install_self()?;
        println!("installed -> {}", dest.display());
        std::process::exit(0);
    }
    if matches!(iter.clone().next().map(String::as_str), Some("doctor")) {
        let _ = iter.next();
        for arg in iter {
            match arg.as_str() {
                "--json" => json = true,
                "--help" | "-h" => {
                    print_usage();
                    std::process::exit(0);
                }
                other => anyhow::bail!("unknown setup doctor argument: {other}"),
            }
        }
        return Ok(SetupCommand {
            kind: SetupCommandKind::Doctor,
            json,
        });
    }
    if matches!(
        iter.clone().next().map(String::as_str),
        Some("sessionstimer")
    ) {
        let _ = iter.next();
        let (action, json) = parse_setup_subcommand_args("sessionstimer", iter)?;
        return Ok(SetupCommand {
            kind: SetupCommandKind::SessionsIndexTimer(match action {
                "install" => cortex::setup::SessionsIndexTimerAction::Install,
                "remove" => cortex::setup::SessionsIndexTimerAction::Remove,
                _ => cortex::setup::SessionsIndexTimerAction::Check,
            }),
            json,
        });
    }
    if matches!(
        iter.clone().next().map(String::as_str),
        Some("sessionswatch")
    ) {
        let _ = iter.next();
        let (action, json) = parse_setup_subcommand_args("sessionswatch", iter)?;
        return Ok(SetupCommand {
            kind: SetupCommandKind::SessionsWatchService(match action {
                "install" => cortex::setup::SessionsWatchServiceAction::Install,
                "remove" => cortex::setup::SessionsWatchServiceAction::Remove,
                _ => cortex::setup::SessionsWatchServiceAction::Check,
            }),
            json,
        });
    }
    if matches!(
        iter.clone().next().map(String::as_str),
        Some("sessionshealth")
    ) {
        let _ = iter.next();
        // No action verb to parse (this subcommand has exactly one fixed
        // action) -- reusing parse_setup_subcommand_args here would silently
        // accept nonsense like `sessionshealth install` since
        // that parser treats "install"/"remove"/"check" as valid tokens
        // regardless of subcommand. Parse --json/--help directly instead,
        // matching the `doctor` subcommand's own no-action-verb parsing.
        let mut json = false;
        for arg in iter {
            match arg.as_str() {
                "--json" => json = true,
                "--help" | "-h" => {
                    print_usage();
                    std::process::exit(0);
                }
                other => anyhow::bail!("unknown sessionshealth argument: {other}"),
            }
        }
        return Ok(SetupCommand {
            kind: SetupCommandKind::SessionsWatchService(
                cortex::setup::SessionsWatchServiceAction::HealthCheck,
            ),
            json,
        });
    }
    if matches!(iter.clone().next().map(String::as_str), Some("shell")) {
        let _ = iter.next();
        match iter.next().map(String::as_str) {
            Some("agent") => {
                let (action, json) = parse_setup_subcommand_args("shell agent", iter)?;
                return Ok(SetupCommand {
                    kind: SetupCommandKind::Shell(ShellSetupCommand::Agent(match action {
                        "install" => cortex::setup::ShellAgentAction::Install,
                        "remove" => cortex::setup::ShellAgentAction::Remove,
                        _ => cortex::setup::ShellAgentAction::Check,
                    })),
                    json,
                });
            }
            Some("completions") => {
                let (action, json) = parse_setup_subcommand_args("shell completions", iter)?;
                return Ok(SetupCommand {
                    kind: SetupCommandKind::Shell(ShellSetupCommand::Completions(match action {
                        "install" => cortex::setup::ShellCompletionsAction::Install,
                        "remove" => cortex::setup::ShellCompletionsAction::Remove,
                        _ => cortex::setup::ShellCompletionsAction::Check,
                    })),
                    json,
                });
            }
            Some(other) => {
                anyhow::bail!(
                    "unknown setup shell subcommand: {other} (expected agent|completions)"
                )
            }
            None => anyhow::bail!("setup shell requires a subcommand (agent|completions)"),
        }
    }
    if matches!(
        iter.clone().next().map(String::as_str),
        Some("heartbeatagent")
    ) {
        let _ = iter.next();
        let (action, json) = parse_setup_subcommand_args("heartbeatagent", iter)?;
        return Ok(SetupCommand {
            kind: SetupCommandKind::HeartbeatAgent(match action {
                "install" => cortex::setup::HeartbeatAgentAction::Install,
                "remove" => cortex::setup::HeartbeatAgentAction::Remove,
                _ => cortex::setup::HeartbeatAgentAction::Check,
            }),
            json,
        });
    }
    if matches!(
        iter.clone().next().map(String::as_str),
        Some("debugwrapper")
    ) {
        let _ = iter.next();
        let (action, json) = parse_setup_subcommand_args("debugwrapper", iter)?;
        return Ok(SetupCommand {
            kind: SetupCommandKind::DebugWrapper(match action {
                "install" => cortex::setup::DebugWrapperAction::Install,
                "remove" => cortex::setup::DebugWrapperAction::Remove,
                _ => cortex::setup::DebugWrapperAction::Check,
            }),
            json,
        });
    }
    if matches!(
        iter.clone().next().map(String::as_str),
        Some("debugcompose")
    ) {
        let _ = iter.next();
        let (action, json) = parse_setup_subcommand_args("debugcompose", iter)?;
        return Ok(SetupCommand {
            kind: SetupCommandKind::DebugCompose(match action {
                "install" => cortex::setup::DebugComposeAction::Install,
                "remove" => cortex::setup::DebugComposeAction::Remove,
                _ => cortex::setup::DebugComposeAction::Check,
            }),
            json,
        });
    }
    for arg in args {
        match arg.as_str() {
            "check" => mode = cortex::setup::SetupMode::Check,
            "repair" => mode = cortex::setup::SetupMode::Repair,
            "--json" => json = true,
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => anyhow::bail!("unknown setup argument: {other}"),
        }
    }
    Ok(SetupCommand {
        kind: SetupCommandKind::Main(mode),
        json,
    })
}

fn parse_deploy_command(args: &[String]) -> Result<DeployCommand> {
    let (subcommand, rest) = args.split_first().ok_or_else(|| {
        anyhow::anyhow!("deploy requires a subcommand: preflight, local, remote, or agent")
    })?;
    let mut json = false;
    let mut dry_run = false;
    let mut host: Option<String> = None;
    let mut remote_home: Option<String> = None;
    // agent-specific
    let mut agent_hosts: Vec<String> = Vec::new();
    let mut agent_target: Option<String> = None;
    let mut agent_token: Option<String> = None;
    // `None` = flag not passed → preserve the host's existing setting on upgrade.
    let mut agent_docker: Option<bool> = None;
    let mut agent_journald: Option<bool> = None;
    let mut agent_binary: Option<String> = None;
    let mut i = 0usize;
    while i < rest.len() {
        match rest[i].as_str() {
            "--json" => json = true,
            "--dry-run" if matches!(subcommand.as_str(), "local" | "remote") => dry_run = true,
            "--home" if subcommand == "remote" => {
                i += 1;
                remote_home = Some(required_arg(rest, i, "--home")?);
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            "--hosts" if subcommand == "agent" => {
                i += 1;
                agent_hosts = parse_host_list(&required_arg(rest, i, "--hosts")?);
            }
            "--target" if subcommand == "agent" => {
                i += 1;
                agent_target = Some(required_arg(rest, i, "--target")?);
            }
            "--heartbeat-token" if subcommand == "agent" => anyhow::bail!(
                "--heartbeat-token exposes credentials in process arguments; use --heartbeat-token-file PATH"
            ),
            "--heartbeat-token-file" if subcommand == "agent" => {
                i += 1;
                let token_path = required_arg(rest, i, "--heartbeat-token-file")?;
                agent_token = Some(
                    std::fs::read_to_string(&token_path)
                        .with_context(|| format!("read heartbeat token file {token_path}"))?
                        .trim_end_matches(['\r', '\n'])
                        .to_string(),
                );
            }
            "--binary" if subcommand == "agent" => {
                i += 1;
                agent_binary = Some(required_arg(rest, i, "--binary")?);
            }
            "--docker" if subcommand == "agent" => agent_docker = Some(true),
            "--journald" if subcommand == "agent" => agent_journald = Some(true),
            other if subcommand == "remote" && !other.starts_with('-') => {
                if host.replace(other.to_string()).is_some() {
                    anyhow::bail!("deploy remote accepts exactly one host");
                }
            }
            other => anyhow::bail!("unknown deploy {subcommand} argument: {other}"),
        }
        i += 1;
    }
    let kind = match subcommand.as_str() {
        "preflight" => DeployCommandKind::Preflight,
        "local" => DeployCommandKind::Local { dry_run },
        "remote" => DeployCommandKind::Remote {
            host: host.ok_or_else(|| anyhow::anyhow!("deploy remote requires a host"))?,
            dry_run,
            home: remote_home,
        },
        "agent" => DeployCommandKind::Agent {
            hosts: agent_hosts,
            target: agent_target,
            token: agent_token,
            docker: agent_docker,
            journald: agent_journald,
            binary: agent_binary,
        },
        other => anyhow::bail!("unknown deploy subcommand: {other}"),
    };
    Ok(DeployCommand { kind, json })
}

fn parse_update_command(args: &[String]) -> Result<UpdateCommand> {
    let mut json = false;
    let mut dry_run = false;
    let mut profile: Option<String> = None;
    let mut binary: Option<String> = None;
    let mut rest = Vec::new();
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json = true,
            "--dry-run" => {
                dry_run = true;
            }
            "--profile" => {
                i += 1;
                profile = Some(required_arg(args, i, "--profile")?);
            }
            "--binary" => {
                i += 1;
                binary = Some(required_arg(args, i, "--binary")?);
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => rest.push(other.to_string()),
        }
        i += 1;
    }

    if rest.first().map(String::as_str) == Some("config") {
        if dry_run {
            anyhow::bail!("--dry-run is only valid for `cortex update` run scopes");
        }
        if binary.is_some() {
            anyhow::bail!("--binary is only valid for `cortex update clients|agents`");
        }
        return parse_update_config_command(&rest[1..], json, profile);
    }

    let scope = match rest.as_slice() {
        [] => cortex::update::UpdateScope::All,
        [scope] if scope == "all" => cortex::update::UpdateScope::All,
        [scope] if scope == "server" => cortex::update::UpdateScope::Server,
        [scope] if scope == "clients" || scope == "agents" => cortex::update::UpdateScope::Clients,
        [other] => anyhow::bail!("unknown update scope: {other}"),
        _ => anyhow::bail!("update accepts at most one scope"),
    };
    if scope == cortex::update::UpdateScope::Server && binary.is_some() {
        anyhow::bail!("--binary is only valid for `cortex update all|clients|agents`");
    }
    Ok(UpdateCommand {
        kind: UpdateCommandKind::Run {
            scope,
            dry_run,
            profile,
            binary,
        },
        json,
    })
}

fn parse_update_config_command(
    args: &[String],
    json: bool,
    profile: Option<String>,
) -> Result<UpdateCommand> {
    let (target, rest) = args
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("update config requires server or clients"))?;
    match target.as_str() {
        "server" => {
            let mut host = None;
            let mut home = None;
            let mut i = 0usize;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--host" => {
                        i += 1;
                        host = Some(required_arg(rest, i, "--host")?);
                    }
                    "--home" => {
                        i += 1;
                        home = Some(required_arg(rest, i, "--home")?);
                    }
                    other => anyhow::bail!("unknown update config server argument: {other}"),
                }
                i += 1;
            }
            Ok(UpdateCommand {
                kind: UpdateCommandKind::ConfigServer {
                    host: host
                        .ok_or_else(|| anyhow::anyhow!("update config server requires --host"))?,
                    home: home
                        .ok_or_else(|| anyhow::anyhow!("update config server requires --home"))?,
                    profile,
                },
                json,
            })
        }
        "clients" | "agents" => {
            let mut hosts = Vec::new();
            let mut target = None;
            let mut docker = None;
            let mut journald = None;
            let mut i = 0usize;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--hosts" => {
                        i += 1;
                        hosts = parse_host_list(&required_arg(rest, i, "--hosts")?);
                    }
                    "--target" => {
                        i += 1;
                        target = Some(required_arg(rest, i, "--target")?);
                    }
                    "--docker" => docker = Some(true),
                    "--journald" => journald = Some(true),
                    other => anyhow::bail!("unknown update config clients argument: {other}"),
                }
                i += 1;
            }
            Ok(UpdateCommand {
                kind: UpdateCommandKind::ConfigClients {
                    hosts,
                    target,
                    docker,
                    journald,
                    profile,
                },
                json,
            })
        }
        other => anyhow::bail!("unknown update config target: {other}"),
    }
}

fn required_arg(args: &[String], index: usize, flag: &str) -> Result<String> {
    args.get(index)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("{flag} requires a value"))
}

fn parse_host_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .map(str::to_string)
        .collect()
}

/// Which path `ingest shell agent index` should take, given its own flags
/// plus the global `--http`/`--server`/`--token` flags already folded into
/// `args` by the caller. Pure decision logic, deliberately separated from
/// the side-effecting dispatch (constructing a `RuntimeCore`, making the
/// network call) so the precedence rules are unit-testable without mocking
/// either of those.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ShellAgentIndexDispatch {
    Remote(String),
    Local,
}

/// Test-review addition: this precedence logic (per-command `--server`
/// overrides global; `--http` alone with no resolvable server bails;
/// `--token` with no resolvable server bails rather than silently
/// discarding the token) had zero test coverage prior to this extraction —
/// see `main_tests.rs`'s `resolve_shell_agent_index_dispatch_*` tests.
fn resolve_shell_agent_index_dispatch(
    args: &cli::ShellAgentIndexArgs,
    flags: &cli::GlobalFlags,
) -> Result<ShellAgentIndexDispatch> {
    if let Some(server) = args.server.clone() {
        return Ok(ShellAgentIndexDispatch::Remote(server));
    }
    if flags.force_http {
        anyhow::bail!(
            "--http requires --server URL for `ingest shell agent index`; pass --server explicitly"
        );
    }
    if args.token.is_some() {
        anyhow::bail!(
            "--token has no effect without --server for `ingest shell agent index`; pass --server to forward, or drop --token to import locally"
        );
    }
    Ok(ShellAgentIndexDispatch::Local)
}

fn parse_setup_subcommand_args<'a>(
    name: &str,
    args: impl Iterator<Item = &'a String>,
) -> Result<(&'static str, bool)> {
    let mut action = "check";
    let mut action_seen = false;
    let mut json = false;
    for arg in args {
        match arg.as_str() {
            "install" | "remove" | "check" => {
                if action_seen {
                    anyhow::bail!("{name} action specified more than once");
                }
                action_seen = true;
                action = match arg.as_str() {
                    "install" => "install",
                    "remove" => "remove",
                    _ => "check",
                };
            }
            "--json" => json = true,
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => anyhow::bail!("unknown {name} argument: {other}"),
        }
    }
    Ok((action, json))
}

fn parse_doctor_command(args: &[String]) -> Result<DoctorBinaryCommand> {
    let mut json = false;
    let mut saw_binary = false;
    for arg in args {
        match arg.as_str() {
            "binary" => saw_binary = true,
            "--json" => json = true,
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => anyhow::bail!("unknown doctor argument: {other}"),
        }
    }
    if !saw_binary {
        anyhow::bail!("doctor requires `binary`");
    }
    Ok(DoctorBinaryCommand { json })
}

/// Top-level usage to stderr — used by error/misuse fallbacks. Explicit help
/// (`--help`/`help`/`<cmd> --help`) is handled earlier by
/// `cli::help::maybe_handle_help` and prints to stdout instead.
fn print_usage() {
    cli::help::print_top_level_help_stderr();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {}
            Err(e) => {
                tracing::error!(error = %e, "Failed to install CTRL+C handler");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to install SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("Shutdown signal received");
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;
