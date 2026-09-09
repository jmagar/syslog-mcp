use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};

use super::docker::DockerUnavailableError;
use super::format::{is_stopped_status, status_from_target, unresolved_status};
use super::types::{
    CommandOutput, CommandRunner, ComposeCommandResult, ComposeDefaults, ComposeDiagnostic,
    ComposeDryRun, ComposeInvocation, ComposeMutation, ComposeStatus, ComposeTarget,
    ComposeTargetSummary, DiagnosticSeverity, DockerInspect, ListenerInfo, MountInfo,
    MutationOptions, ResolvedComposeTarget, TargetConfidence, TargetSource,
};

pub(crate) const DIAG_DOCKER_UNAVAILABLE: &str = "docker_unavailable";
pub(crate) const DIAG_TARGET_UNRESOLVED: &str = "target_unresolved";
pub(crate) const DIAG_SYSTEMD_CHECK_FAILED: &str = "systemd_check_failed";

pub struct ComposeService<I, R> {
    pub(super) inspector: I,
    pub(super) runner: R,
    pub(super) defaults: ComposeDefaults,
}

impl<I, R> ComposeService<I, R> {
    pub fn new(inspector: I, runner: R, defaults: ComposeDefaults) -> Self {
        Self {
            inspector,
            runner,
            defaults,
        }
    }

    pub(crate) fn compose_invocation(
        &self,
        target: &ResolvedComposeTarget,
        mutation: ComposeMutation,
    ) -> ComposeInvocation {
        let mut args = compose_base_args(target);
        args.extend(compose_mutation_args(mutation, &target.target.service));
        self.invocation(target, args)
    }

    pub(crate) fn logs_invocation(
        &self,
        target: &ResolvedComposeTarget,
        tail: u32,
    ) -> ComposeInvocation {
        let mut args = compose_base_args(target);
        args.push("logs".into());
        args.push("--tail".into());
        args.push(tail.to_string());
        args.push(target.target.service.clone());
        self.invocation(target, args)
    }

    fn invocation(&self, target: &ResolvedComposeTarget, args: Vec<String>) -> ComposeInvocation {
        let env = target
            .compose_working_dir
            .as_deref()
            .and_then(compose_env_file)
            .map(|path| vec![("CORTEX_ENV_FILE".to_string(), path.display().to_string())])
            .unwrap_or_default();
        ComposeInvocation {
            program: crate::env::var("CORTEX_COMPOSE_PROGRAM").unwrap_or_else(|_| "docker".into()),
            args,
            env,
            current_dir: target.compose_working_dir.clone(),
            timeout: self.defaults.timeout,
            output_limit_bytes: self.defaults.output_limit_bytes,
        }
    }

    fn config_invocation(&self, target: &ResolvedComposeTarget) -> ComposeInvocation {
        let mut args = compose_base_args(target);
        args.extend(["config".into(), "--format".into(), "json".into()]);
        self.invocation(target, args)
    }
}

fn compose_base_args(target: &ResolvedComposeTarget) -> Vec<String> {
    let mut args = vec!["compose".into()];
    if let Some(project_dir) = &target.compose_working_dir {
        args.push("--project-directory".into());
        args.push(project_dir.display().to_string());
        if let Some(env_path) = compose_env_file(project_dir) {
            args.push("--env-file".into());
            args.push(env_path.display().to_string());
        }
    }
    for file in &target.compose_files {
        args.push("-f".into());
        args.push(file.display().to_string());
    }
    if let Some(project_name) = &target.compose_project {
        args.push("--project-name".into());
        args.push(project_name.clone());
    }
    args
}

fn compose_mutation_args(mutation: ComposeMutation, service: &str) -> Vec<String> {
    let mut args = Vec::new();
    match mutation {
        ComposeMutation::Up => {
            args.push("up".into());
            args.push("-d".into());
        }
        ComposeMutation::Restart => {
            args.push("restart".into());
        }
        ComposeMutation::Pull => {
            args.push("pull".into());
        }
        ComposeMutation::Down => {
            args.push("stop".into());
        }
    }
    args.push(service.into());
    args
}

impl<I: DockerInspect, R> ComposeService<I, R> {
    pub fn resolve_target(&self, requested: &ComposeTarget) -> Result<ResolvedComposeTarget> {
        let service = requested
            .service
            .clone()
            .unwrap_or_else(|| self.defaults.service.clone());
        let container_name = requested
            .container_name
            .clone()
            .unwrap_or_else(|| self.defaults.container_name.clone());

        if requested.compose_file.is_some() || requested.project_dir.is_some() {
            return Ok(ResolvedComposeTarget {
                target: ComposeTargetSummary {
                    project_dir: requested.project_dir.clone(),
                    compose_file: requested.compose_file.clone(),
                    project_name: requested.project_name.clone(),
                    service,
                    container_name,
                },
                source: TargetSource::Explicit,
                confidence: TargetConfidence::Confirmed,
                diagnostics: Vec::new(),
                compose_files: requested.compose_file.clone().into_iter().collect(),
                compose_working_dir: requested.project_dir.clone(),
                compose_project: requested.project_name.clone(),
            });
        }

        if let Some(info) = self.inspector.inspect_container(&container_name)? {
            let target = target_from_container(&info, &self.defaults);
            validate_requested_selectors(requested, &target)?;
            return Ok(target);
        }

        let candidates = self.inspector.find_candidates(&service, &container_name)?;
        if candidates.len() == 1 {
            let target = target_from_container(&candidates[0], &self.defaults);
            validate_requested_selectors(requested, &target)?;
            return Ok(target);
        }
        if candidates.len() > 1 {
            return Ok(ResolvedComposeTarget {
                target: ComposeTargetSummary {
                    project_dir: None,
                    compose_file: None,
                    project_name: requested.project_name.clone(),
                    service,
                    container_name,
                },
                source: TargetSource::LiveContainerLabels,
                confidence: TargetConfidence::Ambiguous,
                diagnostics: vec![ComposeDiagnostic {
                    severity: DiagnosticSeverity::Unsafe,
                    code: "multiple_compose_candidates".into(),
                    message: format!("found {} candidate cortex containers", candidates.len()),
                }],
                compose_files: Vec::new(),
                compose_working_dir: None,
                compose_project: requested.project_name.clone(),
            });
        }

        let cwd = std::env::current_dir()?;
        let cwd_file = cwd.join("docker-compose.yml");
        if cwd_file.exists() {
            return Ok(ResolvedComposeTarget {
                target: ComposeTargetSummary {
                    project_dir: Some(cwd.clone()),
                    compose_file: Some(cwd_file.clone()),
                    project_name: requested.project_name.clone(),
                    service,
                    container_name,
                },
                source: TargetSource::CurrentWorkingDirectory,
                confidence: TargetConfidence::Unsafe,
                diagnostics: vec![ComposeDiagnostic {
                    severity: DiagnosticSeverity::Unsafe,
                    code: "cwd_fallback_requires_confirmation".into(),
                    message:
                        "cwd docker-compose.yml is not enough for mutation without --allow-cwd-target"
                            .into(),
                }],
                compose_files: vec![cwd_file],
                compose_working_dir: Some(cwd),
                compose_project: requested.project_name.clone(),
            });
        }

        Err(anyhow!("could not resolve cortex compose target"))
    }

    pub fn preflight_mutation(
        &self,
        mutation: ComposeMutation,
        target: &ResolvedComposeTarget,
        options: &MutationOptions,
    ) -> Result<()> {
        if target.confidence == TargetConfidence::Ambiguous {
            return Err(anyhow!("refusing mutation: target is ambiguous"));
        }
        if target.source == TargetSource::CurrentWorkingDirectory && !options.allow_cwd_target {
            return Err(anyhow!(
                "refusing mutation: cwd target requires --allow-cwd-target"
            ));
        }
        if target.target.project_name.is_some()
            && target.target.project_dir.is_none()
            && target.target.compose_file.is_none()
            && target.source != TargetSource::LiveContainerLabels
        {
            return Err(anyhow!(
                "refusing mutation: --project-name alone is not a safe target"
            ));
        }
        for file in &target.compose_files {
            if !file.exists() {
                return Err(anyhow!(
                    "refusing mutation: compose file does not exist: {}",
                    file.display()
                ));
            }
        }

        if target.source == TargetSource::LiveContainerLabels
            && target.confidence != TargetConfidence::Confirmed
        {
            return Err(anyhow!(
                "refusing mutation: live container is missing required compose labels"
            ));
        }

        let ownership = if mutation_requires_ownership_probe(mutation) {
            let target_container = self
                .inspector
                .inspect_container(&target.target.container_name)?;

            // Guard: if the running container has an unexpected /data mount,
            // refuse Up to prevent silently switching SQLite files.
            if matches!(mutation, ComposeMutation::Up)
                && let Some(info) = &target_container
                && let Some(mount) = info.mounts.iter().find(|m| m.target == "/data")
                && let Err(diagnostic) = data_mount_diagnostic(target, mount)
            {
                return Err(anyhow!(
                    "refusing up: {}\nFix: recreate with the intended \
                                 CORTEX_DATA_VOLUME/CORTEX_VOLUME_NAME, or update the \
                                 env file if this mount is intentional.",
                    diagnostic.message
                ));
            }

            let target_container_id = target_container.as_ref().map(|info| info.id.as_str());
            let published_ports = target_container
                .as_ref()
                .map(|info| {
                    info.ports
                        .iter()
                        .filter_map(|port| port.public_port)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let systemd = self
                .inspector
                .systemd_status("cortex.service")
                .map_err(|error| {
                    anyhow!("refusing mutation: could not verify systemd ownership: {error}")
                })?;
            let listeners = self.inspector.listeners(&[1514, 3100]).map_err(|error| {
                anyhow!("refusing mutation: could not verify port listeners: {error}")
            })?;
            let mut non_target_listener = false;
            for listener in &listeners {
                if !listener_belongs_to_target(
                    &self.inspector,
                    listener,
                    &target.target.container_name,
                    target_container_id,
                    &published_ports,
                )? {
                    non_target_listener = true;
                    break;
                }
            }
            Some((
                systemd.as_ref().is_some_and(|s| s.active),
                non_target_listener,
            ))
        } else {
            None
        };

        match mutation {
            ComposeMutation::Up | ComposeMutation::Restart
                if ownership.is_some_and(|(systemd_active, non_target_listener)| {
                    systemd_active || non_target_listener
                }) =>
            {
                return Err(anyhow!(
                    "refusing mutation: systemd or non-target listener owns syslog ports"
                ));
            }
            ComposeMutation::Down if target.source != TargetSource::LiveContainerLabels => {
                return Err(anyhow!(
                    "refusing down: target must be confirmed compose-owned"
                ));
            }
            ComposeMutation::Down if options.non_interactive && !options.yes => {
                return Err(anyhow!(
                    "refusing down: --yes is required in non-interactive mode"
                ));
            }
            ComposeMutation::Pull
            | ComposeMutation::Up
            | ComposeMutation::Restart
            | ComposeMutation::Down => {}
        }

        Ok(())
    }

    pub fn status(&self, requested: &ComposeTarget) -> Result<ComposeStatus> {
        let target = match self.resolve_target(requested) {
            Ok(target) => target,
            Err(error) => {
                return Ok(unresolved_status(
                    requested,
                    &self.defaults,
                    unresolved_code(&error),
                    format!("could not resolve cortex compose target: {error}"),
                ));
            }
        };
        let container_name = target.target.container_name.clone();
        let info = match self.inspector.inspect_container(&container_name) {
            Ok(info) => info,
            Err(error) => {
                let mut status = status_from_target(target, None, None);
                status.diagnostics.push(ComposeDiagnostic {
                    severity: DiagnosticSeverity::Error,
                    code: unresolved_code(&error).into(),
                    message: error.to_string(),
                });
                return Ok(status);
            }
        };
        let mut systemd_error = None;
        let systemd = match self.inspector.systemd_status("cortex.service") {
            Ok(systemd) => systemd,
            Err(error) => {
                systemd_error = Some(error.to_string());
                None
            }
        };
        let mut status = status_from_target(target, info, systemd);
        // Detect DB drift: verify the container's /data mount matches what the
        // configured volume/bind expects. Named volumes are valid; bind mounts are
        // valid. Only error when the volume name is unexpected (e.g. orphaned from a
        // previous COMPOSE_PROJECT_NAME). Only check while the container is running.
        if status
            .status
            .as_deref()
            .map(|s| !is_stopped_status(s))
            .unwrap_or(false)
        {
            let data_mount = status.data_mounts.iter().find(|m| m.target == "/data");
            match data_mount {
                None => {
                    status.diagnostics.push(ComposeDiagnostic {
                        severity: DiagnosticSeverity::Error,
                        code: "data_volume_missing".into(),
                        message: "container has no /data mount — cortex DB is inaccessible".into(),
                    });
                }
                Some(mount) => {
                    if let Err(diagnostic) =
                        data_mount_diagnostic(&status_as_target(&status), mount)
                    {
                        status.diagnostics.push(diagnostic);
                    }
                }
            }
        }
        if let Some(error) = systemd_error {
            status.diagnostics.push(ComposeDiagnostic {
                severity: DiagnosticSeverity::Error,
                code: DIAG_SYSTEMD_CHECK_FAILED.into(),
                message: format!("could not verify cortex.service state: {error}"),
            });
        }
        if status.systemd.as_ref().is_some_and(|s| s.active) {
            let code = if status.compose_project.is_some() {
                "owner_mismatch"
            } else {
                "systemd_active"
            };
            status.diagnostics.push(ComposeDiagnostic {
                severity: DiagnosticSeverity::Warning,
                code: code.into(),
                message: "cortex.service is active".into(),
            });
        }
        Ok(status)
    }
}

fn status_as_target(status: &ComposeStatus) -> ResolvedComposeTarget {
    ResolvedComposeTarget {
        target: ComposeTargetSummary {
            project_dir: status.compose_working_dir.clone(),
            compose_file: status.compose_files.first().cloned(),
            project_name: status.compose_project.clone(),
            service: status.service.clone().unwrap_or_else(|| "cortex".into()),
            container_name: status.container_name.clone(),
        },
        source: TargetSource::LiveContainerLabels,
        confidence: TargetConfidence::Confirmed,
        diagnostics: Vec::new(),
        compose_files: status.compose_files.clone(),
        compose_working_dir: status.compose_working_dir.clone(),
        compose_project: status.compose_project.clone(),
    }
}

enum ExpectedDataMount {
    Bind(PathBuf),
    Volume(String),
}

fn data_mount_diagnostic(
    target: &ResolvedComposeTarget,
    mount: &MountInfo,
) -> Result<(), ComposeDiagnostic> {
    match expected_data_mount(target) {
        ExpectedDataMount::Volume(expected_volume) => {
            if mount.kind == "volume"
                && mount.volume_name.as_deref() == Some(expected_volume.as_str())
            {
                return Ok(());
            }
            let actual = mount_description(mount);
            Err(ComposeDiagnostic {
                severity: DiagnosticSeverity::Error,
                code: "data_mount_unexpected".into(),
                message: format!(
                    "container /data uses {actual}, expected volume '{expected_volume}'"
                ),
            })
        }
        ExpectedDataMount::Bind(expected_path) => {
            if mount.kind == "bind"
                && mount
                    .source
                    .as_ref()
                    .is_some_and(|source| paths_equivalent(source, &expected_path))
            {
                return Ok(());
            }
            let actual = mount_description(mount);
            Err(ComposeDiagnostic {
                severity: DiagnosticSeverity::Error,
                code: "data_mount_unexpected".into(),
                message: format!(
                    "container /data uses {actual}, expected bind '{}'",
                    expected_path.display()
                ),
            })
        }
    }
}

fn expected_data_mount(target: &ResolvedComposeTarget) -> ExpectedDataMount {
    let data_volume = env_or_compose_file_value(target, "CORTEX_DATA_VOLUME");
    if let Some(value) = data_volume.filter(|v| !v.trim().is_empty()) {
        let path = PathBuf::from(&value);
        if path.is_absolute() {
            return ExpectedDataMount::Bind(normalize_path(path));
        }
        if (value.starts_with("./") || value.starts_with("../"))
            && let Some(project_dir) = &target.compose_working_dir
        {
            return ExpectedDataMount::Bind(normalize_path(project_dir.join(path)));
        }
        return ExpectedDataMount::Volume(value);
    }
    ExpectedDataMount::Volume(
        env_or_compose_file_value(target, "CORTEX_VOLUME_NAME")
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| "cortex-data".to_string()),
    )
}

fn env_or_compose_file_value(target: &ResolvedComposeTarget, key: &str) -> Option<String> {
    if let Ok(value) = crate::env::var(key) {
        return Some(value);
    }
    target
        .compose_working_dir
        .as_deref()
        .and_then(compose_env_file)
        .and_then(|path| read_env_value(&path, key))
}

fn read_env_value(path: &Path, key: &str) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, value) = line.split_once('=')?;
        if name.trim() == key {
            return Some(
                value
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_string(),
            );
        }
    }
    None
}

fn mount_description(mount: &MountInfo) -> String {
    match mount.kind.as_str() {
        "volume" => format!(
            "volume '{}'",
            mount.volume_name.as_deref().unwrap_or("unknown")
        ),
        "bind" => format!(
            "bind '{}'",
            mount
                .source
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "unknown".into())
        ),
        other => format!("{other} mount"),
    }
}

fn paths_equivalent(actual: &Path, expected: &Path) -> bool {
    normalize_path(actual) == normalize_path(expected)
}

fn normalize_path(path: impl AsRef<Path>) -> PathBuf {
    path.as_ref()
        .canonicalize()
        .unwrap_or_else(|_| path.as_ref().to_path_buf())
}

fn compose_env_file(project_dir: &Path) -> Option<PathBuf> {
    if let Ok(path) = crate::env::var("CORTEX_ENV_FILE") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
    }

    // Docker Compose only looks for .env in the project directory for YAML
    // substitution. The installed cortex compose bundle stores compose
    // files under ~/.cortex/compose/ and its env file one level up.
    if let Some(path) = project_dir
        .parent()
        .map(|p| p.join(".env"))
        .filter(|p| p.is_file())
    {
        return Some(path);
    }

    if let Ok(home) = crate::setup::cortex_home_dir() {
        let path = home.join(".env");
        if path.is_file() {
            return Some(path);
        }
    }

    project_dir
        .join(".env")
        .is_file()
        .then(|| project_dir.join(".env"))
}

impl<I: DockerInspect, R: CommandRunner> ComposeService<I, R> {
    fn provision_backup_bind(&self, target: &ResolvedComposeTarget) -> Result<()> {
        let output = self.runner.run(&self.config_invocation(target))?;
        if output.timed_out || output.exit_status != Some(0) {
            return Err(anyhow!(
                "could not resolve Compose backup bind: {}",
                output.stderr.trim()
            ));
        }
        if output.stdout_truncated {
            return Err(anyhow!(
                "could not resolve Compose backup bind: config output was truncated"
            ));
        }
        let config: serde_json::Value = serde_json::from_str(&output.stdout)
            .map_err(|error| anyhow!("could not parse Compose config JSON: {error}"))?;
        let volumes = config
            .pointer(&format!("/services/{}/volumes", target.target.service))
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| anyhow!("Compose service has no volume list"))?;
        let backup = volumes
            .iter()
            .find(|volume| {
                volume.get("target").and_then(serde_json::Value::as_str) == Some("/backups")
            })
            .ok_or_else(|| anyhow!("Compose service has no /backups mount"))?;
        if backup.get("type").and_then(serde_json::Value::as_str) != Some("bind") {
            return Err(anyhow!("Compose /backups mount must be a bind mount"));
        }
        let source = backup
            .get("source")
            .and_then(serde_json::Value::as_str)
            .map(PathBuf::from)
            .filter(|path| path.is_absolute() && path != Path::new("/"))
            .ok_or_else(|| anyhow!("Compose /backups bind must resolve to a safe absolute path"))?;
        std::fs::create_dir_all(&source)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }

    pub fn run_mutation(
        &self,
        mutation: ComposeMutation,
        requested: &ComposeTarget,
        options: &MutationOptions,
    ) -> Result<ComposeCommandResult> {
        let target = self.resolve_target(requested)?;
        self.preflight_mutation(mutation, &target, options)?;
        let invocation = self.compose_invocation(&target, mutation);
        if options.dry_run {
            return Ok(ComposeCommandResult::DryRun(ComposeDryRun {
                dry_run: true,
                command: std::iter::once(invocation.program.clone())
                    .chain(invocation.args.clone())
                    .collect(),
                target: target.target,
                preflight: "passed".into(),
            }));
        }
        if mutation == ComposeMutation::Up {
            self.provision_backup_bind(&target)?;
        }
        self.runner
            .run(&invocation)
            .map(ComposeCommandResult::Executed)
    }

    pub fn logs(&self, requested: &ComposeTarget, tail: Option<u32>) -> Result<CommandOutput> {
        let target = self.resolve_target(requested)?;
        if target.source == TargetSource::CurrentWorkingDirectory {
            return Err(anyhow!(
                "refusing logs: cwd target requires explicit compose target"
            ));
        }
        if target.confidence != TargetConfidence::Confirmed {
            return Err(anyhow!("refusing logs: target is not confirmed"));
        }
        let invocation = self.logs_invocation(&target, tail.unwrap_or(100));
        self.runner.run(&invocation)
    }
}

fn listener_belongs_to_target<I: DockerInspect>(
    inspector: &I,
    listener: &ListenerInfo,
    container_name: &str,
    container_id: Option<&str>,
    published_ports: &[u16],
) -> Result<bool> {
    if listener.belongs_to_target {
        return Ok(true);
    }
    if !published_ports.contains(&listener.port) {
        return Ok(false);
    }
    // If ss shows process info with the users: field, verify it is docker-proxy.
    // Any other named process definitively owns the port and is not our target.
    // When running without root, ss omits process info (no users: field), so we
    // fall through to the docker ps ownership check below.
    if let Some(process) = listener.process.as_deref()
        && process.contains("users:")
        && !process.contains("docker-proxy")
    {
        return Ok(false);
    }
    // Use docker ps --filter publish=PORT to confirm ownership. This works without
    // root privileges, unlike ss process inspection, and handles the common
    // non-root deployment scenario correctly.
    let Some(owner) = inspector.published_port_owner(listener.port)? else {
        return Ok(false);
    };
    Ok(owner == container_name
        || container_id.is_some_and(|id| id == owner || id.starts_with(&owner)))
}

pub(crate) fn unresolved_code(error: &anyhow::Error) -> &'static str {
    if error.downcast_ref::<DockerUnavailableError>().is_some() {
        DIAG_DOCKER_UNAVAILABLE
    } else {
        DIAG_TARGET_UNRESOLVED
    }
}

fn mutation_requires_ownership_probe(mutation: ComposeMutation) -> bool {
    matches!(
        mutation,
        ComposeMutation::Up | ComposeMutation::Restart | ComposeMutation::Down
    )
}

fn validate_requested_selectors(
    requested: &ComposeTarget,
    target: &ResolvedComposeTarget,
) -> Result<()> {
    if let Some(project_name) = &requested.project_name
        && target.target.project_name.as_ref() != Some(project_name)
    {
        return Err(anyhow!(
            "requested project_name {project_name:?} does not match resolved compose project {:?}",
            target.target.project_name
        ));
    }
    if let Some(service) = &requested.service
        && &target.target.service != service
    {
        return Err(anyhow!(
            "requested service {service:?} does not match resolved compose service {:?}",
            target.target.service
        ));
    }
    Ok(())
}

fn label<'a>(info: &'a super::types::ContainerInfo, key: &str) -> Option<&'a str> {
    info.labels.get(key).map(String::as_str)
}

fn split_compose_files(value: Option<&str>) -> Vec<PathBuf> {
    value
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect()
}

pub(crate) fn target_from_container(
    info: &super::types::ContainerInfo,
    defaults: &ComposeDefaults,
) -> ResolvedComposeTarget {
    let project = label(info, "com.docker.compose.project").map(str::to_string);
    let service_label = label(info, "com.docker.compose.service").map(str::to_string);
    let working_dir_label =
        label(info, "com.docker.compose.project.working_dir").map(PathBuf::from);
    let config_files_label = label(info, "com.docker.compose.project.config_files");
    let compose_files = split_compose_files(config_files_label);

    let mut missing = Vec::new();
    if project.is_none() {
        missing.push("com.docker.compose.project");
    }
    if service_label.is_none() {
        missing.push("com.docker.compose.service");
    }
    if working_dir_label.is_none() {
        missing.push("com.docker.compose.project.working_dir");
    }
    if compose_files.is_empty() {
        missing.push("com.docker.compose.project.config_files");
    }

    let service = service_label.unwrap_or_else(|| defaults.service.clone());
    let container_name = info.name.trim_start_matches('/').to_string();
    let diagnostics = if missing.is_empty() {
        Vec::new()
    } else {
        vec![ComposeDiagnostic {
            severity: DiagnosticSeverity::Unsafe,
            code: "incomplete_compose_labels".into(),
            message: format!(
                "container is missing required compose labels: {}",
                missing.join(", ")
            ),
        }]
    };
    let confidence = if missing.is_empty() {
        TargetConfidence::Confirmed
    } else {
        TargetConfidence::Unsafe
    };
    ResolvedComposeTarget {
        target: ComposeTargetSummary {
            project_dir: working_dir_label.clone(),
            compose_file: compose_files.first().cloned(),
            project_name: project.clone(),
            service,
            container_name,
        },
        source: TargetSource::LiveContainerLabels,
        confidence,
        diagnostics,
        compose_files,
        compose_working_dir: working_dir_label,
        compose_project: project,
    }
}
