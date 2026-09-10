//! Declarative release-version management for cortex.
//!
//! `release/components.toml` is the single source of truth for which files
//! carry the version and how to read/rewrite each one. This is a lean,
//! single-component adaptation of axon's `xtask` release-versions system: it
//! keeps the declarative manifest, the per-kind readers/writers, and the
//! parity gate, but drops axon's multi-component git-diff / release-plan
//! machinery (cortex ships exactly one component on a simple `auto-tag` flow).

use regex::Regex;
use semver::Version;
use serde::Deserialize;
use std::path::Path;
use std::process::Command;

type ReleaseResult<T> = Result<T, ReleaseVersionError>;

macro_rules! release_bail {
    ($($arg:tt)*) => {
        return Err($crate::version::ReleaseVersionError::msg(format!($($arg)*)))
    };
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReleaseVersionError {
    message: String,
}

impl ReleaseVersionError {
    fn msg(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ReleaseVersionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.message.fmt(formatter)
    }
}

impl std::error::Error for ReleaseVersionError {}

trait ReleaseContext<T> {
    fn release_context(self, message: impl Into<String>) -> ReleaseResult<T>;
    fn with_release_context(self, message: impl FnOnce() -> String) -> ReleaseResult<T>;
}

impl<T, E> ReleaseContext<T> for Result<T, E>
where
    E: std::fmt::Display,
{
    fn release_context(self, message: impl Into<String>) -> ReleaseResult<T> {
        let message = message.into();
        self.map_err(|error| ReleaseVersionError::msg(format!("{message}: {error}")))
    }
    fn with_release_context(self, message: impl FnOnce() -> String) -> ReleaseResult<T> {
        self.map_err(|error| ReleaseVersionError::msg(format!("{}: {error}", message())))
    }
}

impl<T> ReleaseContext<T> for Option<T> {
    fn release_context(self, message: impl Into<String>) -> ReleaseResult<T> {
        self.ok_or_else(|| ReleaseVersionError::msg(message))
    }
    fn with_release_context(self, message: impl FnOnce() -> String) -> ReleaseResult<T> {
        self.ok_or_else(|| ReleaseVersionError::msg(message()))
    }
}

// ---------------------------------------------------------------------------
// Manifest model
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct Manifest {
    schema_version: u32,
    components: Vec<Component>,
}

#[derive(Debug, Deserialize)]
struct Component {
    id: String,
    #[allow(dead_code)]
    name: String,
    tag_prefix: String,
    version_source: VersionFile,
    version_files: Vec<VersionFile>,
}

#[derive(Debug, Deserialize, Clone)]
struct VersionFile {
    kind: VersionKind,
    path: String,
    package: Option<String>,
    json_pointer: Option<String>,
    /// Regex with exactly one capture group around a semver. Required for
    /// (and only valid on) `regex_version`.
    pattern: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum VersionKind {
    /// `version = "X.Y.Z"` in a Cargo `[package]` table.
    CargoPackage,
    /// A named package's `version` inside `Cargo.lock`.
    CargoLockPackage,
    /// A string at a JSON pointer (e.g. `/version`, `/info/version`).
    JsonVersion,
    /// A custom textual match captured by `pattern`'s single group. Covers
    /// cortex-specific carriers: the `cortex:vX.Y.Z` image tag in `server.json`
    /// and the `CORTEX_VERSION:-X.Y.Z` default in `docker-compose.prod.yml`.
    RegexVersion,
    /// A `## [X.Y.Z]` heading must exist in a Keep-a-Changelog file.
    ChangelogHeading,
    /// The file must NOT carry a top-level `version` key (plugin manifests).
    JsonNoVersion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum BumpLevel {
    Patch,
    Minor,
    Major,
}

// ---------------------------------------------------------------------------
// Public commands
// ---------------------------------------------------------------------------

/// Verify all version-bearing files agree with the canonical source.
pub(crate) fn check_sync(root: &Path) -> ReleaseResult<()> {
    run_parity(root, false)
}

/// Release gate: version sync plus a CHANGELOG entry for the current version.
pub(crate) fn check_release(root: &Path) -> ReleaseResult<()> {
    run_parity(root, true)
}

fn run_parity(root: &Path, require_changelog: bool) -> ReleaseResult<()> {
    let manifest = load_manifest(root)?;
    let mut errors = Vec::new();

    for component in &manifest.components {
        let version = read_version(root, &component.version_source)?;
        Version::parse(&version).with_release_context(|| {
            format!("{} version is not valid semver: {version}", component.id)
        })?;
        for error in check_component_parity(root, component, &version)? {
            errors.push(format!("{}: {error}", component.id));
        }
        if require_changelog && !component_has_changelog(component) {
            errors.push(format!(
                "{}: no changelog_heading version file declared but a changelog entry is required",
                component.id
            ));
        }
    }

    if !errors.is_empty() {
        for error in &errors {
            eprintln!("version error: {error}");
        }
        release_bail!("version check failed ({} error(s))", errors.len());
    }

    let version = read_version(root, &manifest.components[0].version_source)?;
    println!(
        "OK: {} version-bearing file(s) in sync at {version}.",
        total_version_files(&manifest)
    );
    Ok(())
}

/// Bump every version-bearing file to the next patch/minor/major version.
pub(crate) fn bump(root: &Path, level: BumpLevel) -> ReleaseResult<()> {
    let manifest = load_manifest(root)?;
    let component = sole_component(&manifest)?;

    let current = read_version(root, &component.version_source)?;
    let current = Version::parse(&current).with_release_context(|| {
        format!("{} version is not valid semver: {current}", component.id)
    })?;
    let next = match level {
        BumpLevel::Patch => Version::new(current.major, current.minor, current.patch + 1),
        BumpLevel::Minor => Version::new(current.major, current.minor + 1, 0),
        BumpLevel::Major => Version::new(current.major + 1, 0, 0),
    }
    .to_string();

    apply_version(root, component, &next)?;
    println!("Bumped {} {current} → {next}", component.id);
    Ok(())
}

/// Re-apply the canonical version (`version_source`, e.g. Cargo.toml) to every
/// other version-bearing file. Used as a fixup step after release-please's
/// native `rust` strategy bumps Cargo.toml/Cargo.lock/CHANGELOG.md directly:
/// it can't reach every carrier in `release/components.toml` (the
/// `regex_version` patterns such as server.json's image tag and
/// docker-compose.prod.yml's default tag, and the nested harness lockfiles
/// under `tests/live/`), so this rewrites every version file — a no-op for
/// the ones already current — to match.
pub(crate) fn sync_version(root: &Path) -> ReleaseResult<()> {
    let manifest = load_manifest(root)?;
    let component = sole_component(&manifest)?;
    let version = read_version(root, &component.version_source)?;
    Version::parse(&version).with_release_context(|| {
        format!("{} version is not valid semver: {version}", component.id)
    })?;
    apply_version(root, component, &version)?;
    println!("Synced {} version files to {version}", component.id);
    Ok(())
}

fn apply_version(root: &Path, component: &Component, next: &str) -> ReleaseResult<()> {
    for file in &component.version_files {
        let path = root.join(&file.path);
        let content = std::fs::read_to_string(&path)
            .with_release_context(|| format!("failed to read {}", file.path))?;
        let updated = match file.kind {
            VersionKind::CargoPackage => {
                replace_cargo_package_version(&content, file.package.as_deref(), next)?
            }
            VersionKind::CargoLockPackage => {
                replace_cargo_lock_package_version(&content, file.package.as_deref(), next)?
            }
            VersionKind::JsonVersion => {
                replace_json_version(&content, file.json_pointer.as_deref(), next)?
            }
            VersionKind::RegexVersion => {
                replace_regex_version(&content, file.pattern.as_deref(), next)?
            }
            VersionKind::ChangelogHeading => ensure_changelog_heading(&content, next)?,
            VersionKind::JsonNoVersion => content.clone(),
        };
        if updated != content {
            std::fs::write(&path, updated)
                .with_release_context(|| format!("failed to write {}", file.path))?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Manifest loading & validation
// ---------------------------------------------------------------------------

fn load_manifest(root: &Path) -> ReleaseResult<Manifest> {
    let path = root.join("release/components.toml");
    let content =
        std::fs::read_to_string(&path).release_context("failed to read release/components.toml")?;
    let manifest: Manifest =
        toml::from_str(&content).release_context("failed to parse release/components.toml")?;
    if manifest.schema_version != 1 {
        release_bail!(
            "unsupported release/components.toml schema_version {}",
            manifest.schema_version
        );
    }
    validate_manifest(root, &manifest)?;
    Ok(manifest)
}

fn validate_manifest(root: &Path, manifest: &Manifest) -> ReleaseResult<()> {
    if manifest.components.is_empty() {
        release_bail!("release manifest declares no components");
    }
    let mut ids = std::collections::HashSet::new();
    for component in &manifest.components {
        if component.id.trim().is_empty() {
            release_bail!("release manifest contains an empty component id");
        }
        if !ids.insert(component.id.as_str()) {
            release_bail!("duplicate release component id {}", component.id);
        }
        if component.tag_prefix.trim().is_empty() {
            release_bail!("{} has an empty tag_prefix", component.id);
        }
        validate_version_file(component, "version_source", &component.version_source)?;
        if !is_version_source_kind(component.version_source.kind) {
            release_bail!(
                "{} version_source kind {:?} cannot be read as a version",
                component.id,
                component.version_source.kind
            );
        }
        for file in &component.version_files {
            validate_version_file(component, "version_files", file)?;
            if !root.join(&file.path).is_file() {
                release_bail!(
                    "{} version file does not exist: {}",
                    component.id,
                    file.path
                );
            }
        }
        if !component
            .version_files
            .iter()
            .any(|file| same_version_file(file, &component.version_source))
        {
            release_bail!(
                "{} version_source is not listed in version_files",
                component.id
            );
        }
    }
    Ok(())
}

fn validate_version_file(
    component: &Component,
    field: &str,
    file: &VersionFile,
) -> ReleaseResult<()> {
    let require_empty_package = |file: &VersionFile| -> ReleaseResult<()> {
        if file.package.is_some() {
            release_bail!(
                "{} {field} {} {:?} must not set package",
                component.id,
                file.path,
                file.kind
            );
        }
        Ok(())
    };
    let require_empty_pointer = |file: &VersionFile| -> ReleaseResult<()> {
        if file.json_pointer.is_some() {
            release_bail!(
                "{} {field} {} {:?} must not set json_pointer",
                component.id,
                file.path,
                file.kind
            );
        }
        Ok(())
    };
    let require_empty_pattern = |file: &VersionFile| -> ReleaseResult<()> {
        if file.pattern.is_some() {
            release_bail!(
                "{} {field} {} {:?} must not set pattern",
                component.id,
                file.path,
                file.kind
            );
        }
        Ok(())
    };

    match file.kind {
        VersionKind::CargoPackage | VersionKind::CargoLockPackage => {
            if file.package.as_deref().unwrap_or("").trim().is_empty() {
                release_bail!(
                    "{} {field} {} {:?} requires package",
                    component.id,
                    file.path,
                    file.kind
                );
            }
            require_empty_pointer(file)?;
            require_empty_pattern(file)?;
        }
        VersionKind::JsonVersion => {
            require_empty_package(file)?;
            require_empty_pattern(file)?;
            let pointer = file.json_pointer.as_deref().unwrap_or("");
            if !pointer.starts_with('/') {
                release_bail!(
                    "{} {field} {} json_version requires an absolute json_pointer",
                    component.id,
                    file.path
                );
            }
        }
        VersionKind::RegexVersion => {
            require_empty_package(file)?;
            require_empty_pointer(file)?;
            let pattern = file.pattern.as_deref().release_context(format!(
                "{} {field} {} regex_version requires pattern",
                component.id, file.path
            ))?;
            let regex = Regex::new(pattern).with_release_context(|| {
                format!(
                    "{} {field} {} has an invalid pattern",
                    component.id, file.path
                )
            })?;
            if regex.captures_len() != 2 {
                release_bail!(
                    "{} {field} {} pattern must have exactly one capture group",
                    component.id,
                    file.path
                );
            }
        }
        VersionKind::ChangelogHeading | VersionKind::JsonNoVersion => {
            require_empty_package(file)?;
            require_empty_pointer(file)?;
            require_empty_pattern(file)?;
        }
    }
    Ok(())
}

fn same_version_file(left: &VersionFile, right: &VersionFile) -> bool {
    left.kind == right.kind
        && left.path == right.path
        && left.package == right.package
        && left.json_pointer == right.json_pointer
        && left.pattern == right.pattern
}

fn is_version_source_kind(kind: VersionKind) -> bool {
    matches!(
        kind,
        VersionKind::CargoPackage
            | VersionKind::CargoLockPackage
            | VersionKind::JsonVersion
            | VersionKind::RegexVersion
    )
}

fn component_has_changelog(component: &Component) -> bool {
    component
        .version_files
        .iter()
        .any(|file| file.kind == VersionKind::ChangelogHeading)
}

fn sole_component(manifest: &Manifest) -> ReleaseResult<&Component> {
    match manifest.components.as_slice() {
        [component] => Ok(component),
        _ => release_bail!(
            "bump-version expects exactly one component, found {}",
            manifest.components.len()
        ),
    }
}

fn total_version_files(manifest: &Manifest) -> usize {
    manifest
        .components
        .iter()
        .map(|component| component.version_files.len())
        .sum()
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

fn read_version(root: &Path, file: &VersionFile) -> ReleaseResult<String> {
    let content = std::fs::read_to_string(root.join(&file.path))
        .with_release_context(|| format!("failed to read {}", file.path))?;
    match file.kind {
        VersionKind::CargoPackage => read_cargo_package_version(&content, file.package.as_deref())
            .with_release_context(|| format!("failed to read Cargo version from {}", file.path)),
        VersionKind::CargoLockPackage => {
            read_cargo_lock_package_version(&content, file.package.as_deref()).with_release_context(
                || format!("failed to read Cargo.lock version from {}", file.path),
            )
        }
        VersionKind::JsonVersion => read_json_version(&content, file.json_pointer.as_deref())
            .with_release_context(|| format!("failed to read JSON version from {}", file.path)),
        VersionKind::RegexVersion => read_regex_version(&content, file.pattern.as_deref())
            .with_release_context(|| format!("failed to read version from {}", file.path)),
        VersionKind::ChangelogHeading | VersionKind::JsonNoVersion => {
            release_bail!("{:?} is not a canonical version source", file.kind)
        }
    }
}

fn check_component_parity(
    root: &Path,
    component: &Component,
    expected: &str,
) -> ReleaseResult<Vec<String>> {
    let mut errors = Vec::new();
    for file in &component.version_files {
        let content = match std::fs::read_to_string(root.join(&file.path)) {
            Ok(content) => content,
            Err(error) => {
                errors.push(format!("{}: failed to read: {error}", file.path));
                continue;
            }
        };
        let result = match file.kind {
            VersionKind::CargoPackage => check_eq(
                read_cargo_package_version(&content, file.package.as_deref()),
                expected,
            ),
            VersionKind::CargoLockPackage => check_eq(
                read_cargo_lock_package_version(&content, file.package.as_deref()),
                expected,
            ),
            VersionKind::JsonVersion => check_eq(
                read_json_version(&content, file.json_pointer.as_deref()),
                expected,
            ),
            VersionKind::RegexVersion => check_eq(
                read_regex_version(&content, file.pattern.as_deref()),
                expected,
            ),
            VersionKind::ChangelogHeading => check_changelog_heading(&content, expected),
            VersionKind::JsonNoVersion => check_json_no_top_level_version(&content),
        };
        if let Err(error) = result {
            errors.push(format!("{}: {error}", file.path));
        }
    }
    Ok(errors)
}

fn check_eq(actual: ReleaseResult<String>, expected: &str) -> ReleaseResult<()> {
    let actual = actual?;
    if actual != expected {
        release_bail!("expected version {expected}, found {actual}");
    }
    Ok(())
}

fn read_cargo_package_version(content: &str, package: Option<&str>) -> ReleaseResult<String> {
    let value: toml::Value = toml::from_str(content).release_context("invalid TOML")?;
    let package_table = value
        .get("package")
        .and_then(|value| value.as_table())
        .release_context("missing [package] table")?;
    if let Some(expected) = package {
        let name = package_table
            .get("name")
            .and_then(|value| value.as_str())
            .release_context("missing package.name")?;
        if name != expected {
            release_bail!("expected package {expected}, found {name}");
        }
    }
    if let Some(version) = package_table
        .get("version")
        .and_then(|value| value.as_str())
    {
        return Ok(version.to_owned());
    }
    let inherits_workspace_version = package_table
        .get("version")
        .and_then(|value| value.as_table())
        .and_then(|table| table.get("workspace"))
        .and_then(|value| value.as_bool())
        == Some(true);
    if !inherits_workspace_version {
        release_bail!("missing package.version");
    }
    value
        .get("workspace")
        .and_then(|value| value.as_table())
        .and_then(|workspace| workspace.get("package"))
        .and_then(|value| value.as_table())
        .and_then(|package| package.get("version"))
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned)
        .release_context("missing workspace.package.version")
}

fn read_cargo_lock_package_version(content: &str, package: Option<&str>) -> ReleaseResult<String> {
    let package = package.release_context("cargo_lock_package requires package")?;
    let section = content
        .split("[[package]]")
        .skip(1)
        .find(|section| cargo_lock_field(section, "name").as_deref() == Some(package))
        .with_release_context(|| format!("missing Cargo.lock package {package}"))?;
    cargo_lock_field(section, "version")
        .with_release_context(|| format!("missing Cargo.lock package {package} version"))
}

fn read_json_version(content: &str, pointer: Option<&str>) -> ReleaseResult<String> {
    let value: serde_json::Value = serde_json::from_str(content).release_context("invalid JSON")?;
    let pointer = pointer.unwrap_or("/version");
    value
        .pointer(pointer)
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned)
        .with_release_context(|| format!("missing JSON version field at {pointer}"))
}

fn read_regex_version(content: &str, pattern: Option<&str>) -> ReleaseResult<String> {
    let regex = compile_pattern(pattern)?;
    regex
        .captures(content)
        .and_then(|captures| captures.get(1))
        .map(|m| m.as_str().to_owned())
        .release_context("pattern did not match")
}

fn check_changelog_heading(content: &str, expected: &str) -> ReleaseResult<()> {
    let heading = format!("## [{expected}]");
    if !content.lines().any(|line| line.starts_with(&heading)) {
        release_bail!("missing '{heading}' heading");
    }
    Ok(())
}

fn check_json_no_top_level_version(content: &str) -> ReleaseResult<()> {
    let value: serde_json::Value = serde_json::from_str(content).release_context("invalid JSON")?;
    if value.get("version").is_some() {
        release_bail!("must not contain a top-level version key");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

fn replace_cargo_package_version(
    content: &str,
    package: Option<&str>,
    next: &str,
) -> ReleaseResult<String> {
    read_cargo_package_version(content, package)?;
    let parsed: toml::Value = toml::from_str(content).release_context("invalid TOML")?;
    let package_inherits = parsed
        .get("package")
        .and_then(|value| value.as_table())
        .and_then(|package| package.get("version"))
        .and_then(|value| value.as_table())
        .and_then(|version| version.get("workspace"))
        .and_then(|value| value.as_bool())
        == Some(true);
    let target_table = if package_inherits {
        "[workspace.package]"
    } else {
        "[package]"
    };
    let mut in_target = false;
    let mut replaced = false;
    let mut output = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == target_table {
            in_target = true;
        } else if in_target && trimmed.starts_with('[') {
            in_target = false;
        }
        let mut next_line = line.to_owned();
        if in_target
            && trimmed.starts_with("version")
            && extract_toml_string_assignment(trimmed).is_some()
        {
            let leading = &line[..line.len() - line.trim_start().len()];
            next_line = format!(r#"{leading}version = "{next}""#);
            replaced = true;
        }
        output.push(next_line);
    }
    if !replaced {
        release_bail!("missing Cargo version in {target_table}");
    }
    Ok(preserve_trailing_newline(content, output.join("\n")))
}

fn replace_cargo_lock_package_version(
    content: &str,
    package: Option<&str>,
    next: &str,
) -> ReleaseResult<String> {
    let package = package.release_context("cargo_lock_package requires package")?;
    read_cargo_lock_package_version(content, Some(package))?;
    let mut output = Vec::new();
    let mut active: Option<String> = None;
    let mut replaced = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            active = None;
        } else if let Some(name) = cargo_lock_assignment(trimmed, "name") {
            active = Some(name);
        }
        let mut next_line = line.to_owned();
        if active.as_deref() == Some(package)
            && trimmed.starts_with("version")
            && cargo_lock_assignment(trimmed, "version").is_some()
        {
            let leading = &line[..line.len() - line.trim_start().len()];
            next_line = format!(r#"{leading}version = "{next}""#);
            replaced = true;
        }
        output.push(next_line);
    }
    if !replaced {
        release_bail!("missing Cargo.lock package {package} version");
    }
    Ok(preserve_trailing_newline(content, output.join("\n")))
}

fn replace_json_version(content: &str, pointer: Option<&str>, next: &str) -> ReleaseResult<String> {
    let pointer = pointer.unwrap_or("/version");
    let mut value: serde_json::Value =
        serde_json::from_str(content).release_context("invalid JSON")?;
    let target = value
        .pointer_mut(pointer)
        .with_release_context(|| format!("missing JSON version field at {pointer}"))?;
    if !target.is_string() {
        release_bail!("JSON version field at {pointer} is not a string");
    }
    *target = serde_json::Value::String(next.to_owned());
    let mut serialized =
        serde_json::to_string_pretty(&value).release_context("failed to serialize JSON")?;
    if content.ends_with('\n') {
        serialized.push('\n');
    }
    Ok(serialized)
}

/// Replace every capture-group-1 occurrence of the pattern with `next`.
fn replace_regex_version(
    content: &str,
    pattern: Option<&str>,
    next: &str,
) -> ReleaseResult<String> {
    let regex = compile_pattern(pattern)?;
    let mut output = String::with_capacity(content.len());
    let mut cursor = 0;
    let mut replaced = false;
    for captures in regex.captures_iter(content) {
        let group = captures
            .get(1)
            .release_context("pattern matched without a capture group")?;
        output.push_str(&content[cursor..group.start()]);
        output.push_str(next);
        cursor = group.end();
        replaced = true;
    }
    if !replaced {
        release_bail!("pattern did not match");
    }
    output.push_str(&content[cursor..]);
    Ok(output)
}

fn ensure_changelog_heading(content: &str, next: &str) -> ReleaseResult<String> {
    let heading = format!("## [{next}]");
    if content.lines().any(|line| line.starts_with(&heading)) {
        return Ok(content.to_owned());
    }
    let date = release_date()?;
    let entry = format!("## [{next}] - {date}");

    // Preferred: insert directly under an existing `## [Unreleased]` heading,
    // matching cortex's Keep-a-Changelog layout.
    if let Some(index) = content
        .lines()
        .position(|line| line.starts_with("## [Unreleased]"))
    {
        let mut lines: Vec<String> = content.lines().map(ToOwned::to_owned).collect();
        lines.insert(index + 1, String::new());
        lines.insert(index + 2, entry);
        return Ok(preserve_trailing_newline(content, lines.join("\n")));
    }

    // Fallback: insert under the top-level `# ` title.
    let block = format!("{entry}\n\n### Changed\n\n- Release version bump.\n\n");
    let mut lines = content.lines();
    let Some(first) = lines.next() else {
        return Ok(format!("# Changelog\n\n{block}"));
    };
    if first.starts_with("# ") {
        let rest = lines.collect::<Vec<_>>().join("\n");
        Ok(if rest.trim().is_empty() {
            format!("{first}\n\n{block}")
        } else {
            preserve_trailing_newline(content, format!("{first}\n\n{block}{}", rest.trim_start()))
        })
    } else {
        Ok(format!("{block}{content}"))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn compile_pattern(pattern: Option<&str>) -> ReleaseResult<Regex> {
    let pattern = pattern.release_context("regex_version requires pattern")?;
    let regex = Regex::new(pattern).release_context("invalid pattern")?;
    if regex.captures_len() != 2 {
        release_bail!("pattern must have exactly one capture group");
    }
    Ok(regex)
}

fn extract_toml_string_assignment(line: &str) -> Option<&str> {
    let (_, value) = line.split_once('=')?;
    value.trim().strip_prefix('"')?.strip_suffix('"')
}

fn cargo_lock_field(section: &str, key: &str) -> Option<String> {
    section
        .lines()
        .find_map(|line| cargo_lock_assignment(line.trim(), key))
}

fn cargo_lock_assignment(line: &str, key: &str) -> Option<String> {
    let prefix = format!("{key} = ");
    line.strip_prefix(&prefix)
        .and_then(|value| value.trim().strip_prefix('"')?.strip_suffix('"'))
        .map(ToOwned::to_owned)
}

fn release_date() -> ReleaseResult<String> {
    let output = Command::new("date")
        .arg("+%F")
        .output()
        .release_context("failed to run date +%F")?;
    if !output.status.success() {
        release_bail!(
            "date +%F failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let date = String::from_utf8(output.stdout).release_context("date +%F returned non-UTF-8")?;
    let date = date.trim();
    if !is_iso_date(date) {
        release_bail!("date +%F returned invalid date: {date}");
    }
    Ok(date.to_owned())
}

fn is_iso_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 10
        && bytes[0..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-'
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[7] == b'-'
        && bytes[8..10].iter().all(u8::is_ascii_digit)
}

fn preserve_trailing_newline(original: &str, mut updated: String) -> String {
    if original.ends_with('\n') && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated
}

#[cfg(test)]
#[path = "version_tests.rs"]
mod tests;
