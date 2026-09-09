//! Candidate generator for shell completion. `cortex __complete <ctx>` prints
//! one `value\tdescription` line per candidate (description optional).
//!
//! Contexts:
//! - `actions`            → CLI command names + descriptions
//! - `subcommands <path>` → canonical one-word children for a command path
//! - `flags <command>`    → that command's flags + help
//! - `value <flag>`       → values for a flag: fixed enums + relative-time hints
//!   inline, or live hostnames/apps/source IDs from the DB (cached ~60s, hard
//!   timeout, degrading to empty so completion never blocks or errors).

use anyhow::{Result, bail};
use cortex::mcp::ValueKind;
use std::time::{Duration, Instant, SystemTime};

const CACHE_TTL_SECS: u64 = 60;
const DYNAMIC_CANDIDATE_CAP: usize = 500;
const DB_BUSY_TIMEOUT_MS: u64 = 150;
/// Hard wall-clock deadline for the distinct-column scan itself. `busy_timeout`
/// only bounds lock-wait, not execution, so a progress handler enforces this to
/// keep Tab snappy even on a large DB.
const DB_QUERY_DEADLINE_MS: u64 = 150;
#[cfg(test)]
const COMMAND_CHILDREN: &[(&str, &[&str])] = cortex::surfaces::CLI_CHILDREN;

/// Top-level completion entry. `args[0]` is the context kind.
pub(crate) fn complete(args: &[String]) -> Result<Vec<String>> {
    let (kind, rest) = args
        .split_first()
        .map(|(k, r)| (k.as_str(), r))
        .ok_or_else(|| anyhow::anyhow!("completion context required"))?;
    match kind {
        "actions" => Ok(action_candidates()),
        "subcommands" => Ok(subcommand_candidates(rest)),
        "flags" => Ok(flag_candidates(rest)),
        "value" => Ok(value_candidates(
            rest.first().map(|s| s.as_str()).unwrap_or(""),
        )),
        other => bail!("unknown completion context '{other}'"),
    }
}

fn command_children(path: &str) -> &'static [&'static str] {
    cortex::surfaces::cli_children(path)
}

fn completion_words(args: &[String]) -> Vec<&str> {
    if let [path] = args {
        path.split_whitespace().collect()
    } else {
        args.iter().map(String::as_str).collect()
    }
}

/// Resolve only the canonical command prefix. Once a positional or option is
/// reached, the already-resolved leaf is retained and later words are ignored.
fn resolve_command_path(args: &[String]) -> String {
    let words = completion_words(args);
    let Some(root) = words.first().copied().filter(|word| {
        crate::cli::registry_actions()
            .iter()
            .any(|(candidate, _)| candidate == word)
    }) else {
        return String::new();
    };

    let mut path = root.to_string();
    for word in words.iter().skip(1) {
        if command_children(&path).contains(word) {
            path.push(' ');
            path.push_str(word);
        } else {
            break;
        }
    }
    path
}

fn subcommand_candidates(args: &[String]) -> Vec<String> {
    command_children(&resolve_command_path(args))
        .iter()
        .map(|value| (*value).to_string())
        .collect()
}

fn action_candidates() -> Vec<String> {
    crate::cli::registry_actions()
        .into_iter()
        .map(|(name, desc)| format!("{name}\t{desc}"))
        .collect()
}

fn flag_candidates(args: &[String]) -> Vec<String> {
    let command = resolve_command_path(args);
    let mut out = Vec::new();
    for f in crate::cli::registry_flags(&command) {
        out.push(format!("{}\t{}", f.flag, f.help));
        if !f.short.is_empty() {
            out.push(format!("{}\t{}", f.short, f.help));
        }
    }
    out
}

fn value_candidates(flag: &str) -> Vec<String> {
    match value_kind_for_flag(flag) {
        ValueKind::Enum(items) => items.iter().map(|s| s.to_string()).collect(),
        ValueKind::Time => time_hints(),
        ValueKind::Host => dynamic_cached("host", "hostname"),
        ValueKind::App => dynamic_cached("app", "app_name"),
        ValueKind::Source => dynamic_cached("source", "source_ip"),
        ValueKind::None | ValueKind::Text => Vec::new(),
    }
}

/// Resolve a flag (long or short) to its completion kind by scanning the
/// registry. The canonical vocabulary maps each flag to one kind everywhere,
/// so the first match is authoritative.
fn value_kind_for_flag(flag: &str) -> ValueKind {
    for action in cortex::mcp::action_names() {
        for f in cortex::mcp::flags_for(action).unwrap_or(&[]) {
            if f.flag == flag || (!f.short.is_empty() && f.short == flag) {
                return f.value_kind;
            }
        }
    }
    ValueKind::Text
}

fn time_hints() -> Vec<String> {
    ["15m", "30m", "1h", "6h", "1d", "2d", "yesterday", "today"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// Live values for `kind` (cache key) sourced from DB column `column`. Reads a
/// ~60s tmp cache; on miss/expiry runs a bounded read-only query. ANY failure
/// (DB missing, locked, timeout) yields the stale cache if present, else an
/// empty Vec — completion silently degrades to static candidates and never
/// blocks or errors.
fn dynamic_cached(kind: &str, column: &str) -> Vec<String> {
    let path = cache_path(kind);
    if let Some(fresh) = read_fresh(path.as_deref(), CACHE_TTL_SECS) {
        return fresh;
    }
    match query_distinct(column) {
        Ok(values) => {
            if let Some(p) = path.as_deref() {
                let _ = write_cache(p, &values);
            }
            values
        }
        Err(_) => read_any(path.as_deref()).unwrap_or_default(),
    }
}

/// Bounded, recent-biased, read-only distinct-column scan. `column` is one of a
/// fixed internal allowlist (hostname/app_name/source_ip) — never user input —
/// so the format! is not an injection vector. Capped at DYNAMIC_CANDIDATE_CAP.
fn query_distinct(column: &str) -> Result<Vec<String>> {
    let db = db_path();
    let conn = rusqlite::Connection::open_with_flags(
        &db,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(Duration::from_millis(DB_BUSY_TIMEOUT_MS))?;
    // `busy_timeout` only bounds lock contention, not query execution. Enforce a
    // real per-query deadline with a progress handler: it fires every ~1000 VM
    // steps and aborts the statement (→ SQLITE_INTERRUPT → Err → caller falls
    // back to cache/empty) once the deadline passes.
    let deadline = Instant::now() + Duration::from_millis(DB_QUERY_DEADLINE_MS);
    conn.progress_handler(1000, Some(move || Instant::now() >= deadline))?;
    let sql = format!(
        "SELECT DISTINCT {column} FROM \
         (SELECT {column} FROM logs ORDER BY id DESC LIMIT 100000) sub \
         WHERE {column} IS NOT NULL AND {column} != '' LIMIT {DYNAMIC_CANDIDATE_CAP}"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
    Ok(rows.filter_map(|r| r.ok()).collect())
}

fn db_path() -> String {
    crate::env::var("CORTEX_DB_PATH").unwrap_or_else(|_| "data/cortex.db".to_string())
}

fn cache_path(kind: &str) -> Option<std::path::PathBuf> {
    let dir = crate::env::var_os("XDG_RUNTIME_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("cortex-complete");
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir.join(kind))
}

fn read_fresh(path: Option<&std::path::Path>, ttl_secs: u64) -> Option<Vec<String>> {
    let path = path?;
    let meta = std::fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    let age = SystemTime::now().duration_since(modified).ok()?;
    if age.as_secs() <= ttl_secs {
        read_any(Some(path))
    } else {
        None
    }
}

fn read_any(path: Option<&std::path::Path>) -> Option<Vec<String>> {
    let content = std::fs::read_to_string(path?).ok()?;
    Some(
        content
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| l.to_string())
            .collect(),
    )
}

fn write_cache(path: &std::path::Path, values: &[String]) -> std::io::Result<()> {
    std::fs::write(path, values.join("\n"))
}

#[cfg(test)]
#[path = "complete_tests.rs"]
mod tests;
