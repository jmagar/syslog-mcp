//! Stable, versioned Agent Observatory identities.

use std::fmt;

/// Maximum encoded projected-event key size from the Agent Observatory contract.
pub const MAX_EVENT_KEY_BYTES: usize = 1024;

/// Validation failures produced while constructing durable identities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// A required component was empty after trimming.
    Empty(&'static str),
    /// A source kind or projection variant was not strict ASCII lower snake case.
    InvalidLowerSnake(&'static str),
    /// A projected-event key exceeded the durable contract limit.
    EventKeyTooLong {
        /// Encoded UTF-8 byte length.
        actual: usize,
        /// Maximum permitted UTF-8 byte length.
        max: usize,
    },
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty(component) => write!(formatter, "{component} must be non-empty"),
            Self::InvalidLowerSnake(component) => {
                write!(formatter, "{component} must be ASCII lower snake case")
            }
            Self::EventKeyTooLong { actual, max } => {
                write!(formatter, "event key is {actual} bytes; maximum is {max}")
            }
        }
    }
}

impl std::error::Error for IdentityError {}

fn required<'a>(value: &'a str, component: &'static str) -> Result<&'a str, IdentityError> {
    let value = value.trim();
    if value.is_empty() {
        Err(IdentityError::Empty(component))
    } else {
        Ok(value)
    }
}

fn length_prefixed(parts: &[&str]) -> String {
    parts
        .iter()
        .map(|part| format!("{}:{part}", part.len()))
        .collect::<Vec<_>>()
        .join("|")
}

/// Convert a provider tool label into its stable contract value.
///
/// Known tools become lowercase names. Unknown labels remain Unicode-preserving
/// apart from Unicode lowercase conversion and surrounding-whitespace trimming.
pub fn canonical_tool(tool: &str) -> Result<String, IdentityError> {
    let tool = required(tool, "tool")?;
    let normalized = tool.to_lowercase();

    if let Some(provider) = crate::scanner::providers::canonical_transcript_provider(&normalized) {
        return Ok(provider.to_string());
    }

    let source = normalized
        .strip_prefix("unknown:")
        .map(str::trim)
        .unwrap_or(normalized.as_str());
    if source.is_empty() {
        return Err(IdentityError::Empty("tool"));
    }
    Ok(format!("unknown:{source}"))
}

/// Build the version-one run identity from host, canonical tool, and native session.
pub fn run_key(host: &str, tool: &str, session: &str) -> Result<String, IdentityError> {
    let host = required(host, "host")?;
    let tool = canonical_tool(tool)?;
    let session = required(session, "session")?;
    Ok(format!(
        "v1|{}",
        length_prefixed(&[host, tool.as_str(), session])
    ))
}

/// Build the version-one repository identity from host and canonical common Git directory.
pub fn repository_key(host: &str, common_git_dir: &str) -> Result<String, IdentityError> {
    let host = required(host, "host")?;
    let common_git_dir = required(common_git_dir, "common_git_dir")?;
    Ok(format!("v1|{}", length_prefixed(&[host, common_git_dir])))
}

/// Build the version-one worktree identity from host and canonical worktree path.
pub fn worktree_key(host: &str, worktree_path: &str) -> Result<String, IdentityError> {
    let host = required(host, "host")?;
    let worktree_path = required(worktree_path, "worktree_path")?;
    Ok(format!("v1|{}", length_prefixed(&[host, worktree_path])))
}

/// Build the version-one actor identity nested under a complete run key.
pub fn actor_key(run_key: &str, actor_id: &str) -> Result<String, IdentityError> {
    let run_key = required(run_key, "run_key")?;
    let actor_id = required(actor_id, "actor_id")?;
    Ok(format!("v1|{}", length_prefixed(&[run_key, actor_id])))
}

fn is_ascii_lower_snake(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_lowercase() || bytes.last() == Some(&b'_') {
        return false;
    }

    let mut previous_was_underscore = false;
    for byte in bytes {
        match byte {
            b'a'..=b'z' | b'0'..=b'9' => previous_was_underscore = false,
            b'_' if !previous_was_underscore => previous_was_underscore = true,
            _ => return false,
        }
    }
    true
}

/// Build a deterministic projected-event key.
///
/// Source kinds and projection variants are strict ASCII lower snake case. The
/// source primary key is trimmed but otherwise preserved, including delimiters.
pub fn event_key(
    source_kind: &str,
    source_primary_key: &str,
    projection_variant: &str,
) -> Result<String, IdentityError> {
    let source_kind = required(source_kind, "source_kind")?;
    let source_primary_key = required(source_primary_key, "source_primary_key")?;
    let projection_variant = required(projection_variant, "projection_variant")?;

    if !is_ascii_lower_snake(source_kind) {
        return Err(IdentityError::InvalidLowerSnake("source_kind"));
    }
    if !is_ascii_lower_snake(projection_variant) {
        return Err(IdentityError::InvalidLowerSnake("projection_variant"));
    }

    let key = format!("v1:{source_kind}:{source_primary_key}:{projection_variant}");
    let actual = key.len();
    if actual > MAX_EVENT_KEY_BYTES {
        return Err(IdentityError::EventKeyTooLong {
            actual,
            max: MAX_EVENT_KEY_BYTES,
        });
    }
    Ok(key)
}

#[cfg(test)]
#[path = "identity_tests.rs"]
mod tests;
