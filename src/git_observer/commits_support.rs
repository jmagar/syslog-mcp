//! Bounded parser for exact Git commit metadata and numstat summaries.

use chrono::{DateTime, SecondsFormat};
use sha2::{Digest, Sha256};
use std::fmt;

pub(super) const COMMIT_MARKER: &[u8] = b"CORTEX_COMMIT_V1";
const MAX_COMMIT_FIELD_BYTES: usize = 16 * 1024;

pub const COMMIT_SHOW_FORMAT: &str =
    "CORTEX_COMMIT_V1%x00%H%x00%P%x00%an%x00%ae%x00%aI%x00%cI%x00%s%x00";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitParseOptions {
    pub max_input_bytes: usize,
    pub max_commits: usize,
    pub max_paths_per_commit: usize,
    pub store_changed_paths: bool,
    pub store_author_name: bool,
    pub store_author_email_hash: bool,
}

impl Default for CommitParseOptions {
    fn default() -> Self {
        Self {
            max_input_bytes: 256 * 1024,
            max_commits: 500,
            max_paths_per_commit: 2_000,
            store_changed_paths: true,
            store_author_name: true,
            store_author_email_hash: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitPathChange {
    pub path: Vec<u8>,
    pub previous_path: Option<Vec<u8>>,
    pub insertions: Option<u64>,
    pub deletions: Option<u64>,
    pub binary: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCommit {
    pub sha: String,
    pub parent_shas: Vec<String>,
    pub author_name: Option<String>,
    pub author_email_hash: Option<String>,
    pub authored_at: String,
    pub committed_at: String,
    pub subject: String,
    pub changed_files: u64,
    pub insertions: u64,
    pub deletions: u64,
    pub binary_files: u64,
    pub changed_paths: Vec<CommitPathChange>,
    pub paths_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitParseErrorKind {
    InvalidOptions(&'static str),
    InputTooLong { actual: usize, max: usize },
    MissingTerminator,
    ExpectedMarker,
    MissingMetadataField(&'static str),
    InvalidMetadataSeparator,
    FieldTooLong { actual: usize, max: usize },
    InvalidObjectId(&'static str),
    InvalidParents,
    InvalidUtf8(&'static str),
    InvalidTimestamp(&'static str),
    InvalidNumstat,
    MissingRenamePath,
    TooManyCommits { max: usize },
    DuplicateCommit,
    InvalidRequestedObjectId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitParseError {
    pub commit_index: usize,
    pub token_index: usize,
    pub kind: CommitParseErrorKind,
}

impl CommitParseError {
    pub(super) fn new(commit_index: usize, token_index: usize, kind: CommitParseErrorKind) -> Self {
        Self {
            commit_index,
            token_index,
            kind,
        }
    }
}

impl fmt::Display for CommitParseErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOptions(name) => write!(formatter, "invalid parser option: {name}"),
            Self::InputTooLong { actual, max } => {
                write!(formatter, "input is {actual} bytes; maximum is {max}")
            }
            Self::MissingTerminator => formatter.write_str("input is missing its final NUL"),
            Self::ExpectedMarker => formatter.write_str("expected commit marker"),
            Self::MissingMetadataField(name) => write!(formatter, "missing {name} field"),
            Self::InvalidMetadataSeparator => {
                formatter.write_str("metadata is missing its blank separator")
            }
            Self::FieldTooLong { actual, max } => {
                write!(formatter, "field is {actual} bytes; maximum is {max}")
            }
            Self::InvalidObjectId(name) => write!(formatter, "invalid {name} object ID"),
            Self::InvalidParents => formatter.write_str("invalid parent object ID list"),
            Self::InvalidUtf8(name) => write!(formatter, "{name} is not UTF-8"),
            Self::InvalidTimestamp(name) => write!(formatter, "{name} is not RFC 3339"),
            Self::InvalidNumstat => formatter.write_str("invalid numstat record"),
            Self::MissingRenamePath => formatter.write_str("rename paths are missing"),
            Self::TooManyCommits { max } => write!(formatter, "commit count exceeds {max}"),
            Self::DuplicateCommit => formatter.write_str("duplicate commit object ID"),
            Self::InvalidRequestedObjectId => formatter.write_str("invalid requested object ID"),
        }
    }
}

impl fmt::Display for CommitParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "commit stream record {} token {}: {}",
            self.commit_index, self.token_index, self.kind
        )
    }
}

impl std::error::Error for CommitParseError {}

pub(super) fn is_object_id(value: &[u8]) -> bool {
    matches!(value.len(), 40 | 64) && value.iter().all(u8::is_ascii_hexdigit)
}

pub(super) fn bounded_field(
    field: &[u8],
    commit_index: usize,
    token_index: usize,
) -> Result<&[u8], CommitParseError> {
    if field.len() > MAX_COMMIT_FIELD_BYTES {
        return Err(CommitParseError::new(
            commit_index,
            token_index,
            CommitParseErrorKind::FieldTooLong {
                actual: field.len(),
                max: MAX_COMMIT_FIELD_BYTES,
            },
        ));
    }
    Ok(field)
}

pub(super) fn utf8(
    field: &[u8],
    name: &'static str,
    commit_index: usize,
    token_index: usize,
) -> Result<String, CommitParseError> {
    std::str::from_utf8(bounded_field(field, commit_index, token_index)?)
        .map(str::to_string)
        .map_err(|_| {
            CommitParseError::new(
                commit_index,
                token_index,
                CommitParseErrorKind::InvalidUtf8(name),
            )
        })
}

pub(super) fn object_id(
    field: &[u8],
    name: &'static str,
    commit_index: usize,
    token_index: usize,
) -> Result<String, CommitParseError> {
    bounded_field(field, commit_index, token_index)?;
    if !is_object_id(field) {
        return Err(CommitParseError::new(
            commit_index,
            token_index,
            CommitParseErrorKind::InvalidObjectId(name),
        ));
    }
    Ok(String::from_utf8(field.to_vec()).expect("object ID is ASCII"))
}

pub(super) fn parents(
    field: &[u8],
    commit_index: usize,
    token_index: usize,
) -> Result<Vec<String>, CommitParseError> {
    bounded_field(field, commit_index, token_index)?;
    if field.is_empty() {
        return Ok(Vec::new());
    }
    field
        .split(|byte| *byte == b' ')
        .map(|parent| {
            if !is_object_id(parent) {
                return Err(CommitParseError::new(
                    commit_index,
                    token_index,
                    CommitParseErrorKind::InvalidParents,
                ));
            }
            Ok(String::from_utf8(parent.to_vec()).expect("object ID is ASCII"))
        })
        .collect()
}

pub(super) fn timestamp(
    field: &[u8],
    name: &'static str,
    commit_index: usize,
    token_index: usize,
) -> Result<String, CommitParseError> {
    let value = utf8(field, name, commit_index, token_index)?;
    DateTime::parse_from_rfc3339(&value)
        .map(|timestamp| timestamp.to_rfc3339_opts(SecondsFormat::Secs, true))
        .map_err(|_| {
            CommitParseError::new(
                commit_index,
                token_index,
                CommitParseErrorKind::InvalidTimestamp(name),
            )
        })
}

fn trim_ascii(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |index| index + 1);
    &value[start..end]
}

pub(super) fn email_hash(value: &[u8]) -> Option<String> {
    let value = trim_ascii(value);
    if value.is_empty() {
        return None;
    }
    let normalized = value.iter().map(u8::to_ascii_lowercase).collect::<Vec<_>>();
    Some(format!("{:x}", Sha256::digest(normalized)))
}

fn parse_count(value: &[u8]) -> Option<u64> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(value).ok()?.parse().ok()
}

pub(super) fn add_numstat(
    commit: &mut ParsedCommit,
    header: &[u8],
    old_path: Option<&[u8]>,
    new_path: &[u8],
    options: CommitParseOptions,
    commit_index: usize,
    token_index: usize,
) -> Result<(), CommitParseError> {
    bounded_field(new_path, commit_index, token_index)?;
    if new_path.is_empty() {
        return Err(CommitParseError::new(
            commit_index,
            token_index,
            CommitParseErrorKind::MissingRenamePath,
        ));
    }
    if let Some(old_path) = old_path {
        bounded_field(old_path, commit_index, token_index)?;
        if old_path.is_empty() {
            return Err(CommitParseError::new(
                commit_index,
                token_index,
                CommitParseErrorKind::MissingRenamePath,
            ));
        }
    }

    let mut parts = header.splitn(3, |byte| *byte == 9);
    let added = parts.next();
    let deleted = parts.next();
    let path = parts.next();
    if added.is_none() || deleted.is_none() || path.is_none() {
        return Err(CommitParseError::new(
            commit_index,
            token_index,
            CommitParseErrorKind::InvalidNumstat,
        ));
    }
    let added = added.expect("checked");
    let deleted = deleted.expect("checked");
    let binary = added == b"-" && deleted == b"-";
    let (insertions, deletions) = if binary {
        (None, None)
    } else {
        let Some(insertions) = parse_count(added) else {
            return Err(CommitParseError::new(
                commit_index,
                token_index,
                CommitParseErrorKind::InvalidNumstat,
            ));
        };
        let Some(deletions) = parse_count(deleted) else {
            return Err(CommitParseError::new(
                commit_index,
                token_index,
                CommitParseErrorKind::InvalidNumstat,
            ));
        };
        (Some(insertions), Some(deletions))
    };

    commit.changed_files = commit.changed_files.checked_add(1).ok_or_else(|| {
        CommitParseError::new(
            commit_index,
            token_index,
            CommitParseErrorKind::InvalidNumstat,
        )
    })?;
    if binary {
        commit.binary_files += 1;
    } else {
        commit.insertions = commit
            .insertions
            .checked_add(insertions.expect("numeric entry"))
            .ok_or_else(|| {
                CommitParseError::new(
                    commit_index,
                    token_index,
                    CommitParseErrorKind::InvalidNumstat,
                )
            })?;
        commit.deletions = commit
            .deletions
            .checked_add(deletions.expect("numeric entry"))
            .ok_or_else(|| {
                CommitParseError::new(
                    commit_index,
                    token_index,
                    CommitParseErrorKind::InvalidNumstat,
                )
            })?;
    }

    if options.store_changed_paths {
        if commit.changed_paths.len() < options.max_paths_per_commit {
            commit.changed_paths.push(CommitPathChange {
                path: new_path.to_vec(),
                previous_path: old_path.map(<[u8]>::to_vec),
                insertions,
                deletions,
                binary,
            });
        } else {
            commit.paths_truncated = true;
        }
    }
    Ok(())
}
