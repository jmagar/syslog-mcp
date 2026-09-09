use chrono::Utc;
use hmac::{Hmac, Mac};
use lab_auth::AuthContext;
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::{
    CURSOR_CLOCK_SKEW_SECS, CURSOR_TTL_SECS, CursorKeys, SessionStreamRequest, StreamError,
};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(super) struct StreamCursor {
    pub(super) version: u8,
    pub(super) position: i64,
    pub(super) principal: String,
    pub(super) filters: String,
    pub(super) issued_at: i64,
    pub(super) signature: String,
}

pub(super) fn principal_key(auth: &AuthContext) -> String {
    format!("{}:{}", auth.issuer, auth.sub)
}

pub(super) fn fingerprint<T: Serialize>(value: &T) -> Result<String, StreamError> {
    let bytes = serde_json::to_vec(value).map_err(|_| StreamError::Invalid("invalid filters"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn cursor_mac(
    position: i64,
    principal: &str,
    filters: &str,
    issued_at: i64,
    key: &[u8],
) -> Hmac<Sha256> {
    let body = format!("1\0{position}\0{principal}\0{filters}\0{issued_at}");
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts arbitrary key lengths");
    mac.update(body.as_bytes());
    mac
}

fn cursor_signature(
    position: i64,
    principal: &str,
    filters: &str,
    issued_at: i64,
    key: &[u8],
) -> String {
    hex::encode(
        cursor_mac(position, principal, filters, issued_at, key)
            .finalize()
            .into_bytes(),
    )
}

pub(crate) fn encode_cursor_with_keys(
    position: i64,
    principal: &str,
    filters: &str,
    issued_at: i64,
    keys: &CursorKeys,
) -> String {
    let cursor = StreamCursor {
        version: 1,
        position,
        principal: principal.into(),
        filters: filters.into(),
        issued_at,
        signature: cursor_signature(position, principal, filters, issued_at, &keys.current),
    };
    hex::encode(serde_json::to_vec(&cursor).expect("cursor is serializable"))
}

pub(super) fn decode_cursor_with_keys(
    value: &str,
    keys: &CursorKeys,
) -> Result<StreamCursor, StreamError> {
    if value.len() > 2048 {
        return Err(StreamError::Invalid("invalid cursor"));
    }
    let bytes = hex::decode(value).map_err(|_| StreamError::Invalid("invalid cursor"))?;
    let cursor: StreamCursor =
        serde_json::from_slice(&bytes).map_err(|_| StreamError::Invalid("invalid cursor"))?;
    if cursor.version != 1 || cursor.position < 0 {
        return Err(StreamError::Invalid("invalid cursor"));
    }
    let tag = hex::decode(&cursor.signature)
        .map_err(|_| StreamError::Invalid("cursor signature is invalid"))?;
    if tag.len() != 32 {
        return Err(StreamError::Invalid("cursor signature is invalid"));
    }
    let valid_for = |key: &[u8]| {
        cursor_mac(
            cursor.position,
            &cursor.principal,
            &cursor.filters,
            cursor.issued_at,
            key,
        )
        .verify_slice(&tag)
        .is_ok()
    };
    if !valid_for(&keys.current) && !keys.previous.iter().any(|key| valid_for(key)) {
        return Err(StreamError::Invalid("cursor signature is invalid"));
    }
    Ok(cursor)
}

#[cfg(test)]
pub(super) fn test_cursor_keys() -> CursorKeys {
    CursorKeys::resolved(Some("test-only-cursor-key"), &[], true).unwrap()
}

#[cfg(test)]
pub(super) fn encode_cursor(
    position: i64,
    principal: &str,
    filters: &str,
    issued_at: i64,
) -> String {
    encode_cursor_with_keys(position, principal, filters, issued_at, &test_cursor_keys())
}

#[cfg(test)]
pub(super) fn decode_cursor(value: &str) -> Result<StreamCursor, StreamError> {
    decode_cursor_with_keys(value, &test_cursor_keys())
}

pub(crate) fn session_filter_fingerprint(
    project: &str,
    tool: &str,
    session_id: &str,
    host: &str,
) -> Result<String, StreamError> {
    fingerprint(&SessionStreamRequest {
        project: project.into(),
        tool: tool.into(),
        session_id: session_id.into(),
        host: host.into(),
        cursor: None,
    })
}

pub(crate) fn principal(auth: &AuthContext) -> String {
    principal_key(auth)
}

pub(crate) fn decode_session_handoff(
    value: &str,
    auth: &AuthContext,
    project: &str,
    tool: &str,
    session_id: &str,
    host: &str,
    keys: &CursorKeys,
) -> Result<i64, StreamError> {
    let cursor = decode_cursor_with_keys(value, keys)?;
    if cursor.principal != principal_key(auth) {
        return Err(StreamError::Forbidden(
            "cursor belongs to another principal",
        ));
    }
    if cursor.filters != session_filter_fingerprint(project, tool, session_id, host)? {
        return Err(StreamError::Invalid(
            "cursor does not match session filters",
        ));
    }
    let age = Utc::now().timestamp() - cursor.issued_at;
    if !(-CURSOR_CLOCK_SKEW_SECS..=CURSOR_TTL_SECS).contains(&age) {
        return Err(StreamError::Expired);
    }
    Ok(cursor.position)
}
