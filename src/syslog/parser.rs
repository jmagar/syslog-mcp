use chrono::Utc;
use tracing::{debug, warn};

use crate::db;

/// Syslog facility names (RFC 5424).
const FACILITIES: &[&str] = &[
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv",
    "ftp", "ntp", "audit", "alert", "clock", "local0", "local1", "local2", "local3", "local4",
    "local5", "local6", "local7",
];

/// Truncate a string to at most `max` bytes, respecting UTF-8 char boundaries.
fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Returns true if `s` looks like an ISO 8601 timestamp (YYYY-MM-DDTHH:...).
/// UniFi OS incorrectly puts a timestamp in the syslog hostname field.
///
/// Validates separator positions AND digit positions to avoid false positives
/// on strings that happen to have `-` and `T` at the right offsets.
pub(super) fn looks_like_timestamp(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 19
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[0].is_ascii_digit()
        && b[1].is_ascii_digit()
        && b[2].is_ascii_digit()
        && b[3].is_ascii_digit()
        && b[5].is_ascii_digit()
        && b[6].is_ascii_digit()
        && b[8].is_ascii_digit()
        && b[9].is_ascii_digit()
}

/// Extract a single value from a CEF extension string (`key1=val1 key2=val2 ...`).
///
/// Values may contain spaces; the next `WORD=` boundary (a space followed by a word
/// containing no spaces and then `=`) terminates the current value.
pub(super) fn cef_ext_value(extensions: &str, key: &str) -> Option<String> {
    let key_eq_len = key.len() + 1;
    let start =
        if extensions.starts_with(key) && extensions.as_bytes().get(key.len()) == Some(&b'=') {
            key_eq_len
        } else {
            let bytes = extensions.as_bytes();
            let key_bytes = key.as_bytes();
            let mut found = None;
            let mut i = 0;
            while i + key_eq_len < bytes.len() {
                if bytes[i] == b' '
                    && bytes[i + 1..].starts_with(key_bytes)
                    && bytes.get(i + 1 + key.len()) == Some(&b'=')
                {
                    found = Some(i + 1 + key_eq_len);
                    break;
                }
                i += 1;
            }
            found?
        };
    let rest = &extensions[start..];

    let mut end = rest.len();
    let bytes = rest.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b' ' {
            let after = &rest[i + 1..];
            if let Some(eq) = after.find('=') {
                if !after[..eq].contains(' ') {
                    end = i;
                    break;
                }
            }
        }
        i += 1;
    }

    let value = rest[..end].trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

/// Parsed fields extracted from a CEF syslog message.
pub(super) struct CefFields {
    pub hostname: Option<String>,
    pub app_name: Option<String>,
    pub message: Option<String>,
}

/// Extract hostname, app_name, and message from a reconstructed CEF syslog body.
///
/// `text` is `app_name_fragment + " " + message_body` as produced by syslog_loose
/// when parsing a UniFi CEF message. The function finds the embedded `CEF:` block,
/// parses the pipe-delimited header, and extracts extension fields.
///
/// Returns a `CefFields` with:
/// - hostname: `UNIFIdeviceName` extension value; falls back to CEF Device Product
/// - app_name: CEF event name
/// - message: `msg` extension value; falls back to the full CEF string
pub(super) fn extract_cef_fields(text: &str) -> CefFields {
    let cef_pos = match text.find("CEF:") {
        Some(p) => p,
        None => {
            return CefFields {
                hostname: None,
                app_name: None,
                message: None,
            }
        }
    };

    let cef_str = &text[cef_pos..];
    let parts: Vec<&str> = cef_str.splitn(8, '|').collect();
    if parts.len() < 8 {
        return CefFields {
            hostname: None,
            app_name: None,
            message: None,
        };
    }

    let event_name = parts[5].to_string();
    let extensions = parts[7];
    let hostname =
        cef_ext_value(extensions, "UNIFIdeviceName").or_else(|| Some(parts[2].to_string()));
    let message = cef_ext_value(extensions, "msg").unwrap_or_else(|| cef_str.to_string());

    CefFields {
        hostname,
        app_name: Some(event_name),
        message: Some(message),
    }
}

/// Parse a raw syslog message (RFC 3164 / RFC 5424 / loose).
///
/// Handles UniFi CEF messages where the hostname field contains a timestamp
/// and the real device name is embedded in the CEF extension `UNIFIdeviceName`.
///
/// `source_ip` is the actual network sender address (e.g. "192.168.1.10:514"),
/// recorded separately from the hostname claimed in the message body.
pub(super) fn parse_syslog(raw: &str, source_ip: String) -> db::LogBatchEntry {
    let msg = syslog_loose::parse_message(raw, syslog_loose::Variant::Either);

    let severity_num = msg.severity.map(|s| s as u8).unwrap_or(6);
    let facility_num = msg.facility.map(|f| f as u8);

    let severity = db::SEVERITY_LEVELS
        .get(severity_num as usize)
        .unwrap_or(&"info")
        .to_string();

    let facility = facility_num.and_then(|f| FACILITIES.get(f as usize).map(|s| s.to_string()));

    let timestamp = msg
        .timestamp
        .map(|dt| dt.with_timezone(&Utc).to_rfc3339())
        .unwrap_or_else(|| Utc::now().to_rfc3339());

    let raw_hostname = msg.hostname.map(|h| h.to_string()).unwrap_or_default();
    let raw_app_name = msg.appname.map(|a| a.to_string());
    let process_id = msg.procid.map(|p| match p {
        syslog_loose::ProcId::PID(n) => n.to_string(),
        syslog_loose::ProcId::Name(s) => s.to_string(),
    });
    let raw_message = msg.msg.to_string();

    // Format dispatch:
    // Vendor-specific fields extracted from the message body override syslog
    // header values. The header is a fallback when the vendor format provides
    // no value. Keep the standard RFC path as the final branch.
    let (hostname, app_name, message) = if looks_like_timestamp(&raw_hostname)
        && (raw_app_name.as_deref().unwrap_or("").contains("CEF:") || raw_message.contains("CEF:"))
    {
        // SECURITY NOTE: The hostname stored here is extracted from the CEF message
        // body (UNIFIdeviceName extension field), NOT validated against the network
        // source. Any LAN device can craft a CEF message with an arbitrary
        // UNIFIdeviceName and impersonate a legitimate host. `source_ip` is the
        // only trustworthy identity: it reflects the actual network sender address
        // recorded by the OS at socket receive/accept time, not message content.
        let full_text = match &raw_app_name {
            Some(app) => format!("{app} {raw_message}"),
            None => raw_message.clone(),
        };
        let cef = extract_cef_fields(&full_text);
        if cef.hostname.is_none() && cef.app_name.is_none() && cef.message.is_none() {
            let preview = &full_text[..full_text.len().min(200)];
            warn!(msg = preview, "CEF heuristic triggered but all fields are None — malformed CEF body, using raw fallback");
        }
        if let Some(ref cef_host) = cef.hostname {
            if !raw_hostname.is_empty() && cef_host != &raw_hostname {
                debug!(
                    cef_hostname = %cef_host,
                    syslog_header_hostname = %raw_hostname,
                    source_ip = %source_ip,
                    "CEF hostname differs from syslog-header hostname; \
                     CEF value is from message content and is not network-verified"
                );
            }
        }
        (
            truncate(&cef.hostname.unwrap_or_else(|| raw_hostname.clone()), 255).to_string(),
            cef.app_name
                .or(raw_app_name)
                .map(|s| truncate(&s, 128).to_string()),
            truncate(&cef.message.unwrap_or(raw_message), 8192).to_string(),
        )
    } else {
        let hostname = if raw_hostname.is_empty() {
            "unknown".to_string()
        } else {
            raw_hostname
        };
        (hostname, raw_app_name, raw_message)
    };

    db::LogBatchEntry {
        timestamp,
        hostname,
        facility,
        severity,
        app_name,
        process_id,
        message,
        raw: raw.to_string(),
        source_ip,
        docker_checkpoint: None,
    }
}

#[cfg(test)]
#[path = "parser_tests.rs"]
mod tests;
