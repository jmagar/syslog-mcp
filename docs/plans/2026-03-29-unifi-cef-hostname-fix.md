# UniFi CEF Hostname Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix syslog hostname parsing for UniFi devices, which send CEF-formatted syslog with a timestamp in the hostname field and the real device name embedded in the message body.

**Architecture:** Add three pure functions to `src/syslog.rs` — `looks_like_timestamp`, `cef_ext_value`, and `extract_cef_fields` — then update `parse_syslog` to call them when it detects a timestamp-as-hostname. No new files, no new dependencies.

**Tech Stack:** Rust, `syslog_loose` crate (already a dependency), `#[cfg(test)]` unit tests in-module.

---

## Background

UniFi OS sends RFC 5424 syslog with a malformed hostname field. Example raw message:

```
<14>1 2026-03-29T02:52:21+00:00 2026-03-29T02:52:21.587Z The - - - Mothership CEF:0|Ubiquiti|UniFi OS|5.1.5|1|Test Syslog|1|UNIFIhost=Host UNIFIdeviceName=The Mothership UNIFIdeviceModel=UCGMAX UNIFIdeviceIp=76.213.118.20 UNIFIdeviceMac=9C:05:D6:CA:81:3B UNIFIdeviceVersion=5.1.5 msg=Test Syslog
```

What `syslog_loose` currently produces:
- `hostname` → `2026-03-29T02:52:21.587Z` (wrong — second timestamp in message)
- `app_name` → `The` (wrong — first word of device name)
- `message`  → `Mothership CEF:0|...` (truncated — device name fragment + CEF body)

What we want:
- `hostname` → `The Mothership` (from `UNIFIdeviceName` CEF extension)
- `app_name` → `Test Syslog` (from CEF event name, field 5)
- `message`  → `Test Syslog` (from `msg` CEF extension, or full CEF string as fallback)

## File Map

| File | Change |
|------|--------|
| `src/syslog.rs` | Add 3 helper functions + update `parse_syslog` + add `#[cfg(test)]` module |

---

## Task 1: Add `looks_like_timestamp` with tests

**Files:**
- Modify: `src/syslog.rs`

- [ ] **Step 1: Add the failing test**

Add a `#[cfg(test)]` module at the bottom of `src/syslog.rs` (after the closing brace of `parse_syslog`):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_looks_like_timestamp_true() {
        assert!(looks_like_timestamp("2026-03-29T02:52:21.587Z"));
        assert!(looks_like_timestamp("2026-03-29T02:52:21+00:00"));
        assert!(looks_like_timestamp("2024-01-01T00:00:00Z"));
    }

    #[test]
    fn test_looks_like_timestamp_false() {
        assert!(!looks_like_timestamp("The Mothership"));
        assert!(!looks_like_timestamp("dookie"));
        assert!(!looks_like_timestamp("unknown"));
        assert!(!looks_like_timestamp(""));
        assert!(!looks_like_timestamp("192.168.1.1"));
    }
}
```

- [ ] **Step 2: Run to confirm it fails**

```bash
cargo test test_looks_like_timestamp 2>&1
```

Expected: `error[E0425]: cannot find function `looks_like_timestamp``

- [ ] **Step 3: Implement `looks_like_timestamp`**

Add this function to `src/syslog.rs` just before `parse_syslog`:

```rust
/// Returns true if `s` looks like an ISO 8601 timestamp (YYYY-MM-DDTHH:…).
/// UniFi OS incorrectly puts a timestamp in the syslog hostname field.
fn looks_like_timestamp(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 19 && b[4] == b'-' && b[7] == b'-' && b[10] == b'T'
}
```

- [ ] **Step 4: Run to confirm it passes**

```bash
cargo test test_looks_like_timestamp 2>&1
```

Expected: `test tests::test_looks_like_timestamp_true ... ok` and `test tests::test_looks_like_timestamp_false ... ok`

- [ ] **Step 5: Commit**

```bash
cd /home/jmagar/workspace/syslog-mcp
git add src/syslog.rs
git commit -m "test: add looks_like_timestamp with unit tests"
```

---

## Task 2: Add `cef_ext_value` with tests

**Files:**
- Modify: `src/syslog.rs`

CEF extension strings look like `key1=value1 key2=value2` where values may contain spaces (e.g., `UNIFIdeviceName=The Mothership`). The function must find the end of a value by detecting the next `WORD=` boundary (a word with no spaces followed by `=`).

- [ ] **Step 1: Add the failing tests**

Inside the `#[cfg(test)]` module, add:

```rust
    #[test]
    fn test_cef_ext_value_simple() {
        let ext = "UNIFIdeviceModel=UCGMAX UNIFIdeviceIp=76.213.118.20";
        assert_eq!(cef_ext_value(ext, "UNIFIdeviceModel"), Some("UCGMAX".to_string()));
        assert_eq!(cef_ext_value(ext, "UNIFIdeviceIp"), Some("76.213.118.20".to_string()));
    }

    #[test]
    fn test_cef_ext_value_with_spaces_in_value() {
        let ext = "UNIFIdeviceName=The Mothership UNIFIdeviceModel=UCGMAX";
        assert_eq!(
            cef_ext_value(ext, "UNIFIdeviceName"),
            Some("The Mothership".to_string())
        );
    }

    #[test]
    fn test_cef_ext_value_last_field() {
        // msg= is last, no trailing key — value runs to end of string
        let ext = "UNIFIdeviceVersion=5.1.5 msg=Test Syslog";
        assert_eq!(cef_ext_value(ext, "msg"), Some("Test Syslog".to_string()));
    }

    #[test]
    fn test_cef_ext_value_missing_key() {
        let ext = "UNIFIdeviceModel=UCGMAX";
        assert_eq!(cef_ext_value(ext, "nonexistent"), None);
    }

    #[test]
    fn test_cef_ext_value_long_msg() {
        let ext = "UNIFIdeviceVersion=5.1.5 msg=Jacob Magar changed Syslog Settings CEF Logging setting from \"undefined\" to \"enabled\". Source IP: 76.213.118.20";
        assert_eq!(
            cef_ext_value(ext, "msg"),
            Some("Jacob Magar changed Syslog Settings CEF Logging setting from \"undefined\" to \"enabled\". Source IP: 76.213.118.20".to_string())
        );
    }
```

- [ ] **Step 2: Run to confirm it fails**

```bash
cargo test test_cef_ext_value 2>&1
```

Expected: `error[E0425]: cannot find function `cef_ext_value``

- [ ] **Step 3: Implement `cef_ext_value`**

Add this function to `src/syslog.rs` just before `parse_syslog`:

```rust
/// Extract a single value from a CEF extension string (`key1=val1 key2=val2 …`).
///
/// Values may contain spaces; the next `WORD=` boundary (a space followed by a word
/// containing no spaces and then `=`) terminates the current value.
fn cef_ext_value(extensions: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=");
    let start = extensions.find(needle.as_str())? + needle.len();
    let rest = &extensions[start..];

    let mut end = rest.len();
    let bytes = rest.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b' ' {
            let after = &rest[i + 1..];
            if let Some(eq) = after.find('=') {
                // It's a key boundary only if there are no spaces before the '='
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
```

- [ ] **Step 4: Run to confirm it passes**

```bash
cargo test test_cef_ext_value 2>&1
```

Expected: all `test_cef_ext_value_*` tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/syslog.rs
git commit -m "feat: add cef_ext_value helper for CEF extension parsing"
```

---

## Task 3: Add `extract_cef_fields` with tests

**Files:**
- Modify: `src/syslog.rs`

CEF format: `CEF:0|Vendor|Product|Version|EventClassId|EventName|Severity|extensions`

This function receives the full reconstructed message text (app_name fragment + message body), finds the `CEF:` block, splits on `|`, and returns `(hostname, app_name, message)` suitable for direct use in `ParsedLog`.

- [ ] **Step 1: Add the failing tests**

Inside the `#[cfg(test)]` module, add:

```rust
    #[test]
    fn test_extract_cef_fields_test_syslog() {
        let text = "The Mothership CEF:0|Ubiquiti|UniFi OS|5.1.5|1|Test Syslog|1|UNIFIhost=Host UNIFIdeviceName=The Mothership UNIFIdeviceModel=UCGMAX UNIFIdeviceIp=76.213.118.20 UNIFIdeviceMac=9C:05:D6:CA:81:3B UNIFIdeviceVersion=5.1.5 msg=Test Syslog";
        let (hostname, app_name, message) = extract_cef_fields(text);
        assert_eq!(hostname, Some("The Mothership".to_string()));
        assert_eq!(app_name, Some("Test Syslog".to_string()));
        assert_eq!(message, Some("Test Syslog".to_string()));
    }

    #[test]
    fn test_extract_cef_fields_config_change() {
        let text = "The Mothership CEF:0|Ubiquiti|UniFi OS|5.1.5|1005|Admin Made Config Changes|2|UNIFIhost=Host UNIFIdeviceName=The Mothership UNIFIdeviceModel=UCGMAX UNIFIdeviceIp=76.213.118.20 UNIFIdeviceMac=9C:05:D6:CA:81:3B UNIFIdeviceVersion=5.1.5 msg=Jacob Magar changed Syslog Settings CEF Logging setting from \"undefined\" to \"enabled\". Source IP: 76.213.118.20";
        let (hostname, app_name, message) = extract_cef_fields(text);
        assert_eq!(hostname, Some("The Mothership".to_string()));
        assert_eq!(app_name, Some("Admin Made Config Changes".to_string()));
        assert!(message.unwrap().starts_with("Jacob Magar changed Syslog Settings"));
    }

    #[test]
    fn test_extract_cef_fields_no_cef() {
        let (hostname, app_name, message) = extract_cef_fields("normal syslog message");
        assert_eq!(hostname, None);
        assert_eq!(app_name, None);
        assert_eq!(message, None);
    }

    #[test]
    fn test_extract_cef_fields_fallback_hostname() {
        // When UNIFIdeviceName is absent, fall back to CEF Device Product (field 2)
        let text = "CEF:0|Ubiquiti|UniFi OS|5.1.5|1|Test|1|msg=hello";
        let (hostname, app_name, _) = extract_cef_fields(text);
        assert_eq!(hostname, Some("UniFi OS".to_string()));
        assert_eq!(app_name, Some("Test".to_string()));
    }
```

- [ ] **Step 2: Run to confirm it fails**

```bash
cargo test test_extract_cef_fields 2>&1
```

Expected: `error[E0425]: cannot find function `extract_cef_fields``

- [ ] **Step 3: Implement `extract_cef_fields`**

Add this function to `src/syslog.rs` just before `parse_syslog`:

```rust
/// Extract hostname, app_name, and message from a reconstructed CEF syslog body.
///
/// `text` is `app_name_fragment + " " + message_body` as produced by syslog_loose
/// when parsing a UniFi CEF message. The function finds the embedded `CEF:` block,
/// parses the pipe-delimited header, and extracts extension fields.
///
/// Returns `(hostname, app_name, message)`:
/// - hostname  : `UNIFIdeviceName` extension value; falls back to CEF Device Product (field 2)
/// - app_name  : CEF event name (field 5, e.g. "Test Syslog", "Admin Made Config Changes")
/// - message   : `msg` extension value; falls back to the full CEF string
fn extract_cef_fields(text: &str) -> (Option<String>, Option<String>, Option<String>) {
    let cef_pos = match text.find("CEF:") {
        Some(p) => p,
        None => return (None, None, None),
    };

    let cef_str = &text[cef_pos..];
    // CEF header has exactly 8 pipe-delimited fields; splitn keeps the rest in field 7
    let parts: Vec<&str> = cef_str.splitn(8, '|').collect();
    if parts.len() < 8 {
        return (None, None, None);
    }

    let event_name = parts[5].to_string();
    let extensions = parts[7];

    let hostname = cef_ext_value(extensions, "UNIFIdeviceName")
        .or_else(|| Some(parts[2].to_string())); // fallback: CEF Device Product

    let message = cef_ext_value(extensions, "msg")
        .unwrap_or_else(|| cef_str.to_string());

    (hostname, Some(event_name), Some(message))
}
```

- [ ] **Step 4: Run to confirm it passes**

```bash
cargo test test_extract_cef_fields 2>&1
```

Expected: all `test_extract_cef_fields_*` tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/syslog.rs
git commit -m "feat: add extract_cef_fields for UniFi CEF syslog parsing"
```

---

## Task 4: Wire CEF detection into `parse_syslog` with integration test

**Files:**
- Modify: `src/syslog.rs`

- [ ] **Step 1: Add the failing integration test**

Inside the `#[cfg(test)]` module, add:

```rust
    #[test]
    fn test_parse_syslog_unifi_cef_hostname() {
        // Real-world UniFi OS RFC 5424 message: timestamp in hostname field, device name split
        // across app_name ("The") and message body ("Mothership CEF:0|...")
        let raw = "<14>1 2026-03-29T02:52:21+00:00 2026-03-29T02:52:21.587Z The - - - Mothership CEF:0|Ubiquiti|UniFi OS|5.1.5|1|Test Syslog|1|UNIFIhost=Host UNIFIdeviceName=The Mothership UNIFIdeviceModel=UCGMAX UNIFIdeviceIp=76.213.118.20 UNIFIdeviceMac=9C:05:D6:CA:81:3B UNIFIdeviceVersion=5.1.5 msg=Test Syslog";
        let parsed = parse_syslog(raw);
        assert_eq!(parsed.hostname, "The Mothership");
        assert_eq!(parsed.app_name.as_deref(), Some("Test Syslog"));
        assert_eq!(parsed.message, "Test Syslog");
    }

    #[test]
    fn test_parse_syslog_normal_unaffected() {
        // Standard RFC 3164 message must still parse correctly
        let raw = "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8";
        let parsed = parse_syslog(raw);
        assert_eq!(parsed.hostname, "mymachine");
        assert_eq!(parsed.app_name.as_deref(), Some("su"));
        assert!(parsed.message.contains("su root"));
    }
```

- [ ] **Step 2: Run to confirm it fails**

```bash
cargo test test_parse_syslog 2>&1
```

Expected: `test tests::test_parse_syslog_unifi_cef_hostname ... FAILED` (hostname is still a timestamp).

- [ ] **Step 3: Update `parse_syslog` to use CEF extraction**

Replace the existing `parse_syslog` function in `src/syslog.rs` with:

```rust
/// Parse a raw syslog message (RFC 3164 / RFC 5424 / loose).
///
/// Handles UniFi CEF messages where the hostname field contains a timestamp
/// and the real device name is embedded in the CEF extension `UNIFIdeviceName`.
fn parse_syslog(raw: &str) -> ParsedLog {
    let msg = syslog_loose::parse_message(raw, syslog_loose::Variant::Either);

    let severity_num = msg.severity.map(|s| s as u8).unwrap_or(6); // default info
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

    // Reconstruct the full message text (syslog_loose splits "The Mothership CEF:…" across
    // app_name and message when parsing UniFi RFC 5424 messages)
    let full_text = match &raw_app_name {
        Some(app) => format!("{app} {raw_message}"),
        None => raw_message.clone(),
    };

    let (hostname, app_name, message) =
        if looks_like_timestamp(&raw_hostname) && full_text.contains("CEF:") {
            let (h, a, m) = extract_cef_fields(&full_text);
            (
                h.unwrap_or_else(|| raw_hostname.clone()),
                a.or(raw_app_name),
                m.unwrap_or(raw_message),
            )
        } else {
            let hostname = if raw_hostname.is_empty() {
                "unknown".to_string()
            } else {
                raw_hostname
            };
            (hostname, raw_app_name, raw_message)
        };

    ParsedLog {
        timestamp,
        hostname,
        facility,
        severity,
        app_name,
        process_id,
        message,
        raw: raw.to_string(),
    }
}
```

- [ ] **Step 4: Run all tests**

```bash
cargo test 2>&1
```

Expected: all tests pass, including:
- `test tests::test_parse_syslog_unifi_cef_hostname ... ok`
- `test tests::test_parse_syslog_normal_unaffected ... ok`
- all previous CEF helper tests still pass

- [ ] **Step 5: Clippy + fmt**

```bash
cargo clippy 2>&1
cargo fmt 2>&1
cargo test 2>&1
```

Expected: no clippy warnings, no fmt diffs, all tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/syslog.rs
git commit -m "fix: parse UniFi CEF hostname from UNIFIdeviceName extension field"
```

---

## Task 5: Verify live fix

- [ ] **Step 1: Rebuild and redeploy**

```bash
cd /home/jmagar/workspace/syslog-mcp
docker compose build && docker compose up -d
```

- [ ] **Step 2: Send a test event from UniFi**

Trigger a test syslog event from the UniFi controller (System → Remote Logging → Send Test).

- [ ] **Step 3: Confirm hostname is now correct**

```bash
curl -s -X POST http://localhost:3100/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_hosts","arguments":{}}}' \
  | jq '.result.content[0].text' | jq 'fromjson | .hosts[] | select(.hostname | contains("Mothership"))'
```

Expected: an entry with `"hostname": "The Mothership"` and a recent `last_seen`.

- [ ] **Step 4: Final commit + push**

```bash
git push
```
