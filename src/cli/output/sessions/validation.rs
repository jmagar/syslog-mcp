//! Exit-status policy for bounded AI transcript operations.

use anyhow::{Result, bail};
use cortex::scanner::{AiDoctorReport, IndexResult};

pub(crate) fn ensure_index_success(response: &IndexResult) -> Result<()> {
    if response.file_errors.is_empty()
        && response.storage_blocked_chunks == 0
        && response.parse_errors == 0
    {
        if response.dropped_metadata_fields > 0 {
            eprintln!(
                "warning: {} transcript metadata field(s) were dropped",
                response.dropped_metadata_fields
            );
        }
        Ok(())
    } else if response.storage_blocked_chunks > 0 {
        bail!(
            "{} transcript chunk(s) blocked by storage guardrails",
            response.storage_blocked_chunks
        )
    } else if response.parse_errors > 0 {
        bail!(
            "{} transcript record(s) failed to parse",
            response.parse_errors
        )
    } else {
        bail!(
            "{} transcript file(s) failed to index",
            response.file_errors.len()
        )
    }
}

pub(crate) fn ensure_ai_doctor_success(
    response: &AiDoctorReport,
    strict_permissions: bool,
) -> Result<()> {
    if strict_permissions
        && ((response.claude_root.exists && !response.claude_root.strict_ok)
            || (response.codex_root.exists && !response.codex_root.strict_ok)
            || (response.gemini_root.exists && !response.gemini_root.strict_ok))
    {
        bail!("AI transcript root permission check failed");
    }
    Ok(())
}
