use anyhow::{Result, anyhow, bail};
use serde_json::Value;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt};

pub(super) const MAX_FRAME_BYTES: usize = 2 * 1024 * 1024;

pub(super) async fn read_frame<R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<Option<String>> {
    let mut bytes = Vec::new();
    let read = reader
        .take((MAX_FRAME_BYTES + 1) as u64)
        .read_until(b'\n', &mut bytes)
        .await?;
    if read > MAX_FRAME_BYTES {
        bail!("Gemini stdout frame exceeds assessment limit");
    }
    if read == 0 {
        return Ok(None);
    }
    Ok(Some(String::from_utf8(bytes)?))
}

pub(super) struct GeminiStreamState {
    max_output_bytes: usize,
    text: String,
    result_text: Option<String>,
    saw_success: bool,
}

impl GeminiStreamState {
    pub(super) fn new(max_output_bytes: usize) -> Self {
        Self {
            max_output_bytes,
            text: String::new(),
            result_text: None,
            saw_success: false,
        }
    }

    fn check_output_size(&self, size: usize) -> Result<()> {
        if size > self.max_output_bytes {
            bail!("Gemini assessment output exceeds limit");
        }
        Ok(())
    }

    pub(super) fn handle_line<F>(&mut self, line: &str, on_delta: &mut F) -> Result<()>
    where
        F: FnMut(&str) -> Result<()> + Send,
    {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Ok(());
        }
        let value: Value = serde_json::from_str(trimmed)
            .map_err(|err| anyhow!("malformed Gemini stream JSON: {err}: {trimmed}"))?;
        match value.get("type").and_then(Value::as_str) {
            Some("tool_use") => self.handle_tool_use(&value)?,
            Some("tool_result") => {}
            Some("error") => bail!("Gemini headless stream error: {value}"),
            Some("message") if value.get("role").and_then(Value::as_str) == Some("assistant") => {
                if let Some(delta) = message_content(&value, self.max_output_bytes)? {
                    self.push_delta(&delta, on_delta)?;
                }
            }
            Some("result") => self.handle_result(&value)?,
            _ if contains_tool_event(&value) => {
                bail!("Gemini headless emitted a tool event in assessment-only mode");
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_result(&mut self, value: &Value) -> Result<()> {
        if value.get("status").and_then(Value::as_str) != Some("success") {
            bail!("Gemini headless returned unsuccessful result: {value}");
        }
        if let Some(text) = value.get("response").and_then(Value::as_str)
            && !text.trim().is_empty()
        {
            self.check_output_size(text.len())?;
            self.result_text = Some(text.to_string());
        }
        self.saw_success = true;
        Ok(())
    }

    fn handle_tool_use(&mut self, value: &Value) -> Result<()> {
        let tool_name = value
            .get("name")
            .and_then(Value::as_str)
            .or_else(|| value.get("tool_name").and_then(Value::as_str));
        match tool_name {
            Some("activate_skill") | Some("update_topic") => Ok(()),
            Some("write_file") => {
                let Some(content) = value
                    .get("parameters")
                    .and_then(|params| params.get("content"))
                    .and_then(Value::as_str)
                    .filter(|content| !content.trim().is_empty())
                else {
                    bail!(
                        "Gemini headless emitted write_file without assessment content; raw event: {value}"
                    );
                };
                self.check_output_size(content.len())?;
                self.result_text = Some(content.to_string());
                Ok(())
            }
            _ => bail!(
                "Gemini headless emitted unexpected tool call '{}' in assessment mode; raw event: {value}",
                tool_name.unwrap_or("unknown")
            ),
        }
    }

    fn push_delta<F>(&mut self, delta: &str, on_delta: &mut F) -> Result<()>
    where
        F: FnMut(&str) -> Result<()> + Send,
    {
        if delta.is_empty() {
            return Ok(());
        }
        self.check_output_size(self.text.len().saturating_add(delta.len()))?;
        self.text.push_str(delta);
        on_delta(delta)
    }

    pub(super) fn finish(self) -> Result<String> {
        if !self.saw_success {
            bail!("Gemini headless stream ended without a success result");
        }
        if let Some(result) = self.result_text
            && !result.trim().is_empty()
        {
            return Ok(result);
        }
        if !self.text.trim().is_empty() {
            return Ok(self.text);
        }
        bail!("Gemini headless returned no assessment text");
    }
}

fn message_content(value: &Value, max_bytes: usize) -> Result<Option<String>> {
    if let Some(content) = value.get("content").and_then(Value::as_str) {
        if content.len() > max_bytes {
            bail!("Gemini assessment output exceeds limit");
        }
        return Ok(Some(content.to_string()));
    }
    if let Some(parts) = value.get("content").and_then(Value::as_array) {
        let mut out = String::new();
        for part in parts {
            if let Some(text) = part
                .as_str()
                .or_else(|| part.get("text").and_then(Value::as_str))
            {
                if out.len().saturating_add(text.len()) > max_bytes {
                    bail!("Gemini assessment output exceeds limit");
                }
                out.push_str(text);
            }
        }
        return Ok((!out.is_empty()).then_some(out));
    }
    Ok(None)
}

fn contains_tool_event(value: &Value) -> bool {
    match value {
        Value::String(s) => matches!(s.as_str(), "tool_use" | "tool_result"),
        Value::Array(items) => items.iter().any(contains_tool_event),
        Value::Object(map) => map.iter().any(|(key, value)| {
            key == "tool_use"
                || key == "tool_result"
                || (key == "type"
                    && value
                        .as_str()
                        .is_some_and(|s| s == "tool_use" || s == "tool_result"))
                || contains_tool_event(value)
        }),
        _ => false,
    }
}

#[cfg(test)]
#[path = "gemini_stream_tests.rs"]
mod tests;
