//! Shared provider/model selection for every Cortex LLM operation.
use anyhow::{Result, bail};

use crate::assessment::{GeminiAssessConfig, run_gemini_assessment};
use crate::codex_assessment::CodexAssessConfig;

#[derive(Clone)]
pub(crate) enum LlmBackend {
    Codex(CodexAssessConfig),
    Gemini(GeminiAssessConfig),
}

impl LlmBackend {
    /// One selector for all operations. An explicit model in CORTEX_LLM
    /// takes precedence over the legacy per-invocation --model flag.
    pub(crate) fn from_config(
        model: Option<String>,
        config: &crate::config::LlmConfig,
    ) -> Result<Self> {
        let environment = config
            .environment
            .clone()
            .unwrap_or_else(crate::config::LlmEnvironment::capture);
        let selector = environment
            .values
            .get("CORTEX_LLM")
            .map(|value| {
                value
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("CORTEX_LLM must be valid UTF-8"))
            })
            .transpose()?
            .unwrap_or("codex");
        Self::resolve_environment(selector, model, config.timeout_secs, &environment)
    }

    #[cfg(test)]
    pub(crate) fn from_env(model: Option<String>, timeout_secs: u64) -> Result<Self> {
        Self::from_config(
            model,
            &crate::config::LlmConfig {
                timeout_secs,
                ..Default::default()
            },
        )
    }

    #[cfg(test)]
    fn resolve(selector: &str, model: Option<String>, timeout_secs: u64) -> Result<Self> {
        Self::resolve_environment(
            selector,
            model,
            timeout_secs,
            &crate::config::LlmEnvironment::capture(),
        )
    }

    fn resolve_environment(
        selector: &str,
        model: Option<String>,
        timeout_secs: u64,
        environment: &crate::config::LlmEnvironment,
    ) -> Result<Self> {
        let text = |key: &str| -> Result<Option<String>> {
            environment
                .values
                .get(key)
                .map(|value| {
                    value
                        .to_str()
                        .map(str::to_owned)
                        .ok_or_else(|| anyhow::anyhow!("{key} must be valid UTF-8"))
                })
                .transpose()
        };
        let path = |key: &str| environment.values.get(key).map(std::path::PathBuf::from);
        let (provider, selected_model) = match selector.trim().split_once('/') {
            Some((provider, model)) if !model.trim().is_empty() => {
                (provider, Some(model.trim().to_owned()))
            }
            Some(_) => {
                bail!("CORTEX_LLM model cannot be empty; use codex[/MODEL] or gemini[/MODEL]")
            }
            None => (selector.trim(), None),
        };
        let model = selected_model.or(model.filter(|value| !value.trim().is_empty()));
        match provider {
            "codex" | "codex-app-server" => Ok(Self::Codex(CodexAssessConfig {
                program: text("CORTEX_CODEX_CMD")?.unwrap_or_else(|| "codex".into()),
                model,
                source_home: path("CORTEX_CODEX_HOME")
                    .or_else(|| path("CODEX_HOME"))
                    .unwrap_or_else(|| path("HOME").unwrap_or_default().join(".codex")),
            })),
            "gemini" | "gemini-cli" => Ok(Self::Gemini(GeminiAssessConfig {
                program: text("CORTEX_HEADLESS_GEMINI_CMD")?
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or_else(|| "gemini".into()),
                model: model.unwrap_or_else(|| crate::assessment::DEFAULT_GEMINI_MODEL.into()),
                source_home: path("CORTEX_HEADLESS_GEMINI_HOME")
                    .filter(|value| !value.as_os_str().is_empty())
                    .or_else(|| path("HOME")),
                timeout_secs: timeout_secs.max(1),
            })),
            _ => bail!("invalid CORTEX_LLM; use codex[/MODEL] or gemini[/MODEL]"),
        }
    }

    pub(crate) fn provider(&self) -> &'static str {
        match self {
            Self::Codex(_) => "codex-app-server",
            Self::Gemini(_) => "gemini-cli",
        }
    }

    pub(crate) fn model(&self) -> String {
        match self {
            Self::Codex(config) => config
                .model
                .clone()
                .unwrap_or_else(|| "server-default".into()),
            Self::Gemini(config) => config.model.clone(),
        }
    }

    pub(crate) fn program(&self) -> String {
        match self {
            Self::Codex(config) => config.program.clone(),
            Self::Gemini(config) => config.program.clone(),
        }
    }

    pub(crate) async fn run<F>(
        &self,
        prompt: &str,
        max_output_bytes: usize,
        on_delta: F,
    ) -> Result<String>
    where
        F: FnMut(&str) -> Result<()> + Send,
    {
        match self {
            Self::Codex(config) => {
                crate::codex_assessment::run(prompt, config, max_output_bytes, on_delta).await
            }
            Self::Gemini(config) => {
                run_gemini_assessment(prompt, config, max_output_bytes, on_delta).await
            }
        }
    }
}

#[cfg(test)]
#[path = "llm_backend_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "llm_routing_tests.rs"]
mod routing_tests;
