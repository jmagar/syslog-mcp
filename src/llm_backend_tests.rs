use super::*;
use serial_test::serial;

pub(super) struct EnvGuard(&'static str, Option<std::ffi::OsString>);

impl EnvGuard {
    pub(super) fn set(key: &'static str, value: Option<&str>) -> Self {
        let guard = Self(key, crate::env::var_os(key));
        match value {
            Some(value) => crate::env::set_test_var(key, value),
            None => crate::env::remove_test_var(key),
        }
        guard
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match self.1.take() {
            Some(value) => crate::env::set_test_var(self.0, value),
            None => crate::env::remove_test_var(self.0),
        }
    }
}

#[test]
#[serial]
fn one_env_selects_provider_and_model_and_ignores_legacy_model_variables() {
    let _codex = EnvGuard::set("CORTEX_CODEX_MODEL", Some("old-codex-model"));
    let _gemini = EnvGuard::set("CORTEX_HEADLESS_GEMINI_MODEL", Some("old-gemini-model"));
    for (selector, provider, model) in [
        (None, "codex-app-server", "server-default"),
        (Some("codex"), "codex-app-server", "server-default"),
        (
            Some("gemini"),
            "gemini-cli",
            crate::assessment::DEFAULT_GEMINI_MODEL,
        ),
        (
            Some("codex/pinned-model"),
            "codex-app-server",
            "pinned-model",
        ),
        (Some("gemini/pinned-model"), "gemini-cli", "pinned-model"),
    ] {
        let _selector = EnvGuard::set("CORTEX_LLM", selector);
        let backend = LlmBackend::from_env(None, 77).unwrap();
        assert_eq!(backend.provider(), provider);
        assert_eq!(backend.model(), model);
        if let LlmBackend::Gemini(config) = backend {
            assert_eq!(config.timeout_secs, 77);
        }
    }
}

#[test]
fn global_model_wins_over_per_invocation_model() {
    let backend = LlmBackend::resolve("codex/global", Some("local".into()), 42).unwrap();
    assert_eq!(backend.model(), "global");
    let backend = LlmBackend::resolve("gemini", Some("local".into()), 42).unwrap();
    assert_eq!(backend.model(), "local");
}

#[test]
fn invalid_selection_never_falls_back_or_echoes_arbitrary_config() {
    for selector in ["", " ", "unknown/secret", "codex/", "gemini/   "] {
        let Err(error) = LlmBackend::resolve(selector, None, 42) else {
            panic!("invalid selector was accepted");
        };
        assert!(error.to_string().contains("CORTEX_LLM"));
        assert!(!error.to_string().contains("secret"));
    }
}

#[test]
#[serial]
fn captured_configuration_survives_overlay_and_process_changes() {
    use crate::config::{Config, PluginEnvGuard};
    let _selector = EnvGuard::set("CORTEX_LLM", Some("codex/process-model"));
    let config = {
        let _overlay = PluginEnvGuard::install(
            [
                ("CORTEX_LLM".into(), "gemini/managed-model".into()),
                (
                    "CORTEX_HEADLESS_GEMINI_CMD".into(),
                    "/managed/gemini".into(),
                ),
                ("CORTEX_HEADLESS_GEMINI_HOME".into(), "/managed/home".into()),
            ]
            .into(),
        );
        Config::load_for_inspection().unwrap()
    };
    let backend = LlmBackend::from_config(Some("request-model".into()), &config.llm).unwrap();
    assert_eq!(backend.provider(), "gemini-cli");
    assert_eq!(backend.model(), "managed-model");
    assert_eq!(backend.program(), "/managed/gemini");
    let LlmBackend::Gemini(gemini) = backend else {
        unreachable!()
    };
    assert_eq!(
        gemini.source_home.unwrap(),
        std::path::Path::new("/managed/home")
    );
    assert!(
        serde_json::to_value(&config.llm)
            .unwrap()
            .get("environment")
            .is_none()
    );
}

#[test]
#[serial]
fn invalid_captured_selection_is_deferred_until_llm_use() {
    use crate::config::{Config, PluginEnvGuard};
    let _overlay = PluginEnvGuard::install([("CORTEX_LLM".into(), "invalid".into())].into());
    let config = Config::load_for_inspection().unwrap();
    assert!(LlmBackend::from_config(None, &config.llm).is_err());
}

#[cfg(unix)]
#[test]
#[serial]
fn non_unicode_process_selection_is_not_replaced_by_a_default() {
    use std::os::unix::ffi::OsStringExt;
    let _guard = EnvGuard::set("CORTEX_LLM", None);
    crate::env::set_test_var("CORTEX_LLM", std::ffi::OsString::from_vec(vec![0xff]));
    let config = crate::config::Config::load_for_inspection().unwrap();
    let Err(error) = LlmBackend::from_config(None, &config.llm) else {
        panic!("invalid UTF-8 accepted")
    };
    assert!(error.to_string().contains("UTF-8"));
}
