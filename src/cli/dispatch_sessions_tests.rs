#[test]
fn ai_search_args_into_request_keeps_filters() {
    let req = crate::cli::SessionsSearchArgs {
        query: "error".to_string(),
        project: Some("/repo".to_string()),
        tool: Some("codex".to_string()),
        since: Some("2026-01-01T00:00:00Z".to_string()),
        until: None,
        limit: Some(25),
        json: true,
    }
    .into_request();

    assert_eq!(req.query, "error");
    assert_eq!(req.project.as_deref(), Some("/repo"));
    assert_eq!(req.tool.as_deref(), Some("codex"));
    assert_eq!(req.since.as_deref(), Some("2026-01-01T00:00:00Z"));
    assert_eq!(req.until, None);
    assert_eq!(req.limit, Some(25));
}

mod assess {
    use crate::cli::http_client::HttpClient;
    use crate::cli::{AssessAbuseArgs, AssessSkillArgs, CliMode, dispatch};
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::any};

    async fn http_mode() -> (MockServer, CliMode) {
        let server = MockServer::start().await;
        let client = HttpClient::discover(Some(server.uri()), Some("test-token".into()))
            .expect("discover ok");
        Mock::given(any())
            .respond_with(ResponseTemplate::new(404))
            .with_priority(255)
            .expect(0)
            .mount(&server)
            .await;
        (server, CliMode::Http(client))
    }

    #[tokio::test]
    async fn run_assess_skill_rejects_http_mode_when_llm_requested() {
        // Mirrors run_ai_assess's local-only guard exactly (dispatch_sessions.rs).
        // `cortex assess skill` must refuse to run the LLM step over HTTP —
        // deterministic-findings-only is fine over HTTP, LLM assessment is not.
        let (_server, http_mode) = http_mode().await;
        let args = AssessSkillArgs {
            skill: Some("frustration-assessment".to_string()),
            no_llm: false,
            ..Default::default()
        };
        let err = dispatch::run_assess_skill(&http_mode, args)
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("runs the LLM selected by CORTEX_LLM on the local host"));
    }

    #[tokio::test]
    async fn run_assess_skill_allows_http_mode_with_no_llm() {
        let (_server, http_mode) = http_mode().await;
        let args = AssessSkillArgs {
            skill: Some("frustration-assessment".to_string()),
            no_llm: true,
            ..Default::default()
        };
        // Deterministic-only path is not local-only; it must NOT fail with the
        // provider local-only message (it is expected to bail with
        // "not yet implemented" today, since no HTTP route/client method
        // exists for assess skill in this phase).
        let err = dispatch::run_assess_skill(&http_mode, args)
            .await
            .unwrap_err();
        assert!(
            !format!("{err}").contains("runs the LLM selected by CORTEX_LLM on the local host")
        );
    }

    #[tokio::test]
    async fn run_assess_abuse_rejects_http_mode_when_llm_requested() {
        let (_server, http_mode) = http_mode().await;
        let args = AssessAbuseArgs {
            no_llm: false,
            ..Default::default()
        };
        let err = dispatch::run_assess_abuse(&http_mode, args)
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("runs the LLM selected by CORTEX_LLM on the local host"));
    }
}
