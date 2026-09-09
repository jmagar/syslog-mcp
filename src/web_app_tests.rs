use axum::body::to_bytes;
use axum::http::{Request, StatusCode, header};
use tower::util::ServiceExt;

use super::*;

async fn get(path: &str) -> axum::response::Response {
    router()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(path)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn app_route_serves_workspace_shell_with_no_store_and_csp() {
    let response = get("/app/investigate").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert!(
        response
            .headers()
            .get(header::CONTENT_SECURITY_POLICY)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("script-src 'self'")
    );
    let csp = response
        .headers()
        .get(header::CONTENT_SECURITY_POLICY)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(csp.contains("style-src 'self' 'unsafe-inline'"));
    assert!(!csp.contains("script-src 'self' 'unsafe-inline'"));
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let html = String::from_utf8(body.to_vec()).unwrap();
    assert!(html.contains("Cortex investigation workspace"));
    assert!(html.contains("/app/assets/cytoscape-3.34.0.min.js"));
    assert!(!html.contains("CORTEX_API_TOKEN="));
    assert!(html.contains("data-clear-token"));
}

#[tokio::test]
async fn app_spa_fallback_is_scoped_under_app_only() {
    let response = get("/app/some/deep/link").await;
    assert_eq!(response.status(), StatusCode::OK);

    for path in ["/api/stats", "/mcp", "/health", "/v1/logs"] {
        let response = get(path).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
    }
}

#[tokio::test]
async fn app_assets_have_expected_cache_policy() {
    let response = get("/app/assets/app.js").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );

    let response = get("/app/assets/cytoscape-3.34.0.min.js").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "public, max-age=31536000, immutable"
    );
}

#[tokio::test]
async fn app_script_uses_text_nodes_for_dynamic_content() {
    assert!(!APP_JS.contains("innerHTML"));
    assert!(APP_JS.contains("textContent"));
    assert!(APP_JS.contains("document.createElement"));
    assert!(APP_JS.contains("/api/v1/investigations/ask"));
    assert!(!APP_JS.contains("/api/ai/ask-history"));
}

#[tokio::test]
async fn app_rendering_contract_covers_xss_fixtures() {
    let fixtures = [
        ("service name", r#"<script>alert("service")</script>"#),
        ("graph label", r#"<img src=x onerror=alert("graph")>"#),
        ("tooltip", r#"" onmouseover="alert('tip')" data-x=""#),
        ("log excerpt", r#"<svg><script>alert("log")</script></svg>"#),
        ("html entities", "&lt;script&gt;alert(1)&lt;/script&gt;"),
        ("svg payload", r#"<svg/onload=alert("svg")>"#),
        ("ansi escapes", "\u{1b}[31mred\u{1b}[0m <b>bold</b>"),
        (
            "bearer-looking string",
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
        ),
        (
            "cookie text",
            "Cookie: session=abc123; CORTEX_API_TOKEN=secret",
        ),
        (
            "url userinfo",
            "https://admin:password@example.test/path?q=<script>",
        ),
    ];

    // Browser textContent preserves payloads as literal text. Cortex's app
    // intentionally relies on that DOM contract instead of ad hoc escaping.
    for (label, payload) in fixtures {
        assert_eq!(payload.to_string(), payload, "{label}");
    }

    for forbidden_sink in [
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "Range().createContextualFragment",
        "setHTML",
    ] {
        assert!(
            !APP_JS.contains(forbidden_sink),
            "dynamic rendering must not use {forbidden_sink}"
        );
    }

    for expected_safe_sink in [
        "el.textContent = value == null ? \"\" : String(value);",
        "ui.selectedTitle.textContent = data.label || data.id;",
        "ui.serverVersion.textContent = version.version || \"Unknown\";",
        "ui.schemaVersion.textContent = `Schema ${version.schema_version ?? \"--\"}`;",
        "ui.hostCount.textContent = String(latestHosts.length);",
        "ui.logCount.textContent = String(stats.total_logs ?? stats.total ?? \"--\");",
    ] {
        assert!(
            APP_JS.contains(expected_safe_sink),
            "missing safe text sink: {expected_safe_sink}"
        );
    }

    // Cytoscape renders labels onto its own canvas/SVG renderer from data fields;
    // the app does not configure HTML labels, HTML tooltips, or a plugin that
    // would turn graph data into DOM markup.
    assert!(APP_JS.contains("\"label\": \"data(label)\""));
    assert!(!APP_JS.contains("cytoscape-node-html-label"));
    assert!(!APP_JS.contains("tippy("));
    assert!(!APP_JS.contains("qtip"));
}

#[tokio::test]
async fn graph_dependency_is_pinned_and_documented() {
    assert!(CYTOSCAPE_JS.contains("cytoscape"));
    assert!(include_str!("../web/vendor/THIRD_PARTY.md").contains("Version: `3.34.0`"));
    assert!(
        include_str!("../web/vendor/cytoscape-3.34.0.package.json")
            .contains("\"name\": \"cytoscape\"")
    );
    assert!(
        include_str!("../web/vendor/cytoscape-3.34.0.package.json")
            .contains("\"license\": \"MIT\"")
    );
    assert!(
        include_str!("../web/vendor/cytoscape-3.34.0.LICENSE")
            .contains("Permission is hereby granted")
    );
}
