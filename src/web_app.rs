use crate::surfaces::get;
use axum::{
    Router,
    body::Body,
    http::{
        HeaderValue, StatusCode,
        header::{CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE},
    },
    response::{IntoResponse, Response},
};

const INDEX_HTML: &str = include_str!("../web/app/index.html");
const APP_CSS: &str = include_str!("../web/app/app.css");
const APP_JS: &str = include_str!("../web/app/app.js");
const CYTOSCAPE_JS: &str = include_str!("../web/vendor/cytoscape-3.34.0.min.js");

// Cytoscape positions its canvas layers with element style properties. CSP
// treats those properties as inline styles, so the workspace must permit
// style attributes even though all stylesheet and script resources remain
// same-origin. Script execution deliberately does not receive unsafe-inline.
const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; \
                  img-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; \
                  frame-ancestors 'none'";
const NO_STORE: &str = "no-store";
const IMMUTABLE: &str = "public, max-age=31536000, immutable";

pub fn router() -> Router {
    use crate::surfaces::ContractRouterExt as _;
    Router::new()
        .contract_route("GET /app", get(index))
        .contract_route("GET /app/", get(index))
        .contract_route("GET /app/investigate", get(index))
        .contract_route("GET /app/assets/{*path}", get(asset))
        .contract_route("GET /app/{*path}", get(index))
}

async fn index() -> Response {
    text_response(
        StatusCode::OK,
        "text/html; charset=utf-8",
        NO_STORE,
        Some(CSP),
        INDEX_HTML,
    )
}

async fn asset(axum::extract::Path(path): axum::extract::Path<String>) -> Response {
    match path.as_str() {
        "app.css" => text_response(
            StatusCode::OK,
            "text/css; charset=utf-8",
            NO_STORE,
            Some(CSP),
            APP_CSS,
        ),
        "app.js" => text_response(
            StatusCode::OK,
            "application/javascript; charset=utf-8",
            NO_STORE,
            Some(CSP),
            APP_JS,
        ),
        "cytoscape-3.34.0.min.js" => text_response(
            StatusCode::OK,
            "application/javascript; charset=utf-8",
            IMMUTABLE,
            Some(CSP),
            CYTOSCAPE_JS,
        ),
        _ => text_response(
            StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            NO_STORE,
            Some(CSP),
            "not found",
        ),
    }
}

fn text_response(
    status: StatusCode,
    content_type: &'static str,
    cache_control: &'static str,
    csp: Option<&'static str>,
    body: &'static str,
) -> Response {
    let mut response = (status, Body::from(body)).into_response();
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static(cache_control));
    if let Some(csp) = csp {
        headers.insert(CONTENT_SECURITY_POLICY, HeaderValue::from_static(csp));
    }
    response
}

#[cfg(test)]
#[path = "web_app_tests.rs"]
mod tests;
