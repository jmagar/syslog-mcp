use cortex::{mcp::router, testing};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use lab_auth::{
    jwt::AccessClaims,
    metadata::canonical_resource_url,
    types::{AuthorizationCodeRow, RegisteredClient},
};
use sha2::{Digest, Sha256};
use std::{env, fs, net::SocketAddr, path::PathBuf, time::{SystemTime, UNIX_EPOCH}};

fn claims(auth: &lab_auth::state::AuthState, scope: &str, offset: i64) -> AccessClaims {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    AccessClaims {
        iss: auth.config.public_url.as_ref().unwrap().as_str().trim_end_matches('/').into(),
        sub: "live-user@example.invalid".into(),
        aud: canonical_resource_url(auth),
        exp: (now + offset) as usize,
        iat: now as usize,
        jti: format!("cortex-live-{now}-{scope}"),
        scope: scope.into(),
        azp: String::new(),
    }
}

fn replace_header(token: &str, header: serde_json::Value, keep_signature: bool) -> String {
    let mut parts = token.split('.');
    let _old_header = parts.next().unwrap();
    let payload = parts.next().unwrap();
    let signature = parts.next().unwrap();
    let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    if keep_signature { format!("{header}.{payload}.{signature}") } else { format!("{header}.{payload}.") }
}

#[tokio::main]
async fn main() {
    let port: u16 = env::args().nth(1).unwrap().parse().unwrap();
    let data = PathBuf::from(env::args().nth(2).unwrap());
    let token_path = PathBuf::from(env::args().nth(3).unwrap());
    fs::create_dir_all(&data).unwrap();
    let (state, auth) = testing::oauth_state_with_auth_state(&data).await;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let client_id = format!("cortex-live-client-{now}");
    let authorization_code = format!("cortex-live-code-{now}");
    let code_verifier = format!("cortex-live-verifier-{now}");
    let redirect_uri = "http://127.0.0.1:7777/callback".to_string();
    let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
    auth.store.register_client(RegisteredClient {
        client_id: client_id.clone(),
        redirect_uris: vec![redirect_uri.clone()],
        created_at: now,
    }).await.unwrap();
    auth.store.insert_auth_code(AuthorizationCodeRow {
        code: authorization_code.clone(),
        client_id: client_id.clone(),
        subject: "live-user@example.invalid".to_string(),
        redirect_uri: redirect_uri.clone(),
        scope: "cortex:read".to_string(),
        code_challenge,
        code_challenge_method: "S256".to_string(),
        provider_refresh_token: None,
        created_at: now,
        expires_at: now + 300,
    }).await.unwrap();
    let other_dir = data.join("foreign-key"); fs::create_dir_all(&other_dir).unwrap();
    let (_, foreign) = testing::oauth_state_with_auth_state(&other_dir).await;
    let mut wrong_issuer = claims(&auth, "cortex:read", 900); wrong_issuer.iss = "https://attacker.invalid".into();
    let mut wrong_audience = claims(&auth, "cortex:read", 900); wrong_audience.aud = "https://other.invalid/mcp".into();
    let read = auth.signing_keys.issue_access_token(&claims(&auth, "cortex:read", 900)).unwrap();
    let tokens = serde_json::json!({
        "read": read,
        "admin": auth.signing_keys.issue_access_token(&claims(&auth, "cortex:admin", 900)).unwrap(),
        "empty": auth.signing_keys.issue_access_token(&claims(&auth, "", 900)).unwrap(),
        "expired": auth.signing_keys.issue_access_token(&claims(&auth, "cortex:read", -120)).unwrap(),
        "wrong_issuer": auth.signing_keys.issue_access_token(&wrong_issuer).unwrap(),
        "wrong_audience": auth.signing_keys.issue_access_token(&wrong_audience).unwrap(),
        "wrong_key": foreign.signing_keys.issue_access_token(&claims(&auth, "cortex:read", 900)).unwrap(),
        "unknown_kid": replace_header(&read, serde_json::json!({"alg":"RS256","typ":"JWT","kid":"cortex-live-unknown-kid"}), true),
        "alg_none": replace_header(&read, serde_json::json!({"alg":"none","typ":"JWT"}), false),
        "lifecycle": {
            "client_id": client_id,
            "authorization_code": authorization_code,
            "code_verifier": code_verifier,
            "redirect_uri": redirect_uri,
            "scope": "cortex:read"
        }
    });
    fs::write(&token_path, serde_json::to_vec(&tokens).unwrap()).unwrap();
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127,0,0,1], port))).await.unwrap();
    println!("READY {}", listener.local_addr().unwrap());
    axum::serve(listener, router(state)).await.unwrap();
}
