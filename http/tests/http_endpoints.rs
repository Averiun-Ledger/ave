// Ave HTTP - Endpoint integration tests (auth-only surface)
//
// These tests exercise the Axum routes for login and protected auth endpoints
// using the real handlers and middleware, backed by an in-memory temp DB.

use std::sync::Arc;

use axum::{
    body::{self, Body},
    http::{Request, StatusCode},
    routing::{get, post},
    Extension, Router,
};
use axum::middleware;
use ave_bridge::auth::{AuthConfig, RateLimitConfig};
use ave_http::auth::{
    admin_handlers, login_handler,
    middleware::ApiKeyAuthNew,
    system_handlers,
};
use ave_http::auth::database::AuthDatabase;
use ave_http::auth::models::LoginResponse;
use serde_json::json;
use tower::ServiceExt; // for `oneshot`

#[allow(deprecated)] // tempdir::into_path is stable and fine for test fixtures
fn build_auth_db() -> Arc<AuthDatabase> {
    let mut config = AuthConfig::default();
    config.enable = true;
    config.superadmin = "admin".to_string();
    config.database_path = tempfile::tempdir()
        .expect("temp dir").keep();
        
    // Keep rate limiting enabled but generous for these tests
    config.rate_limit = RateLimitConfig {
        max_requests: 1_000,
        ..RateLimitConfig::default()
    };

    Arc::new(AuthDatabase::new(config, "AdminPass123!").unwrap())
}

fn build_app(db: Arc<AuthDatabase>) -> Router {
    let protected = Router::new()
        .route("/admin/users", get(admin_handlers::list_users))
        .route("/me", get(system_handlers::get_me))
        .route_layer(middleware::from_extractor::<ApiKeyAuthNew>());

    Router::new()
        .route("/login", post(login_handler::login))
        .merge(protected)
        .layer(Extension(db))
}

async fn login_and_get_key(app: &Router) -> String {
    let req = Request::builder()
        .method("POST")
        .uri("/login")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"username": "admin", "password": "AdminPass123!"}).to_string(),
        ))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes =
        body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let login: LoginResponse = serde_json::from_slice(&bytes).unwrap();
    login.api_key
}

#[tokio::test]
async fn login_success_returns_api_key() {
    let db = build_auth_db();
    let app = build_app(db);

    let req = Request::builder()
        .method("POST")
        .uri("/login")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"username": "admin", "password": "AdminPass123!"}).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes =
        body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let login: LoginResponse = serde_json::from_slice(&bytes).unwrap();
    assert!(!login.api_key.is_empty());
    assert_eq!(login.user.username, "admin");
}

#[tokio::test]
async fn login_with_bad_password_fails() {
    let db = build_auth_db();
    let app = build_app(db);

    let req = Request::builder()
        .method("POST")
        .uri("/login")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"username": "admin", "password": "wrong"}).to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn protected_endpoint_requires_auth() {
    let db = build_auth_db();
    let app = build_app(db);

    let req = Request::builder()
        .method("GET")
        .uri("/me")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn get_me_returns_user_info() {
    let db = build_auth_db();
    let app = build_app(db);
    let key = login_and_get_key(&app).await;

    let req = Request::builder()
        .method("GET")
        .uri("/me")
        .header("X-API-Key", key)
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["username"], "admin");
}

#[tokio::test]
async fn admin_list_users_returns_superadmin() {
    let db = build_auth_db();
    let app = build_app(db);
    let key = login_and_get_key(&app).await;

    let req = Request::builder()
        .method("GET")
        .uri("/admin/users")
        .header("X-API-Key", key)
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let users: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(users.as_array().is_some());
    let names: Vec<String> = users
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|u| u.get("username").and_then(|n| n.as_str()).map(|s| s.to_string()))
        .collect();
    assert!(names.contains(&"admin".to_string()));
}
