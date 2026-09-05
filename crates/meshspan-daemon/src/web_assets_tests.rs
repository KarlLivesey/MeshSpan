// SPDX-License-Identifier: GPL-2.0-only

use std::error::Error;

use axum::Router;
use axum::body::to_bytes;
use axum::http::Request;
use axum::routing::get;
use tower::ServiceExt as _;

use super::*;

#[tokio::test]
async fn serves_exact_embedded_bytes_without_runtime_paths() -> Result<(), Box<dyn Error>> {
    assert!(EMBEDDED_ASSETS.len() >= 3);
    for asset in EMBEDDED_ASSETS {
        let response = request("GET", asset.route, None).await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_TYPE], asset.media_type);
        assert_eq!(
            response.headers()[header::X_CONTENT_TYPE_OPTIONS],
            "nosniff"
        );
        assert_eq!(response.headers()[header::X_FRAME_OPTIONS], "DENY");
        assert_eq!(
            response.headers()[header::CONTENT_SECURITY_POLICY],
            CONTENT_SECURITY_POLICY
        );
        let expected_cache = if asset.route == "/index.html" {
            "no-cache"
        } else {
            "public, max-age=31536000, immutable"
        };
        assert_eq!(response.headers()[header::CACHE_CONTROL], expected_cache);
        let bytes = to_bytes(response.into_body(), 16 * 1024 * 1024).await?;
        assert_eq!(bytes.as_ref(), asset.bytes);

        let head = request("HEAD", asset.route, None).await?;
        assert_eq!(head.status(), StatusCode::OK);
        assert_eq!(
            head.headers()[header::CONTENT_LENGTH],
            asset.bytes.len().to_string()
        );
        assert!(to_bytes(head.into_body(), 1).await?.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn navigation_and_api_routes_remain_distinct() -> Result<(), Box<dyn Error>> {
    let index = EMBEDDED_ASSETS
        .iter()
        .find(|asset| asset.route == "/index.html")
        .ok_or("missing index")?;
    for route in ["/", "/sign-in", "/admin/backups", "/unknown-page"] {
        let response = request("GET", route, Some("text/html,application/xhtml+xml;q=0.9")).await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            to_bytes(response.into_body(), 16 * 1024 * 1024)
                .await?
                .as_ref(),
            index.bytes
        );
    }
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/api/latest/status")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(
        to_bytes(response.into_body(), 64).await?.as_ref(),
        b"native API response"
    );
    assert_eq!(
        request("GET", "/admin/backups", Some("application/json"))
            .await?
            .status(),
        StatusCode::NOT_FOUND
    );
    Ok(())
}

#[tokio::test]
async fn missing_assets_api_and_source_paths_never_return_html() -> Result<(), Box<dyn Error>> {
    for route in [
        "/api",
        "/api/latest/missing",
        "/assets",
        "/assets/missing.js",
        "/assets/index.js.map",
        "/.vite/manifest.json",
        "/src/main.tsx",
        "/assets/../index.html",
        "/%2e%2e/index.html",
        "/%61pi/latest/unknown",
        "/.well-known/acme-challenge/missing",
        "/daemon-state/local.sqlite3",
    ] {
        let response = request("GET", route, Some("text/html")).await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{route}");
        assert!(!response.headers().contains_key(header::CONTENT_TYPE));
        assert!(to_bytes(response.into_body(), 1).await?.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn rejects_methods_payloads_and_excessive_paths() -> Result<(), Box<dyn Error>> {
    for method in ["POST", "PUT", "DELETE", "OPTIONS"] {
        assert_eq!(
            request(method, "/", None).await?.status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
    }
    for (name, value) in [
        (header::CONTENT_LENGTH, "1"),
        (header::TRANSFER_ENCODING, "chunked"),
    ] {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(name, value)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    assert_eq!(
        request("GET", &format!("/{}", "a".repeat(2048)), None)
            .await?
            .status(),
        StatusCode::URI_TOO_LONG
    );
    Ok(())
}

fn app() -> Router {
    Router::new()
        .route(
            "/api/latest/status",
            get(|| async { "native API response" }),
        )
        .fallback(serve)
}

async fn request(
    method: &str,
    route: &str,
    accept: Option<&str>,
) -> Result<Response, Box<dyn Error>> {
    let mut request = Request::builder().method(method).uri(route);
    if let Some(accept) = accept {
        request = request.header(header::ACCEPT, accept);
    }
    Ok(app().oneshot(request.body(Body::empty())?).await?)
}
