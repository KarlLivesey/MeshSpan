// SPDX-License-Identifier: GPL-2.0-only

//! Public application code, never a filesystem-serving or data-authorisation route.

use axum::body::Body;
use axum::http::{HeaderMap, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};

struct WebAsset {
    route: &'static str,
    media_type: &'static str,
    bytes: &'static [u8],
}

include!(concat!(env!("OUT_DIR"), "/web_assets.rs"));

const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";

pub(crate) async fn serve(method: Method, uri: Uri, headers: HeaderMap) -> Response {
    if uri.path().len() > 2048 {
        return rejected(StatusCode::URI_TOO_LONG);
    }
    if method != Method::GET && method != Method::HEAD {
        return rejected(StatusCode::METHOD_NOT_ALLOWED);
    }
    if headers.contains_key(header::TRANSFER_ENCODING)
        || headers
            .get(header::CONTENT_LENGTH)
            .is_some_and(|length| length != "0")
    {
        return rejected(StatusCode::BAD_REQUEST);
    }
    let route = if is_navigation(uri.path(), &headers) {
        "/index.html"
    } else {
        uri.path()
    };
    let Some(asset) = EMBEDDED_ASSETS.iter().find(|asset| asset.route == route) else {
        return rejected(StatusCode::NOT_FOUND);
    };
    let cache = if asset.route == "/index.html" {
        "no-cache"
    } else {
        "public, max-age=31536000, immutable"
    };
    let body = if method == Method::HEAD {
        Body::empty()
    } else {
        Body::from(asset.bytes)
    };
    let mut response = (
        [
            (header::CONTENT_TYPE, asset.media_type),
            (header::CACHE_CONTROL, cache),
            (header::CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::X_FRAME_OPTIONS, "DENY"),
            (header::REFERRER_POLICY, "no-referrer"),
        ],
        body,
    )
        .into_response();
    // A HEAD describes the same representation without copying or transmitting it.
    response
        .headers_mut()
        .insert(header::CONTENT_LENGTH, asset.bytes.len().into());
    response
}

fn is_navigation(route: &str, headers: &HeaderMap) -> bool {
    if route == "/" {
        return true;
    }
    if route.contains(['.', '%', '\\'])
        || ["/api", "/assets"].iter().any(|prefix| {
            route == *prefix
                || route
                    .strip_prefix(prefix)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        })
    {
        return false;
    }
    headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|accept| {
            accept
                .split(',')
                .any(|item| item.trim().split(';').next() == Some("text/html"))
        })
}

fn rejected(code: StatusCode) -> Response {
    (code, [(header::CACHE_CONTROL, "no-store")]).into_response()
}

#[cfg(test)]
#[path = "web_assets_tests.rs"]
mod tests;
