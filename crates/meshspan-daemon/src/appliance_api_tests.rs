// SPDX-License-Identifier: GPL-2.0-only

use std::error::Error;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use tower::ServiceExt as _;

use super::{
    AdministrationApiRoutes, ApplianceApiRoutes, AuthenticationApiRoutes, FileApiRoutes,
    SessionApiRoutes,
};

const ROUTES: [&str; 20] = [
    "/contract",
    "/setup",
    "/session/create",
    "/session/current",
    "/session/revoke",
    "/session/step-up",
    "/authentication/passkey/challenge",
    "/authentication/passkey/register",
    "/authentication/totp",
    "/authentication/recovery",
    "/authentication/api-key",
    "/authentication/methods",
    "/authentication/revoke",
    "/administration/identity",
    "/files/directory",
    "/files/object",
    "/files/read",
    "/files/mutate",
    "/files/upload",
    "/files/volumes",
];

#[tokio::test]
async fn typed_composition_retains_every_required_route_family() -> Result<(), Box<dyn Error>> {
    let router = appliance_routes().into_router();
    for route in ROUTES {
        let response = router
            .clone()
            .oneshot(Request::get(route).body(Body::empty())?)
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT, "{route}");
    }
    Ok(())
}

fn appliance_routes() -> ApplianceApiRoutes {
    ApplianceApiRoutes::new(
        marker("/contract"),
        marker("/setup"),
        SessionApiRoutes::new(
            marker("/session/create"),
            marker("/session/current"),
            marker("/session/revoke"),
            marker("/session/step-up"),
        ),
        AuthenticationApiRoutes::new(
            marker("/authentication/passkey/challenge"),
            marker("/authentication/passkey/register"),
            marker("/authentication/totp"),
            marker("/authentication/recovery"),
            marker("/authentication/api-key"),
            marker("/authentication/methods"),
            marker("/authentication/revoke"),
        ),
        AdministrationApiRoutes::new(marker("/administration/identity")),
        FileApiRoutes::new(
            marker("/files/directory"),
            marker("/files/object"),
            marker("/files/read"),
            marker("/files/mutate"),
            marker("/files/upload"),
            marker("/files/volumes"),
        ),
    )
}

fn marker(route: &'static str) -> Router {
    Router::new().route(route, get(|| async { StatusCode::NO_CONTENT }))
}
