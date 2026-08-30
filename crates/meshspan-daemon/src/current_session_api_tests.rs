// SPDX-License-Identifier: GPL-2.0-only

use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode};
use meshspan_api_contract::{
    ApiError, ApiErrorCode, CurrentSessionResponse, PrincipalId, SessionId,
};
use meshspan_domain::UnixMicros;
use tower::ServiceExt;

use crate::{
    BrowserAuthenticationError, CurrentSessionController, CurrentSessionError,
    current_session_api_router,
};

#[tokio::test]
async fn current_session_route_validates_authenticated_identity_response()
-> Result<(), Box<dyn std::error::Error>> {
    let router = current_session_api_router(FakeController { reject: false })?;
    let response = router
        .oneshot(
            Request::get("/api/latest/sessions/current")
                .header("cookie", "meshspan_session=opaque")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("cache-control"),
        Some(&"no-store".parse()?)
    );
    let body = to_bytes(response.into_body(), 2_048).await?;
    let current = serde_json::from_slice::<CurrentSessionResponse>(&body)?;
    assert_eq!(
        current.session_id.as_str(),
        "01010101-0101-4101-8101-010101010101"
    );
    assert_eq!(
        current.principal_id.as_str(),
        "02020202-0202-4202-8202-020202020202"
    );
    assert!(current.administration_available);
    Ok(())
}

#[tokio::test]
async fn rejected_current_session_has_one_non_disclosing_error()
-> Result<(), Box<dyn std::error::Error>> {
    let response = current_session_api_router(FakeController { reject: true })?
        .oneshot(Request::get("/api/latest/sessions/current").body(Body::empty())?)
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = to_bytes(response.into_body(), 2_048).await?;
    let error = serde_json::from_slice::<ApiError>(&body)?;
    assert_eq!(error.code, ApiErrorCode::Unauthenticated);
    assert_eq!(error.message, "authentication was rejected");
    Ok(())
}

struct FakeController {
    reject: bool,
}

impl CurrentSessionController for FakeController {
    fn current_session(
        &mut self,
        _headers: &HeaderMap,
        _now: UnixMicros,
    ) -> Result<CurrentSessionResponse, CurrentSessionError> {
        if self.reject {
            return Err(CurrentSessionError::Authentication(
                BrowserAuthenticationError::Rejected,
            ));
        }
        Ok(CurrentSessionResponse {
            session_id: SessionId::from_uuid_bytes(versioned(1))
                .ok_or(CurrentSessionError::InvalidEvidence)?,
            principal_id: PrincipalId::from_uuid_bytes(versioned(2))
                .ok_or(CurrentSessionError::InvalidEvidence)?,
            expires_at_epoch_micros: 100,
            administration_available: true,
        })
    }
}

fn versioned(value: u8) -> [u8; 16] {
    let mut bytes = [value; 16];
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes
}
