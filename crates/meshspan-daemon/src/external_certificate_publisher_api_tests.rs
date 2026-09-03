// SPDX-License-Identifier: GPL-2.0-only

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use meshspan_api_contract::{
    CertificateGeneration, ExternalCertificatePublicationId as ApiPublicationId,
    PublicCertificateId as ApiCertificateId, PublishExternalCertificateRequest,
    PublishExternalCertificateResponse, decode_publish_external_certificate_request,
};
use meshspan_domain::{PrincipalId, UnixMicros, uuid_v8};
use tower::ServiceExt as _;

use crate::{
    ExternalCertificatePublisherController, ExternalCertificatePublisherError,
    IdentityAdministrator, external_certificate_publisher_api_router,
};

#[tokio::test]
async fn authentication_rejection_precedes_oversized_body_consumption()
-> Result<(), Box<dyn std::error::Error>> {
    let published = Arc::new(AtomicUsize::new(0));
    let router = external_certificate_publisher_api_router(MockController {
        authenticated: false,
        published: Arc::clone(&published),
    })?;
    let request = Request::builder()
        .method("POST")
        .uri("/api/latest/admin/certificates/external")
        .header("content-type", "application/json")
        .body(Body::from(vec![b'x'; 256 * 1_024]))?;
    let response = router.oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(published.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn authenticated_publication_returns_only_validated_secret_free_contract()
-> Result<(), Box<dyn std::error::Error>> {
    let published = Arc::new(AtomicUsize::new(0));
    let router = external_certificate_publisher_api_router(MockController {
        authenticated: true,
        published: Arc::clone(&published),
    })?;
    let request_body = valid_request_body();
    let request = Request::builder()
        .method("POST")
        .uri("/api/latest/admin/certificates/external")
        .header("authorization", "Bearer ignored-by-controller")
        .header("content-type", "application/json")
        .body(Body::from(request_body))?;
    let response = router.oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), 64 * 1_024).await?;
    let text = std::str::from_utf8(&body)?;
    assert!(!text.contains("PRIVATE KEY"));
    assert!(!text.contains("certificate_chain_pem"));
    assert_eq!(published.load(Ordering::SeqCst), 1);
    Ok(())
}

struct MockController {
    authenticated: bool,
    published: Arc<AtomicUsize>,
}

impl ExternalCertificatePublisherController for MockController {
    fn authenticate(
        &self,
        _headers: &axum::http::HeaderMap,
        _now: UnixMicros,
    ) -> Result<IdentityAdministrator, ExternalCertificatePublisherError> {
        if self.authenticated {
            Ok(IdentityAdministrator {
                principal_id: PrincipalId::from_bytes([9; 16])
                    .map_err(|_| ExternalCertificatePublisherError::Failed)?,
                now: UnixMicros::new(1),
            })
        } else {
            Err(ExternalCertificatePublisherError::Unauthenticated)
        }
    }

    fn publish(
        &mut self,
        _administrator: IdentityAdministrator,
        request: PublishExternalCertificateRequest,
    ) -> Result<PublishExternalCertificateResponse, ExternalCertificatePublisherError> {
        self.published.fetch_add(1, Ordering::SeqCst);
        Ok(PublishExternalCertificateResponse {
            operation_id: request.operation_id,
            publication_id: ApiPublicationId::from_uuid_bytes(uuid_v8([10; 16]))
                .ok_or(ExternalCertificatePublisherError::Failed)?,
            certificate_id: ApiCertificateId::from_uuid_bytes(uuid_v8([11; 16]))
                .ok_or(ExternalCertificatePublisherError::Failed)?,
            generation: CertificateGeneration::from_value(7)
                .ok_or(ExternalCertificatePublisherError::Failed)?,
            certificate_names: request.certificate_names,
            public_key_fingerprint: "12".repeat(32),
            not_before_epoch_micros: 1,
            not_after_epoch_micros: 2,
            revision: 3,
        })
    }
}

fn valid_request_body() -> Vec<u8> {
    let chain = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
        "A".repeat(64)
    );
    let key = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
        "B".repeat(64)
    );
    let value = serde_json::json!({
        "operation_id": "01010101-0101-8101-8101-010101010101",
        "generation": "7",
        "certificate_names": ["files.example.test"],
        "certificate_chain_pem": chain,
        "private_key_pkcs8_pem": key,
    });
    let encoded = serde_json::to_vec(&value).unwrap_or_default();
    debug_assert!(decode_publish_external_certificate_request(&encoded).is_ok());
    encoded
}
