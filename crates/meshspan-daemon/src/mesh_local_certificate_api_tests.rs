// SPDX-License-Identifier: GPL-2.0-only

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use meshspan_api_contract::{
    CertificateGeneration, MeshLocalCertificateAuthorityId as ApiAuthorityId,
    MeshLocalCertificateIssuanceId as ApiIssuanceId, ProvisionMeshLocalCertificateRequest,
    ProvisionMeshLocalCertificateResponse, PublicCertificateId as ApiCertificateId,
    decode_provision_mesh_local_certificate_request,
};
use meshspan_domain::{PrincipalId, UnixMicros, uuid_v8};
use tower::ServiceExt as _;

use crate::{
    IdentityAdministrator, MeshLocalCertificateProvisioningController,
    MeshLocalCertificateProvisioningError, mesh_local_certificate_api_router,
};

#[tokio::test]
async fn authentication_rejection_precedes_local_certificate_body_consumption()
-> Result<(), Box<dyn std::error::Error>> {
    let provisions = Arc::new(AtomicUsize::new(0));
    let router = mesh_local_certificate_api_router(MockController {
        authenticated: false,
        provisions: Arc::clone(&provisions),
    })?;
    let request = Request::builder()
        .method("POST")
        .uri("/api/latest/admin/certificates/local")
        .header("content-type", "application/json")
        .body(Body::from(vec![b'x'; 128 * 1_024]))?;
    let response = router.oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(provisions.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn authenticated_local_provisioning_returns_public_trust_without_private_material()
-> Result<(), Box<dyn std::error::Error>> {
    let provisions = Arc::new(AtomicUsize::new(0));
    let router = mesh_local_certificate_api_router(MockController {
        authenticated: true,
        provisions: Arc::clone(&provisions),
    })?;
    let request = Request::builder()
        .method("POST")
        .uri("/api/latest/admin/certificates/local")
        .header("authorization", "Bearer ignored-by-controller")
        .header("content-type", "application/json")
        .body(Body::from(valid_request_body()))?;
    let response = router.oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), 64 * 1_024).await?;
    let text = std::str::from_utf8(&body)?;
    assert!(text.contains("BEGIN CERTIFICATE"));
    assert!(!text.contains("PRIVATE KEY"));
    assert_eq!(provisions.load(Ordering::SeqCst), 1);
    Ok(())
}

struct MockController {
    authenticated: bool,
    provisions: Arc<AtomicUsize>,
}

impl MeshLocalCertificateProvisioningController for MockController {
    fn authenticate(
        &self,
        _headers: &axum::http::HeaderMap,
        _now: UnixMicros,
    ) -> Result<IdentityAdministrator, MeshLocalCertificateProvisioningError> {
        if self.authenticated {
            Ok(IdentityAdministrator {
                principal_id: PrincipalId::from_bytes([9; 16])
                    .map_err(|_| MeshLocalCertificateProvisioningError::Failed)?,
                now: UnixMicros::new(1),
            })
        } else {
            Err(MeshLocalCertificateProvisioningError::Unauthenticated)
        }
    }

    fn provision(
        &mut self,
        _administrator: IdentityAdministrator,
        request: ProvisionMeshLocalCertificateRequest,
    ) -> Result<ProvisionMeshLocalCertificateResponse, MeshLocalCertificateProvisioningError> {
        self.provisions.fetch_add(1, Ordering::SeqCst);
        Ok(ProvisionMeshLocalCertificateResponse {
            operation_id: request.operation_id,
            authority_id: ApiAuthorityId::from_uuid_bytes(uuid_v8([10; 16]))
                .ok_or(MeshLocalCertificateProvisioningError::Failed)?,
            issuance_id: ApiIssuanceId::from_uuid_bytes(uuid_v8([11; 16]))
                .ok_or(MeshLocalCertificateProvisioningError::Failed)?,
            certificate_id: ApiCertificateId::from_uuid_bytes(uuid_v8([12; 16]))
                .ok_or(MeshLocalCertificateProvisioningError::Failed)?,
            generation: CertificateGeneration::from_value(1)
                .ok_or(MeshLocalCertificateProvisioningError::Failed)?,
            certificate_names: request.certificate_names,
            trust_anchor_pem: concat!(
                "-----BEGIN CERTIFICATE-----\n",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
                "-----END CERTIFICATE-----\n"
            )
            .to_owned(),
            public_key_fingerprint: "12".repeat(32),
            not_before_epoch_micros: 1,
            not_after_epoch_micros: 2,
            revision: 3,
        })
    }
}

fn valid_request_body() -> Vec<u8> {
    let value = serde_json::json!({
        "operation_id": "01010101-0101-8101-8101-010101010101",
        "certificate_names": ["files.example.test"]
    });
    let encoded = serde_json::to_vec(&value).unwrap_or_default();
    debug_assert!(decode_provision_mesh_local_certificate_request(&encoded).is_ok());
    encoded
}
