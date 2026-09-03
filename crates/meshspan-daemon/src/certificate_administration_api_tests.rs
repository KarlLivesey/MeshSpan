// SPDX-License-Identifier: GPL-2.0-only

use std::sync::{Arc, Mutex};

use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode};
use meshspan_api_contract::{
    AcmeConfigurationId, CertificateOrderId, ProvisionCertificateRequest,
    ProvisionCertificateResponse, decode_provision_certificate_request,
};
use meshspan_domain::{PrincipalId, UnixMicros};
use tower::ServiceExt;

use crate::{
    CertificateProvisioningController, CertificateProvisioningError, IdentityAdministrator,
    certificate_provisioning_api_router,
};

#[tokio::test]
async fn rejects_before_consuming_or_decoding_a_certificate_body()
-> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let response = router(Arc::clone(&calls))?
        .oneshot(
            Request::post("/api/latest/admin/certificates/acme")
                .header("content-type", "application/json")
                .body(Body::from("not-json"))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        calls.lock().map_err(|_| "calls")?.as_slice(),
        ["authenticate"]
    );
    Ok(())
}

#[tokio::test]
async fn authenticates_then_returns_one_validated_durable_result()
-> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let request = request()?;
    let response = router(Arc::clone(&calls))?
        .oneshot(
            Request::post("/api/latest/admin/certificates/acme")
                .header("content-type", "application/json")
                .header("x-test-auth", "yes")
                .body(Body::from(serde_json::to_vec(&request)?))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let response: ProvisionCertificateResponse =
        serde_json::from_slice(&to_bytes(response.into_body(), 16_384).await?)?;
    assert_eq!(response.operation_id, request.operation_id);
    assert_eq!(response.certificate_names, ["files.example.test"]);
    assert_eq!(
        calls.lock().map_err(|_| "calls")?.as_slice(),
        ["authenticate", "provision"]
    );
    Ok(())
}

fn router(
    calls: Arc<Mutex<Vec<&'static str>>>,
) -> Result<axum::Router, crate::CertificateProvisioningApiError> {
    certificate_provisioning_api_router(FakeController { calls })
}

struct FakeController {
    calls: Arc<Mutex<Vec<&'static str>>>,
}

impl CertificateProvisioningController for FakeController {
    fn authenticate(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<IdentityAdministrator, CertificateProvisioningError> {
        self.record("authenticate")?;
        if headers
            .get("x-test-auth")
            .and_then(|value| value.to_str().ok())
            != Some("yes")
        {
            return Err(CertificateProvisioningError::Unauthenticated);
        }
        Ok(IdentityAdministrator {
            principal_id: PrincipalId::from_bytes(versioned(10))
                .map_err(|_| CertificateProvisioningError::Failed)?,
            now,
        })
    }

    fn provision(
        &mut self,
        _administrator: IdentityAdministrator,
        request: ProvisionCertificateRequest,
    ) -> Result<ProvisionCertificateResponse, CertificateProvisioningError> {
        self.record("provision")?;
        Ok(ProvisionCertificateResponse {
            operation_id: request.operation_id,
            configuration_id: AcmeConfigurationId::from_uuid_bytes(versioned(11))
                .ok_or(CertificateProvisioningError::Failed)?,
            order_id: CertificateOrderId::from_uuid_bytes(versioned(12))
                .ok_or(CertificateProvisioningError::Failed)?,
            certificate_names: request.certificate_names,
            revision: 7,
        })
    }
}

impl FakeController {
    fn record(&self, call: &'static str) -> Result<(), CertificateProvisioningError> {
        self.calls
            .lock()
            .map_err(|_| CertificateProvisioningError::Unavailable)?
            .push(call);
        Ok(())
    }
}

fn request() -> Result<ProvisionCertificateRequest, Box<dyn std::error::Error>> {
    let value = serde_json::json!({
        "operation_id": "12121212-1212-4212-9212-121212121212",
        "directory_url": "https://acme.example.test/directory",
        "certificate_names": ["files.example.test"],
        "challenge": {"kind": "http01"}
    });
    Ok(decode_provision_certificate_request(&serde_json::to_vec(
        &value,
    )?)?)
}

fn versioned(seed: u8) -> [u8; 16] {
    let mut value = [seed; 16];
    value[6] = 0x40;
    value[8] = 0x80;
    value
}
