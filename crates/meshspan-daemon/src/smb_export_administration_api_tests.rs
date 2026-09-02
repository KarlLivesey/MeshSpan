// SPDX-License-Identifier: GPL-2.0-only

use std::sync::{Arc, Mutex};

use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode};
use meshspan_api_contract::{
    ObjectId, OperationId, PublishSmbExportRequest, PublishSmbExportResponse,
    SmbExportGatewaySelection, SmbExportId, VolumeId, WithdrawSmbExportRequest,
    WithdrawSmbExportResponse,
};
use meshspan_domain::{PrincipalId, UnixMicros};
use tower::ServiceExt;

use crate::{
    IdentityAdministrator, SmbExportAdministrationController, SmbExportAdministrationError,
    smb_export_administration_api_router,
};

#[tokio::test]
async fn rejects_before_consuming_or_decoding_a_publication_body()
-> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let router = router(Arc::clone(&calls))?;
    let response = router
        .oneshot(
            Request::post(format!(
                "/api/latest/admin/volumes/{}/smb-exports",
                public_uuid(1)
            ))
            .header("content-type", "application/json")
            .body(Body::from("not-json"))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(locked_calls(&calls)?.as_slice(), ["authenticate"]);
    Ok(())
}

#[tokio::test]
async fn preserves_unavailable_authentication_authority_status()
-> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let response = router(calls)?
        .oneshot(
            Request::post(format!(
                "/api/latest/admin/volumes/{}/smb-exports",
                public_uuid(1)
            ))
            .header("content-type", "application/json")
            .header("x-test-auth", "unavailable")
            .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    Ok(())
}

#[tokio::test]
async fn publishes_and_withdraws_an_exact_validated_export()
-> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let router = router(Arc::clone(&calls))?;
    let publication = publication_request()?;
    let published = router
        .clone()
        .oneshot(
            Request::post(format!(
                "/api/latest/admin/volumes/{}/smb-exports",
                public_uuid(1)
            ))
            .header("content-type", "application/json")
            .header("x-test-auth", "yes")
            .body(Body::from(serde_json::to_vec(&publication)?))?,
        )
        .await?;
    assert_eq!(published.status(), StatusCode::CREATED);
    let published: PublishSmbExportResponse =
        serde_json::from_slice(&to_bytes(published.into_body(), 16_384).await?)?;
    assert_eq!(published.operation_id, publication.operation_id);
    assert_eq!(published.share_name, publication.share_name);

    let withdrawal = WithdrawSmbExportRequest {
        operation_id: api_operation(5)?,
        reason: "retire this share".to_owned(),
    };
    let withdrawn = router
        .oneshot(
            Request::post(format!(
                "/api/latest/admin/smb-exports/{}/withdrawals",
                published.export_id.as_str()
            ))
            .header("content-type", "application/json")
            .header("x-test-auth", "yes")
            .body(Body::from(serde_json::to_vec(&withdrawal)?))?,
        )
        .await?;
    assert_eq!(withdrawn.status(), StatusCode::OK);
    let withdrawn: WithdrawSmbExportResponse =
        serde_json::from_slice(&to_bytes(withdrawn.into_body(), 16_384).await?)?;
    assert_eq!(withdrawn.operation_id, withdrawal.operation_id);
    assert_eq!(withdrawn.export_id, published.export_id);
    assert_eq!(
        locked_calls(&calls)?.as_slice(),
        ["authenticate", "publish", "authenticate", "withdraw"]
    );
    Ok(())
}

fn router(
    calls: Arc<Mutex<Vec<&'static str>>>,
) -> Result<axum::Router, crate::SmbExportAdministrationApiError> {
    smb_export_administration_api_router(FakeController { calls })
}

struct FakeController {
    calls: Arc<Mutex<Vec<&'static str>>>,
}

impl SmbExportAdministrationController for FakeController {
    fn authenticate(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<IdentityAdministrator, SmbExportAdministrationError> {
        self.record("authenticate")?;
        match headers
            .get("x-test-auth")
            .and_then(|value| value.to_str().ok())
        {
            Some("yes") => Ok(IdentityAdministrator {
                principal_id: PrincipalId::from_bytes(versioned(10))
                    .map_err(|_| SmbExportAdministrationError::Failed)?,
                now,
            }),
            Some("unavailable") => Err(SmbExportAdministrationError::Unavailable),
            _ => Err(SmbExportAdministrationError::Unauthenticated),
        }
    }

    fn publish(
        &mut self,
        _administrator: IdentityAdministrator,
        volume_id: &str,
        request: PublishSmbExportRequest,
    ) -> Result<PublishSmbExportResponse, SmbExportAdministrationError> {
        self.record("publish")?;
        if volume_id != public_uuid(1) {
            return Err(SmbExportAdministrationError::InvalidInput);
        }
        Ok(PublishSmbExportResponse {
            operation_id: request.operation_id,
            export_id: api_export(4)?,
            volume_id: api_volume(1)?,
            root_object_id: request.root_object_id,
            share_name: request.share_name,
            gateways: request.gateways,
            encryption_required: request.encryption_required,
            revision: 7,
        })
    }

    fn withdraw(
        &mut self,
        _administrator: IdentityAdministrator,
        export_id: &str,
        request: WithdrawSmbExportRequest,
    ) -> Result<WithdrawSmbExportResponse, SmbExportAdministrationError> {
        self.record("withdraw")?;
        if export_id != public_uuid(4) {
            return Err(SmbExportAdministrationError::InvalidInput);
        }
        Ok(WithdrawSmbExportResponse {
            operation_id: request.operation_id,
            export_id: api_export(4)?,
            revision: 8,
        })
    }
}

impl FakeController {
    fn record(&self, call: &'static str) -> Result<(), SmbExportAdministrationError> {
        self.calls
            .lock()
            .map_err(|_| SmbExportAdministrationError::Unavailable)?
            .push(call);
        Ok(())
    }
}

fn publication_request() -> Result<PublishSmbExportRequest, Box<dyn std::error::Error>> {
    Ok(PublishSmbExportRequest {
        operation_id: api_operation(2)?,
        root_object_id: ObjectId::from_uuid_bytes(versioned(3)).ok_or("object")?,
        share_name: serde_json::from_value(serde_json::json!("documents"))?,
        gateways: SmbExportGatewaySelection::AllEligible,
        encryption_required: true,
    })
}

fn api_operation(seed: u8) -> Result<OperationId, SmbExportAdministrationError> {
    OperationId::from_uuid_bytes(versioned(seed)).ok_or(SmbExportAdministrationError::Failed)
}

fn api_export(seed: u8) -> Result<SmbExportId, SmbExportAdministrationError> {
    SmbExportId::from_uuid_bytes(versioned(seed)).ok_or(SmbExportAdministrationError::Failed)
}

fn api_volume(seed: u8) -> Result<VolumeId, SmbExportAdministrationError> {
    VolumeId::from_uuid_bytes(versioned(seed)).ok_or(SmbExportAdministrationError::Failed)
}

fn locked_calls<'a>(
    calls: &'a Arc<Mutex<Vec<&'static str>>>,
) -> Result<std::sync::MutexGuard<'a, Vec<&'static str>>, &'static str> {
    calls.lock().map_err(|_| "poisoned calls")
}

fn public_uuid(seed: u8) -> String {
    let bytes = versioned(seed);
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

fn versioned(seed: u8) -> [u8; 16] {
    let mut value = [seed; 16];
    value[6] = 0x40;
    value[8] = 0x80;
    value
}
