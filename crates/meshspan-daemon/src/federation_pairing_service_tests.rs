// SPDX-License-Identifier: GPL-2.0-only

//! The public issuance route uses real consensus, protected keys and durable cancellation.

use super::{RunningAuthority, command_context};
use crate::federation_pairing_api::federation_pairing_api_router;
use crate::federation_pairing_service::FederationPairingService;
use crate::{
    ConsensusAuthenticationAuthority, GatewaySessionIdentity, LocalWrappingKey,
    RotatingHttpsIdentity,
};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use meshspan_api_contract::CreateFederationPairingInvitationResponse;
use meshspan_domain::{FederationPairingInvitation, PartitionId, UnixMicros};
use meshspan_metadata::{
    AuthoritativeCommand, AuthoritativeRepository, CancelFederationPairingInvitation,
    FederationPairingInvitationState, PartitionDatabase,
};
use std::sync::Arc;
use tower::ServiceExt;

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

#[path = "federation_pairing_acceptance_tests.rs"]
mod acceptance;

#[path = "federation_connection_tests.rs"]
mod connection;

#[path = "federation_storage_grant_api_tests.rs"]
mod storage_grants;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn federation_pairing_cancellation_http_returns_exact_receipt_on_retry() -> TestResult<()> {
    let fixture = RunningAuthority::start().await?;
    let result = cancel_through_http(&fixture).await;
    fixture.shutdown().await?;
    result
}

async fn cancel_through_http(fixture: &RunningAuthority) -> TestResult<()> {
    let router = router(fixture)?;
    let issue = serde_json::json!({"operation_id": "21111111-1111-8111-8111-111111111111",
        "pairing_endpoint": "https://files.example.test", "valid_for_seconds": 60});
    let response = post(&router, fixture, &issue).await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let issued: CreateFederationPairingInvitationResponse =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
    let mut cancel = serde_json::json!({"operation_id": "31111111-1111-8111-8111-111111111111",
        "invitation_id": issued.invitation_id, "expected_invitation_revision": 2, "reason": "No longer needed"});
    let route = "/api/latest/admin/federation/invitations/cancel";
    let response = post_route(&router, fixture, &cancel, route).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let first = to_bytes(response.into_body(), 4096).await?;
    let receipt: meshspan_api_contract::CancelFederationPairingInvitationResponse =
        serde_json::from_slice(&first)?;
    assert_eq!(receipt.committed_revision, 3);
    let response = post_route(&self::router(fixture)?, fixture, &cancel, route).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(first, to_bytes(response.into_body(), 4096).await?);
    cancel["reason"] = "Different intent".into();
    assert_eq!(
        post_route(&router, fixture, &cancel, route).await?.status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        post(&router, fixture, &issue).await?.status(),
        StatusCode::CONFLICT
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn federation_pairing_http_issuance_replays_and_cancellation_survives_reopen()
-> TestResult<()> {
    let fixture = RunningAuthority::start().await?;
    let result = exercise(&fixture).await;
    fixture.shutdown().await?;
    result
}

async fn exercise(fixture: &RunningAuthority) -> TestResult<()> {
    let router = router(fixture)?;
    let body = serde_json::json!({
        "operation_id": "11111111-1111-8111-8111-111111111111",
        "pairing_endpoint": "https://files.example.test:8443", "valid_for_seconds": 900
    });
    let denied = router
        .clone()
        .oneshot(
            Request::post("/api/latest/admin/federation/invitations")
                .body(Body::from(vec![0; 4096]))?,
        )
        .await?;
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    let first = post(&router, fixture, &body).await?;
    assert_eq!(first.status(), StatusCode::CREATED);
    assert_eq!(
        first.headers().get("cache-control").ok_or("cache header")?,
        "no-store"
    );
    let bytes = to_bytes(first.into_body(), 4096).await?;
    let response: CreateFederationPairingInvitationResponse = serde_json::from_slice(&bytes)?;
    assert_eq!(response.committed_revision, 2);
    let invitation = FederationPairingInvitation::parse(&response.connection_code)?;
    assert_eq!(invitation.endpoint(), "https://files.example.test:8443");
    assert_eq!(
        invitation.expires_at().get() - invitation.issued_at().get(),
        900_000_000
    );
    let replay = post(&router, fixture, &body).await?;
    assert_eq!(replay.status(), StatusCode::CREATED);
    assert_eq!(to_bytes(replay.into_body(), 4096).await?, bytes);
    let mut changed = body.clone();
    changed["valid_for_seconds"] = 901.into();
    assert_eq!(
        post(&router, fixture, &changed).await?.status(),
        StatusCode::CONFLICT
    );
    verify_and_cancel(fixture, &invitation)?;
    assert_eq!(
        post(&self::router(fixture)?, fixture, &body)
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    Ok(())
}

fn verify_and_cancel(
    fixture: &RunningAuthority,
    invitation: &FederationPairingInvitation,
) -> TestResult<()> {
    let authority = authority(fixture)?;
    tokio::task::block_in_place(|| -> TestResult<()> {
        let stored = authority
            .reader()
            .federation_pairing_invitation(invitation.relationship_id())?
            .ok_or("invitation")?;
        assert_eq!(stored.invitation.material_verifier, invitation.verifier());
        assert_eq!(stored.issued_by, fixture.administrator_id);
        assert_eq!(stored.state, FederationPairingInvitationState::Open);
        assert!(
            authority
                .reader()
                .federation_relationship(invitation.relationship_id())?
                .is_none()
        );
        let command = AuthoritativeCommand::CancelFederationPairingInvitation(
            CancelFederationPairingInvitation {
                relationship_id: invitation.relationship_id(),
                expected_invitation_revision: stored.revision,
                reason: "Withdraw unused pairing".into(),
            },
        );
        let context = command_context(
            fixture.administrator_id,
            70,
            71,
            invitation.issued_at().get() + 1,
            None,
        )?;
        let receipt = authority.commit_authoritative(context, &command)?;
        assert_eq!(receipt.committed_revision.get(), 3);
        let replay = authority.commit_authoritative(context, &command)?;
        assert_eq!(receipt.result_digest, replay.result_digest);
        let reopened = self::authority(fixture)?;
        assert_eq!(
            reopened
                .reader()
                .federation_pairing_invitation(invitation.relationship_id())?
                .ok_or("cancelled invitation")?
                .state,
            FederationPairingInvitationState::Cancelled
        );
        Ok(())
    })
}

fn authority(fixture: &RunningAuthority) -> TestResult<ConsensusAuthenticationAuthority> {
    Ok(ConsensusAuthenticationAuthority::new(
        AuthoritativeRepository::new(PartitionDatabase::open(
            &fixture.directory.path().join("partition.sqlite3"),
            PartitionId::from_bytes([2; 16])?,
            UnixMicros::new(1),
        )?),
        fixture.handle.clone(),
        tokio::runtime::Handle::current(),
    ))
}

fn router(fixture: &RunningAuthority) -> TestResult<Router> {
    let certificate =
        meshspan_certificates::CertificateAuthority::new()?.issue_node("files.example.test")?;
    let certified = rustls::sign::CertifiedKey::from_der(
        vec![rustls::pki_types::CertificateDer::from(
            certificate.certificate_der().to_vec(),
        )],
        rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.private_key().to_vec()).into(),
        &meshspan_rustls_provider::provider(),
    )?;
    router_with_identity(
        fixture,
        RotatingHttpsIdentity::new_bootstrap(Arc::new(certified))?,
    )
}

fn router_with_identity(
    fixture: &RunningAuthority,
    https: RotatingHttpsIdentity,
) -> TestResult<Router> {
    Ok(federation_pairing_api_router(
        FederationPairingService::new(
            authority(fixture)?,
            authority(fixture)?,
            LocalWrappingKey::open_or_create(
                &fixture.directory.path().join("volume-wrapping.key"),
            )?,
            crate::federation_pairing_service::PairingGateway {
                gateway: GatewaySessionIdentity::new(fixture.node_id, 1)?,
                https,
                federation:
                    crate::local_federation_identity::LocalFederationIdentity::open_or_create(
                        &fixture.directory.path().join("federation-identity.v1"),
                        crate::api_http::current_time().ok_or("clock")?,
                    )?,
            },
        ),
    )?)
}

async fn post(
    router: &Router,
    fixture: &RunningAuthority,
    body: &serde_json::Value,
) -> TestResult<axum::http::Response<Body>> {
    post_route(
        router,
        fixture,
        body,
        "/api/latest/admin/federation/invitations",
    )
    .await
}

async fn post_route(
    router: &Router,
    fixture: &RunningAuthority,
    body: &serde_json::Value,
    route: &str,
) -> TestResult<axum::http::Response<Body>> {
    Ok(router
        .clone()
        .oneshot(
            Request::post(route)
                .header("content-type", "application/json")
                .header(
                    "authorization",
                    format!("Bearer {}", fixture.api_key.expose_encoded().as_str()),
                )
                .body(Body::from(serde_json::to_vec(body)?))?,
        )
        .await?)
}
