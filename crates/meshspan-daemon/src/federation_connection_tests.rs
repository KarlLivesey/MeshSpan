// SPDX-License-Identifier: GPL-2.0-only

//! Two independent consensus authorities pair through the real pinned TLS client and listener.

use super::{
    RunningAuthority, TestResult, authority, post, post_route, router, router_with_identity,
};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
    middleware::{self, Next},
};
use meshspan_api_contract::{ConnectFederationResponse, CreateFederationPairingInvitationResponse};
use meshspan_domain::{FederationPairingInvitation, MeshId, PartitionId};
use meshspan_metadata::FederationRelationshipState;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::oneshot;
use tower::ServiceExt;

const CONNECT: &str = "/api/latest/admin/federation/connections";
const CLIENT_OPERATION: &str = "51111111-1111-8111-8111-111111111111";

#[path = "federation_session_tests.rs"]
mod sessions;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn federation_connection_recovers_lost_approval_reply_over_real_tls() -> TestResult<()> {
    let inviter = RunningAuthority::start().await?;
    let joiner = RunningAuthority::start_with_mesh(
        PartitionId::from_bytes([2; 16])?,
        MeshId::from_bytes([91; 16])?,
    )
    .await?;
    let result = pair_with_lost_reply(&inviter, &joiner).await;
    joiner.shutdown().await?;
    inviter.shutdown().await?;
    result
}

async fn pair_with_lost_reply(
    inviter: &RunningAuthority,
    joiner: &RunningAuthority,
) -> TestResult<()> {
    let sessions = sessions::SessionHosts::new(inviter, joiner)?;
    let identity = tls_identity()?;
    let routes = router_with_identity(inviter, identity.clone())?;
    let requests = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&requests);
    let wire_routes = routes.clone().layer(middleware::from_fn(
        move |request: Request<Body>, next: Next| {
            let counter = Arc::clone(&counter);
            async move {
                let response = next.run(request).await;
                if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                    // The peer committed, but the caller receives no usable approval receipt.
                    axum::response::IntoResponse::into_response(StatusCode::SERVICE_UNAVAILABLE)
                } else {
                    response
                }
            }
        },
    ));
    let server = crate::HttpsServer::bind(
        sessions.inviter_address()?,
        identity.server_config(),
        wire_routes,
    )
    .await?;
    let endpoint = format!("https://{}", server.local_addr()?);
    let (stop, stopped) = oneshot::channel();
    let running = tokio::spawn(server.run_until(async {
        drop(stopped.await);
    }));
    let result = async {
        let relationship = exercise_pairing(
            inviter,
            joiner,
            &routes,
            &endpoint,
            &requests,
            &sessions.joiner_origin()?,
        )
        .await?;
        sessions.verify(inviter, joiner, relationship).await
    }
    .await;
    sessions.close();
    assert!(stop.send(()).is_ok());
    running.await??;
    result
}

async fn exercise_pairing(
    inviter: &RunningAuthority,
    joiner: &RunningAuthority,
    remote_routes: &Router,
    endpoint: &str,
    requests: &AtomicUsize,
    local_endpoint: &str,
) -> TestResult<meshspan_domain::FederationRelationshipId> {
    let response = post(remote_routes, inviter, &serde_json::json!({
        "operation_id": "41111111-1111-8111-8111-111111111111", "pairing_endpoint": endpoint, "valid_for_seconds": 900,
    })).await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let issued: CreateFederationPairingInvitationResponse =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
    let invitation = FederationPairingInvitation::parse(&issued.connection_code)?;
    let body = serde_json::json!({"operation_id": CLIENT_OPERATION,
        "connection_code": issued.connection_code, "local_endpoint": local_endpoint});
    let routes = router(joiner)?;
    assert_eq!(
        post_route(&routes, joiner, &body, CONNECT).await?.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let intent = verify_interrupted_pairing(inviter, joiner, &invitation)?;
    let client_operation = meshspan_domain::OperationId::from_bytes(
        crate::create_mesh_setup::parse_uuid(CLIENT_OPERATION)?,
    )?;
    let response = post_route(&router(joiner)?, joiner, &body, CONNECT).await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let receipt = to_bytes(response.into_body(), 4096).await?;
    let parsed: ConnectFederationResponse = serde_json::from_slice(&receipt)?;
    assert_eq!(parsed.committed_revision, 4);
    let committed = authority(joiner)?
        .reader()
        .resolve_operation(client_operation)?
        .ok_or("final receipt")?;
    assert_eq!(committed.committed_revision.get(), 4);
    assert_eq!(
        committed.entity.kind,
        meshspan_metadata::EntityKind::FederationRelationship
    );
    assert_eq!(parsed.relationship_id.as_str(), issued.invitation_id);
    verify_mutual_records(inviter, joiner, &invitation)?;
    let replay = post_route(&router(joiner)?, joiner, &body, CONNECT).await?;
    assert_eq!(replay.status(), StatusCode::CREATED);
    assert_eq!(to_bytes(replay.into_body(), 4096).await?, receipt);
    assert_eq!(requests.load(Ordering::SeqCst), 3);
    let mut changed = body;
    changed["local_endpoint"] = "https://changed.example.test".into();
    assert_eq!(
        post_route(&routes, joiner, &changed, CONNECT)
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(requests.load(Ordering::SeqCst), 3);
    assert_eq!(
        authority(joiner)?
            .reader()
            .federation_connection_intent(invitation.relationship_id())?
            .ok_or("retained")?,
        intent
    );
    Ok(invitation.relationship_id())
}

fn verify_interrupted_pairing(
    inviter: &RunningAuthority,
    joiner: &RunningAuthority,
    invitation: &FederationPairingInvitation,
) -> TestResult<meshspan_metadata::FederationConnectionIntentRecord> {
    let reader = authority(joiner)?;
    let intent = reader
        .reader()
        .federation_connection_intent(invitation.relationship_id())?
        .ok_or("intent")?;
    assert_eq!(intent.revision.get(), 2);
    let operation = meshspan_domain::OperationId::from_bytes(
        crate::create_mesh_setup::parse_uuid(CLIENT_OPERATION)?,
    )?;
    assert!(reader.reader().resolve_operation(operation)?.is_none());
    assert!(
        reader
            .reader()
            .federation_relationship(invitation.relationship_id())?
            .is_none()
    );
    assert_eq!(
        authority(inviter)?
            .reader()
            .federation_relationship(invitation.relationship_id())?
            .ok_or("remote approval")?
            .state,
        FederationRelationshipState::Active
    );
    Ok(intent)
}

fn verify_mutual_records(
    inviter: &RunningAuthority,
    joiner: &RunningAuthority,
    invitation: &FederationPairingInvitation,
) -> TestResult<()> {
    let left = authority(inviter)?
        .reader()
        .federation_pairing_connection(invitation.relationship_id())?
        .ok_or("inviting peer")?;
    let right = authority(joiner)?
        .reader()
        .federation_pairing_connection(invitation.relationship_id())?
        .ok_or("joining peer")?;
    assert_eq!(left.connection.local, right.connection.remote);
    assert_eq!(left.connection.remote, right.connection.local);
    assert_ne!(
        left.connection.local.peer.mesh_id,
        right.connection.local.peer.mesh_id
    );
    for fixture in [inviter, joiner] {
        let reader = authority(fixture)?;
        assert_eq!(
            reader
                .reader()
                .federation_relationship(invitation.relationship_id())?
                .ok_or("relationship")?
                .state,
            FederationRelationshipState::Active
        );
        assert_eq!(
            reader
                .reader()
                .topology_nodes(None, meshspan_metadata::PageLimit::new(10)?)?
                .items
                .len(),
            1
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn federation_connection_rejects_unauthenticated_before_body() -> TestResult<()> {
    let fixture = RunningAuthority::start().await?;
    let response = router(&fixture)?
        .oneshot(Request::post(CONNECT).body(Body::from(vec![0; 30 * 1024]))?)
        .await?;
    let status = response.status();
    fixture.shutdown().await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    Ok(())
}

fn tls_identity() -> TestResult<crate::RotatingHttpsIdentity> {
    let certificate =
        meshspan_certificates::CertificateAuthority::new()?.issue_node("files.example.test")?;
    let certified = rustls::sign::CertifiedKey::from_der(
        vec![rustls::pki_types::CertificateDer::from(
            certificate.certificate_der().to_vec(),
        )],
        rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.private_key().to_vec()).into(),
        &meshspan_rustls_provider::provider(),
    )?;
    Ok(crate::RotatingHttpsIdentity::new_bootstrap(Arc::new(
        certified,
    ))?)
}
