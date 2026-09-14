// SPDX-License-Identifier: GPL-2.0-only

//! Real-router acceptance, durable peer binding and early rejection through consensus.

use super::{RunningAuthority, TestResult, authority, post, router};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use meshspan_api_contract::{
    AcceptFederationPairingResponse, CreateFederationPairingInvitationResponse,
};
use meshspan_domain::{FederationPairingInvitation, MeshId, NodeId, UnixMicros};
use meshspan_metadata::{
    FederationPairingInvitationState, FederationPairingPeer, FederationRelationshipState,
    RecordName, SignedFederationPairingPeer,
};
use tower::ServiceExt;

const ROUTE: &str = "/api/latest/federation/pairings/accept";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn federation_acceptance_retains_exact_peer_and_receipt_across_reopen() -> TestResult<()> {
    let fixture = RunningAuthority::start().await?;
    let result = acceptance_round_trip(&fixture).await;
    fixture.shutdown().await?;
    result
}

async fn acceptance_round_trip(fixture: &RunningAuthority) -> TestResult<()> {
    let routes = router(fixture)?;
    let invitation = issue(&routes, fixture).await?;
    let peer = remote_peer(fixture, &invitation)?;
    let body = request_body(&peer)?;
    let response = accept(&routes, &invitation, &body).await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        response.headers().get("cache-control").ok_or("cache")?,
        "no-store"
    );
    let first = to_bytes(response.into_body(), 26 * 1024).await?;
    let approved: AcceptFederationPairingResponse = serde_json::from_slice(&first)?;
    assert_eq!(approved.committed_revision, 4);
    let local = meshspan_metadata::decode_federation_pairing_peer(
        &URL_SAFE_NO_PAD.decode(approved.peer_record)?,
    )?;
    assert!(local.verify(
        invitation.relationship_id(),
        invitation.mesh_id(),
        invitation.verifier(),
        now()?
    ));
    assert_eq!(local.peer.mesh_id, invitation.mesh_id());
    assert_eq!(local.peer.node_id, fixture.node_id);
    assert_eq!(local.peer.endpoint, invitation.endpoint());
    assert_ne!(local.peer.verifying_key, peer.peer.verifying_key);
    let stored = verify_retained_approval(fixture, &invitation, &peer, &local)?;
    let replay = accept(&router(fixture)?, &invitation, &body).await?;
    assert_eq!(replay.status(), StatusCode::CREATED);
    assert_eq!(first, to_bytes(replay.into_body(), 26 * 1024).await?);
    let mut changed = body;
    changed["operation_id"] = "81111111-1111-8111-8111-111111111111".into();
    assert_eq!(
        accept(&routes, &invitation, &changed).await?.status(),
        StatusCode::CONFLICT
    );
    let mut other_peer = peer;
    other_peer.peer.endpoint = "https://different.example.test".into();
    let identity = remote_identity(fixture)?;
    other_peer.signature = identity
        .signing
        .sign_pairing(other_peer.peer.pairing_digest(
            invitation.relationship_id(),
            invitation.mesh_id(),
            invitation.verifier(),
        ));
    assert_eq!(
        accept(&routes, &invitation, &request_body(&other_peer)?)
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        authority(fixture)?
            .reader()
            .federation_pairing_connection(invitation.relationship_id())?
            .ok_or("connection")?,
        stored
    );
    Ok(())
}

fn verify_retained_approval(
    fixture: &RunningAuthority,
    invitation: &FederationPairingInvitation,
    remote: &SignedFederationPairingPeer,
    local: &SignedFederationPairingPeer,
) -> TestResult<meshspan_metadata::FederationPairingConnectionRecord> {
    let authority = authority(fixture)?;
    let reader = authority.reader();
    let nodes = reader.topology_nodes(None, meshspan_metadata::PageLimit::new(10)?)?;
    assert_eq!(nodes.items.len(), 1);
    assert!(nodes.next.is_none());
    let stored = reader
        .federation_pairing_connection(invitation.relationship_id())?
        .ok_or("connection")?;
    assert_eq!(stored.revision.get(), 3);
    assert_eq!(&stored.connection.remote, remote);
    assert_eq!(&stored.connection.local, local);
    assert_eq!(
        reader
            .federation_pairing_invitation(invitation.relationship_id())?
            .ok_or("invitation")?
            .state,
        FederationPairingInvitationState::Consumed
    );
    assert_eq!(
        reader
            .federation_relationship(invitation.relationship_id())?
            .ok_or("relationship")?
            .state,
        FederationRelationshipState::Active
    );
    Ok(stored)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn federation_acceptance_rejects_before_body_and_never_consumes_invalid_peer()
-> TestResult<()> {
    let fixture = RunningAuthority::start().await?;
    let result = rejection_round_trip(&fixture).await;
    fixture.shutdown().await?;
    result
}

async fn rejection_round_trip(fixture: &RunningAuthority) -> TestResult<()> {
    let routes = router(fixture)?;
    let denied = routes
        .clone()
        .oneshot(Request::post(ROUTE).body(Body::from(vec![0; 30 * 1024]))?)
        .await?;
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    let invitation = issue(&routes, fixture).await?;
    let peer = remote_peer(fixture, &invitation)?;
    let mut bad = peer.clone();
    bad.signature[0] ^= 1;
    assert_eq!(
        accept(&routes, &invitation, &request_body(&bad)?)
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    bad = peer.clone();
    bad.peer.certificate_der = vec![0x30; 80];
    bad.signature = remote_identity(fixture)?
        .signing
        .sign_pairing(bad.peer.pairing_digest(
            invitation.relationship_id(),
            invitation.mesh_id(),
            invitation.verifier(),
        ));
    assert_eq!(
        accept(&routes, &invitation, &request_body(&bad)?)
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    let reader = authority(fixture)?;
    assert!(
        reader
            .reader()
            .federation_pairing_connection(invitation.relationship_id())?
            .is_none()
    );
    assert!(
        reader
            .reader()
            .federation_relationship(invitation.relationship_id())?
            .is_none()
    );
    assert_eq!(
        reader
            .reader()
            .federation_pairing_invitation(invitation.relationship_id())?
            .ok_or("invitation")?
            .state,
        FederationPairingInvitationState::Open
    );
    let cancel = serde_json::json!({"operation_id":"61111111-1111-8111-8111-111111111111", "invitation_id":crate::create_mesh_setup::format_uuid(invitation.relationship_id().as_bytes()),
        "expected_invitation_revision":2,"reason":"Cancel before connection"});
    let response = super::post_route(
        &routes,
        fixture,
        &cancel,
        "/api/latest/admin/federation/invitations/cancel",
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        accept(&routes, &invitation, &request_body(&peer)?)
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    Ok(())
}

async fn issue(
    routes: &Router,
    fixture: &RunningAuthority,
) -> TestResult<FederationPairingInvitation> {
    let response = post(
        routes,
        fixture,
        &serde_json::json!({"operation_id":"41111111-1111-8111-8111-111111111111",
        "pairing_endpoint":"https://files.example.test:8443", "valid_for_seconds":900}),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let result: CreateFederationPairingInvitationResponse =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
    Ok(FederationPairingInvitation::parse(&result.connection_code)?)
}

fn now() -> TestResult<UnixMicros> {
    crate::api_http::current_time().ok_or_else(|| "clock".into())
}

fn remote_identity(
    fixture: &RunningAuthority,
) -> TestResult<crate::local_federation_identity::LocalFederationIdentity> {
    Ok(
        crate::local_federation_identity::LocalFederationIdentity::open_or_create(
            &fixture.directory.path().join("remote-federation.v1"),
            now()?,
        )?,
    )
}

fn remote_peer(
    fixture: &RunningAuthority,
    invitation: &FederationPairingInvitation,
) -> TestResult<SignedFederationPairingPeer> {
    let identity = remote_identity(fixture)?;
    let peer = FederationPairingPeer {
        mesh_id: MeshId::from_bytes([91; 16])?,
        node_id: NodeId::from_bytes([92; 16])?,
        name: RecordName::new("Remote office")?,
        endpoint: "https://remote.example.test:8443".into(),
        certificate_der: identity
            .certificate
            .certificate_chain()
            .first()
            .ok_or("certificate")?
            .clone(),
        verifying_key: identity.signing.verifying_key(),
        valid_from: identity.valid_from,
        valid_until: identity.valid_until,
    };
    let signature = identity.signing.sign_pairing(peer.pairing_digest(
        invitation.relationship_id(),
        invitation.mesh_id(),
        invitation.verifier(),
    ));
    Ok(SignedFederationPairingPeer { peer, signature })
}

fn request_body(peer: &SignedFederationPairingPeer) -> TestResult<serde_json::Value> {
    Ok(
        serde_json::json!({"operation_id":"71111111-1111-8111-8111-111111111111",
        "peer_record": URL_SAFE_NO_PAD.encode(meshspan_metadata::encode_federation_pairing_peer(peer)?)}),
    )
}

async fn accept(
    routes: &Router,
    invitation: &FederationPairingInvitation,
    body: &serde_json::Value,
) -> TestResult<axum::http::Response<Body>> {
    Ok(routes
        .clone()
        .oneshot(
            Request::post(ROUTE)
                .header("content-type", "application/json")
                .header(
                    "authorization",
                    format!("MeshSpan-Pairing {}", invitation.expose_encoded().as_str()),
                )
                .body(Body::from(serde_json::to_vec(body)?))?,
        )
        .await?)
}
