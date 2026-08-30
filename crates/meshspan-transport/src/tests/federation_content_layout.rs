// SPDX-License-Identifier: GPL-2.0-only

use std::error::Error;

use ed25519_dalek::SigningKey;
use meshspan_domain::{DurationMicros, FederationRelationshipId, MeshId, UnixMicros};
use meshspan_protocol::WireLimits;
use meshspan_protocol::v1::federation_envelope::Message;
use meshspan_protocol::v1::{
    FederatedContentLayoutPage, FederatedContentShardRoute, FederationEnvelope,
    FetchFederatedContentLayout, ShardIdentity, VersionedPayload,
};
use rustls::pki_types::CertificateDer;

use crate::{
    FederationContentLayoutPageExpectation, FederationExchangeContext, FederationLocalIdentity,
    FederationLocalIdentityBinding, FederationPeerRegistry, FederationReplayGuard, TransportError,
    receive_federation, send_federation, signed_federation_content_layout_fetch,
    signed_federation_content_layout_page,
};

use super::{AuthorityPageProof, certificate_fingerprint, validated_federation, version};

pub(super) fn prove_signed_content_layout_fetch(
    registry: &FederationPeerRegistry,
    connection: &quinn::Connection,
    certificate: &CertificateDer<'_>,
    signing_key: &SigningKey,
    limits: WireLimits,
) -> Result<(), Box<dyn Error>> {
    let identity = client_identity(certificate, signing_key)?;
    let context = exchange_context(91, 92, 93, 94)?;
    let outbound = signed_federation_content_layout_fetch(
        &identity,
        context,
        layout_fetch(),
        limits,
        UnixMicros::new(1_500_000),
    )?;
    let expected_binding = outbound.expectation().transit_binding();
    let validated = validated_federation(outbound.envelope(), limits)?;
    let mut replay = federation_replay()?;
    let authenticated = registry.authenticate_content_layout_fetch(
        connection,
        &validated,
        UnixMicros::new(1_500_000),
        &mut replay,
    )?;
    assert_eq!(authenticated.transit_binding(), expected_binding);
    assert_eq!(authenticated.request().manifest_id, vec![97; 16]);
    assert_eq!(authenticated.request().cursor, vec![98; 16]);
    assert_eq!(authenticated.request().limit, 2);
    assert_eq!(
        authenticated.response_context([99; 32])?.request_id,
        [91; 16]
    );
    assert!(matches!(
        registry.authenticate_content_layout_fetch(
            connection,
            &validated,
            UnixMicros::new(1_500_001),
            &mut replay,
        ),
        Err(TransportError::ReplayedFederationMessage)
    ));

    let mut wrong_manifest = outbound.envelope().clone();
    layout_fetch_mut(&mut wrong_manifest).manifest_id[0] ^= 1;
    let mut wrong_cursor = outbound.envelope().clone();
    layout_fetch_mut(&mut wrong_cursor).cursor[0] ^= 1;
    for tampered in [wrong_manifest, wrong_cursor] {
        let mut fresh_replay = federation_replay()?;
        assert!(matches!(
            registry.authenticate_content_layout_fetch(
                connection,
                &validated_federation(&tampered, limits)?,
                UnixMicros::new(1_500_000),
                &mut fresh_replay,
            ),
            Err(TransportError::UntrustedFederationPeer)
        ));
    }
    Ok(())
}

pub(super) async fn prove_federation_content_layout_page(
    proof: &mut AuthorityPageProof<'_>,
) -> Result<(), Box<dyn Error>> {
    let (expectation, request_context, outbound) = layout_page_exchange(proof)?;
    send_federation(proof.send, outbound.envelope(), proof.limits).await?;
    let received = receive_federation(proof.receive, proof.limits).await?;
    let mut replay = federation_replay()?;
    let page = proof.registry.authenticate_content_layout_page(
        proof.connection,
        &received,
        &expectation,
        UnixMicros::new(1_500_000),
        &mut replay,
    )?;
    assert_eq!(page.manifest_id(), &[97; 16]);
    assert_eq!(
        page.layout_header()
            .ok_or("missing layout header")?
            .format_version,
        1
    );
    assert_eq!(page.chunks().len(), 2);
    assert_eq!(page.next_cursor(), &[100; 16]);
    assert!(matches!(
        proof.registry.authenticate_content_layout_page(
            proof.connection,
            &received,
            &expectation,
            UnixMicros::new(1_500_001),
            &mut replay,
        ),
        Err(TransportError::ReplayedFederationMessage)
    ));
    prove_hostile_pages(proof, &expectation, request_context, outbound.envelope())
}

fn layout_page_exchange(
    proof: &AuthorityPageProof<'_>,
) -> Result<
    (
        FederationContentLayoutPageExpectation,
        FederationExchangeContext,
        crate::OutboundFederationContentLayoutPage,
    ),
    Box<dyn Error>,
> {
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let identity = client_identity(&proof.certificates.client_certificate, &signing_key)?;
    let request_context = exchange_context(101, 102, 103, 104)?;
    let fetch = signed_federation_content_layout_fetch(
        &identity,
        request_context,
        layout_fetch(),
        proof.limits,
        UnixMicros::new(1_500_000),
    )?;
    let response_context = FederationExchangeContext::new(
        request_context.version,
        request_context.request_id,
        request_context.operation_id,
        request_context.trace_id,
        request_context.deadline,
        [105; 32],
    )?;
    let outbound = signed_federation_content_layout_page(
        proof.server_identity,
        response_context,
        layout_page(),
        proof.limits,
        UnixMicros::new(1_500_000),
    )?;
    Ok((fetch.expectation().clone(), request_context, outbound))
}

fn prove_hostile_pages(
    proof: &AuthorityPageProof<'_>,
    expectation: &FederationContentLayoutPageExpectation,
    request_context: FederationExchangeContext,
    original: &FederationEnvelope,
) -> Result<(), Box<dyn Error>> {
    let mut variants = Vec::new();
    let mut wrong_grant = original.clone();
    layout_page_mut(&mut wrong_grant).grant_id[0] ^= 1;
    variants.push(wrong_grant);
    let mut wrong_manifest = original.clone();
    layout_page_mut(&mut wrong_manifest).manifest_id[0] ^= 1;
    variants.push(wrong_manifest);
    let mut corrupt_header = original.clone();
    layout_page_mut(&mut corrupt_header)
        .layout_header
        .as_mut()
        .ok_or("missing layout header")?
        .canonical_bytes[0] ^= 1;
    variants.push(corrupt_header);
    let mut corrupt_chunk = original.clone();
    layout_page_mut(&mut corrupt_chunk).chunks[0].canonical_bytes[0] ^= 1;
    variants.push(corrupt_chunk);
    let mut corrupt_signature = original.clone();
    layout_page_mut(&mut corrupt_signature).signature[0] ^= 1;
    variants.push(corrupt_signature);
    for variant in variants {
        reject_page(proof, expectation, &variant)?;
    }

    let reflected = signed_federation_content_layout_page(
        proof.server_identity,
        request_context,
        layout_page(),
        proof.limits,
        UnixMicros::new(1_500_000),
    )?;
    reject_page(proof, expectation, reflected.envelope())
}

fn reject_page(
    proof: &AuthorityPageProof<'_>,
    expectation: &FederationContentLayoutPageExpectation,
    envelope: &FederationEnvelope,
) -> Result<(), Box<dyn Error>> {
    let mut replay = federation_replay()?;
    assert!(matches!(
        proof.registry.authenticate_content_layout_page(
            proof.connection,
            &validated_federation(envelope, proof.limits)?,
            expectation,
            UnixMicros::new(1_500_000),
            &mut replay,
        ),
        Err(TransportError::UntrustedFederationPeer)
    ));
    Ok(())
}

fn client_identity<'a>(
    certificate: &'a CertificateDer<'_>,
    signing_key: &'a SigningKey,
) -> Result<FederationLocalIdentity<'a>, Box<dyn Error>> {
    Ok(FederationLocalIdentity::authenticate(
        FederationLocalIdentityBinding {
            relationship_id: FederationRelationshipId::from_bytes([1; 16])?,
            local_mesh_id: MeshId::from_bytes([2; 16])?,
            remote_mesh_id: MeshId::from_bytes([3; 16])?,
            authority_epoch: 1,
            identity_generation: 1,
            certificate_fingerprint: certificate_fingerprint(certificate),
            verifying_key: signing_key.verifying_key().to_bytes(),
            valid_from: UnixMicros::new(1),
            valid_until: UnixMicros::new(3_000_000),
        },
        certificate.as_ref(),
        signing_key,
        UnixMicros::new(1_500_000),
    )?)
}

fn exchange_context(
    request_id: u8,
    operation_id: u8,
    trace_id: u8,
    replay_nonce: u8,
) -> Result<FederationExchangeContext, TransportError> {
    FederationExchangeContext::new(
        version(1, 2),
        [request_id; 16],
        [operation_id; 16],
        [trace_id; 16],
        UnixMicros::new(2_000_000),
        [replay_nonce; 32],
    )
}

fn layout_fetch() -> FetchFederatedContentLayout {
    FetchFederatedContentLayout {
        grant_id: vec![95; 16],
        resource_scope: Some(resource_scope()),
        manifest_id: vec![97; 16],
        export_token: vec![106; 32],
        manifest_object_digest: vec![107; 32],
        cursor: vec![98; 16],
        limit: 2,
        signature: Vec::new(),
    }
}

fn route(index: u64) -> FederatedContentShardRoute {
    FederatedContentShardRoute {
        provider_node_id: vec![108; 16],
        target_id: vec![109; 16],
        target_generation: 1,
        shard: Some(ShardIdentity {
            manifest_digest: vec![110; 32],
            stripe_index: index,
            shard_index: 0,
            generation: 1,
        }),
        expected_length: 16,
        expected_digest: vec![111; 32],
    }
}

fn layout_page() -> FederatedContentLayoutPage {
    FederatedContentLayoutPage {
        grant_id: vec![95; 16],
        resource_scope: Some(resource_scope()),
        manifest_id: vec![97; 16],
        export_token: vec![106; 32],
        manifest_object_digest: vec![107; 32],
        layout_header: Some(VersionedPayload {
            format_version: 1,
            canonical_bytes: b"portable-layout-header".to_vec(),
        }),
        chunks: vec![
            VersionedPayload {
                format_version: 1,
                canonical_bytes: b"portable-chunk-0".to_vec(),
            },
            VersionedPayload {
                format_version: 1,
                canonical_bytes: b"portable-chunk-1".to_vec(),
            },
        ],
        next_cursor: vec![100; 16],
        page_digest: Vec::new(),
        signature: Vec::new(),
        shard_routes: vec![route(0), route(1)],
    }
}

fn resource_scope() -> VersionedPayload {
    VersionedPayload {
        format_version: 1,
        canonical_bytes: b"volume:finance/folder:quarterly".to_vec(),
    }
}

fn federation_replay() -> Result<FederationReplayGuard, TransportError> {
    FederationReplayGuard::new(8, DurationMicros::new(1_000_000))
}

fn layout_fetch_mut(envelope: &mut FederationEnvelope) -> &mut FetchFederatedContentLayout {
    let Some(Message::FetchContentLayout(fetch)) = envelope.message.as_mut() else {
        unreachable!("fixture content layout fetch")
    };
    fetch
}

fn layout_page_mut(envelope: &mut FederationEnvelope) -> &mut FederatedContentLayoutPage {
    let Some(Message::ContentLayoutPage(page)) = envelope.message.as_mut() else {
        unreachable!("fixture content layout page")
    };
    page
}
