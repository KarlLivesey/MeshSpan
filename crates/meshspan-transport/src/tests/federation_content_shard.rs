// SPDX-License-Identifier: GPL-2.0-only

use std::error::Error;

use ed25519_dalek::SigningKey;
use meshspan_domain::{DurationMicros, FederationRelationshipId, MeshId, UnixMicros};
use meshspan_protocol::WireLimits;
use meshspan_protocol::v1::federation_envelope::Message;
use meshspan_protocol::v1::{
    FederatedContentShardHeader, FederationEnvelope, FetchFederatedContentShard, ShardIdentity,
    VersionedPayload,
};
use rustls::pki_types::CertificateDer;

use crate::{
    FederationContentShardExpectation, FederationExchangeContext, FederationLocalIdentity,
    FederationLocalIdentityBinding, FederationPeerRegistry, FederationReplayGuard, TransportError,
    receive_federation, send_federation, signed_federation_content_shard_fetch,
    signed_federation_content_shard_header,
};

use super::{AuthorityPageProof, certificate_fingerprint, validated_federation, version};

pub(super) fn prove_signed_content_shard_fetch(
    registry: &FederationPeerRegistry,
    connection: &quinn::Connection,
    certificate: &CertificateDer<'_>,
    signing_key: &SigningKey,
    limits: WireLimits,
) -> Result<(), Box<dyn Error>> {
    let identity = client_identity(certificate, signing_key)?;
    let outbound = signed_federation_content_shard_fetch(
        &identity,
        exchange_context(111, 112, 113, 114)?,
        shard_fetch(),
        limits,
        UnixMicros::new(1_500_000),
    )?;
    let validated = validated_federation(outbound.envelope(), limits)?;
    let mut replay = replay_guard()?;
    let authenticated = registry.authenticate_content_shard_fetch(
        connection,
        &validated,
        UnixMicros::new(1_500_000),
        &mut replay,
    )?;
    assert_eq!(authenticated.operation_id()?.as_bytes(), [112; 16]);
    assert_eq!(authenticated.request().target_generation, 5);
    assert!(matches!(
        registry.authenticate_content_shard_fetch(
            connection,
            &validated,
            UnixMicros::new(1_500_001),
            &mut replay,
        ),
        Err(TransportError::ReplayedFederationMessage)
    ));

    let mut changed = outbound.envelope().clone();
    shard_fetch_mut(&mut changed).expected_digest[0] ^= 1;
    let mut fresh = replay_guard()?;
    assert!(matches!(
        registry.authenticate_content_shard_fetch(
            connection,
            &validated_federation(&changed, limits)?,
            UnixMicros::new(1_500_000),
            &mut fresh,
        ),
        Err(TransportError::UntrustedFederationPeer)
    ));
    Ok(())
}

pub(super) async fn prove_federation_content_shard_header(
    proof: &mut AuthorityPageProof<'_>,
) -> Result<(), Box<dyn Error>> {
    let (expectation, request_context, outbound) = shard_header_exchange(proof)?;
    send_federation(proof.send, outbound.envelope(), proof.limits).await?;
    let received = receive_federation(proof.receive, proof.limits).await?;
    let mut replay = replay_guard()?;
    let header = proof.registry.authenticate_content_shard_header(
        proof.connection,
        &received,
        &expectation,
        UnixMicros::new(1_500_000),
        &mut replay,
    )?;
    assert_eq!(header.declared_length(), 19);
    assert_eq!(header.content_digest(), &[104; 32]);
    assert_eq!(header.maximum_frame_bytes(), 8);

    let mut wrong_route = outbound.envelope().clone();
    shard_header_mut(&mut wrong_route).target_id[0] ^= 1;
    reject_header(proof, &expectation, &wrong_route)?;
    let mut wrong_digest = outbound.envelope().clone();
    shard_header_mut(&mut wrong_digest).content_digest[0] ^= 1;
    reject_header(proof, &expectation, &wrong_digest)?;

    let reflected = signed_federation_content_shard_header(
        proof.server_identity,
        request_context,
        shard_header(),
        proof.limits,
        UnixMicros::new(1_500_000),
    )?;
    reject_header(proof, &expectation, reflected.envelope())
}

fn shard_header_exchange(
    proof: &AuthorityPageProof<'_>,
) -> Result<
    (
        FederationContentShardExpectation,
        FederationExchangeContext,
        crate::OutboundFederationContentShardHeader,
    ),
    Box<dyn Error>,
> {
    let client_key = SigningKey::from_bytes(&[42; 32]);
    let identity = client_identity(&proof.certificates.client_certificate, &client_key)?;
    let request_context = exchange_context(121, 122, 123, 124)?;
    let fetch = signed_federation_content_shard_fetch(
        &identity,
        request_context,
        shard_fetch(),
        proof.limits,
        UnixMicros::new(1_500_000),
    )?;
    let response_context = FederationExchangeContext::new(
        request_context.version,
        request_context.request_id,
        request_context.operation_id,
        request_context.trace_id,
        request_context.deadline,
        [125; 32],
    )?;
    let outbound = signed_federation_content_shard_header(
        proof.server_identity,
        response_context,
        shard_header(),
        proof.limits,
        UnixMicros::new(1_500_000),
    )?;
    Ok((fetch.expectation().clone(), request_context, outbound))
}

fn reject_header(
    proof: &AuthorityPageProof<'_>,
    expectation: &FederationContentShardExpectation,
    envelope: &FederationEnvelope,
) -> Result<(), Box<dyn Error>> {
    let mut replay = replay_guard()?;
    assert!(matches!(
        proof.registry.authenticate_content_shard_header(
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

fn shard_fetch() -> FetchFederatedContentShard {
    FetchFederatedContentShard {
        grant_id: vec![95; 16],
        resource_scope: Some(resource_scope()),
        manifest_id: vec![97; 16],
        export_token: vec![102; 32],
        manifest_object_digest: vec![103; 32],
        provider_node_id: vec![105; 16],
        target_id: vec![98; 16],
        target_generation: 5,
        shard: Some(shard()),
        expected_length: 19,
        expected_digest: vec![104; 32],
        signature: Vec::new(),
    }
}

fn shard_header() -> FederatedContentShardHeader {
    FederatedContentShardHeader {
        grant_id: vec![95; 16],
        resource_scope: Some(resource_scope()),
        manifest_id: vec![97; 16],
        export_token: vec![102; 32],
        manifest_object_digest: vec![103; 32],
        provider_node_id: vec![105; 16],
        target_id: vec![98; 16],
        target_generation: 5,
        shard: Some(shard()),
        declared_length: 19,
        content_digest: vec![104; 32],
        maximum_frame_bytes: 8,
        served_at_unix_micros: 1_500_000,
        signature: Vec::new(),
    }
}

fn shard() -> ShardIdentity {
    ShardIdentity {
        manifest_digest: vec![99; 32],
        stripe_index: 2,
        shard_index: 0,
        generation: 1,
    }
}

fn resource_scope() -> VersionedPayload {
    VersionedPayload {
        format_version: 1,
        canonical_bytes: b"volume:finance/folder:quarterly".to_vec(),
    }
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

fn replay_guard() -> Result<FederationReplayGuard, TransportError> {
    FederationReplayGuard::new(8, DurationMicros::new(1_000_000))
}

fn shard_fetch_mut(envelope: &mut FederationEnvelope) -> &mut FetchFederatedContentShard {
    let Some(Message::FetchContentShard(fetch)) = envelope.message.as_mut() else {
        unreachable!("fixture content shard fetch")
    };
    fetch
}

fn shard_header_mut(envelope: &mut FederationEnvelope) -> &mut FederatedContentShardHeader {
    let Some(Message::ContentShardHeader(header)) = envelope.message.as_mut() else {
        unreachable!("fixture content shard header")
    };
    header
}
