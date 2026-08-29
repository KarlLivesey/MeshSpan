// SPDX-License-Identifier: GPL-2.0-only

use std::error::Error;

use ed25519_dalek::SigningKey;
use meshspan_domain::{DurationMicros, FederationRelationshipId, MeshId, UnixMicros};
use meshspan_protocol::WireLimits;
use meshspan_protocol::v1::federation_envelope::Message as FederationMessage;
use meshspan_protocol::v1::{
    FederatedBranchPage, FederationEnvelope, FetchFederatedBranchPage, VersionedPayload,
};
use rustls::pki_types::CertificateDer;

use crate::{
    FederationBranchPageExpectation, FederationExchangeContext, FederationLocalIdentity,
    FederationLocalIdentityBinding, FederationPeerRegistry, FederationReplayGuard,
    OutboundFederationBranchPage, TransportError, receive_federation, send_federation,
    signed_federation_branch_fetch, signed_federation_branch_page,
};

use super::{AuthorityPageProof, certificate_fingerprint, validated_federation, version};

pub(super) fn prove_signed_branch_fetch(
    registry: &FederationPeerRegistry,
    connection: &quinn::Connection,
    certificate: &CertificateDer<'_>,
    signing_key: &SigningKey,
    limits: WireLimits,
) -> Result<(), Box<dyn Error>> {
    let identity = branch_identity(certificate, signing_key)?;
    let context = exchange_context(61, 62, 63, 64)?;
    let outbound = signed_federation_branch_fetch(
        &identity,
        context,
        branch_fetch(vec![65; 16], b"volume:finance".to_vec()),
        limits,
        UnixMicros::new(1_500_000),
    )?;
    let validated = validated_federation(outbound.envelope(), limits)?;
    let mut replay = federation_replay()?;
    let authenticated = registry.authenticate_branch_fetch(
        connection,
        &validated,
        UnixMicros::new(1_500_000),
        &mut replay,
    )?;
    assert_eq!(
        authenticated.relationship_id(),
        identity.binding().relationship_id
    );
    assert_eq!(
        authenticated.remote_mesh_id(),
        identity.binding().local_mesh_id
    );
    assert_eq!(authenticated.request().grant_id, vec![65; 16]);
    assert_eq!(
        authenticated.request().requested_head_ids,
        vec![vec![66; 16]]
    );
    assert_eq!(authenticated.request().known_commit_ids, vec![vec![67; 16]]);
    assert_eq!(
        authenticated.response_context([68; 32])?.request_id,
        [61; 16]
    );
    assert!(matches!(
        authenticated.response_context(context.replay_nonce),
        Err(TransportError::InvalidConfiguration)
    ));
    assert!(matches!(
        registry.authenticate_branch_fetch(
            connection,
            &validated,
            UnixMicros::new(1_500_001),
            &mut replay,
        ),
        Err(TransportError::ReplayedFederationMessage)
    ));
    prove_tampered_fetch_is_rejected(registry, connection, outbound.envelope(), limits)
}

pub(super) async fn prove_federation_branch_page(
    proof: &mut AuthorityPageProof<'_>,
) -> Result<(), Box<dyn Error>> {
    let exchange = branch_page_exchange(proof)?;
    send_federation(proof.send, exchange.outbound.envelope(), proof.limits).await?;
    let received = receive_federation(proof.receive, proof.limits).await?;
    let mut replay = federation_replay()?;
    let page = proof.registry.authenticate_branch_page(
        proof.connection,
        &received,
        &exchange.expectation,
        UnixMicros::new(1_500_000),
        &mut replay,
    )?;
    assert_eq!(page.grant_id(), &[55; 16]);
    assert_eq!(page.branch_commits().len(), 1);
    assert_eq!(page.immutable_object_digests(), &[vec![59; 32]]);
    assert_eq!(page.next_cursor(), &[60; 16]);
    assert!(matches!(
        proof.registry.authenticate_branch_page(
            proof.connection,
            &received,
            &exchange.expectation,
            UnixMicros::new(1_500_001),
            &mut replay,
        ),
        Err(TransportError::ReplayedFederationMessage)
    ));
    prove_hostile_branch_pages(proof, &exchange)
}

struct BranchPageExchange {
    expectation: FederationBranchPageExpectation,
    request_context: FederationExchangeContext,
    outbound: OutboundFederationBranchPage,
}

fn branch_page_exchange(
    proof: &AuthorityPageProof<'_>,
) -> Result<BranchPageExchange, Box<dyn Error>> {
    let client_signing_key = SigningKey::from_bytes(&[42; 32]);
    let client_identity = FederationLocalIdentity::authenticate(
        FederationLocalIdentityBinding {
            relationship_id: proof.authenticated.relationship_id(),
            local_mesh_id: proof.authenticated.remote_mesh_id(),
            remote_mesh_id: proof.authenticated.local_mesh_id(),
            authority_epoch: 1,
            identity_generation: 1,
            certificate_fingerprint: certificate_fingerprint(
                &proof.certificates.client_certificate,
            ),
            verifying_key: client_signing_key.verifying_key().to_bytes(),
            valid_from: UnixMicros::new(1),
            valid_until: UnixMicros::new(3_000_000),
        },
        proof.certificates.client_certificate.as_ref(),
        &client_signing_key,
        UnixMicros::new(1_500_000),
    )?;
    let request_context = exchange_context(51, 52, 53, 54)?;
    let resource_scope = resource_scope(b"volume:finance/folder:quarterly".to_vec());
    let fetch = signed_federation_branch_fetch(
        &client_identity,
        request_context,
        branch_fetch(vec![55; 16], resource_scope.canonical_bytes.clone()),
        proof.limits,
        UnixMicros::new(1_500_000),
    )?;
    let response_context = FederationExchangeContext::new(
        request_context.version,
        request_context.request_id,
        request_context.operation_id,
        request_context.trace_id,
        request_context.deadline,
        [58; 32],
    )?;
    let outbound = signed_federation_branch_page(
        proof.server_identity,
        response_context,
        branch_page(vec![55; 16], resource_scope),
        proof.limits,
        UnixMicros::new(1_500_000),
    )?;
    Ok(BranchPageExchange {
        expectation: fetch.expectation().clone(),
        request_context,
        outbound,
    })
}

fn prove_hostile_branch_pages(
    proof: &AuthorityPageProof<'_>,
    exchange: &BranchPageExchange,
) -> Result<(), Box<dyn Error>> {
    let original = exchange.outbound.envelope();
    let mut variants = Vec::new();
    let mut wrong_grant = original.clone();
    branch_page_mut(&mut wrong_grant).grant_id[0] ^= 1;
    variants.push(wrong_grant);
    let mut wrong_resource = original.clone();
    branch_page_resource_mut(&mut wrong_resource).canonical_bytes[0] ^= 1;
    variants.push(wrong_resource);
    let mut corrupt_commit = original.clone();
    branch_page_mut(&mut corrupt_commit).branch_commits[0].canonical_bytes[0] ^= 1;
    variants.push(corrupt_commit);
    let mut bad_signature = original.clone();
    branch_page_mut(&mut bad_signature).signature[0] ^= 1;
    variants.push(bad_signature);
    for variant in variants {
        reject_branch_page(proof, &exchange.expectation, &variant)?;
    }
    let reflected = signed_federation_branch_page(
        proof.server_identity,
        exchange.request_context,
        branch_page_mut(&mut original.clone()).clone(),
        proof.limits,
        UnixMicros::new(1_500_000),
    )?;
    reject_branch_page(proof, &exchange.expectation, reflected.envelope())
}

fn reject_branch_page(
    proof: &AuthorityPageProof<'_>,
    expectation: &FederationBranchPageExpectation,
    envelope: &FederationEnvelope,
) -> Result<(), Box<dyn Error>> {
    let mut replay = federation_replay()?;
    assert!(matches!(
        proof.registry.authenticate_branch_page(
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

fn prove_tampered_fetch_is_rejected(
    registry: &FederationPeerRegistry,
    connection: &quinn::Connection,
    original: &FederationEnvelope,
    limits: WireLimits,
) -> Result<(), Box<dyn Error>> {
    let mut wrong_head = original.clone();
    branch_fetch_mut(&mut wrong_head).requested_head_ids[0][0] ^= 1;
    let mut wrong_known = original.clone();
    branch_fetch_mut(&mut wrong_known).known_commit_ids[0][0] ^= 1;
    for tampered in [wrong_head, wrong_known] {
        let mut replay = federation_replay()?;
        assert!(matches!(
            registry.authenticate_branch_fetch(
                connection,
                &validated_federation(&tampered, limits)?,
                UnixMicros::new(1_500_000),
                &mut replay,
            ),
            Err(TransportError::UntrustedFederationPeer)
        ));
    }
    Ok(())
}

fn branch_identity<'a>(
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

fn branch_fetch(grant_id: Vec<u8>, canonical_scope: Vec<u8>) -> FetchFederatedBranchPage {
    FetchFederatedBranchPage {
        grant_id,
        resource_scope: Some(resource_scope(canonical_scope)),
        requested_head_ids: vec![vec![66; 16]],
        known_commit_ids: vec![vec![67; 16]],
        cursor: vec![68; 16],
        limit: 2,
        signature: Vec::new(),
    }
}

fn branch_page(grant_id: Vec<u8>, scope: VersionedPayload) -> FederatedBranchPage {
    FederatedBranchPage {
        grant_id,
        resource_scope: Some(scope),
        branch_commits: vec![VersionedPayload {
            format_version: 1,
            canonical_bytes: b"immutable-history-commit".to_vec(),
        }],
        immutable_object_digests: vec![vec![59; 32]],
        next_cursor: vec![60; 16],
        page_digest: Vec::new(),
        signature: Vec::new(),
    }
}

fn resource_scope(canonical_bytes: Vec<u8>) -> VersionedPayload {
    VersionedPayload {
        format_version: 1,
        canonical_bytes,
    }
}

fn federation_replay() -> Result<FederationReplayGuard, TransportError> {
    FederationReplayGuard::new(8, DurationMicros::new(1_000_000))
}

fn branch_page_mut(envelope: &mut FederationEnvelope) -> &mut FederatedBranchPage {
    let Some(FederationMessage::BranchPage(page)) = envelope.message.as_mut() else {
        unreachable!("fixture branch page")
    };
    page
}

fn branch_fetch_mut(envelope: &mut FederationEnvelope) -> &mut FetchFederatedBranchPage {
    let Some(FederationMessage::FetchBranchPage(fetch)) = envelope.message.as_mut() else {
        unreachable!("fixture branch fetch")
    };
    fetch
}

fn branch_page_resource_mut(envelope: &mut FederationEnvelope) -> &mut VersionedPayload {
    let Some(resource) = branch_page_mut(envelope).resource_scope.as_mut() else {
        unreachable!("fixture branch resource")
    };
    resource
}
