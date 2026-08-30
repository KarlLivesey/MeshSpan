// SPDX-License-Identifier: GPL-2.0-only

use std::error::Error;

use ed25519_dalek::SigningKey;
use meshspan_domain::{DurationMicros, FederationRelationshipId, MeshId, OperationId, UnixMicros};
use meshspan_protocol::WireLimits;
use meshspan_protocol::v1::{
    FederatedStorageCapability, FederatedStorageReceipt, RemoteShardAction,
    RequestFederatedStorageCapability, ShardIdentity,
};
use rustls::pki_types::CertificateDer;

use crate::{
    FederationExchangeContext, FederationLocalIdentity, FederationLocalIdentityBinding,
    FederationPeerRegistry, FederationReplayGuard, TransportError,
    signed_federation_storage_capability, signed_federation_storage_capability_request,
    signed_federation_storage_receipt,
};

use super::{AuthorityPageProof, certificate_fingerprint, validated_federation, version};

mod inventory;

pub(super) fn prove_signed_storage_capability_request(
    registry: &FederationPeerRegistry,
    connection: &quinn::Connection,
    certificate: &CertificateDer<'_>,
    signing_key: &SigningKey,
    limits: WireLimits,
) -> Result<(), Box<dyn Error>> {
    let identity = client_identity(certificate, signing_key)?;
    let context = exchange_context(91, 92, 93, 94)?;
    let outbound = signed_federation_storage_capability_request(
        &identity,
        context,
        capability_request(),
        limits,
        UnixMicros::new(1_500_000),
    )?;
    let validated = validated_federation(outbound.envelope(), limits)?;
    let mut replay = federation_replay()?;
    let authenticated = registry.authenticate_storage_capability_request(
        connection,
        &validated,
        UnixMicros::new(1_500_000),
        &mut replay,
    )?;
    assert_eq!(
        authenticated.remote_mesh_id(),
        identity.binding().local_mesh_id
    );
    assert_eq!(authenticated.request().scope_digest, vec![104; 32]);
    assert_eq!(
        authenticated.operation_id(),
        OperationId::from_bytes([92; 16])?
    );
    assert_eq!(authenticated.request_replay_nonce()?, [94; 32]);
    assert_ne!(authenticated.request_digest(), [0; 32]);
    assert_eq!(
        authenticated.response_context([95; 32])?.request_id,
        [91; 16]
    );
    assert!(matches!(
        authenticated.response_context(context.replay_nonce),
        Err(TransportError::InvalidConfiguration)
    ));
    assert!(matches!(
        registry.authenticate_storage_capability_request(
            connection,
            &validated,
            UnixMicros::new(1_500_001),
            &mut replay,
        ),
        Err(TransportError::ReplayedFederationMessage)
    ));
    let retry_context = exchange_context(96, 92, 97, 98)?;
    let retry = signed_federation_storage_capability_request(
        &identity,
        retry_context,
        capability_request(),
        limits,
        UnixMicros::new(1_500_002),
    )?;
    let authenticated_retry = registry.authenticate_storage_capability_request(
        connection,
        &validated_federation(retry.envelope(), limits)?,
        UnixMicros::new(1_500_002),
        &mut replay,
    )?;
    assert_eq!(
        authenticated_retry.operation_id(),
        authenticated.operation_id()
    );
    assert_eq!(
        authenticated_retry.request_digest(),
        authenticated.request_digest()
    );
    reject_tampered_request(registry, connection, outbound.envelope(), limits)?;
    inventory::prove_signed_storage_inventory_fetch(registry, connection, &identity, limits)
}

pub(super) fn prove_storage_capability_response(
    proof: &AuthorityPageProof<'_>,
) -> Result<(), Box<dyn Error>> {
    let client_signing_key = SigningKey::from_bytes(&[42; 32]);
    let client_identity =
        client_identity(&proof.certificates.client_certificate, &client_signing_key)?;
    let request_context = exchange_context(111, 112, 113, 114)?;
    let request = signed_federation_storage_capability_request(
        &client_identity,
        request_context,
        capability_request(),
        proof.limits,
        UnixMicros::new(1_500_000),
    )?;
    let response_context = FederationExchangeContext::new(
        request_context.version,
        request_context.request_id,
        request_context.operation_id,
        request_context.trace_id,
        request_context.deadline,
        [115; 32],
    )?;
    let response = signed_federation_storage_capability(
        proof.server_identity,
        response_context,
        capability(),
        proof.limits,
        UnixMicros::new(1_500_000),
    )?;
    let validated = validated_federation(response.envelope(), proof.limits)?;
    let mut replay = federation_replay()?;
    let authenticated = proof.registry.authenticate_storage_capability(
        proof.connection,
        &validated,
        request.expectation(),
        UnixMicros::new(1_500_000),
        &mut replay,
    )?;
    assert_eq!(authenticated.capability().maximum_bytes, 1_024);
    assert_ne!(authenticated.capability_digest(), [0; 32]);
    let receipt_expectation = authenticated.receipt_expectation().clone();
    assert!(matches!(
        proof.registry.authenticate_storage_capability(
            proof.connection,
            &validated,
            request.expectation(),
            UnixMicros::new(1_500_001),
            &mut replay,
        ),
        Err(TransportError::ReplayedFederationMessage)
    ));
    prove_signed_hostile_capabilities(proof, request.expectation(), response_context)?;
    prove_storage_receipt(proof, &receipt_expectation, request_context)?;
    inventory::prove_storage_inventory_page(proof, &client_identity)
}

fn prove_storage_receipt(
    proof: &AuthorityPageProof<'_>,
    expectation: &crate::FederationStorageReceiptExpectation,
    request_context: FederationExchangeContext,
) -> Result<(), Box<dyn Error>> {
    let receipt_context = FederationExchangeContext::new(
        request_context.version,
        request_context.request_id,
        request_context.operation_id,
        request_context.trace_id,
        request_context.deadline,
        [117; 32],
    )?;
    let signed = signed_federation_storage_receipt(
        proof.server_identity,
        receipt_context,
        receipt(expectation.capability_digest()),
        proof.limits,
        UnixMicros::new(1_600_000),
    )?;
    let validated = validated_federation(signed.envelope(), proof.limits)?;
    let mut replay = federation_replay()?;
    let authenticated = proof.registry.authenticate_storage_receipt(
        proof.connection,
        &validated,
        expectation,
        UnixMicros::new(1_600_000),
        &mut replay,
    )?;
    assert_eq!(authenticated.receipt().affected_bytes, 1_024);
    assert_eq!(authenticated.receipt().result_digest, vec![120; 32]);
    assert!(matches!(
        proof.registry.authenticate_storage_receipt(
            proof.connection,
            &validated,
            expectation,
            UnixMicros::new(1_600_001),
            &mut replay,
        ),
        Err(TransportError::ReplayedFederationMessage)
    ));
    prove_hostile_receipts(proof, expectation, receipt_context)
}

fn prove_hostile_receipts(
    proof: &AuthorityPageProof<'_>,
    expectation: &crate::FederationStorageReceiptExpectation,
    context: FederationExchangeContext,
) -> Result<(), Box<dyn Error>> {
    let mut wrong_capability = receipt(expectation.capability_digest());
    wrong_capability.capability_digest[0] ^= 1;
    let mut excessive = receipt(expectation.capability_digest());
    excessive.affected_bytes = 1_025;
    let mut wrong_action = receipt(expectation.capability_digest());
    wrong_action.action = RemoteShardAction::Get.into();
    let mut wrong_allocation = receipt(expectation.capability_digest());
    wrong_allocation.allocation_id = vec![122; 16];
    let mut predates_issue = receipt(expectation.capability_digest());
    predates_issue.completed_at_unix_micros = 1_499_999;
    for hostile in [
        wrong_capability,
        excessive,
        wrong_action,
        wrong_allocation,
        predates_issue,
    ] {
        let signed = signed_federation_storage_receipt(
            proof.server_identity,
            context,
            hostile,
            proof.limits,
            UnixMicros::new(1_600_000),
        )?;
        let mut replay = federation_replay()?;
        assert!(matches!(
            proof.registry.authenticate_storage_receipt(
                proof.connection,
                &validated_federation(signed.envelope(), proof.limits)?,
                expectation,
                UnixMicros::new(1_600_000),
                &mut replay,
            ),
            Err(TransportError::UntrustedFederationPeer)
        ));
    }
    Ok(())
}

fn prove_signed_hostile_capabilities(
    proof: &AuthorityPageProof<'_>,
    expectation: &crate::FederationStorageCapabilityExpectation,
    response_context: FederationExchangeContext,
) -> Result<(), Box<dyn Error>> {
    let mut excessive = capability();
    excessive.maximum_bytes = 2_049;
    let mut wrong_action = capability();
    wrong_action.action = RemoteShardAction::Get.into();
    let mut wrong_allocation = capability();
    wrong_allocation.allocation_id = vec![122; 16];
    let mut reflected_nonce = capability();
    reflected_nonce.capability_nonce = vec![114; 32];
    for hostile in [excessive, wrong_action, wrong_allocation, reflected_nonce] {
        let signed = signed_federation_storage_capability(
            proof.server_identity,
            response_context,
            hostile,
            proof.limits,
            UnixMicros::new(1_500_000),
        )?;
        let mut replay = federation_replay()?;
        assert!(matches!(
            proof.registry.authenticate_storage_capability(
                proof.connection,
                &validated_federation(signed.envelope(), proof.limits)?,
                expectation,
                UnixMicros::new(1_500_000),
                &mut replay,
            ),
            Err(TransportError::UntrustedFederationPeer)
        ));
    }
    let mut overlong = capability();
    overlong.valid_until_unix_micros = response_context.deadline.get() + 1;
    assert!(matches!(
        signed_federation_storage_capability(
            proof.server_identity,
            response_context,
            overlong,
            proof.limits,
            UnixMicros::new(1_500_000),
        ),
        Err(TransportError::InvalidConfiguration)
    ));
    Ok(())
}

fn reject_tampered_request(
    registry: &FederationPeerRegistry,
    connection: &quinn::Connection,
    original: &meshspan_protocol::v1::FederationEnvelope,
    limits: WireLimits,
) -> Result<(), Box<dyn Error>> {
    let mut tampered = original.clone();
    let Some(meshspan_protocol::v1::federation_envelope::Message::RequestStorageCapability(
        request,
    )) = tampered.message.as_mut()
    else {
        unreachable!("fixture storage request")
    };
    request.scope_digest[0] ^= 1;
    let mut replay = federation_replay()?;
    assert!(matches!(
        registry.authenticate_storage_capability_request(
            connection,
            &validated_federation(&tampered, limits)?,
            UnixMicros::new(1_500_000),
            &mut replay,
        ),
        Err(TransportError::UntrustedFederationPeer)
    ));
    let mut substituted = original.clone();
    let Some(meshspan_protocol::v1::federation_envelope::Message::RequestStorageCapability(
        request,
    )) = substituted.message.as_mut()
    else {
        unreachable!("fixture storage request")
    };
    request.allocation_id = vec![122; 16];
    let mut replay = federation_replay()?;
    assert!(matches!(
        registry.authenticate_storage_capability_request(
            connection,
            &validated_federation(&substituted, limits)?,
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

fn capability_request() -> RequestFederatedStorageCapability {
    RequestFederatedStorageCapability {
        grant_id: vec![101; 16],
        allocation_id: vec![121; 16],
        target_id: vec![102; 16],
        target_generation: 7,
        shard: Some(shard()),
        action: RemoteShardAction::Put.into(),
        maximum_bytes: 2_048,
        scope_digest: vec![104; 32],
        signature: Vec::new(),
    }
}

fn capability() -> FederatedStorageCapability {
    FederatedStorageCapability {
        grant_id: vec![101; 16],
        allocation_id: vec![121; 16],
        target_id: vec![102; 16],
        target_generation: 7,
        shard: Some(shard()),
        action: RemoteShardAction::Put.into(),
        maximum_bytes: 1_024,
        valid_until_unix_micros: 1_900_000,
        capability_nonce: vec![116; 32],
        canonical_capability: b"exact-data-plane-permit".to_vec(),
        signature: Vec::new(),
    }
}

fn receipt(capability_digest: [u8; 32]) -> FederatedStorageReceipt {
    FederatedStorageReceipt {
        grant_id: vec![101; 16],
        allocation_id: vec![121; 16],
        target_id: vec![102; 16],
        target_generation: 7,
        shard: Some(shard()),
        action: RemoteShardAction::Put.into(),
        affected_bytes: 1_024,
        completed_at_unix_micros: 1_550_000,
        capability_digest: capability_digest.to_vec(),
        result_digest: vec![120; 32],
        signature: Vec::new(),
    }
}

fn shard() -> ShardIdentity {
    ShardIdentity {
        manifest_digest: vec![103; 32],
        stripe_index: 8,
        shard_index: 9,
        generation: 10,
    }
}

fn federation_replay() -> Result<FederationReplayGuard, TransportError> {
    FederationReplayGuard::new(8, DurationMicros::new(1_000_000))
}
