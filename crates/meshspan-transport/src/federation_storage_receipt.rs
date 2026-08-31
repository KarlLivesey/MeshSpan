// SPDX-License-Identifier: GPL-2.0-only

//! Signed remote-storage lifecycle receipts bound to one authenticated issued capability.

use ed25519_dalek::{Signature, Signer, VerifyingKey};
use meshspan_domain::UnixMicros;
use meshspan_protocol::v1::federation_envelope::Message;
use meshspan_protocol::v1::{FederatedStorageReceipt, FederationEnvelope, FederationHeader};
use meshspan_protocol::{
    ValidatedFederationEnvelope, WireLimits, encode_federation_frame,
    federation_storage_receipt_signing_payload,
};

use crate::federation_authority_page::{exact, federation_header};
use crate::federation_storage_capability::{
    FederationStorageReceiptExpectation, validate_outbound_context,
    verify_correlated_response_header,
};
use crate::{
    FederationExchangeContext, FederationLocalIdentity, FederationPeerRegistry,
    FederationReplayGuard, TransportError,
};

/// Signed storage receipt envelope ready for bounded federation framing.
#[derive(Clone, Debug, PartialEq)]
pub struct OutboundFederationStorageReceipt {
    envelope: FederationEnvelope,
}

impl OutboundFederationStorageReceipt {
    /// Returns the exact signed wire receipt.
    #[must_use]
    pub const fn envelope(&self) -> &FederationEnvelope {
        &self.envelope
    }
}

/// Lifecycle receipt whose peer, capability, result, time and signature all agree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedFederationStorageReceipt {
    receipt: FederatedStorageReceipt,
}

impl AuthenticatedFederationStorageReceipt {
    /// Returns the exact provider-signed lifecycle receipt.
    #[must_use]
    pub const fn receipt(&self) -> &FederatedStorageReceipt {
        &self.receipt
    }
}

/// Constructs and signs one exact remote-storage lifecycle receipt.
///
/// # Errors
///
/// Rejects stale/future completion times, invalid correlation or an excessive envelope.
pub fn signed_federation_storage_receipt(
    identity: &FederationLocalIdentity<'_>,
    context: FederationExchangeContext,
    mut receipt: FederatedStorageReceipt,
    limits: WireLimits,
    now: UnixMicros,
) -> Result<OutboundFederationStorageReceipt, TransportError> {
    let binding = identity.binding();
    validate_outbound_context(binding, context, now)?;
    let completed_at = UnixMicros::new(receipt.completed_at_unix_micros);
    if completed_at.get() <= 0 || completed_at > now {
        return Err(TransportError::InvalidConfiguration);
    }
    let header = federation_header(binding, context);
    receipt.signature.clear();
    receipt.signature = identity
        .signing_key()
        .sign(&federation_storage_receipt_signing_payload(
            &header, &receipt,
        )?)
        .to_bytes()
        .to_vec();
    let envelope = FederationEnvelope {
        header: Some(header),
        message: Some(Message::StorageReceipt(receipt)),
    };
    encode_federation_frame(&envelope, limits)?;
    Ok(OutboundFederationStorageReceipt { envelope })
}

impl FederationPeerRegistry {
    /// Authenticates one lifecycle receipt against the exact issued capability and TLS peer.
    ///
    /// # Errors
    ///
    /// Rejects correlation, capability, affected-byte, completion-time, signature, authority or
    /// replay substitution.
    pub fn authenticate_storage_receipt(
        &self,
        connection: &quinn::Connection,
        envelope: &ValidatedFederationEnvelope,
        expected: &FederationStorageReceiptExpectation,
        now: UnixMicros,
        replay: &mut FederationReplayGuard,
    ) -> Result<AuthenticatedFederationStorageReceipt, TransportError> {
        let (binding, _) = self.connection_binding(connection, now)?;
        let envelope = envelope.as_inner();
        let header = envelope
            .header
            .as_ref()
            .ok_or(TransportError::UntrustedFederationPeer)?;
        let Message::StorageReceipt(receipt) = envelope
            .message
            .as_ref()
            .ok_or(TransportError::UntrustedFederationPeer)?
        else {
            return Err(TransportError::UntrustedFederationPeer);
        };
        verify_receipt_shape(binding, header, receipt, expected, now)?;
        replay.check(binding.relationship_id, header, now)?;
        verify_receipt_signature(binding.verifying_key, header, receipt)?;
        replay.record(binding.relationship_id, header)?;
        Ok(AuthenticatedFederationStorageReceipt {
            receipt: receipt.clone(),
        })
    }
}

fn verify_receipt_shape(
    binding: crate::FederationPeerBinding,
    header: &FederationHeader,
    receipt: &FederatedStorageReceipt,
    expected: &FederationStorageReceiptExpectation,
    now: UnixMicros,
) -> Result<(), TransportError> {
    verify_correlated_response_header(
        binding,
        header,
        expected.local_identity,
        expected.request_context,
    )?;
    let capability = &expected.capability;
    let completed_at = UnixMicros::new(receipt.completed_at_unix_micros);
    let valid_until = UnixMicros::new(capability.valid_until_unix_micros);
    let valid = exact::<32>(&header.replay_nonce)? != expected.capability_response_nonce
        && receipt.grant_id == capability.grant_id
        && receipt.allocation_id == capability.allocation_id
        && receipt.target_id == capability.target_id
        && receipt.target_generation == capability.target_generation
        && receipt.shard == capability.shard
        && receipt.action == capability.action
        && receipt.affected_bytes <= capability.maximum_bytes
        && completed_at >= expected.issued_at
        && completed_at < valid_until
        && completed_at <= now
        && exact::<32>(&receipt.capability_digest)? == expected.capability_digest;
    if valid {
        Ok(())
    } else {
        Err(TransportError::UntrustedFederationPeer)
    }
}

fn verify_receipt_signature(
    verifying_key: [u8; 32],
    header: &FederationHeader,
    receipt: &FederatedStorageReceipt,
) -> Result<(), TransportError> {
    let signature = exact::<64>(&receipt.signature)?;
    let payload = federation_storage_receipt_signing_payload(header, receipt)?;
    VerifyingKey::from_bytes(&verifying_key)
        .map_err(|_| TransportError::UntrustedFederationPeer)?
        .verify_strict(&payload, &Signature::from_bytes(&signature))
        .map_err(|_| TransportError::UntrustedFederationPeer)
}
