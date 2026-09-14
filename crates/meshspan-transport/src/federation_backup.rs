// SPDX-License-Identifier: GPL-2.0-only

//! Signed backup conversations authenticated as swarms, never enrolled storage nodes.

mod relay;
mod relay_response;
mod response;

use ed25519_dalek::{Signature, Signer, VerifyingKey};
use meshspan_domain::{FederationRelationshipId, MeshId, UnixMicros};
use meshspan_protocol::v1::{FederationEnvelope, FederationHeader, federation_envelope::Message};
use meshspan_protocol::{
    ValidatedFederationEnvelope, WireLimits, encode_federation_frame,
    federation_backup_request_digest_payload, federation_backup_signing_payload,
};
use sha2::{Digest, Sha256};

use crate::federation_authority_page::{exact, federation_header};
use crate::federation_storage_capability::{
    validate_outbound_context, verify_inbound_request_header,
};
use crate::{
    FederationExchangeContext, FederationLocalIdentity, FederationLocalIdentityBinding,
    FederationPeerBinding, FederationPeerRegistry, FederationReplayGuard, TransportError,
};

pub use relay::{AuthenticatedFederationBackupRelay, federation_backup_relay_digest};
pub use relay_response::FederationBackupOwnerResponseExpectation;
pub use response::{AuthenticatedFederationBackupResponse, FederationBackupResponseExpectation};

/// Signed backup message with immutable correlation state for its expected response.
#[derive(Clone, Debug, PartialEq)]
pub struct OutboundFederationBackupMessage {
    envelope: FederationEnvelope,
    identity: FederationLocalIdentityBinding,
    context: FederationExchangeContext,
}

impl OutboundFederationBackupMessage {
    /// Exact signed envelope, ready for bounded federation framing.
    #[must_use]
    pub const fn envelope(&self) -> &FederationEnvelope {
        &self.envelope
    }

    /// Starts response validation for capability issuance or execution admission.
    ///
    /// # Errors
    /// Rejects response messages; they do not themselves begin a new conversation.
    pub fn expectation(&self) -> Result<FederationBackupResponseExpectation, TransportError> {
        response::expectation(self)
    }
}

/// Backup request whose current peer identity, signature, header and replay nonce agree.
///
/// This proves the requesting swarm, not its grant or provider permission. The receiving
/// application must recheck allocation, target and operation-specific authority before IO.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthenticatedFederationBackupRequest {
    binding: FederationPeerBinding,
    header: FederationHeader,
    message: Message,
}

impl AuthenticatedFederationBackupRequest {
    /// Reconstructs the exact canonical signed frame for forwarding without changing its identity.
    #[must_use]
    pub fn signed_envelope(&self) -> FederationEnvelope {
        FederationEnvelope {
            header: Some(self.header.clone()),
            message: Some(self.message.clone()),
        }
    }

    /// Exact public peer-identity snapshot verified at admission, for current-authority fencing.
    /// This is evidence of past authentication, not proof that the identity remains current.
    #[must_use]
    pub const fn peer_binding(&self) -> FederationPeerBinding {
        self.binding
    }

    /// Certificate-bound consumer swarm.
    #[must_use]
    pub const fn remote_mesh_id(&self) -> MeshId {
        self.binding.remote_mesh_id
    }

    /// Certificate-bound provider swarm.
    #[must_use]
    pub const fn local_mesh_id(&self) -> MeshId {
        self.binding.local_mesh_id
    }

    /// Exact mutually approved relationship.
    #[must_use]
    pub const fn relationship_id(&self) -> FederationRelationshipId {
        self.binding.relationship_id
    }

    /// Current relationship authority fence verified at admission.
    #[must_use]
    pub const fn authority_epoch(&self) -> u64 {
        self.binding.authority_epoch
    }

    /// Exact immutable request (`RequestBackupCapability` or `ExecuteBackup` only).
    #[must_use]
    pub const fn message(&self) -> &Message {
        &self.message
    }

    /// Exact request nonce which neither a capability nor a response may reflect.
    ///
    /// # Errors
    /// Rejects impossible internal state with a malformed already-validated nonce.
    pub fn request_replay_nonce(&self) -> Result<[u8; 32], TransportError> {
        exact(&self.header.replay_nonce)
    }

    /// Correlates a reply while requiring a fresh, non-reflected response nonce.
    ///
    /// # Errors
    /// Rejects reflected nonce or invalid correlation state.
    pub fn response_context(
        &self,
        nonce: [u8; 32],
    ) -> Result<FederationExchangeContext, TransportError> {
        if nonce == exact::<32>(&self.header.replay_nonce)? {
            return Err(TransportError::InvalidConfiguration);
        }
        FederationExchangeContext::new(
            self.header
                .version
                .ok_or(TransportError::InvalidConfiguration)?,
            exact(&self.header.request_id)?,
            exact(&self.header.operation_id)?,
            exact(&self.header.trace_id)?,
            UnixMicros::new(self.header.deadline_unix_micros),
            nonce,
        )
    }

    /// Stable complete capability-request digest for the provider's signed response.
    ///
    /// # Errors
    /// Rejects execution messages and canonical encoding failure.
    pub fn capability_request_digest(&self) -> Result<[u8; 32], TransportError> {
        let Message::RequestBackupCapability(value) = &self.message else {
            return Err(TransportError::InvalidConfiguration);
        };
        Ok(Sha256::digest(federation_backup_request_digest_payload(value)?).into())
    }
}

/// Signs one of the five bounded backup conversation messages.
///
/// # Errors
/// Rejects other message families, invalid scope/correlation, expired permits, future receipts
/// and excessive framing. No signing key is copied or exported.
pub fn signed_federation_backup_message(
    identity: &FederationLocalIdentity<'_>,
    context: FederationExchangeContext,
    mut message: Message,
    limits: WireLimits,
    now: UnixMicros,
) -> Result<OutboundFederationBackupMessage, TransportError> {
    validate_outbound_context(identity.binding(), context, now)?;
    validate_time(&message, now)?;
    // Bound and validate before cloning/encoding the canonical signed payload. Signature bytes
    // are replaced, not trusted; they have a fixed final length.
    *signature_mut(&mut message)? = vec![1; 64];
    let header = federation_header(identity.binding(), context);
    let mut envelope = FederationEnvelope {
        header: Some(header),
        message: Some(message),
    };
    encode_federation_frame(&envelope, limits)?;
    let message = envelope
        .message
        .as_mut()
        .ok_or(TransportError::InvalidConfiguration)?;
    let signature = identity
        .signing_key()
        .sign(&federation_backup_signing_payload(
            envelope
                .header
                .as_ref()
                .ok_or(TransportError::InvalidConfiguration)?,
            message,
        )?)
        .to_bytes();
    *signature_mut(message)? = signature.to_vec();
    Ok(OutboundFederationBackupMessage {
        envelope,
        identity: identity.binding(),
        context,
    })
}

impl FederationPeerRegistry {
    /// Authenticates a capability request or execution request against this current registry.
    ///
    /// # Errors
    /// Rejects wrong family/direction/peer, stale time, signature substitution and replay.
    pub fn authenticate_backup_request(
        &self,
        connection: &quinn::Connection,
        envelope: &ValidatedFederationEnvelope,
        now: UnixMicros,
        replay: &mut FederationReplayGuard,
    ) -> Result<AuthenticatedFederationBackupRequest, TransportError> {
        let (binding, _) = self.connection_binding(connection, now)?;
        authenticate_request(binding, envelope.as_inner(), now, replay)
    }
}

fn authenticate_request(
    binding: FederationPeerBinding,
    envelope: &FederationEnvelope,
    now: UnixMicros,
    replay: &mut FederationReplayGuard,
) -> Result<AuthenticatedFederationBackupRequest, TransportError> {
    let header = envelope
        .header
        .as_ref()
        .ok_or(TransportError::UntrustedFederationPeer)?;
    let message = envelope
        .message
        .as_ref()
        .ok_or(TransportError::UntrustedFederationPeer)?;
    if !matches!(
        message,
        Message::RequestBackupCapability(_)
            | Message::ExecuteBackup(_)
            | Message::FetchBackupAllocations(_)
    ) {
        return Err(TransportError::UntrustedFederationPeer);
    }
    verify_inbound_request_header(binding, header)?;
    if header.deadline_unix_micros > binding.valid_until.get() {
        return Err(TransportError::UntrustedFederationPeer);
    }
    validate_time(message, now)?;
    replay.check(binding.relationship_id, header, now)?;
    verify_signature(binding, header, message)?;
    replay.record(binding.relationship_id, header)?;
    Ok(AuthenticatedFederationBackupRequest {
        binding,
        header: header.clone(),
        message: message.clone(),
    })
}

fn signature_mut(message: &mut Message) -> Result<&mut Vec<u8>, TransportError> {
    match message {
        Message::RequestBackupCapability(value) => Ok(&mut value.signature),
        Message::BackupCapability(value) => Ok(&mut value.signature),
        Message::ExecuteBackup(value) => Ok(&mut value.signature),
        Message::BackupReady(value) => Ok(&mut value.signature),
        Message::BackupResult(value) => Ok(&mut value.signature),
        Message::FetchBackupAllocations(value) => Ok(&mut value.signature),
        Message::BackupAllocationPage(value) => Ok(&mut value.signature),
        _ => Err(TransportError::InvalidConfiguration),
    }
}

fn verify_signature(
    binding: FederationPeerBinding,
    header: &FederationHeader,
    message: &Message,
) -> Result<(), TransportError> {
    let bytes = match message {
        Message::RequestBackupCapability(value) => &value.signature,
        Message::BackupCapability(value) => &value.signature,
        Message::ExecuteBackup(value) => &value.signature,
        Message::BackupReady(value) => &value.signature,
        Message::BackupResult(value) => &value.signature,
        Message::FetchBackupAllocations(value) => &value.signature,
        Message::BackupAllocationPage(value) => &value.signature,
        _ => return Err(TransportError::UntrustedFederationPeer),
    };
    VerifyingKey::from_bytes(&binding.verifying_key)
        .map_err(|_| TransportError::UntrustedFederationPeer)?
        .verify_strict(
            &federation_backup_signing_payload(header, message)?,
            &Signature::from_bytes(&exact(bytes)?),
        )
        .map_err(|_| TransportError::UntrustedFederationPeer)
}

fn validate_time(message: &Message, now: UnixMicros) -> Result<(), TransportError> {
    if let Message::BackupAllocationPage(page) = message
        && page.allocations.iter().any(|allocation| {
            allocation.valid_from_unix_micros > now.get()
                || allocation.valid_until_unix_micros <= now.get()
        })
    {
        return Err(TransportError::StaleFederationMessage);
    }
    let permit = match message {
        Message::BackupCapability(value) => value.permit.as_ref(),
        Message::ExecuteBackup(value) => value.permit.as_ref(),
        Message::BackupResult(value) if value.completed_at_unix_micros > now.get() => {
            return Err(TransportError::UntrustedFederationPeer);
        }
        _ => None,
    };
    if permit.is_some_and(|permit| {
        permit.issued_at_unix_micros > now.get() || permit.expires_at_unix_micros <= now.get()
    }) {
        return Err(TransportError::UntrustedFederationPeer);
    }
    Ok(())
}
