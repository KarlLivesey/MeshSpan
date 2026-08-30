// SPDX-License-Identifier: GPL-2.0-only

//! Signed, exactly correlated federation storage capabilities over authenticated relationships.

use ed25519_dalek::{Signature, Signer, VerifyingKey};
use meshspan_domain::{OperationId, UnixMicros};
use meshspan_protocol::v1::federation_envelope::Message;
use meshspan_protocol::v1::{
    FederatedStorageCapability, FederationEnvelope, FederationHeader,
    RequestFederatedStorageCapability,
};
use meshspan_protocol::{
    ValidatedFederationEnvelope, WireLimits, encode_federation_frame,
    federation_storage_capability_digest_payload,
    federation_storage_capability_request_digest_payload,
    federation_storage_capability_request_signing_payload,
    federation_storage_capability_signing_payload,
};
use sha2::{Digest, Sha256};

use crate::federation_authority_page::{exact, federation_header};
use crate::{
    FederationExchangeContext, FederationLocalIdentity, FederationLocalIdentityBinding,
    FederationPeerBinding, FederationPeerRegistry, FederationReplayGuard, TransportError,
};

/// Signed capability request plus the exact state needed to authenticate its response.
#[derive(Clone, Debug, PartialEq)]
pub struct OutboundFederationStorageCapabilityRequest {
    envelope: FederationEnvelope,
    expectation: FederationStorageCapabilityExpectation,
}

impl OutboundFederationStorageCapabilityRequest {
    /// Returns the exact signed wire request.
    #[must_use]
    pub const fn envelope(&self) -> &FederationEnvelope {
        &self.envelope
    }

    /// Returns the exact request state against which the response must be checked.
    #[must_use]
    pub const fn expectation(&self) -> &FederationStorageCapabilityExpectation {
        &self.expectation
    }
}

/// Capability request whose TLS peer, relationship, signature and replay nonce agree.
#[derive(Clone, Debug)]
pub struct AuthenticatedFederationStorageCapabilityRequest {
    binding: FederationPeerBinding,
    header: FederationHeader,
    request: RequestFederatedStorageCapability,
    operation_id: OperationId,
    request_digest: [u8; 32],
}

impl AuthenticatedFederationStorageCapabilityRequest {
    /// Returns the exact admitted relationship.
    #[must_use]
    pub const fn relationship_id(&self) -> meshspan_domain::FederationRelationshipId {
        self.binding.relationship_id
    }

    /// Returns the certificate-authenticated requesting swarm.
    #[must_use]
    pub const fn remote_mesh_id(&self) -> meshspan_domain::MeshId {
        self.binding.remote_mesh_id
    }

    /// Returns the structurally validated signed request.
    #[must_use]
    pub const fn request(&self) -> &RequestFederatedStorageCapability {
        &self.request
    }

    /// Returns the typed idempotent operation identity proven by the signed header.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Returns a digest of the complete logical request, independent of fresh envelope fields.
    #[must_use]
    pub const fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }

    /// Returns the request nonce which an issued capability must not reflect.
    ///
    /// # Errors
    ///
    /// Rejects impossible stored state if the already-validated nonce is not exactly 32 bytes.
    pub fn request_replay_nonce(&self) -> Result<[u8; 32], TransportError> {
        exact(&self.header.replay_nonce)
    }

    /// Correlates the response with the request while requiring a fresh responder nonce.
    ///
    /// # Errors
    ///
    /// Rejects a reflected nonce or malformed request context.
    pub fn response_context(
        &self,
        replay_nonce: [u8; 32],
    ) -> Result<FederationExchangeContext, TransportError> {
        if replay_nonce == exact::<32>(&self.header.replay_nonce)? {
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
            replay_nonce,
        )
    }
}

/// Exact local request state against which one issued capability is authenticated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationStorageCapabilityExpectation {
    local_identity: FederationLocalIdentityBinding,
    request_context: FederationExchangeContext,
    request: RequestFederatedStorageCapability,
}

impl FederationStorageCapabilityExpectation {
    fn new(
        local_identity: FederationLocalIdentityBinding,
        request_context: FederationExchangeContext,
        request: RequestFederatedStorageCapability,
    ) -> Self {
        Self {
            local_identity,
            request_context,
            request,
        }
    }
}

/// Signed capability envelope ready for bounded federation framing.
#[derive(Clone, Debug, PartialEq)]
pub struct OutboundFederationStorageCapability {
    envelope: FederationEnvelope,
    capability_digest: [u8; 32],
}

impl OutboundFederationStorageCapability {
    /// Returns the exact signed wire response.
    #[must_use]
    pub const fn envelope(&self) -> &FederationEnvelope {
        &self.envelope
    }

    /// Returns the exact signed capability digest required by every lifecycle receipt.
    #[must_use]
    pub const fn capability_digest(&self) -> [u8; 32] {
        self.capability_digest
    }
}

/// Storage capability whose peer, request, expiry, nonce and signature all agree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedFederationStorageCapability {
    capability: FederatedStorageCapability,
    capability_digest: [u8; 32],
    receipt_expectation: FederationStorageReceiptExpectation,
}

impl AuthenticatedFederationStorageCapability {
    /// Returns the exact provider-signed capability fields.
    #[must_use]
    pub const fn capability(&self) -> &FederatedStorageCapability {
        &self.capability
    }

    /// Returns the digest which every lifecycle receipt must echo exactly.
    #[must_use]
    pub const fn capability_digest(&self) -> [u8; 32] {
        self.capability_digest
    }

    /// Returns the exact authority and correlation required for a later lifecycle receipt.
    #[must_use]
    pub const fn receipt_expectation(&self) -> &FederationStorageReceiptExpectation {
        &self.receipt_expectation
    }
}

/// Exact issued capability state against which a lifecycle receipt is authenticated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationStorageReceiptExpectation {
    pub(crate) local_identity: FederationLocalIdentityBinding,
    pub(crate) request_context: FederationExchangeContext,
    pub(crate) capability: FederatedStorageCapability,
    pub(crate) capability_digest: [u8; 32],
    pub(crate) capability_response_nonce: [u8; 32],
    pub(crate) issued_at: UnixMicros,
}

impl FederationStorageReceiptExpectation {
    /// Returns the exact digest that the provider receipt must echo.
    #[must_use]
    pub const fn capability_digest(&self) -> [u8; 32] {
        self.capability_digest
    }
}

/// Constructs and signs one exact remote-storage capability request.
///
/// # Errors
///
/// Rejects stale deadlines or a request outside negotiated wire bounds.
pub fn signed_federation_storage_capability_request(
    identity: &FederationLocalIdentity<'_>,
    context: FederationExchangeContext,
    mut request: RequestFederatedStorageCapability,
    limits: WireLimits,
    now: UnixMicros,
) -> Result<OutboundFederationStorageCapabilityRequest, TransportError> {
    let binding = identity.binding();
    validate_outbound_context(binding, context, now)?;
    let header = federation_header(binding, context);
    request.signature.clear();
    request.signature = identity
        .signing_key()
        .sign(&federation_storage_capability_request_signing_payload(
            &header, &request,
        ))
        .to_bytes()
        .to_vec();
    let expectation =
        FederationStorageCapabilityExpectation::new(binding, context, request.clone());
    let envelope = FederationEnvelope {
        header: Some(header),
        message: Some(Message::RequestStorageCapability(request)),
    };
    encode_federation_frame(&envelope, limits)?;
    Ok(OutboundFederationStorageCapabilityRequest {
        envelope,
        expectation,
    })
}

/// Constructs and signs one exact, bounded remote-storage capability response.
///
/// # Errors
///
/// Rejects stale or overlong capability validity and any response outside wire bounds.
pub fn signed_federation_storage_capability(
    identity: &FederationLocalIdentity<'_>,
    context: FederationExchangeContext,
    mut capability: FederatedStorageCapability,
    limits: WireLimits,
    now: UnixMicros,
) -> Result<OutboundFederationStorageCapability, TransportError> {
    let binding = identity.binding();
    validate_outbound_context(binding, context, now)?;
    let issued_at = UnixMicros::new(capability.issued_at_unix_micros);
    let valid_until = UnixMicros::new(capability.valid_until_unix_micros);
    if issued_at.get() <= 0
        || issued_at > now
        || valid_until <= now
        || valid_until <= issued_at
        || valid_until > context.deadline
        || valid_until > binding.valid_until
    {
        return Err(TransportError::InvalidConfiguration);
    }
    let header = federation_header(binding, context);
    capability.signature.clear();
    capability.signature = identity
        .signing_key()
        .sign(&federation_storage_capability_signing_payload(
            &header,
            &capability,
        ))
        .to_bytes()
        .to_vec();
    let capability_digest = storage_capability_digest(&capability);
    let envelope = FederationEnvelope {
        header: Some(header),
        message: Some(Message::StorageCapability(capability)),
    };
    encode_federation_frame(&envelope, limits)?;
    Ok(OutboundFederationStorageCapability {
        envelope,
        capability_digest,
    })
}

impl FederationPeerRegistry {
    /// Authenticates one capability request against current TLS and relationship authority.
    ///
    /// # Errors
    ///
    /// Rejects identity, route, signature, deadline or replay substitution.
    pub fn authenticate_storage_capability_request(
        &self,
        connection: &quinn::Connection,
        envelope: &ValidatedFederationEnvelope,
        now: UnixMicros,
        replay: &mut FederationReplayGuard,
    ) -> Result<AuthenticatedFederationStorageCapabilityRequest, TransportError> {
        let (binding, _) = self.connection_binding(connection, now)?;
        let envelope = envelope.as_inner();
        let header = envelope
            .header
            .as_ref()
            .ok_or(TransportError::UntrustedFederationPeer)?;
        let Message::RequestStorageCapability(request) = envelope
            .message
            .as_ref()
            .ok_or(TransportError::UntrustedFederationPeer)?
        else {
            return Err(TransportError::UntrustedFederationPeer);
        };
        verify_inbound_request_header(binding, header)?;
        replay.check(binding.relationship_id, header, now)?;
        verify_capability_request_signature(binding.verifying_key, header, request)?;
        let operation_id = OperationId::from_bytes(exact(&header.operation_id)?)
            .map_err(|_| TransportError::UntrustedFederationPeer)?;
        let request_digest: [u8; 32] = Sha256::digest(
            federation_storage_capability_request_digest_payload(request),
        )
        .into();
        replay.record(binding.relationship_id, header)?;
        Ok(AuthenticatedFederationStorageCapabilityRequest {
            binding,
            header: header.clone(),
            request: request.clone(),
            operation_id,
            request_digest,
        })
    }

    /// Authenticates one issued capability against the exact request and current TLS peer.
    ///
    /// # Errors
    ///
    /// Rejects correlation, subject, ceiling, expiry, nonce, signature, authority or replay
    /// substitution.
    pub fn authenticate_storage_capability(
        &self,
        connection: &quinn::Connection,
        envelope: &ValidatedFederationEnvelope,
        expected: &FederationStorageCapabilityExpectation,
        now: UnixMicros,
        replay: &mut FederationReplayGuard,
    ) -> Result<AuthenticatedFederationStorageCapability, TransportError> {
        let (binding, _) = self.connection_binding(connection, now)?;
        let envelope = envelope.as_inner();
        let header = envelope
            .header
            .as_ref()
            .ok_or(TransportError::UntrustedFederationPeer)?;
        let Message::StorageCapability(capability) = envelope
            .message
            .as_ref()
            .ok_or(TransportError::UntrustedFederationPeer)?
        else {
            return Err(TransportError::UntrustedFederationPeer);
        };
        verify_capability_response_shape(binding, header, capability, expected, now)?;
        replay.check(binding.relationship_id, header, now)?;
        verify_capability_signature(binding.verifying_key, header, capability)?;
        replay.record(binding.relationship_id, header)?;
        let capability_digest = storage_capability_digest(capability);
        Ok(AuthenticatedFederationStorageCapability {
            capability: capability.clone(),
            capability_digest,
            receipt_expectation: FederationStorageReceiptExpectation {
                local_identity: expected.local_identity,
                request_context: expected.request_context,
                capability: capability.clone(),
                capability_digest,
                capability_response_nonce: exact(&header.replay_nonce)?,
                issued_at: UnixMicros::new(capability.issued_at_unix_micros),
            },
        })
    }
}

pub(crate) fn validate_outbound_context(
    binding: FederationLocalIdentityBinding,
    context: FederationExchangeContext,
    now: UnixMicros,
) -> Result<(), TransportError> {
    if context.deadline <= now || context.deadline > binding.valid_until {
        Err(TransportError::InvalidConfiguration)
    } else {
        Ok(())
    }
}

pub(crate) fn verify_inbound_request_header(
    binding: FederationPeerBinding,
    header: &FederationHeader,
) -> Result<(), TransportError> {
    let valid = header.relationship_id == binding.relationship_id.as_bytes()
        && header.sender_mesh_id == binding.remote_mesh_id.as_bytes()
        && header.recipient_mesh_id == binding.local_mesh_id.as_bytes()
        && header.authority_epoch == binding.authority_epoch;
    trusted_if(valid)
}

pub(crate) fn verify_correlated_response_header(
    binding: FederationPeerBinding,
    header: &FederationHeader,
    local: FederationLocalIdentityBinding,
    context: FederationExchangeContext,
) -> Result<(), TransportError> {
    let valid = binding.relationship_id == local.relationship_id
        && binding.local_mesh_id == local.local_mesh_id
        && binding.remote_mesh_id == local.remote_mesh_id
        && binding.authority_epoch == local.authority_epoch
        && header.version == Some(context.version)
        && header.relationship_id == binding.relationship_id.as_bytes()
        && header.sender_mesh_id == binding.remote_mesh_id.as_bytes()
        && header.recipient_mesh_id == binding.local_mesh_id.as_bytes()
        && header.authority_epoch == binding.authority_epoch
        && exact::<16>(&header.request_id).ok() == Some(context.request_id)
        && exact::<16>(&header.operation_id).ok() == Some(context.operation_id)
        && exact::<16>(&header.trace_id).ok() == Some(context.trace_id)
        && header.deadline_unix_micros == context.deadline.get()
        && exact::<32>(&header.replay_nonce).is_ok_and(|nonce| nonce != context.replay_nonce);
    trusted_if(valid)
}

fn verify_capability_request_signature(
    verifying_key: [u8; 32],
    header: &FederationHeader,
    request: &RequestFederatedStorageCapability,
) -> Result<(), TransportError> {
    verify_signature(
        verifying_key,
        &request.signature,
        &federation_storage_capability_request_signing_payload(header, request),
    )
}

fn verify_capability_signature(
    verifying_key: [u8; 32],
    header: &FederationHeader,
    capability: &FederatedStorageCapability,
) -> Result<(), TransportError> {
    verify_signature(
        verifying_key,
        &capability.signature,
        &federation_storage_capability_signing_payload(header, capability),
    )
}

fn verify_signature(
    verifying_key: [u8; 32],
    signature: &[u8],
    payload: &[u8],
) -> Result<(), TransportError> {
    let signature = exact::<64>(signature)?;
    VerifyingKey::from_bytes(&verifying_key)
        .map_err(|_| TransportError::UntrustedFederationPeer)?
        .verify_strict(payload, &Signature::from_bytes(&signature))
        .map_err(|_| TransportError::UntrustedFederationPeer)
}

fn verify_capability_response_shape(
    binding: FederationPeerBinding,
    header: &FederationHeader,
    capability: &FederatedStorageCapability,
    expected: &FederationStorageCapabilityExpectation,
    now: UnixMicros,
) -> Result<(), TransportError> {
    verify_correlated_response_header(
        binding,
        header,
        expected.local_identity,
        expected.request_context,
    )?;
    let request = &expected.request;
    let valid_until = UnixMicros::new(capability.valid_until_unix_micros);
    let issued_at = UnixMicros::new(capability.issued_at_unix_micros);
    let capability_nonce = exact::<32>(&capability.capability_nonce)?;
    let response_nonce = exact::<32>(&header.replay_nonce)?;
    let valid = capability.grant_id == request.grant_id
        && capability.allocation_id == request.allocation_id
        && capability.target_id == request.target_id
        && capability.target_generation == request.target_generation
        && capability.shard == request.shard
        && capability.action == request.action
        && capability.maximum_bytes <= request.maximum_bytes
        && issued_at.get() > 0
        && issued_at <= now
        && issued_at < valid_until
        && valid_until > now
        && valid_until <= expected.request_context.deadline
        && valid_until <= binding.valid_until
        && capability_nonce != expected.request_context.replay_nonce
        && capability_nonce != response_nonce;
    trusted_if(valid)
}

fn storage_capability_digest(capability: &FederatedStorageCapability) -> [u8; 32] {
    Sha256::digest(federation_storage_capability_digest_payload(capability)).into()
}

fn trusted_if(valid: bool) -> Result<(), TransportError> {
    if valid {
        Ok(())
    } else {
        Err(TransportError::UntrustedFederationPeer)
    }
}
