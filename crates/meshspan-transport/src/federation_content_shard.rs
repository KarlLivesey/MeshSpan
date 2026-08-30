// SPDX-License-Identifier: GPL-2.0-only

//! Signed, exactly correlated headers for bounded federated encrypted-shard streams.

use ed25519_dalek::{Signature, Signer, VerifyingKey};
use meshspan_domain::{OperationId, UnixMicros};
use meshspan_protocol::v1::federation_envelope::Message;
use meshspan_protocol::v1::{
    FederatedContentShardHeader, FederationEnvelope, FederationHeader, FetchFederatedContentShard,
};
use meshspan_protocol::{
    ValidatedFederationEnvelope, WireLimits, encode_federation_frame,
    federation_content_shard_fetch_signing_payload,
    federation_content_shard_header_signing_payload,
};

use crate::federation_authority_page::{exact, federation_header};
use crate::{
    FederationExchangeContext, FederationLocalIdentity, FederationLocalIdentityBinding,
    FederationPeerRegistry, FederationReplayGuard, TransportError,
};

/// Signed encrypted-shard fetch and the exact response it permits.
#[derive(Clone, Debug, PartialEq)]
pub struct OutboundFederationContentShardFetch {
    envelope: FederationEnvelope,
    expectation: FederationContentShardExpectation,
}

impl OutboundFederationContentShardFetch {
    /// Returns the exact signed request envelope.
    #[must_use]
    pub const fn envelope(&self) -> &FederationEnvelope {
        &self.envelope
    }

    /// Returns the complete request correlation required of the response.
    #[must_use]
    pub const fn expectation(&self) -> &FederationContentShardExpectation {
        &self.expectation
    }
}

/// Fetch whose signature, mTLS peer, authority epoch and replay nonce agree.
#[derive(Clone, Debug)]
pub struct AuthenticatedFederationContentShardFetch {
    binding: crate::FederationPeerBinding,
    header: FederationHeader,
    request: FetchFederatedContentShard,
}

impl AuthenticatedFederationContentShardFetch {
    /// Returns the certificate-authenticated requesting swarm.
    #[must_use]
    pub const fn remote_mesh_id(&self) -> meshspan_domain::MeshId {
        self.binding.remote_mesh_id
    }

    /// Returns the exact operation identity carried by the signed request header.
    ///
    /// # Errors
    ///
    /// Rejects an invalid identifier despite prior structural validation.
    pub fn operation_id(&self) -> Result<OperationId, TransportError> {
        OperationId::from_bytes(exact(&self.header.operation_id)?)
            .map_err(|_| TransportError::UntrustedFederationPeer)
    }

    /// Returns the exclusive signed request deadline.
    #[must_use]
    pub const fn deadline(&self) -> UnixMicros {
        UnixMicros::new(self.header.deadline_unix_micros)
    }

    /// Returns the structurally validated request.
    #[must_use]
    pub const fn request(&self) -> &FetchFederatedContentShard {
        &self.request
    }

    /// Builds the exact response context while preventing nonce reflection.
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

/// Exact signed request state against which one response is authenticated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationContentShardExpectation {
    local_identity: FederationLocalIdentityBinding,
    request_context: FederationExchangeContext,
    request: FetchFederatedContentShard,
}

/// Signed encrypted-shard response header ready for federation framing.
#[derive(Clone, Debug, PartialEq)]
pub struct OutboundFederationContentShardHeader {
    envelope: FederationEnvelope,
}

impl OutboundFederationContentShardHeader {
    /// Returns the exact signed response envelope.
    #[must_use]
    pub const fn envelope(&self) -> &FederationEnvelope {
        &self.envelope
    }
}

/// Authenticated immutable shard identity and independently bounded transfer shape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedFederationContentShardHeader {
    header: FederatedContentShardHeader,
}

impl AuthenticatedFederationContentShardHeader {
    /// Returns the exact response header after signature and correlation validation.
    #[must_use]
    pub const fn as_inner(&self) -> &FederatedContentShardHeader {
        &self.header
    }

    /// Returns the exact encrypted-byte length.
    #[must_use]
    pub const fn declared_length(&self) -> u64 {
        self.header.declared_length
    }

    /// Returns the exact encrypted-byte digest.
    #[must_use]
    pub fn content_digest(&self) -> &[u8] {
        &self.header.content_digest
    }

    /// Returns the negotiated upper bound for each following frame.
    #[must_use]
    pub const fn maximum_frame_bytes(&self) -> u64 {
        self.header.maximum_frame_bytes
    }
}

/// Constructs and signs one exact federated encrypted-shard request.
///
/// # Errors
///
/// Rejects stale deadlines or any request outside the negotiated wire contract.
pub fn signed_federation_content_shard_fetch(
    identity: &FederationLocalIdentity<'_>,
    context: FederationExchangeContext,
    mut request: FetchFederatedContentShard,
    limits: WireLimits,
    now: UnixMicros,
) -> Result<OutboundFederationContentShardFetch, TransportError> {
    let binding = identity.binding();
    validate_deadline(binding, context, now)?;
    let header = federation_header(binding, context);
    request.signature.clear();
    request.signature = identity
        .signing_key()
        .sign(&federation_content_shard_fetch_signing_payload(
            &header, &request,
        ))
        .to_bytes()
        .to_vec();
    let expectation = FederationContentShardExpectation {
        local_identity: binding,
        request_context: context,
        request: request.clone(),
    };
    let envelope = FederationEnvelope {
        header: Some(header),
        message: Some(Message::FetchContentShard(request)),
    };
    encode_federation_frame(&envelope, limits)?;
    Ok(OutboundFederationContentShardFetch {
        envelope,
        expectation,
    })
}

/// Constructs and signs one exact federated encrypted-shard response header.
///
/// # Errors
///
/// Rejects stale deadlines, a dishonest service instant or an invalid wire shape.
pub fn signed_federation_content_shard_header(
    identity: &FederationLocalIdentity<'_>,
    context: FederationExchangeContext,
    mut response: FederatedContentShardHeader,
    limits: WireLimits,
    now: UnixMicros,
) -> Result<OutboundFederationContentShardHeader, TransportError> {
    let binding = identity.binding();
    validate_deadline(binding, context, now)?;
    if response.served_at_unix_micros != now.get() {
        return Err(TransportError::InvalidConfiguration);
    }
    let header = federation_header(binding, context);
    response.signature.clear();
    response.signature = identity
        .signing_key()
        .sign(&federation_content_shard_header_signing_payload(
            &header, &response,
        ))
        .to_bytes()
        .to_vec();
    let envelope = FederationEnvelope {
        header: Some(header),
        message: Some(Message::ContentShardHeader(response)),
    };
    encode_federation_frame(&envelope, limits)?;
    Ok(OutboundFederationContentShardHeader { envelope })
}

impl FederationPeerRegistry {
    /// Authenticates one encrypted-shard fetch against current mTLS relationship authority.
    ///
    /// # Errors
    ///
    /// Rejects identity, signature, epoch, deadline or replay substitution.
    pub fn authenticate_content_shard_fetch(
        &self,
        connection: &quinn::Connection,
        envelope: &ValidatedFederationEnvelope,
        now: UnixMicros,
        replay: &mut FederationReplayGuard,
    ) -> Result<AuthenticatedFederationContentShardFetch, TransportError> {
        let (binding, _) = self.connection_binding(connection, now)?;
        let envelope = envelope.as_inner();
        let header = envelope
            .header
            .as_ref()
            .ok_or(TransportError::UntrustedFederationPeer)?;
        let Message::FetchContentShard(request) = envelope
            .message
            .as_ref()
            .ok_or(TransportError::UntrustedFederationPeer)?
        else {
            return Err(TransportError::UntrustedFederationPeer);
        };
        verify_request_header(binding, header)?;
        replay.check(binding.relationship_id, header, now)?;
        verify_fetch_signature(binding.verifying_key, header, request)?;
        replay.record(binding.relationship_id, header)?;
        Ok(AuthenticatedFederationContentShardFetch {
            binding,
            header: header.clone(),
            request: request.clone(),
        })
    }

    /// Authenticates one encrypted-shard header against the exact request and current TLS peer.
    ///
    /// # Errors
    ///
    /// Rejects correlation, identity, route, digest, signature, time or replay substitution.
    pub fn authenticate_content_shard_header(
        &self,
        connection: &quinn::Connection,
        envelope: &ValidatedFederationEnvelope,
        expected: &FederationContentShardExpectation,
        now: UnixMicros,
        replay: &mut FederationReplayGuard,
    ) -> Result<AuthenticatedFederationContentShardHeader, TransportError> {
        let (binding, _) = self.connection_binding(connection, now)?;
        let envelope = envelope.as_inner();
        let header = envelope
            .header
            .as_ref()
            .ok_or(TransportError::UntrustedFederationPeer)?;
        let Message::ContentShardHeader(response) = envelope
            .message
            .as_ref()
            .ok_or(TransportError::UntrustedFederationPeer)?
        else {
            return Err(TransportError::UntrustedFederationPeer);
        };
        verify_response_shape(binding, header, response, expected, now)?;
        replay.check(binding.relationship_id, header, now)?;
        verify_header_signature(binding.verifying_key, header, response)?;
        replay.record(binding.relationship_id, header)?;
        Ok(AuthenticatedFederationContentShardHeader {
            header: response.clone(),
        })
    }
}

fn validate_deadline(
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

fn verify_request_header(
    binding: crate::FederationPeerBinding,
    header: &FederationHeader,
) -> Result<(), TransportError> {
    let valid = header.relationship_id == binding.relationship_id.as_bytes()
        && header.sender_mesh_id == binding.remote_mesh_id.as_bytes()
        && header.recipient_mesh_id == binding.local_mesh_id.as_bytes()
        && header.authority_epoch == binding.authority_epoch;
    if valid {
        Ok(())
    } else {
        Err(TransportError::UntrustedFederationPeer)
    }
}

fn verify_fetch_signature(
    verifying_key: [u8; 32],
    header: &FederationHeader,
    request: &FetchFederatedContentShard,
) -> Result<(), TransportError> {
    let signature = exact::<64>(&request.signature)?;
    VerifyingKey::from_bytes(&verifying_key)
        .map_err(|_| TransportError::UntrustedFederationPeer)?
        .verify_strict(
            &federation_content_shard_fetch_signing_payload(header, request),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| TransportError::UntrustedFederationPeer)
}

fn verify_response_shape(
    binding: crate::FederationPeerBinding,
    header: &FederationHeader,
    response: &FederatedContentShardHeader,
    expected: &FederationContentShardExpectation,
    now: UnixMicros,
) -> Result<(), TransportError> {
    let local = expected.local_identity;
    let context = expected.request_context;
    let request = &expected.request;
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
        && exact::<32>(&header.replay_nonce).is_ok_and(|nonce| nonce != context.replay_nonce)
        && response.grant_id == request.grant_id
        && response.resource_scope == request.resource_scope
        && response.manifest_id == request.manifest_id
        && response.export_token == request.export_token
        && response.manifest_object_digest == request.manifest_object_digest
        && response.provider_node_id == request.provider_node_id
        && response.target_id == request.target_id
        && response.target_generation == request.target_generation
        && response.shard == request.shard
        && response.declared_length == request.expected_length
        && response.content_digest == request.expected_digest
        && response.served_at_unix_micros <= now.get()
        && response.served_at_unix_micros < context.deadline.get();
    if valid {
        Ok(())
    } else {
        Err(TransportError::UntrustedFederationPeer)
    }
}

fn verify_header_signature(
    verifying_key: [u8; 32],
    header: &FederationHeader,
    response: &FederatedContentShardHeader,
) -> Result<(), TransportError> {
    let signature = exact::<64>(&response.signature)?;
    VerifyingKey::from_bytes(&verifying_key)
        .map_err(|_| TransportError::UntrustedFederationPeer)?
        .verify_strict(
            &federation_content_shard_header_signing_payload(header, response),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| TransportError::UntrustedFederationPeer)
}
