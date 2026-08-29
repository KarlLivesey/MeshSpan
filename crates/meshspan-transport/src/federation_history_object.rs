// SPDX-License-Identifier: GPL-2.0-only

//! Signed exact-object headers for separately framed federation history bodies.

use ed25519_dalek::{Signature, Signer, VerifyingKey};
use meshspan_domain::UnixMicros;
use meshspan_protocol::v1::federation_envelope::Message;
use meshspan_protocol::v1::{
    FederatedHistoryObjectHeader, FederationEnvelope, FederationHeader,
    FetchFederatedHistoryObject, VersionedPayload,
};
use meshspan_protocol::{
    ValidatedFederationEnvelope, WireLimits, encode_federation_frame,
    federation_history_object_fetch_signing_payload,
    federation_history_object_header_signing_payload,
};

use crate::federation_authority_page::{exact, federation_header};
use crate::{
    FederationExchangeContext, FederationLocalIdentity, FederationLocalIdentityBinding,
    FederationPeerRegistry, FederationReplayGuard, TransportError,
};

/// Signed immutable-object fetch and exact response expectation.
#[derive(Clone, Debug, PartialEq)]
pub struct OutboundFederationHistoryObjectFetch {
    envelope: FederationEnvelope,
    expectation: FederationHistoryObjectExpectation,
}

impl OutboundFederationHistoryObjectFetch {
    /// Returns the exact signed wire request.
    #[must_use]
    pub const fn envelope(&self) -> &FederationEnvelope {
        &self.envelope
    }

    /// Returns the state which the response must echo exactly.
    #[must_use]
    pub const fn expectation(&self) -> &FederationHistoryObjectExpectation {
        &self.expectation
    }
}

/// Object fetch whose mTLS peer, relationship, signature and replay nonce agree.
#[derive(Clone, Debug)]
pub struct AuthenticatedFederationHistoryObjectFetch {
    binding: crate::FederationPeerBinding,
    header: FederationHeader,
    request: FetchFederatedHistoryObject,
}

impl AuthenticatedFederationHistoryObjectFetch {
    /// Returns the certificate-authenticated requesting swarm.
    #[must_use]
    pub const fn remote_mesh_id(&self) -> meshspan_domain::MeshId {
        self.binding.remote_mesh_id
    }

    /// Returns the structurally validated signed request.
    #[must_use]
    pub const fn request(&self) -> &FetchFederatedHistoryObject {
        &self.request
    }

    /// Correlates the response with the request while requiring a fresh nonce.
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

/// Exact request state against which a body header is authenticated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationHistoryObjectExpectation {
    local_identity: FederationLocalIdentityBinding,
    request_context: FederationExchangeContext,
    grant_id: Vec<u8>,
    resource_scope: Option<VersionedPayload>,
    export_token: Vec<u8>,
    object_digest: Vec<u8>,
}

/// Signed object header ready for federation framing.
#[derive(Clone, Debug, PartialEq)]
pub struct OutboundFederationHistoryObjectHeader {
    envelope: FederationEnvelope,
}

impl OutboundFederationHistoryObjectHeader {
    /// Returns the exact signed wire response.
    #[must_use]
    pub const fn envelope(&self) -> &FederationEnvelope {
        &self.envelope
    }
}

/// Authenticated exact object identity and bounded transfer shape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedFederationHistoryObjectHeader {
    header: FederatedHistoryObjectHeader,
}

impl AuthenticatedFederationHistoryObjectHeader {
    /// Returns the exact advertised object digest.
    #[must_use]
    pub fn object_digest(&self) -> &[u8] {
        &self.header.object_digest
    }

    /// Returns the exact source-side export token.
    #[must_use]
    pub fn export_token(&self) -> &[u8] {
        &self.header.export_token
    }

    /// Returns the total canonical body length.
    #[must_use]
    pub const fn declared_length(&self) -> u64 {
        self.header.declared_length
    }

    /// Returns the maximum payload permitted in each following data frame.
    #[must_use]
    pub const fn maximum_frame_bytes(&self) -> u64 {
        self.header.maximum_frame_bytes
    }
}

/// Constructs and signs one exact immutable-object request.
///
/// # Errors
///
/// Rejects stale deadlines or a request outside negotiated wire bounds.
pub fn signed_federation_history_object_fetch(
    identity: &FederationLocalIdentity<'_>,
    context: FederationExchangeContext,
    mut request: FetchFederatedHistoryObject,
    limits: WireLimits,
    now: UnixMicros,
) -> Result<OutboundFederationHistoryObjectFetch, TransportError> {
    let binding = identity.binding();
    validate_deadline(binding, context, now)?;
    let header = federation_header(binding, context);
    request.signature.clear();
    request.signature = identity
        .signing_key()
        .sign(&federation_history_object_fetch_signing_payload(
            &header, &request,
        ))
        .to_bytes()
        .to_vec();
    let expectation = FederationHistoryObjectExpectation {
        local_identity: binding,
        request_context: context,
        grant_id: request.grant_id.clone(),
        resource_scope: request.resource_scope.clone(),
        export_token: request.export_token.clone(),
        object_digest: request.object_digest.clone(),
    };
    let envelope = FederationEnvelope {
        header: Some(header),
        message: Some(Message::FetchHistoryObject(request)),
    };
    encode_federation_frame(&envelope, limits)?;
    Ok(OutboundFederationHistoryObjectFetch {
        envelope,
        expectation,
    })
}

/// Constructs and signs one exact immutable-object response header.
///
/// # Errors
///
/// Rejects stale deadlines or a header outside negotiated wire bounds.
pub fn signed_federation_history_object_header(
    identity: &FederationLocalIdentity<'_>,
    context: FederationExchangeContext,
    mut response: FederatedHistoryObjectHeader,
    limits: WireLimits,
    now: UnixMicros,
) -> Result<OutboundFederationHistoryObjectHeader, TransportError> {
    let binding = identity.binding();
    validate_deadline(binding, context, now)?;
    let header = federation_header(binding, context);
    response.signature.clear();
    response.signature = identity
        .signing_key()
        .sign(&federation_history_object_header_signing_payload(
            &header, &response,
        ))
        .to_bytes()
        .to_vec();
    let envelope = FederationEnvelope {
        header: Some(header),
        message: Some(Message::HistoryObjectHeader(response)),
    };
    encode_federation_frame(&envelope, limits)?;
    Ok(OutboundFederationHistoryObjectHeader { envelope })
}

impl FederationPeerRegistry {
    /// Authenticates one immutable-object fetch against current mTLS relationship authority.
    ///
    /// # Errors
    ///
    /// Rejects identity, signature, authority, deadline or replay substitution.
    pub fn authenticate_history_object_fetch(
        &self,
        connection: &quinn::Connection,
        envelope: &ValidatedFederationEnvelope,
        now: UnixMicros,
        replay: &mut FederationReplayGuard,
    ) -> Result<AuthenticatedFederationHistoryObjectFetch, TransportError> {
        let (binding, _) = self.connection_binding(connection, now)?;
        let envelope = envelope.as_inner();
        let header = envelope
            .header
            .as_ref()
            .ok_or(TransportError::UntrustedFederationPeer)?;
        let Message::FetchHistoryObject(request) = envelope
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
        Ok(AuthenticatedFederationHistoryObjectFetch {
            binding,
            header: header.clone(),
            request: request.clone(),
        })
    }

    /// Authenticates one object header against the exact signed request and current TLS peer.
    ///
    /// # Errors
    ///
    /// Rejects correlation, identity, digest, length, signature, authority or replay substitution.
    pub fn authenticate_history_object_header(
        &self,
        connection: &quinn::Connection,
        envelope: &ValidatedFederationEnvelope,
        expected: &FederationHistoryObjectExpectation,
        now: UnixMicros,
        replay: &mut FederationReplayGuard,
    ) -> Result<AuthenticatedFederationHistoryObjectHeader, TransportError> {
        let (binding, _) = self.connection_binding(connection, now)?;
        let envelope = envelope.as_inner();
        let header = envelope
            .header
            .as_ref()
            .ok_or(TransportError::UntrustedFederationPeer)?;
        let Message::HistoryObjectHeader(response) = envelope
            .message
            .as_ref()
            .ok_or(TransportError::UntrustedFederationPeer)?
        else {
            return Err(TransportError::UntrustedFederationPeer);
        };
        verify_response_shape(binding, header, response, expected)?;
        replay.check(binding.relationship_id, header, now)?;
        verify_header_signature(binding.verifying_key, header, response)?;
        replay.record(binding.relationship_id, header)?;
        Ok(AuthenticatedFederationHistoryObjectHeader {
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
    request: &FetchFederatedHistoryObject,
) -> Result<(), TransportError> {
    let signature = exact::<64>(&request.signature)?;
    VerifyingKey::from_bytes(&verifying_key)
        .map_err(|_| TransportError::UntrustedFederationPeer)?
        .verify_strict(
            &federation_history_object_fetch_signing_payload(header, request),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| TransportError::UntrustedFederationPeer)
}

fn verify_response_shape(
    binding: crate::FederationPeerBinding,
    header: &FederationHeader,
    response: &FederatedHistoryObjectHeader,
    expected: &FederationHistoryObjectExpectation,
) -> Result<(), TransportError> {
    let local = expected.local_identity;
    let context = expected.request_context;
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
        && response.grant_id == expected.grant_id
        && response.resource_scope == expected.resource_scope
        && response.export_token == expected.export_token
        && response.object_digest == expected.object_digest;
    if valid {
        Ok(())
    } else {
        Err(TransportError::UntrustedFederationPeer)
    }
}

fn verify_header_signature(
    verifying_key: [u8; 32],
    header: &FederationHeader,
    response: &FederatedHistoryObjectHeader,
) -> Result<(), TransportError> {
    let signature = exact::<64>(&response.signature)?;
    VerifyingKey::from_bytes(&verifying_key)
        .map_err(|_| TransportError::UntrustedFederationPeer)?
        .verify_strict(
            &federation_history_object_header_signing_payload(header, response),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| TransportError::UntrustedFederationPeer)
}
