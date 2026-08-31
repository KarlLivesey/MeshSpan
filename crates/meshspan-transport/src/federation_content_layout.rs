// SPDX-License-Identifier: GPL-2.0-only

//! Signed, grant-bound portable content-layout pages over authenticated relationships.

use ed25519_dalek::{Signature, Signer, VerifyingKey};
use meshspan_domain::UnixMicros;
use meshspan_protocol::v1::federation_envelope::Message;
use meshspan_protocol::v1::{
    FederatedContentLayoutPage, FederationEnvelope, FederationHeader, FetchFederatedContentLayout,
    VersionedPayload,
};
use meshspan_protocol::{
    ValidatedFederationEnvelope, WireLimits, encode_federation_frame,
    federation_content_layout_fetch_signing_payload, federation_content_layout_page_digest_payload,
    federation_content_layout_page_signing_payload,
};
use sha2::{Digest, Sha256};

use crate::federation_authority_page::{exact, federation_header};
use crate::{
    FederationExchangeContext, FederationLocalIdentity, FederationLocalIdentityBinding,
    FederationPeerRegistry, FederationReplayGuard, TransportError,
};

/// Signed layout fetch plus exact response and key-transit expectations.
#[derive(Clone, Debug, PartialEq)]
pub struct OutboundFederationContentLayoutFetch {
    envelope: FederationEnvelope,
    expectation: FederationContentLayoutPageExpectation,
}

impl OutboundFederationContentLayoutFetch {
    /// Returns the exact signed wire request.
    #[must_use]
    pub const fn envelope(&self) -> &FederationEnvelope {
        &self.envelope
    }

    /// Returns the exact state against which the corresponding page is authenticated.
    #[must_use]
    pub const fn expectation(&self) -> &FederationContentLayoutPageExpectation {
        &self.expectation
    }
}

/// Layout fetch whose TLS peer, relationship fence, signature and nonce all agree.
#[derive(Clone, Debug)]
pub struct AuthenticatedFederationContentLayoutFetch {
    binding: crate::FederationPeerBinding,
    header: FederationHeader,
    request: FetchFederatedContentLayout,
    transit_binding: [u8; 32],
}

impl AuthenticatedFederationContentLayoutFetch {
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
    pub const fn request(&self) -> &FetchFederatedContentLayout {
        &self.request
    }

    /// Returns the digest binding content-key transit to this exact authorised request.
    #[must_use]
    pub const fn transit_binding(&self) -> [u8; 32] {
        self.transit_binding
    }

    /// Constructs an exactly correlated response context with a fresh responder nonce.
    ///
    /// # Errors
    ///
    /// Rejects a reflected response nonce or malformed request correlation fields.
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

/// Exact local request state against which one remote layout page is authenticated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationContentLayoutPageExpectation {
    local_identity: FederationLocalIdentityBinding,
    request_context: FederationExchangeContext,
    grant_id: Vec<u8>,
    resource_scope: Option<VersionedPayload>,
    manifest_id: Vec<u8>,
    export_token: Vec<u8>,
    manifest_object_digest: Vec<u8>,
    transit_binding: [u8; 32],
}

impl FederationContentLayoutPageExpectation {
    /// Returns the digest binding content-key transit to the exact signed request.
    #[must_use]
    pub const fn transit_binding(&self) -> [u8; 32] {
        self.transit_binding
    }
}

/// Signed layout page ready for bounded federation framing.
#[derive(Clone, Debug, PartialEq)]
pub struct OutboundFederationContentLayoutPage {
    envelope: FederationEnvelope,
}

impl OutboundFederationContentLayoutPage {
    /// Returns the exact signed wire response.
    #[must_use]
    pub const fn envelope(&self) -> &FederationEnvelope {
        &self.envelope
    }
}

/// Layout page whose TLS peer, request, digest, signature and nonce all agree.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthenticatedFederationContentLayoutPage {
    page: FederatedContentLayoutPage,
}

impl AuthenticatedFederationContentLayoutPage {
    /// Returns the exact content manifest identity.
    #[must_use]
    pub fn manifest_id(&self) -> &[u8] {
        &self.page.manifest_id
    }

    /// Returns the independently versioned portable layout header.
    #[must_use]
    pub const fn layout_header(&self) -> Option<&VersionedPayload> {
        self.page.layout_header.as_ref()
    }

    /// Returns the bounded provider-neutral layout records.
    #[must_use]
    pub fn chunks(&self) -> &[VersionedPayload] {
        &self.page.chunks
    }

    /// Returns one signed exact provider route for each portable chunk record.
    #[must_use]
    pub fn shard_routes(&self) -> &[meshspan_protocol::v1::FederatedContentShardRoute] {
        &self.page.shard_routes
    }

    /// Returns the opaque signed continuation, empty only at the end.
    #[must_use]
    pub fn next_cursor(&self) -> &[u8] {
        &self.page.next_cursor
    }
}

/// Constructs and signs one bounded content-layout fetch.
///
/// # Errors
///
/// Rejects stale deadlines or any request outside negotiated wire bounds.
pub fn signed_federation_content_layout_fetch(
    identity: &FederationLocalIdentity<'_>,
    context: FederationExchangeContext,
    mut request: FetchFederatedContentLayout,
    limits: WireLimits,
    now: UnixMicros,
) -> Result<OutboundFederationContentLayoutFetch, TransportError> {
    let binding = identity.binding();
    validate_deadline(binding, context, now)?;
    let header = federation_header(binding, context);
    request.signature.clear();
    let transit_binding = content_layout_transit_binding(&header, &request)?;
    request.signature = identity
        .signing_key()
        .sign(&federation_content_layout_fetch_signing_payload(
            &header, &request,
        )?)
        .to_bytes()
        .to_vec();
    let expectation = FederationContentLayoutPageExpectation {
        local_identity: binding,
        request_context: context,
        grant_id: request.grant_id.clone(),
        resource_scope: request.resource_scope.clone(),
        manifest_id: request.manifest_id.clone(),
        export_token: request.export_token.clone(),
        manifest_object_digest: request.manifest_object_digest.clone(),
        transit_binding,
    };
    let envelope = FederationEnvelope {
        header: Some(header),
        message: Some(Message::FetchContentLayout(request)),
    };
    encode_federation_frame(&envelope, limits)?;
    Ok(OutboundFederationContentLayoutFetch {
        envelope,
        expectation,
    })
}

/// Constructs and signs one bounded content-layout page.
///
/// # Errors
///
/// Rejects stale deadlines or any page outside negotiated wire bounds.
pub fn signed_federation_content_layout_page(
    identity: &FederationLocalIdentity<'_>,
    context: FederationExchangeContext,
    mut page: FederatedContentLayoutPage,
    limits: WireLimits,
    now: UnixMicros,
) -> Result<OutboundFederationContentLayoutPage, TransportError> {
    let binding = identity.binding();
    validate_deadline(binding, context, now)?;
    let header = federation_header(binding, context);
    page.page_digest.clear();
    page.signature.clear();
    page.page_digest = content_layout_page_digest(&page)?.to_vec();
    page.signature = identity
        .signing_key()
        .sign(&federation_content_layout_page_signing_payload(
            &header, &page,
        )?)
        .to_bytes()
        .to_vec();
    let envelope = FederationEnvelope {
        header: Some(header),
        message: Some(Message::ContentLayoutPage(page)),
    };
    encode_federation_frame(&envelope, limits)?;
    Ok(OutboundFederationContentLayoutPage { envelope })
}

impl FederationPeerRegistry {
    /// Authenticates one layout fetch against current TLS and relationship authority.
    ///
    /// # Errors
    ///
    /// Rejects stale authority, identity substitution, invalid signatures or replay.
    pub fn authenticate_content_layout_fetch(
        &self,
        connection: &quinn::Connection,
        envelope: &ValidatedFederationEnvelope,
        now: UnixMicros,
        replay: &mut FederationReplayGuard,
    ) -> Result<AuthenticatedFederationContentLayoutFetch, TransportError> {
        let (binding, _) = self.connection_binding(connection, now)?;
        let envelope = envelope.as_inner();
        let header = envelope
            .header
            .as_ref()
            .ok_or(TransportError::UntrustedFederationPeer)?;
        let Message::FetchContentLayout(request) = envelope
            .message
            .as_ref()
            .ok_or(TransportError::UntrustedFederationPeer)?
        else {
            return Err(TransportError::UntrustedFederationPeer);
        };
        verify_request_header(binding, header)?;
        replay.check(binding.relationship_id, header, now)?;
        verify_fetch_signature(binding.verifying_key, header, request)?;
        let transit_binding = content_layout_transit_binding(header, request)?;
        replay.record(binding.relationship_id, header)?;
        Ok(AuthenticatedFederationContentLayoutFetch {
            binding,
            header: header.clone(),
            request: request.clone(),
            transit_binding,
        })
    }

    /// Authenticates one layout page against the exact request and current TLS peer.
    ///
    /// # Errors
    ///
    /// Rejects correlation, grant, scope, manifest, digest, signature, authority or replay
    /// substitution.
    pub fn authenticate_content_layout_page(
        &self,
        connection: &quinn::Connection,
        envelope: &ValidatedFederationEnvelope,
        expected: &FederationContentLayoutPageExpectation,
        now: UnixMicros,
        replay: &mut FederationReplayGuard,
    ) -> Result<AuthenticatedFederationContentLayoutPage, TransportError> {
        let (binding, _) = self.connection_binding(connection, now)?;
        let envelope = envelope.as_inner();
        let header = envelope
            .header
            .as_ref()
            .ok_or(TransportError::UntrustedFederationPeer)?;
        let Message::ContentLayoutPage(page) = envelope
            .message
            .as_ref()
            .ok_or(TransportError::UntrustedFederationPeer)?
        else {
            return Err(TransportError::UntrustedFederationPeer);
        };
        verify_page_shape(binding, header, page, expected)?;
        replay.check(binding.relationship_id, header, now)?;
        verify_page_digest(page)?;
        verify_page_signature(binding.verifying_key, header, page)?;
        replay.record(binding.relationship_id, header)?;
        Ok(AuthenticatedFederationContentLayoutPage { page: page.clone() })
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
    request: &FetchFederatedContentLayout,
) -> Result<(), TransportError> {
    let signature = exact::<64>(&request.signature)?;
    let payload = federation_content_layout_fetch_signing_payload(header, request)?;
    VerifyingKey::from_bytes(&verifying_key)
        .map_err(|_| TransportError::UntrustedFederationPeer)?
        .verify_strict(&payload, &Signature::from_bytes(&signature))
        .map_err(|_| TransportError::UntrustedFederationPeer)
}

fn verify_page_shape(
    binding: crate::FederationPeerBinding,
    header: &FederationHeader,
    page: &FederatedContentLayoutPage,
    expected: &FederationContentLayoutPageExpectation,
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
        && page.grant_id == expected.grant_id
        && page.resource_scope == expected.resource_scope
        && page.manifest_id == expected.manifest_id
        && page.export_token == expected.export_token
        && page.manifest_object_digest == expected.manifest_object_digest;
    if valid {
        Ok(())
    } else {
        Err(TransportError::UntrustedFederationPeer)
    }
}

fn verify_page_digest(page: &FederatedContentLayoutPage) -> Result<(), TransportError> {
    if exact::<32>(&page.page_digest)? == content_layout_page_digest(page)? {
        Ok(())
    } else {
        Err(TransportError::UntrustedFederationPeer)
    }
}

fn verify_page_signature(
    verifying_key: [u8; 32],
    header: &FederationHeader,
    page: &FederatedContentLayoutPage,
) -> Result<(), TransportError> {
    let signature = exact::<64>(&page.signature)?;
    let payload = federation_content_layout_page_signing_payload(header, page)?;
    VerifyingKey::from_bytes(&verifying_key)
        .map_err(|_| TransportError::UntrustedFederationPeer)?
        .verify_strict(&payload, &Signature::from_bytes(&signature))
        .map_err(|_| TransportError::UntrustedFederationPeer)
}

fn content_layout_page_digest(
    page: &FederatedContentLayoutPage,
) -> Result<[u8; 32], TransportError> {
    Ok(Sha256::digest(federation_content_layout_page_digest_payload(page)?).into())
}

fn content_layout_transit_binding(
    header: &FederationHeader,
    request: &FetchFederatedContentLayout,
) -> Result<[u8; 32], TransportError> {
    Ok(
        Sha256::digest(federation_content_layout_fetch_signing_payload(
            header, request,
        )?)
        .into(),
    )
}
