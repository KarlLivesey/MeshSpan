// SPDX-License-Identifier: GPL-2.0-only

//! Signed grant-bound federation history pages over authenticated relationships.

use ed25519_dalek::{Signature, Signer, VerifyingKey};
use meshspan_domain::UnixMicros;
use meshspan_protocol::v1::federation_envelope::Message;
use meshspan_protocol::v1::{
    FederatedBranchPage, FederationEnvelope, FederationHeader, FetchFederatedBranchPage,
    VersionedPayload,
};
use meshspan_protocol::{
    ValidatedFederationEnvelope, WireLimits, encode_federation_frame,
    federation_branch_fetch_signing_payload, federation_branch_page_digest_payload,
    federation_branch_page_signing_payload,
};
use sha2::{Digest, Sha256};

use crate::federation_authority_page::{exact, federation_header};
use crate::{
    FederationExchangeContext, FederationLocalIdentity, FederationLocalIdentityBinding,
    FederationPeerRegistry, FederationReplayGuard, TransportError,
};

/// Signed branch fetch plus the exact state needed to authenticate its response.
#[derive(Clone, Debug, PartialEq)]
pub struct OutboundFederationBranchFetch {
    envelope: FederationEnvelope,
    expectation: FederationBranchPageExpectation,
}

impl OutboundFederationBranchFetch {
    /// Returns the exact signed wire request.
    #[must_use]
    pub const fn envelope(&self) -> &FederationEnvelope {
        &self.envelope
    }

    /// Returns the exact local expectation for the corresponding page.
    #[must_use]
    pub const fn expectation(&self) -> &FederationBranchPageExpectation {
        &self.expectation
    }
}

/// Branch fetch whose TLS peer, relationship fence, signature and nonce all agree.
#[derive(Clone, Debug)]
pub struct AuthenticatedFederationBranchFetch {
    binding: crate::FederationPeerBinding,
    header: FederationHeader,
    request: FetchFederatedBranchPage,
}

impl AuthenticatedFederationBranchFetch {
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

    /// Returns the opaque signed branch request after structural validation.
    #[must_use]
    pub const fn request(&self) -> &FetchFederatedBranchPage {
        &self.request
    }

    /// Constructs an exactly correlated response context with a fresh responder nonce.
    ///
    /// # Errors
    ///
    /// Rejects a reflected response nonce or invalid request correlation fields.
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

/// Exact local request state against which one remote branch page is authenticated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationBranchPageExpectation {
    local_identity: FederationLocalIdentityBinding,
    request_context: FederationExchangeContext,
    grant_id: Vec<u8>,
    resource_scope: Option<VersionedPayload>,
}

impl FederationBranchPageExpectation {
    fn new(
        local_identity: FederationLocalIdentityBinding,
        request_context: FederationExchangeContext,
        request: &FetchFederatedBranchPage,
    ) -> Self {
        Self {
            local_identity,
            request_context,
            grant_id: request.grant_id.clone(),
            resource_scope: request.resource_scope.clone(),
        }
    }
}

/// Signed branch-page envelope ready for bounded federation framing.
#[derive(Clone, Debug, PartialEq)]
pub struct OutboundFederationBranchPage {
    envelope: FederationEnvelope,
}

impl OutboundFederationBranchPage {
    /// Returns the exact signed wire envelope.
    #[must_use]
    pub const fn envelope(&self) -> &FederationEnvelope {
        &self.envelope
    }
}

/// Branch page whose TLS peer, grant, scope, digest, signature and nonce all agree.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthenticatedFederationBranchPage {
    page: FederatedBranchPage,
}

impl AuthenticatedFederationBranchPage {
    /// Returns the exact grant identity carried by the authenticated request and response.
    #[must_use]
    pub fn grant_id(&self) -> &[u8] {
        &self.page.grant_id
    }

    /// Returns the exact independently versioned resource scope.
    #[must_use]
    pub const fn resource_scope(&self) -> Option<&VersionedPayload> {
        self.page.resource_scope.as_ref()
    }

    /// Returns the bounded immutable commit records.
    #[must_use]
    pub fn branch_commits(&self) -> &[VersionedPayload] {
        &self.page.branch_commits
    }

    /// Returns content identities whose immutable bytes must be fetched separately.
    #[must_use]
    pub fn immutable_object_digests(&self) -> &[Vec<u8>] {
        &self.page.immutable_object_digests
    }

    /// Returns the opaque signed continuation, empty only at the end.
    #[must_use]
    pub fn next_cursor(&self) -> &[u8] {
        &self.page.next_cursor
    }
}

/// Constructs and signs one bounded history fetch from current committed local identity.
///
/// # Errors
///
/// Rejects stale deadlines or any request exceeding the negotiated wire contract.
pub fn signed_federation_branch_fetch(
    identity: &FederationLocalIdentity<'_>,
    context: FederationExchangeContext,
    mut request: FetchFederatedBranchPage,
    limits: WireLimits,
    now: UnixMicros,
) -> Result<OutboundFederationBranchFetch, TransportError> {
    let binding = identity.binding();
    if context.deadline <= now || context.deadline > binding.valid_until {
        return Err(TransportError::InvalidConfiguration);
    }
    let header = federation_header(binding, context);
    request.signature.clear();
    request.signature = identity
        .signing_key()
        .sign(&federation_branch_fetch_signing_payload(&header, &request))
        .to_bytes()
        .to_vec();
    let expectation = FederationBranchPageExpectation::new(binding, context, &request);
    let envelope = FederationEnvelope {
        header: Some(header),
        message: Some(Message::FetchBranchPage(request)),
    };
    encode_federation_frame(&envelope, limits)?;
    Ok(OutboundFederationBranchFetch {
        envelope,
        expectation,
    })
}

/// Builds one signed history page from an already authenticated current local identity.
///
/// # Errors
///
/// Rejects stale deadlines or any page exceeding the negotiated wire contract.
pub fn signed_federation_branch_page(
    identity: &FederationLocalIdentity<'_>,
    context: FederationExchangeContext,
    mut page: FederatedBranchPage,
    limits: WireLimits,
    now: UnixMicros,
) -> Result<OutboundFederationBranchPage, TransportError> {
    let binding = identity.binding();
    if context.deadline <= now || context.deadline > binding.valid_until {
        return Err(TransportError::InvalidConfiguration);
    }
    let header = federation_header(binding, context);
    page.page_digest.clear();
    page.signature.clear();
    page.page_digest = branch_page_digest(&page).to_vec();
    page.signature = identity
        .signing_key()
        .sign(&federation_branch_page_signing_payload(&header, &page))
        .to_bytes()
        .to_vec();
    let envelope = FederationEnvelope {
        header: Some(header),
        message: Some(Message::BranchPage(page)),
    };
    encode_federation_frame(&envelope, limits)?;
    Ok(OutboundFederationBranchPage { envelope })
}

impl FederationPeerRegistry {
    /// Authenticates one signed branch fetch against current TLS and relationship authority.
    ///
    /// # Errors
    ///
    /// Rejects stale authority, identity substitution, invalid signatures or replay.
    pub fn authenticate_branch_fetch(
        &self,
        connection: &quinn::Connection,
        envelope: &ValidatedFederationEnvelope,
        now: UnixMicros,
        replay: &mut FederationReplayGuard,
    ) -> Result<AuthenticatedFederationBranchFetch, TransportError> {
        let (binding, _) = self.connection_binding(connection, now)?;
        let envelope = envelope.as_inner();
        let header = envelope
            .header
            .as_ref()
            .ok_or(TransportError::UntrustedFederationPeer)?;
        let Message::FetchBranchPage(request) = envelope
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
        Ok(AuthenticatedFederationBranchFetch {
            binding,
            header: header.clone(),
            request: request.clone(),
        })
    }

    /// Authenticates one branch page against the exact signed request and current TLS peer.
    ///
    /// # Errors
    ///
    /// Rejects correlation, grant, resource, digest, signature, authority or replay substitution.
    pub fn authenticate_branch_page(
        &self,
        connection: &quinn::Connection,
        envelope: &ValidatedFederationEnvelope,
        expected: &FederationBranchPageExpectation,
        now: UnixMicros,
        replay: &mut FederationReplayGuard,
    ) -> Result<AuthenticatedFederationBranchPage, TransportError> {
        let (binding, _) = self.connection_binding(connection, now)?;
        let envelope = envelope.as_inner();
        let header = envelope
            .header
            .as_ref()
            .ok_or(TransportError::UntrustedFederationPeer)?;
        let Message::BranchPage(page) = envelope
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
        Ok(AuthenticatedFederationBranchPage { page: page.clone() })
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
    request: &FetchFederatedBranchPage,
) -> Result<(), TransportError> {
    let signature = exact::<64>(&request.signature)?;
    VerifyingKey::from_bytes(&verifying_key)
        .map_err(|_| TransportError::UntrustedFederationPeer)?
        .verify_strict(
            &federation_branch_fetch_signing_payload(header, request),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| TransportError::UntrustedFederationPeer)
}

fn verify_page_shape(
    binding: crate::FederationPeerBinding,
    header: &FederationHeader,
    page: &FederatedBranchPage,
    expected: &FederationBranchPageExpectation,
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
        && page.resource_scope == expected.resource_scope;
    if valid {
        Ok(())
    } else {
        Err(TransportError::UntrustedFederationPeer)
    }
}

fn verify_page_digest(page: &FederatedBranchPage) -> Result<(), TransportError> {
    if exact::<32>(&page.page_digest)? == branch_page_digest(page) {
        Ok(())
    } else {
        Err(TransportError::UntrustedFederationPeer)
    }
}

fn verify_page_signature(
    verifying_key: [u8; 32],
    header: &FederationHeader,
    page: &FederatedBranchPage,
) -> Result<(), TransportError> {
    let signature = exact::<64>(&page.signature)?;
    VerifyingKey::from_bytes(&verifying_key)
        .map_err(|_| TransportError::UntrustedFederationPeer)?
        .verify_strict(
            &federation_branch_page_signing_payload(header, page),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| TransportError::UntrustedFederationPeer)
}

fn branch_page_digest(page: &FederatedBranchPage) -> [u8; 32] {
    Sha256::digest(federation_branch_page_digest_payload(page)).into()
}
