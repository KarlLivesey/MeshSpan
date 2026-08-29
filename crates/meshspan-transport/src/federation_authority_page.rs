// SPDX-License-Identifier: GPL-2.0-only

//! Signed, revision-bound federation authority pages over an authenticated session.

use ed25519_dalek::{Signature, Signer, VerifyingKey};
use meshspan_domain::UnixMicros;
use meshspan_protocol::v1::federation_envelope::Message;
use meshspan_protocol::v1::{
    FederationAuthorityPage, FederationEnvelope, FederationHeader, FetchFederationAuthority,
    ProtocolVersion, VersionedPayload,
};
use meshspan_protocol::{
    ValidatedFederationEnvelope, WireLimits, encode_federation_frame,
    federation_authority_fetch_signing_payload, federation_authority_page_digest_payload,
    federation_authority_page_signing_payload,
};
use sha2::{Digest, Sha256};

use crate::{
    FederationLocalIdentity, FederationLocalIdentityBinding, FederationPeerRegistry,
    FederationReplayGuard, TransportError,
};

/// Correlation, deadline and one side's anti-replay value for an authority exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationAuthorityContext {
    /// Negotiated exact protocol version.
    pub version: ProtocolVersion,
    /// Request correlation identity shared by both sides.
    pub request_id: [u8; 16],
    /// Idempotent fetch operation identity shared by both sides.
    pub operation_id: [u8; 16],
    /// End-to-end trace identity copied from the request.
    pub trace_id: [u8; 16],
    /// Authoritative deadline shared with the request.
    pub deadline: UnixMicros,
    /// Fresh nonce for this individual envelope.
    pub replay_nonce: [u8; 32],
}

/// Signed authority fetch plus the exact state needed to authenticate its response.
#[derive(Clone, Debug, PartialEq)]
pub struct OutboundFederationAuthorityFetch {
    envelope: FederationEnvelope,
    expectation: FederationAuthorityPageExpectation,
}

impl OutboundFederationAuthorityFetch {
    /// Returns the exact signed wire request.
    #[must_use]
    pub const fn envelope(&self) -> &FederationEnvelope {
        &self.envelope
    }

    /// Returns the exact local expectation for the corresponding page.
    #[must_use]
    pub const fn expectation(&self) -> FederationAuthorityPageExpectation {
        self.expectation
    }
}

/// Authority fetch whose TLS peer, relationship fence, signature and nonce all agree.
#[derive(Clone, Debug)]
pub struct AuthenticatedFederationAuthorityFetch {
    binding: crate::FederationPeerBinding,
    header: FederationHeader,
    request: FetchFederationAuthority,
}

impl AuthenticatedFederationAuthorityFetch {
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

    /// Returns the peer's last applied authority revision; zero requests an initial snapshot.
    #[must_use]
    pub const fn after_revision(&self) -> u64 {
        self.request.after_revision
    }

    /// Returns the opaque continuation supplied by the peer.
    #[must_use]
    pub fn cursor(&self) -> &[u8] {
        &self.request.cursor
    }

    /// Returns the peer's requested positive page bound.
    #[must_use]
    pub const fn limit(&self) -> u32 {
        self.request.limit
    }

    /// Constructs an exactly correlated response context with a fresh responder nonce.
    ///
    /// # Errors
    ///
    /// Rejects a zero or reflected response nonce.
    pub fn response_context(
        &self,
        replay_nonce: [u8; 32],
    ) -> Result<FederationAuthorityContext, TransportError> {
        if replay_nonce == exact::<32>(&self.header.replay_nonce)? {
            return Err(TransportError::InvalidConfiguration);
        }
        FederationAuthorityContext::new(
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

/// Constructs and signs one bounded authority fetch from current committed local identity.
///
/// # Errors
///
/// Rejects stale deadlines, invalid page bounds or an envelope exceeding wire limits.
pub fn signed_federation_authority_fetch(
    identity: &FederationLocalIdentity<'_>,
    context: FederationAuthorityContext,
    after_revision: u64,
    cursor: Vec<u8>,
    limit: u32,
    limits: WireLimits,
    now: UnixMicros,
) -> Result<OutboundFederationAuthorityFetch, TransportError> {
    let binding = identity.binding();
    if context.deadline <= now || context.deadline > binding.valid_until {
        return Err(TransportError::InvalidConfiguration);
    }
    let header = authority_header(binding, context);
    let mut request = FetchFederationAuthority {
        after_revision,
        cursor,
        limit,
        signature: Vec::new(),
    };
    request.signature = identity
        .signing_key()
        .sign(&federation_authority_fetch_signing_payload(
            &header, &request,
        ))
        .to_bytes()
        .to_vec();
    let envelope = FederationEnvelope {
        header: Some(header),
        message: Some(Message::FetchAuthority(request)),
    };
    encode_federation_frame(&envelope, limits)?;
    Ok(OutboundFederationAuthorityFetch {
        envelope,
        expectation: FederationAuthorityPageExpectation::new(binding, context, after_revision),
    })
}

impl FederationAuthorityContext {
    /// Constructs a complete request or response context.
    ///
    /// # Errors
    ///
    /// Rejects unsupported versions, zero identifiers/nonces or non-positive deadlines.
    pub fn new(
        version: ProtocolVersion,
        request_id: [u8; 16],
        operation_id: [u8; 16],
        trace_id: [u8; 16],
        deadline: UnixMicros,
        replay_nonce: [u8; 32],
    ) -> Result<Self, TransportError> {
        let invalid = version.major != 1
            || request_id == [0; 16]
            || operation_id == [0; 16]
            || trace_id == [0; 16]
            || deadline.get() <= 0
            || replay_nonce == [0; 32];
        if invalid {
            Err(TransportError::InvalidConfiguration)
        } else {
            Ok(Self {
                version,
                request_id,
                operation_id,
                trace_id,
                deadline,
                replay_nonce,
            })
        }
    }
}

/// Exact local request state against which one remote authority page is authenticated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationAuthorityPageExpectation {
    local_identity: FederationLocalIdentityBinding,
    request_context: FederationAuthorityContext,
    minimum_authority_revision: u64,
}

impl FederationAuthorityPageExpectation {
    /// Binds a response to the current local relationship and requested revision floor.
    #[must_use]
    pub const fn new(
        local_identity: FederationLocalIdentityBinding,
        request_context: FederationAuthorityContext,
        minimum_authority_revision: u64,
    ) -> Self {
        Self {
            local_identity,
            request_context,
            minimum_authority_revision,
        }
    }
}

/// Signed authority-page envelope ready for bounded federation framing.
#[derive(Clone, Debug, PartialEq)]
pub struct OutboundFederationAuthorityPage {
    envelope: FederationEnvelope,
}

impl OutboundFederationAuthorityPage {
    /// Returns the exact signed wire envelope.
    #[must_use]
    pub const fn envelope(&self) -> &FederationEnvelope {
        &self.envelope
    }
}

/// Authority page whose TLS peer, relationship fence, digest, signature and nonce all agree.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthenticatedFederationAuthorityPage {
    page: FederationAuthorityPage,
}

impl AuthenticatedFederationAuthorityPage {
    /// Returns the peer's exact committed authority revision for this stable page.
    #[must_use]
    pub const fn authority_revision(&self) -> u64 {
        self.page.authority_revision
    }

    /// Returns the independently versioned canonical records.
    #[must_use]
    pub fn records(&self) -> &[VersionedPayload] {
        &self.page.records
    }

    /// Returns the opaque signed continuation, empty only at the end.
    #[must_use]
    pub fn next_cursor(&self) -> &[u8] {
        &self.page.next_cursor
    }
}

/// Builds one signed page from an already authenticated current local identity.
///
/// # Errors
///
/// Rejects stale deadlines, zero revisions or any page exceeding the declared wire bounds.
pub fn signed_federation_authority_page(
    identity: &FederationLocalIdentity<'_>,
    context: FederationAuthorityContext,
    authority_revision: u64,
    records: Vec<VersionedPayload>,
    next_cursor: Vec<u8>,
    limits: WireLimits,
    now: UnixMicros,
) -> Result<OutboundFederationAuthorityPage, TransportError> {
    let binding = identity.binding();
    if authority_revision == 0 || context.deadline <= now || context.deadline > binding.valid_until
    {
        return Err(TransportError::InvalidConfiguration);
    }
    let header = authority_header(binding, context);
    let mut page = FederationAuthorityPage {
        authority_revision,
        records,
        next_cursor,
        page_digest: Vec::new(),
        signature: Vec::new(),
    };
    page.page_digest = authority_page_digest(&page).to_vec();
    page.signature = identity
        .signing_key()
        .sign(&federation_authority_page_signing_payload(&header, &page))
        .to_bytes()
        .to_vec();
    let envelope = FederationEnvelope {
        header: Some(header),
        message: Some(Message::AuthorityPage(page)),
    };
    encode_federation_frame(&envelope, limits)?;
    Ok(OutboundFederationAuthorityPage { envelope })
}

fn authority_header(
    binding: FederationLocalIdentityBinding,
    context: FederationAuthorityContext,
) -> FederationHeader {
    FederationHeader {
        version: Some(context.version),
        relationship_id: binding.relationship_id.as_bytes().to_vec(),
        sender_mesh_id: binding.local_mesh_id.as_bytes().to_vec(),
        recipient_mesh_id: binding.remote_mesh_id.as_bytes().to_vec(),
        request_id: context.request_id.to_vec(),
        operation_id: context.operation_id.to_vec(),
        authority_epoch: binding.authority_epoch,
        deadline_unix_micros: context.deadline.get(),
        trace_id: context.trace_id.to_vec(),
        replay_nonce: context.replay_nonce.to_vec(),
    }
}

impl FederationPeerRegistry {
    /// Authenticates one signed authority fetch against current TLS and relationship authority.
    ///
    /// # Errors
    ///
    /// Rejects stale authority, route substitution, invalid signatures or replay.
    pub fn authenticate_authority_fetch(
        &self,
        connection: &quinn::Connection,
        envelope: &ValidatedFederationEnvelope,
        now: UnixMicros,
        replay: &mut FederationReplayGuard,
    ) -> Result<AuthenticatedFederationAuthorityFetch, TransportError> {
        let (binding, _) = self.connection_binding(connection, now)?;
        let envelope = envelope.as_inner();
        let header = envelope
            .header
            .as_ref()
            .ok_or(TransportError::UntrustedFederationPeer)?;
        let Message::FetchAuthority(request) = envelope
            .message
            .as_ref()
            .ok_or(TransportError::UntrustedFederationPeer)?
        else {
            return Err(TransportError::UntrustedFederationPeer);
        };
        verify_authority_fetch_shape(binding, header)?;
        replay.check(binding.relationship_id, header, now)?;
        verify_authority_fetch_signature(binding.verifying_key, header, request)?;
        replay.record(binding.relationship_id, header)?;
        Ok(AuthenticatedFederationAuthorityFetch {
            binding,
            header: header.clone(),
            request: request.clone(),
        })
    }

    /// Authenticates one authority page against current TLS and relationship authority.
    ///
    /// # Errors
    ///
    /// Rejects stale authority, correlation substitution, digest/signature changes or replay.
    pub fn authenticate_authority_page(
        &self,
        connection: &quinn::Connection,
        envelope: &ValidatedFederationEnvelope,
        expected: FederationAuthorityPageExpectation,
        now: UnixMicros,
        replay: &mut FederationReplayGuard,
    ) -> Result<AuthenticatedFederationAuthorityPage, TransportError> {
        let (binding, _) = self.connection_binding(connection, now)?;
        let envelope = envelope.as_inner();
        let header = envelope
            .header
            .as_ref()
            .ok_or(TransportError::UntrustedFederationPeer)?;
        let Message::AuthorityPage(page) = envelope
            .message
            .as_ref()
            .ok_or(TransportError::UntrustedFederationPeer)?
        else {
            return Err(TransportError::UntrustedFederationPeer);
        };
        verify_authority_page_shape(binding, header, page, expected)?;
        replay.check(binding.relationship_id, header, now)?;
        verify_authority_page_digest(page)?;
        verify_authority_page_signature(binding.verifying_key, header, page)?;
        replay.record(binding.relationship_id, header)?;
        Ok(AuthenticatedFederationAuthorityPage { page: page.clone() })
    }
}

fn verify_authority_fetch_shape(
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

fn verify_authority_fetch_signature(
    verifying_key: [u8; 32],
    header: &FederationHeader,
    request: &FetchFederationAuthority,
) -> Result<(), TransportError> {
    let signature = exact::<64>(&request.signature)?;
    VerifyingKey::from_bytes(&verifying_key)
        .map_err(|_| TransportError::UntrustedFederationPeer)?
        .verify_strict(
            &federation_authority_fetch_signing_payload(header, request),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| TransportError::UntrustedFederationPeer)
}

fn verify_authority_page_shape(
    binding: crate::FederationPeerBinding,
    header: &FederationHeader,
    page: &FederationAuthorityPage,
    expected: FederationAuthorityPageExpectation,
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
        && page.authority_revision >= expected.minimum_authority_revision;
    if valid {
        Ok(())
    } else {
        Err(TransportError::UntrustedFederationPeer)
    }
}

fn verify_authority_page_digest(page: &FederationAuthorityPage) -> Result<(), TransportError> {
    let expected = authority_page_digest(page);
    if exact::<32>(&page.page_digest)? == expected {
        Ok(())
    } else {
        Err(TransportError::UntrustedFederationPeer)
    }
}

fn verify_authority_page_signature(
    verifying_key: [u8; 32],
    header: &FederationHeader,
    page: &FederationAuthorityPage,
) -> Result<(), TransportError> {
    let signature = exact::<64>(&page.signature)?;
    VerifyingKey::from_bytes(&verifying_key)
        .map_err(|_| TransportError::UntrustedFederationPeer)?
        .verify_strict(
            &federation_authority_page_signing_payload(header, page),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| TransportError::UntrustedFederationPeer)
}

fn authority_page_digest(page: &FederationAuthorityPage) -> [u8; 32] {
    Sha256::digest(federation_authority_page_digest_payload(page)).into()
}

fn exact<const SIZE: usize>(value: &[u8]) -> Result<[u8; SIZE], TransportError> {
    value
        .try_into()
        .map_err(|_| TransportError::UntrustedFederationPeer)
}
