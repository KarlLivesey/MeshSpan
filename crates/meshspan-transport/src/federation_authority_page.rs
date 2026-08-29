// SPDX-License-Identifier: GPL-2.0-only

//! Signed, revision-bound federation authority pages over an authenticated session.

use ed25519_dalek::{Signature, Signer, VerifyingKey};
use meshspan_domain::UnixMicros;
use meshspan_protocol::v1::federation_envelope::Message;
use meshspan_protocol::v1::{
    FederationAuthorityPage, FederationEnvelope, FederationHeader, ProtocolVersion,
    VersionedPayload,
};
use meshspan_protocol::{
    ValidatedFederationEnvelope, WireLimits, encode_federation_frame,
    federation_authority_page_digest_payload, federation_authority_page_signing_payload,
};
use sha2::{Digest, Sha256};

use crate::{
    FederationLocalIdentity, FederationLocalIdentityBinding, FederationPeerRegistry,
    FederationReplayGuard, TransportError,
};

/// Fresh correlation and anti-replay fields for one authority-page response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationAuthorityPageContext {
    /// Negotiated exact protocol version.
    pub version: ProtocolVersion,
    /// Request correlation identity copied from the fetch request.
    pub request_id: [u8; 16],
    /// Idempotent fetch operation identity copied from the request.
    pub operation_id: [u8; 16],
    /// End-to-end trace identity copied from the request.
    pub trace_id: [u8; 16],
    /// Authoritative deadline shared with the request.
    pub deadline: UnixMicros,
    /// Fresh response nonce consumed independently from the request nonce.
    pub replay_nonce: [u8; 32],
}

impl FederationAuthorityPageContext {
    /// Constructs a complete response context.
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
    context: FederationAuthorityPageContext,
    minimum_authority_revision: u64,
}

impl FederationAuthorityPageExpectation {
    /// Binds a response to the current local relationship and requested revision floor.
    #[must_use]
    pub const fn new(
        local_identity: FederationLocalIdentityBinding,
        context: FederationAuthorityPageContext,
        minimum_authority_revision: u64,
    ) -> Self {
        Self {
            local_identity,
            context,
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
    context: FederationAuthorityPageContext,
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
    let header = FederationHeader {
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
    };
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

impl FederationPeerRegistry {
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

fn verify_authority_page_shape(
    binding: crate::FederationPeerBinding,
    header: &FederationHeader,
    page: &FederationAuthorityPage,
    expected: FederationAuthorityPageExpectation,
) -> Result<(), TransportError> {
    let local = expected.local_identity;
    let context = expected.context;
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
        && exact::<32>(&header.replay_nonce).ok() == Some(context.replay_nonce)
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
