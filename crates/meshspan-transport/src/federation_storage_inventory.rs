// SPDX-License-Identifier: GPL-2.0-only

//! Signed, bounded federation storage inventory pages over authenticated relationships.

use ed25519_dalek::{Signature, Signer, VerifyingKey};
use meshspan_domain::UnixMicros;
use meshspan_protocol::v1::federation_envelope::Message;
use meshspan_protocol::v1::{
    FederatedStorageInventoryPage, FederationEnvelope, FederationHeader,
    FetchFederatedStorageInventory, VersionedPayload,
};
use meshspan_protocol::{
    ValidatedFederationEnvelope, WireLimits, encode_federation_frame,
    federation_storage_inventory_fetch_signing_payload,
    federation_storage_inventory_page_digest_payload,
    federation_storage_inventory_page_signing_payload,
};
use sha2::{Digest, Sha256};

use crate::federation_authority_page::{exact, federation_header};
use crate::federation_storage_capability::{
    validate_outbound_context, verify_correlated_response_header, verify_inbound_request_header,
};
use crate::{
    FederationExchangeContext, FederationLocalIdentity, FederationLocalIdentityBinding,
    FederationPeerBinding, FederationPeerRegistry, FederationReplayGuard, TransportError,
};

/// Signed inventory fetch plus the exact state needed to authenticate its page.
#[derive(Clone, Debug, PartialEq)]
pub struct OutboundFederationStorageInventoryFetch {
    envelope: FederationEnvelope,
    expectation: FederationStorageInventoryPageExpectation,
}

impl OutboundFederationStorageInventoryFetch {
    /// Returns the exact signed wire request.
    #[must_use]
    pub const fn envelope(&self) -> &FederationEnvelope {
        &self.envelope
    }

    /// Returns the exact request state against which the page must be checked.
    #[must_use]
    pub const fn expectation(&self) -> &FederationStorageInventoryPageExpectation {
        &self.expectation
    }
}

/// Inventory request whose TLS peer, relationship, signature and replay nonce agree.
#[derive(Clone, Debug)]
pub struct AuthenticatedFederationStorageInventoryFetch {
    binding: FederationPeerBinding,
    header: FederationHeader,
    request: FetchFederatedStorageInventory,
}

impl AuthenticatedFederationStorageInventoryFetch {
    /// Returns the certificate-authenticated requesting swarm.
    #[must_use]
    pub const fn remote_mesh_id(&self) -> meshspan_domain::MeshId {
        self.binding.remote_mesh_id
    }

    /// Returns the structurally validated signed query.
    #[must_use]
    pub const fn request(&self) -> &FetchFederatedStorageInventory {
        &self.request
    }

    /// Correlates the page with this request while requiring a fresh responder nonce.
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

/// Exact local inventory query against which one remote page is authenticated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationStorageInventoryPageExpectation {
    local_identity: FederationLocalIdentityBinding,
    request_context: FederationExchangeContext,
    request: FetchFederatedStorageInventory,
}

impl FederationStorageInventoryPageExpectation {
    /// Returns the exact peer-requested record ceiling.
    #[must_use]
    pub const fn request_limit(&self) -> u32 {
        self.request.limit
    }
}

/// Signed inventory page ready for bounded federation framing.
#[derive(Clone, Debug, PartialEq)]
pub struct OutboundFederationStorageInventoryPage {
    envelope: FederationEnvelope,
}

impl OutboundFederationStorageInventoryPage {
    /// Returns the exact signed wire page.
    #[must_use]
    pub const fn envelope(&self) -> &FederationEnvelope {
        &self.envelope
    }
}

/// Inventory page whose peer, query, content digest, signature and nonce all agree.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthenticatedFederationStorageInventoryPage {
    page: FederatedStorageInventoryPage,
}

impl AuthenticatedFederationStorageInventoryPage {
    /// Returns the bounded independently versioned inventory records.
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

/// Constructs and signs one bounded storage inventory fetch.
///
/// # Errors
///
/// Rejects stale deadlines or a query outside negotiated wire bounds.
pub fn signed_federation_storage_inventory_fetch(
    identity: &FederationLocalIdentity<'_>,
    context: FederationExchangeContext,
    mut request: FetchFederatedStorageInventory,
    limits: WireLimits,
    now: UnixMicros,
) -> Result<OutboundFederationStorageInventoryFetch, TransportError> {
    let binding = identity.binding();
    validate_outbound_context(binding, context, now)?;
    let header = federation_header(binding, context);
    request.signature.clear();
    request.signature = identity
        .signing_key()
        .sign(&federation_storage_inventory_fetch_signing_payload(
            &header, &request,
        )?)
        .to_bytes()
        .to_vec();
    let expectation = FederationStorageInventoryPageExpectation {
        local_identity: binding,
        request_context: context,
        request: request.clone(),
    };
    let envelope = FederationEnvelope {
        header: Some(header),
        message: Some(Message::FetchStorageInventory(request)),
    };
    encode_federation_frame(&envelope, limits)?;
    Ok(OutboundFederationStorageInventoryFetch {
        envelope,
        expectation,
    })
}

/// Constructs and signs one bounded storage inventory page with its canonical digest.
///
/// # Errors
///
/// Rejects stale deadlines or a page outside negotiated wire bounds.
pub fn signed_federation_storage_inventory_page(
    identity: &FederationLocalIdentity<'_>,
    context: FederationExchangeContext,
    mut page: FederatedStorageInventoryPage,
    limits: WireLimits,
    now: UnixMicros,
) -> Result<OutboundFederationStorageInventoryPage, TransportError> {
    let binding = identity.binding();
    validate_outbound_context(binding, context, now)?;
    let header = federation_header(binding, context);
    page.page_digest.clear();
    page.signature.clear();
    page.page_digest = inventory_page_digest(&page)?.to_vec();
    page.signature = identity
        .signing_key()
        .sign(&federation_storage_inventory_page_signing_payload(
            &header, &page,
        )?)
        .to_bytes()
        .to_vec();
    let envelope = FederationEnvelope {
        header: Some(header),
        message: Some(Message::StorageInventoryPage(page)),
    };
    encode_federation_frame(&envelope, limits)?;
    Ok(OutboundFederationStorageInventoryPage { envelope })
}

impl FederationPeerRegistry {
    /// Authenticates one inventory fetch against current TLS and relationship authority.
    ///
    /// # Errors
    ///
    /// Rejects identity, route, signature, deadline or replay substitution.
    pub fn authenticate_storage_inventory_fetch(
        &self,
        connection: &quinn::Connection,
        envelope: &ValidatedFederationEnvelope,
        now: UnixMicros,
        replay: &mut FederationReplayGuard,
    ) -> Result<AuthenticatedFederationStorageInventoryFetch, TransportError> {
        let (binding, _) = self.connection_binding(connection, now)?;
        let envelope = envelope.as_inner();
        let header = envelope
            .header
            .as_ref()
            .ok_or(TransportError::UntrustedFederationPeer)?;
        let Message::FetchStorageInventory(request) = envelope
            .message
            .as_ref()
            .ok_or(TransportError::UntrustedFederationPeer)?
        else {
            return Err(TransportError::UntrustedFederationPeer);
        };
        verify_inbound_request_header(binding, header)?;
        replay.check(binding.relationship_id, header, now)?;
        verify_inventory_fetch_signature(binding.verifying_key, header, request)?;
        replay.record(binding.relationship_id, header)?;
        Ok(AuthenticatedFederationStorageInventoryFetch {
            binding,
            header: header.clone(),
            request: request.clone(),
        })
    }

    /// Authenticates one inventory page against the exact query and current TLS peer.
    ///
    /// # Errors
    ///
    /// Rejects correlation, target, page-bound, digest, signature, authority or replay
    /// substitution.
    pub fn authenticate_storage_inventory_page(
        &self,
        connection: &quinn::Connection,
        envelope: &ValidatedFederationEnvelope,
        expected: &FederationStorageInventoryPageExpectation,
        now: UnixMicros,
        replay: &mut FederationReplayGuard,
    ) -> Result<AuthenticatedFederationStorageInventoryPage, TransportError> {
        let (binding, _) = self.connection_binding(connection, now)?;
        let envelope = envelope.as_inner();
        let header = envelope
            .header
            .as_ref()
            .ok_or(TransportError::UntrustedFederationPeer)?;
        let Message::StorageInventoryPage(page) = envelope
            .message
            .as_ref()
            .ok_or(TransportError::UntrustedFederationPeer)?
        else {
            return Err(TransportError::UntrustedFederationPeer);
        };
        verify_inventory_page_shape(binding, header, page, expected)?;
        replay.check(binding.relationship_id, header, now)?;
        verify_inventory_page_digest(page)?;
        verify_inventory_page_signature(binding.verifying_key, header, page)?;
        replay.record(binding.relationship_id, header)?;
        Ok(AuthenticatedFederationStorageInventoryPage { page: page.clone() })
    }
}

fn verify_inventory_fetch_signature(
    verifying_key: [u8; 32],
    header: &FederationHeader,
    request: &FetchFederatedStorageInventory,
) -> Result<(), TransportError> {
    let signature = exact::<64>(&request.signature)?;
    let payload = federation_storage_inventory_fetch_signing_payload(header, request)?;
    VerifyingKey::from_bytes(&verifying_key)
        .map_err(|_| TransportError::UntrustedFederationPeer)?
        .verify_strict(&payload, &Signature::from_bytes(&signature))
        .map_err(|_| TransportError::UntrustedFederationPeer)
}

fn verify_inventory_page_shape(
    binding: FederationPeerBinding,
    header: &FederationHeader,
    page: &FederatedStorageInventoryPage,
    expected: &FederationStorageInventoryPageExpectation,
) -> Result<(), TransportError> {
    verify_correlated_response_header(
        binding,
        header,
        expected.local_identity,
        expected.request_context,
    )?;
    let request = &expected.request;
    let within_requested_limit =
        usize::try_from(request.limit).is_ok_and(|limit| page.records.len() <= limit);
    let valid = page.grant_id == request.grant_id
        && page.target_id == request.target_id
        && page.target_generation == request.target_generation
        && within_requested_limit;
    if valid {
        Ok(())
    } else {
        Err(TransportError::UntrustedFederationPeer)
    }
}

fn verify_inventory_page_digest(
    page: &FederatedStorageInventoryPage,
) -> Result<(), TransportError> {
    if exact::<32>(&page.page_digest)? == inventory_page_digest(page)? {
        Ok(())
    } else {
        Err(TransportError::UntrustedFederationPeer)
    }
}

fn verify_inventory_page_signature(
    verifying_key: [u8; 32],
    header: &FederationHeader,
    page: &FederatedStorageInventoryPage,
) -> Result<(), TransportError> {
    let signature = exact::<64>(&page.signature)?;
    let payload = federation_storage_inventory_page_signing_payload(header, page)?;
    VerifyingKey::from_bytes(&verifying_key)
        .map_err(|_| TransportError::UntrustedFederationPeer)?
        .verify_strict(&payload, &Signature::from_bytes(&signature))
        .map_err(|_| TransportError::UntrustedFederationPeer)
}

fn inventory_page_digest(page: &FederatedStorageInventoryPage) -> Result<[u8; 32], TransportError> {
    Ok(Sha256::digest(federation_storage_inventory_page_digest_payload(page)?).into())
}
