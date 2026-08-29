// SPDX-License-Identifier: GPL-2.0-only

//! Certificate-bound federation peer authentication and bounded replay admission.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, VerifyingKey};
use meshspan_domain::{DurationMicros, FederationRelationshipId, MeshId, UnixMicros};
use meshspan_protocol::v1::federation_envelope::Message;
use meshspan_protocol::v1::{FederationHeader, FederationHello};
use meshspan_protocol::{ValidatedFederationEnvelope, federation_hello_signing_payload};
use sha2::{Digest, Sha256};

use crate::TransportError;
use crate::identity::connection_certificate_fingerprint;

/// One active remote federation identity derived from authoritative relationship metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationPeerBinding {
    /// Mutually approved relationship carrying this identity.
    pub relationship_id: FederationRelationshipId,
    /// Receiving autonomous swarm.
    pub local_mesh_id: MeshId,
    /// Certificate-presenting autonomous swarm.
    pub remote_mesh_id: MeshId,
    /// Exact current relationship authority fence.
    pub authority_epoch: u64,
    /// Exact active remote identity generation.
    pub identity_generation: u64,
    /// SHA-256 fingerprint of the exact remote TLS leaf certificate DER.
    pub certificate_fingerprint: [u8; 32],
    /// Ed25519 public key for signed federation envelopes.
    pub verifying_key: [u8; 32],
    /// First authoritative instant at which this identity is valid, inclusive.
    pub valid_from: UnixMicros,
    /// First authoritative instant at which this identity is expired, exclusive.
    pub valid_until: UnixMicros,
}

/// Immutable lookup which cannot resolve a federation certificate as an enrolled node.
#[derive(Clone, Debug)]
pub struct FederationPeerRegistry {
    by_fingerprint: BTreeMap<[u8; 32], FederationPeerBinding>,
}

impl FederationPeerRegistry {
    /// Builds an unambiguous registry from active, metadata-validated relationship identities.
    ///
    /// # Errors
    ///
    /// Rejects malformed keys, lifetimes, duplicate relationships or certificate fingerprints.
    pub fn new(
        bindings: impl IntoIterator<Item = FederationPeerBinding>,
    ) -> Result<Self, TransportError> {
        let mut by_fingerprint = BTreeMap::new();
        let mut relationships = BTreeSet::new();
        for binding in bindings {
            let invalid = binding.local_mesh_id == binding.remote_mesh_id
                || binding.authority_epoch == 0
                || binding.identity_generation == 0
                || binding.certificate_fingerprint == [0; 32]
                || binding.valid_until <= binding.valid_from
                || VerifyingKey::from_bytes(&binding.verifying_key).is_err()
                || !relationships.insert(binding.relationship_id)
                || by_fingerprint
                    .insert(binding.certificate_fingerprint, binding)
                    .is_some();
            if invalid {
                return Err(TransportError::InvalidConfiguration);
            }
        }
        if by_fingerprint.is_empty() {
            return Err(TransportError::InvalidConfiguration);
        }
        Ok(Self { by_fingerprint })
    }

    /// Authenticates one structurally validated hello against TLS, relationship and signature
    /// authority, then consumes its nonce in the bounded replay guard.
    ///
    /// # Errors
    ///
    /// Rejects unapproved certificates, stale identity/authority, invalid signatures, deadlines
    /// outside the admitted window, replay and exhausted replay capacity.
    pub fn authenticate_hello(
        &self,
        connection: &quinn::Connection,
        envelope: &ValidatedFederationEnvelope,
        now: UnixMicros,
        replay: &mut FederationReplayGuard,
    ) -> Result<AuthenticatedFederationHello, TransportError> {
        let fingerprint = connection_certificate_fingerprint(connection)
            .map_err(|_| TransportError::UntrustedFederationPeer)?;
        let binding = self
            .by_fingerprint
            .get(&fingerprint)
            .copied()
            .ok_or(TransportError::UntrustedFederationPeer)?;
        let envelope = envelope.as_inner();
        let header = envelope
            .header
            .as_ref()
            .ok_or(TransportError::UntrustedFederationPeer)?;
        let Message::Hello(hello) = envelope
            .message
            .as_ref()
            .ok_or(TransportError::UntrustedFederationPeer)?
        else {
            return Err(TransportError::UntrustedFederationPeer);
        };
        verify_binding(binding, fingerprint, header, hello, now)?;
        replay.check(binding.relationship_id, header, now)?;
        verify_signature(binding.verifying_key, header, hello)?;
        replay.record(binding.relationship_id, header)?;
        Ok(AuthenticatedFederationHello {
            binding,
            header: header.clone(),
            hello: hello.clone(),
        })
    }
}

/// Bounded set of still-live authenticated federation nonces.
#[derive(Debug)]
pub struct FederationReplayGuard {
    entries: BTreeMap<(FederationRelationshipId, [u8; 32]), UnixMicros>,
    maximum_entries: usize,
    maximum_message_lifetime: DurationMicros,
}

impl FederationReplayGuard {
    /// Constructs a replay window with explicit memory and deadline bounds.
    ///
    /// # Errors
    ///
    /// Rejects zero bounds.
    pub fn new(
        maximum_entries: usize,
        maximum_message_lifetime: DurationMicros,
    ) -> Result<Self, TransportError> {
        if maximum_entries == 0 || maximum_message_lifetime.get() == 0 {
            return Err(TransportError::InvalidConfiguration);
        }
        Ok(Self {
            entries: BTreeMap::new(),
            maximum_entries,
            maximum_message_lifetime,
        })
    }

    fn check(
        &mut self,
        relationship_id: FederationRelationshipId,
        header: &FederationHeader,
        now: UnixMicros,
    ) -> Result<(), TransportError> {
        self.entries.retain(|_, expiry| *expiry > now);
        let deadline = UnixMicros::new(header.deadline_unix_micros);
        let latest = now
            .checked_add(self.maximum_message_lifetime)
            .ok_or(TransportError::StaleFederationMessage)?;
        let nonce = nonce(header)?;
        if deadline <= now || deadline > latest {
            return Err(TransportError::StaleFederationMessage);
        }
        if self.entries.contains_key(&(relationship_id, nonce)) {
            return Err(TransportError::ReplayedFederationMessage);
        }
        if self.entries.len() >= self.maximum_entries {
            return Err(TransportError::FederationReplayCapacity);
        }
        Ok(())
    }

    fn record(
        &mut self,
        relationship_id: FederationRelationshipId,
        header: &FederationHeader,
    ) -> Result<(), TransportError> {
        let key = (relationship_id, nonce(header)?);
        if self
            .entries
            .insert(key, UnixMicros::new(header.deadline_unix_micros))
            .is_some()
        {
            return Err(TransportError::ReplayedFederationMessage);
        }
        Ok(())
    }
}

/// Hello whose TLS certificate, relationship, current epoch, key, signature and nonce all agree.
#[derive(Clone, Debug)]
pub struct AuthenticatedFederationHello {
    binding: FederationPeerBinding,
    header: FederationHeader,
    hello: FederationHello,
}

impl AuthenticatedFederationHello {
    /// Returns the exact mutually approved relationship.
    #[must_use]
    pub const fn relationship_id(&self) -> FederationRelationshipId {
        self.binding.relationship_id
    }

    /// Returns the certificate-presenting autonomous swarm.
    #[must_use]
    pub const fn remote_mesh_id(&self) -> MeshId {
        self.binding.remote_mesh_id
    }

    /// Returns the validated request header for response correlation.
    #[must_use]
    pub const fn header(&self) -> &FederationHeader {
        &self.header
    }

    /// Returns the signed and validated negotiation offer.
    #[must_use]
    pub const fn hello(&self) -> &FederationHello {
        &self.hello
    }
}

fn verify_binding(
    binding: FederationPeerBinding,
    fingerprint: [u8; 32],
    header: &FederationHeader,
    hello: &FederationHello,
    now: UnixMicros,
) -> Result<(), TransportError> {
    let relationship_id = identifier(&header.relationship_id)
        .and_then(|bytes| FederationRelationshipId::from_bytes(bytes).ok());
    let sender =
        identifier(&header.sender_mesh_id).and_then(|bytes| MeshId::from_bytes(bytes).ok());
    let recipient =
        identifier(&header.recipient_mesh_id).and_then(|bytes| MeshId::from_bytes(bytes).ok());
    let advertised_fingerprint: [u8; 32] = Sha256::digest(&hello.public_identity_chain).into();
    if relationship_id != Some(binding.relationship_id)
        || sender != Some(binding.remote_mesh_id)
        || recipient != Some(binding.local_mesh_id)
        || header.authority_epoch != binding.authority_epoch
        || hello.identity_generation != binding.identity_generation
        || now < binding.valid_from
        || now >= binding.valid_until
        || advertised_fingerprint != fingerprint
        || fingerprint != binding.certificate_fingerprint
    {
        return Err(TransportError::UntrustedFederationPeer);
    }
    Ok(())
}

fn verify_signature(
    verifying_key: [u8; 32],
    header: &FederationHeader,
    hello: &FederationHello,
) -> Result<(), TransportError> {
    let signature: [u8; 64] = hello
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| TransportError::UntrustedFederationPeer)?;
    VerifyingKey::from_bytes(&verifying_key)
        .map_err(|_| TransportError::UntrustedFederationPeer)?
        .verify_strict(
            &federation_hello_signing_payload(header, hello),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| TransportError::UntrustedFederationPeer)
}

fn identifier(value: &[u8]) -> Option<[u8; 16]> {
    value.try_into().ok()
}

fn nonce(header: &FederationHeader) -> Result<[u8; 32], TransportError> {
    header
        .replay_nonce
        .as_slice()
        .try_into()
        .map_err(|_| TransportError::UntrustedFederationPeer)
}
