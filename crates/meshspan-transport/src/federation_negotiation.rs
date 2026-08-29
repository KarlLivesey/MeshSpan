// SPDX-License-Identifier: GPL-2.0-only

//! Signed two-nonce federation welcome negotiation and initiator verification.

use std::collections::BTreeSet;

use ed25519_dalek::{Signature, Signer, VerifyingKey};
use meshspan_domain::{FederationRelationshipId, MeshId, UnixMicros};
use meshspan_protocol::v1::federation_envelope::Message;
use meshspan_protocol::v1::{
    FederationEnvelope, FederationHeader, FederationWelcome, ProtocolVersion,
};
use meshspan_protocol::{
    ValidatedFederationEnvelope, WireLimits, encode_federation_frame,
    federation_welcome_signing_payload,
};

use crate::{
    AuthenticatedFederationHello, FederationLocalIdentity, FederationPeerRegistry,
    FederationReplayGuard, TransportError,
};

/// Local identity, authority revision and resource limits used to answer one valid hello.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationNegotiationConfig {
    versions: Vec<ProtocolVersion>,
    authority_revision: u64,
    wire_limits: WireLimits,
    maximum_streams: u32,
}

impl FederationNegotiationConfig {
    /// Constructs a non-empty exact-version offer with positive authority and stream bounds.
    ///
    /// # Errors
    ///
    /// Rejects duplicate/zero versions, zero revisions or zero streams.
    pub fn new(
        versions: Vec<ProtocolVersion>,
        authority_revision: u64,
        wire_limits: WireLimits,
        maximum_streams: u32,
    ) -> Result<Self, TransportError> {
        let distinct = versions
            .iter()
            .map(|version| (version.major, version.minor))
            .collect::<BTreeSet<_>>();
        if versions.is_empty()
            || distinct.len() != versions.len()
            || versions.iter().any(|version| version.major == 0)
            || authority_revision == 0
            || maximum_streams == 0
        {
            return Err(TransportError::InvalidConfiguration);
        }
        Ok(Self {
            versions,
            authority_revision,
            wire_limits,
            maximum_streams,
        })
    }

    /// Returns the local hard receive/send bounds used for negotiation framing.
    #[must_use]
    pub const fn wire_limits(&self) -> WireLimits {
        self.wire_limits
    }
}

/// Fresh responder values which must come from the daemon's cryptographic randomness seam.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationWelcomeNonces {
    /// Challenge proving the responder signed this exact exchange.
    pub challenge: [u8; 32],
    /// Independent replay identity for the welcome envelope.
    pub replay: [u8; 32],
}

impl FederationWelcomeNonces {
    /// Constructs distinct non-zero challenge and replay nonces.
    ///
    /// # Errors
    ///
    /// Rejects zero or repeated values.
    pub fn new(challenge: [u8; 32], replay: [u8; 32]) -> Result<Self, TransportError> {
        if challenge == [0; 32] || replay == [0; 32] || challenge == replay {
            Err(TransportError::InvalidConfiguration)
        } else {
            Ok(Self { challenge, replay })
        }
    }
}

/// Validated description of the locally emitted hello which a welcome must answer exactly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationHelloExpectation {
    relationship_id: FederationRelationshipId,
    local_mesh_id: MeshId,
    remote_mesh_id: MeshId,
    authority_epoch: u64,
    request_id: [u8; 16],
    operation_id: [u8; 16],
    trace_id: [u8; 16],
    deadline: UnixMicros,
    replay_nonce: [u8; 32],
    challenge_nonce: [u8; 32],
    versions: Vec<ProtocolVersion>,
    maximum_control_bytes: u64,
    maximum_data_frame_bytes: u64,
    maximum_streams: u32,
}

impl FederationHelloExpectation {
    /// Captures one structurally valid locally emitted hello without granting remote authority.
    ///
    /// # Errors
    ///
    /// Rejects an invalid envelope or any message other than `FederationHello`.
    pub fn from_outgoing(
        envelope: &FederationEnvelope,
        limits: WireLimits,
    ) -> Result<Self, TransportError> {
        encode_federation_frame(envelope, limits)?;
        let header = envelope
            .header
            .as_ref()
            .ok_or(TransportError::InvalidFrame)?;
        let Message::Hello(hello) = envelope
            .message
            .as_ref()
            .ok_or(TransportError::InvalidFrame)?
        else {
            return Err(TransportError::InvalidFrame);
        };
        Ok(Self {
            relationship_id: relationship(&header.relationship_id)?,
            local_mesh_id: mesh(&header.sender_mesh_id)?,
            remote_mesh_id: mesh(&header.recipient_mesh_id)?,
            authority_epoch: header.authority_epoch,
            request_id: exact(&header.request_id)?,
            operation_id: exact(&header.operation_id)?,
            trace_id: exact(&header.trace_id)?,
            deadline: UnixMicros::new(header.deadline_unix_micros),
            replay_nonce: exact(&header.replay_nonce)?,
            challenge_nonce: exact(&hello.challenge_nonce)?,
            versions: hello.versions.clone(),
            maximum_control_bytes: hello.maximum_control_bytes,
            maximum_data_frame_bytes: hello.maximum_data_frame_bytes,
            maximum_streams: hello.maximum_streams,
        })
    }
}

/// Mutually authenticated federation connection parameters after both signed challenges pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedFederationSession {
    /// Exact approved relationship.
    pub relationship_id: FederationRelationshipId,
    /// Certificate-authenticated autonomous peer.
    pub remote_mesh_id: MeshId,
    /// Selected exact protocol version.
    pub version: ProtocolVersion,
    /// Peer authority revision advertised by the signed welcome.
    pub remote_authority_revision: u64,
    /// Negotiated maximum control payload bytes.
    pub maximum_control_bytes: u64,
    /// Negotiated maximum bulk-frame bytes.
    pub maximum_data_frame_bytes: u64,
    /// Negotiated maximum concurrent streams.
    pub maximum_streams: u32,
}

/// Responder-side mutually authenticated session after validating and answering one hello.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptedFederationSession {
    /// Exact approved relationship.
    pub relationship_id: FederationRelationshipId,
    /// Certificate-authenticated autonomous peer.
    pub remote_mesh_id: MeshId,
    /// Selected exact protocol version.
    pub version: ProtocolVersion,
    /// Peer identity generation authenticated by its signed hello.
    pub remote_identity_generation: u64,
    /// Negotiated maximum control payload bytes.
    pub maximum_control_bytes: u64,
    /// Negotiated maximum bulk-frame bytes.
    pub maximum_data_frame_bytes: u64,
    /// Negotiated maximum concurrent streams.
    pub maximum_streams: u32,
}

/// Signed welcome envelope paired with the responder's authenticated session proof.
#[derive(Clone, Debug, PartialEq)]
pub struct OutboundFederationWelcome {
    envelope: FederationEnvelope,
    session: AcceptedFederationSession,
}

impl OutboundFederationWelcome {
    /// Returns the signed welcome wire envelope.
    #[must_use]
    pub const fn envelope(&self) -> &FederationEnvelope {
        &self.envelope
    }

    /// Returns the responder-side authenticated session parameters.
    #[must_use]
    pub const fn session(&self) -> AcceptedFederationSession {
        self.session
    }
}

impl AuthenticatedFederationHello {
    /// Builds a signed welcome bound to the authenticated request challenge and lower limits.
    ///
    /// # Errors
    ///
    /// Rejects unsupported versions, invalid/non-fresh nonces or limit conversion failure.
    pub fn signed_welcome(
        &self,
        config: &FederationNegotiationConfig,
        nonces: FederationWelcomeNonces,
        local_identity: &FederationLocalIdentity<'_>,
    ) -> Result<OutboundFederationWelcome, TransportError> {
        let request_challenge: [u8; 32] = exact(&self.hello().challenge_nonce)?;
        if nonces.challenge == request_challenge {
            return Err(TransportError::InvalidConfiguration);
        }
        let selected = highest_common_version(&self.hello().versions, &config.versions)
            .ok_or(TransportError::UnsupportedProtocol)?;
        let binding = self.binding();
        let local_binding = local_identity.binding();
        if local_binding.relationship_id != binding.relationship_id
            || local_binding.local_mesh_id != binding.local_mesh_id
            || local_binding.remote_mesh_id != binding.remote_mesh_id
            || local_binding.authority_epoch != binding.authority_epoch
        {
            return Err(TransportError::InvalidConfiguration);
        }
        let request = self.header();
        let header = FederationHeader {
            version: Some(selected),
            relationship_id: binding.relationship_id.as_bytes().to_vec(),
            sender_mesh_id: binding.local_mesh_id.as_bytes().to_vec(),
            recipient_mesh_id: binding.remote_mesh_id.as_bytes().to_vec(),
            request_id: request.request_id.clone(),
            operation_id: request.operation_id.clone(),
            authority_epoch: binding.authority_epoch,
            deadline_unix_micros: request.deadline_unix_micros,
            trace_id: request.trace_id.clone(),
            replay_nonce: nonces.replay.to_vec(),
        };
        let mut welcome = FederationWelcome {
            selected_version: Some(selected),
            identity_generation: local_binding.identity_generation,
            request_challenge_nonce: request_challenge.to_vec(),
            responder_challenge_nonce: nonces.challenge.to_vec(),
            authority_revision: config.authority_revision,
            maximum_control_bytes: lower_u64(
                self.hello().maximum_control_bytes,
                config.wire_limits.maximum_control_bytes(),
            )?,
            maximum_data_frame_bytes: lower_u64(
                self.hello().maximum_data_frame_bytes,
                config.wire_limits.maximum_data_frame_bytes(),
            )?,
            maximum_streams: self.hello().maximum_streams.min(config.maximum_streams),
            signature: vec![0; 64],
        };
        welcome.signature = local_identity
            .signing_key()
            .sign(&federation_welcome_signing_payload(&header, &welcome))
            .to_bytes()
            .to_vec();
        let session = AcceptedFederationSession {
            relationship_id: binding.relationship_id,
            remote_mesh_id: binding.remote_mesh_id,
            version: selected,
            remote_identity_generation: binding.identity_generation,
            maximum_control_bytes: welcome.maximum_control_bytes,
            maximum_data_frame_bytes: welcome.maximum_data_frame_bytes,
            maximum_streams: welcome.maximum_streams,
        };
        let envelope = FederationEnvelope {
            header: Some(header),
            message: Some(Message::Welcome(welcome)),
        };
        encode_federation_frame(&envelope, config.wire_limits)?;
        Ok(OutboundFederationWelcome { envelope, session })
    }
}

impl FederationPeerRegistry {
    /// Authenticates a signed welcome against TLS, current relationship authority and the exact
    /// locally emitted hello, then consumes the responder's nonce.
    ///
    /// # Errors
    ///
    /// Rejects substituted correlation, challenge, limits, version, identity, signature or replay.
    pub fn authenticate_welcome(
        &self,
        connection: &quinn::Connection,
        envelope: &ValidatedFederationEnvelope,
        expected: &FederationHelloExpectation,
        now: UnixMicros,
        replay: &mut FederationReplayGuard,
    ) -> Result<AuthenticatedFederationSession, TransportError> {
        let (binding, _) = self.connection_binding(connection, now)?;
        let envelope = envelope.as_inner();
        let header = envelope
            .header
            .as_ref()
            .ok_or(TransportError::UntrustedFederationPeer)?;
        let Message::Welcome(welcome) = envelope
            .message
            .as_ref()
            .ok_or(TransportError::UntrustedFederationPeer)?
        else {
            return Err(TransportError::UntrustedFederationPeer);
        };
        verify_welcome_shape(binding, header, welcome, expected)?;
        replay.check(binding.relationship_id, header, now)?;
        verify_welcome_signature(binding.verifying_key, header, welcome)?;
        replay.record(binding.relationship_id, header)?;
        Ok(AuthenticatedFederationSession {
            relationship_id: binding.relationship_id,
            remote_mesh_id: binding.remote_mesh_id,
            version: welcome
                .selected_version
                .ok_or(TransportError::UntrustedFederationPeer)?,
            remote_authority_revision: welcome.authority_revision,
            maximum_control_bytes: welcome.maximum_control_bytes,
            maximum_data_frame_bytes: welcome.maximum_data_frame_bytes,
            maximum_streams: welcome.maximum_streams,
        })
    }
}

fn verify_welcome_shape(
    binding: crate::FederationPeerBinding,
    header: &FederationHeader,
    welcome: &FederationWelcome,
    expected: &FederationHelloExpectation,
) -> Result<(), TransportError> {
    let selected = welcome
        .selected_version
        .ok_or(TransportError::UntrustedFederationPeer)?;
    let valid = relationship(&header.relationship_id).ok() == Some(binding.relationship_id)
        && header.version.as_ref() == Some(&selected)
        && mesh(&header.sender_mesh_id).ok() == Some(binding.remote_mesh_id)
        && mesh(&header.recipient_mesh_id).ok() == Some(binding.local_mesh_id)
        && binding.relationship_id == expected.relationship_id
        && binding.local_mesh_id == expected.local_mesh_id
        && binding.remote_mesh_id == expected.remote_mesh_id
        && header.authority_epoch == binding.authority_epoch
        && header.authority_epoch == expected.authority_epoch
        && exact::<16>(&header.request_id).ok() == Some(expected.request_id)
        && exact::<16>(&header.operation_id).ok() == Some(expected.operation_id)
        && exact::<16>(&header.trace_id).ok() == Some(expected.trace_id)
        && header.deadline_unix_micros == expected.deadline.get()
        && exact::<32>(&header.replay_nonce).ok() != Some(expected.replay_nonce)
        && welcome.identity_generation == binding.identity_generation
        && exact::<32>(&welcome.request_challenge_nonce).ok() == Some(expected.challenge_nonce)
        && exact::<32>(&welcome.responder_challenge_nonce).ok() != Some(expected.challenge_nonce)
        && expected.versions.contains(&selected)
        && welcome.maximum_control_bytes <= expected.maximum_control_bytes
        && welcome.maximum_data_frame_bytes <= expected.maximum_data_frame_bytes
        && welcome.maximum_streams <= expected.maximum_streams;
    if valid {
        Ok(())
    } else {
        Err(TransportError::UntrustedFederationPeer)
    }
}

fn verify_welcome_signature(
    verifying_key: [u8; 32],
    header: &FederationHeader,
    welcome: &FederationWelcome,
) -> Result<(), TransportError> {
    let signature = exact(&welcome.signature)?;
    VerifyingKey::from_bytes(&verifying_key)
        .map_err(|_| TransportError::UntrustedFederationPeer)?
        .verify_strict(
            &federation_welcome_signing_payload(header, welcome),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| TransportError::UntrustedFederationPeer)
}

fn highest_common_version(
    offered: &[ProtocolVersion],
    supported: &[ProtocolVersion],
) -> Option<ProtocolVersion> {
    supported
        .iter()
        .filter(|candidate| offered.iter().any(|offered| offered == *candidate))
        .max_by_key(|version| (version.major, version.minor))
        .copied()
}

fn lower_u64(remote: u64, local: usize) -> Result<u64, TransportError> {
    Ok(remote.min(u64::try_from(local).map_err(|_| TransportError::InvalidConfiguration)?))
}

fn relationship(value: &[u8]) -> Result<FederationRelationshipId, TransportError> {
    FederationRelationshipId::from_bytes(exact(value)?)
        .map_err(|_| TransportError::UntrustedFederationPeer)
}

fn mesh(value: &[u8]) -> Result<MeshId, TransportError> {
    MeshId::from_bytes(exact(value)?).map_err(|_| TransportError::UntrustedFederationPeer)
}

fn exact<const LENGTH: usize>(value: &[u8]) -> Result<[u8; LENGTH], TransportError> {
    value
        .try_into()
        .map_err(|_| TransportError::UntrustedFederationPeer)
}
