// SPDX-License-Identifier: GPL-2.0-only

//! Metadata-bound construction of signed outbound federation negotiation hellos.

use std::collections::BTreeSet;

use ed25519_dalek::{Signer, SigningKey};
use meshspan_domain::{FederationRelationshipId, MeshId, UnixMicros};
use meshspan_protocol::v1::federation_envelope::Message;
use meshspan_protocol::v1::{
    FederationEnvelope, FederationHeader, FederationHello, ProtocolVersion,
};
use meshspan_protocol::{WireLimits, encode_federation_frame, federation_hello_signing_payload};
use sha2::{Digest, Sha256};

use crate::{FederationHelloExpectation, TransportError};

/// Current local public identity and relationship fence derived from authoritative metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationLocalIdentityBinding {
    /// Mutually approved relationship carrying this identity.
    pub relationship_id: FederationRelationshipId,
    /// Autonomous swarm presenting this identity.
    pub local_mesh_id: MeshId,
    /// Intended autonomous peer.
    pub remote_mesh_id: MeshId,
    /// Exact current relationship authority fence.
    pub authority_epoch: u64,
    /// Exact active local identity generation.
    pub identity_generation: u64,
    /// SHA-256 fingerprint of the exact local TLS leaf certificate DER.
    pub certificate_fingerprint: [u8; 32],
    /// Public half of the private signing key kept outside replicated metadata.
    pub verifying_key: [u8; 32],
    /// First authoritative instant at which this identity is valid, inclusive.
    pub valid_from: UnixMicros,
    /// First authoritative instant at which this identity is expired, exclusive.
    pub valid_until: UnixMicros,
}

/// Bounded protocol and resource offer carried by an outbound hello.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationHelloConfig {
    versions: Vec<ProtocolVersion>,
    feature_bits: Vec<u32>,
    wire_limits: WireLimits,
    maximum_streams: u32,
}

impl FederationHelloConfig {
    /// Constructs one deterministic, duplicate-free offer.
    ///
    /// # Errors
    ///
    /// Rejects an empty/excessive version set, unsupported major versions, duplicate features or
    /// zero stream capacity.
    pub fn new(
        versions: Vec<ProtocolVersion>,
        feature_bits: Vec<u32>,
        wire_limits: WireLimits,
        maximum_streams: u32,
    ) -> Result<Self, TransportError> {
        let distinct_versions = versions
            .iter()
            .map(|version| (version.major, version.minor))
            .collect::<BTreeSet<_>>();
        let distinct_features = feature_bits.iter().copied().collect::<BTreeSet<_>>();
        let invalid = versions.is_empty()
            || versions.len() > wire_limits.maximum_items()
            || distinct_versions.len() != versions.len()
            || versions.iter().any(|version| version.major != 1)
            || feature_bits.len() > wire_limits.maximum_items()
            || distinct_features.len() != feature_bits.len()
            || maximum_streams == 0;
        if invalid {
            return Err(TransportError::InvalidConfiguration);
        }
        Ok(Self {
            versions,
            feature_bits,
            wire_limits,
            maximum_streams,
        })
    }

    fn envelope_version(&self) -> Result<ProtocolVersion, TransportError> {
        self.versions
            .iter()
            .max_by_key(|version| (version.major, version.minor))
            .copied()
            .ok_or(TransportError::InvalidConfiguration)
    }
}

/// Fresh correlation and anti-replay values for one outbound federation negotiation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationHelloContext {
    /// Unique request correlation identity.
    pub request_id: [u8; 16],
    /// Idempotent operation identity for this connection attempt.
    pub operation_id: [u8; 16],
    /// End-to-end trace identity.
    pub trace_id: [u8; 16],
    /// Authoritative deadline after which the peer must reject the hello.
    pub deadline: UnixMicros,
    /// Fresh replay identity consumed by the peer.
    pub replay_nonce: [u8; 32],
    /// Independent challenge which the peer must sign into its welcome.
    pub challenge_nonce: [u8; 32],
}

impl FederationHelloContext {
    /// Constructs a complete, non-zero and non-reflected request context.
    ///
    /// # Errors
    ///
    /// Rejects zero identifiers/nonces, equal nonces or a non-positive deadline.
    pub fn new(
        request_id: [u8; 16],
        operation_id: [u8; 16],
        trace_id: [u8; 16],
        deadline: UnixMicros,
        replay_nonce: [u8; 32],
        challenge_nonce: [u8; 32],
    ) -> Result<Self, TransportError> {
        let invalid = request_id == [0; 16]
            || operation_id == [0; 16]
            || trace_id == [0; 16]
            || replay_nonce == [0; 32]
            || challenge_nonce == [0; 32]
            || replay_nonce == challenge_nonce
            || deadline.get() <= 0;
        if invalid {
            return Err(TransportError::InvalidConfiguration);
        }
        Ok(Self {
            request_id,
            operation_id,
            trace_id,
            deadline,
            replay_nonce,
            challenge_nonce,
        })
    }
}

/// Signed hello plus the private local expectation needed to authenticate its welcome.
#[derive(Clone, Debug, PartialEq)]
pub struct OutboundFederationHello {
    envelope: FederationEnvelope,
    expectation: FederationHelloExpectation,
}

impl OutboundFederationHello {
    /// Returns the signed wire envelope.
    #[must_use]
    pub const fn envelope(&self) -> &FederationEnvelope {
        &self.envelope
    }

    /// Returns the exact local state against which a welcome must be checked.
    #[must_use]
    pub const fn expectation(&self) -> &FederationHelloExpectation {
        &self.expectation
    }
}

/// Constructs and signs one outbound federation hello from current committed authority.
///
/// # Errors
///
/// Rejects stale/inconsistent authority, a substituted certificate or signing key, a deadline
/// outside the local identity lifetime, or an envelope exceeding its declared bounds.
pub fn signed_federation_hello(
    identity: FederationLocalIdentityBinding,
    config: &FederationHelloConfig,
    context: FederationHelloContext,
    certificate_der: &[u8],
    signing_key: &SigningKey,
    now: UnixMicros,
) -> Result<OutboundFederationHello, TransportError> {
    validate_local_identity(
        identity,
        certificate_der,
        signing_key,
        context.deadline,
        now,
    )?;
    let header = FederationHeader {
        version: Some(config.envelope_version()?),
        relationship_id: identity.relationship_id.as_bytes().to_vec(),
        sender_mesh_id: identity.local_mesh_id.as_bytes().to_vec(),
        recipient_mesh_id: identity.remote_mesh_id.as_bytes().to_vec(),
        request_id: context.request_id.to_vec(),
        operation_id: context.operation_id.to_vec(),
        authority_epoch: identity.authority_epoch,
        deadline_unix_micros: context.deadline.get(),
        trace_id: context.trace_id.to_vec(),
        replay_nonce: context.replay_nonce.to_vec(),
    };
    let mut hello = FederationHello {
        versions: config.versions.clone(),
        identity_generation: identity.identity_generation,
        public_identity_chain: certificate_der.to_vec(),
        challenge_nonce: context.challenge_nonce.to_vec(),
        feature_bits: config.feature_bits.clone(),
        maximum_control_bytes: usize_to_u64(config.wire_limits.maximum_control_bytes())?,
        maximum_data_frame_bytes: usize_to_u64(config.wire_limits.maximum_data_frame_bytes())?,
        maximum_streams: config.maximum_streams,
        signature: vec![0; 64],
    };
    hello.signature = signing_key
        .sign(&federation_hello_signing_payload(&header, &hello))
        .to_bytes()
        .to_vec();
    let envelope = FederationEnvelope {
        header: Some(header),
        message: Some(Message::Hello(hello)),
    };
    encode_federation_frame(&envelope, config.wire_limits)?;
    let expectation = FederationHelloExpectation::from_outgoing(&envelope, config.wire_limits)?;
    Ok(OutboundFederationHello {
        envelope,
        expectation,
    })
}

fn validate_local_identity(
    identity: FederationLocalIdentityBinding,
    certificate_der: &[u8],
    signing_key: &SigningKey,
    deadline: UnixMicros,
    now: UnixMicros,
) -> Result<(), TransportError> {
    let fingerprint: [u8; 32] = Sha256::digest(certificate_der).into();
    let invalid = identity.local_mesh_id == identity.remote_mesh_id
        || identity.authority_epoch == 0
        || identity.identity_generation == 0
        || certificate_der.is_empty()
        || identity.certificate_fingerprint == [0; 32]
        || fingerprint != identity.certificate_fingerprint
        || signing_key.verifying_key().to_bytes() != identity.verifying_key
        || identity.valid_until <= identity.valid_from
        || now < identity.valid_from
        || now >= identity.valid_until
        || deadline <= now
        || deadline > identity.valid_until;
    if invalid {
        Err(TransportError::InvalidConfiguration)
    } else {
        Ok(())
    }
}

fn usize_to_u64(value: usize) -> Result<u64, TransportError> {
    u64::try_from(value).map_err(|_| TransportError::InvalidConfiguration)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use meshspan_domain::{FederationRelationshipId, MeshId, UnixMicros};
    use meshspan_protocol::WireLimits;
    use meshspan_protocol::v1::ProtocolVersion;
    use sha2::{Digest, Sha256};

    use super::{
        FederationHelloConfig, FederationHelloContext, FederationLocalIdentityBinding,
        signed_federation_hello,
    };
    use crate::TransportError;

    #[test]
    fn outbound_hello_binds_exact_current_metadata_certificate_and_private_key()
    -> Result<(), Box<dyn std::error::Error>> {
        let certificate = b"exact federation certificate";
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let identity = identity(certificate, &signing_key)?;
        let config = config()?;
        let context = context()?;
        let outbound = signed_federation_hello(
            identity,
            &config,
            context,
            certificate,
            &signing_key,
            UnixMicros::new(20),
        )?;
        let header = outbound
            .envelope()
            .header
            .as_ref()
            .ok_or(TransportError::InvalidFrame)?;
        assert_eq!(header.authority_epoch, identity.authority_epoch);
        assert_eq!(header.sender_mesh_id, identity.local_mesh_id.as_bytes());
        assert_eq!(header.recipient_mesh_id, identity.remote_mesh_id.as_bytes());

        let other_key = SigningKey::from_bytes(&[8; 32]);
        for result in [
            signed_federation_hello(
                identity,
                &config,
                context,
                b"substituted certificate",
                &signing_key,
                UnixMicros::new(20),
            ),
            signed_federation_hello(
                identity,
                &config,
                context,
                certificate,
                &other_key,
                UnixMicros::new(20),
            ),
            signed_federation_hello(
                identity,
                &config,
                context,
                certificate,
                &signing_key,
                UnixMicros::new(100),
            ),
        ] {
            assert!(matches!(result, Err(TransportError::InvalidConfiguration)));
        }
        Ok(())
    }

    #[test]
    fn hello_configuration_and_context_reject_ambiguous_or_unbounded_values()
    -> Result<(), Box<dyn std::error::Error>> {
        let limits = limits()?;
        assert!(matches!(
            FederationHelloConfig::new(Vec::new(), Vec::new(), limits, 1),
            Err(TransportError::InvalidConfiguration)
        ));
        assert!(matches!(
            FederationHelloConfig::new(
                vec![ProtocolVersion { major: 1, minor: 0 }; 2],
                Vec::new(),
                limits,
                1,
            ),
            Err(TransportError::InvalidConfiguration)
        ));
        assert!(matches!(
            FederationHelloContext::new(
                [1; 16],
                [2; 16],
                [3; 16],
                UnixMicros::new(50),
                [4; 32],
                [4; 32],
            ),
            Err(TransportError::InvalidConfiguration)
        ));
        Ok(())
    }

    fn identity(
        certificate: &[u8],
        signing_key: &SigningKey,
    ) -> Result<FederationLocalIdentityBinding, Box<dyn std::error::Error>> {
        Ok(FederationLocalIdentityBinding {
            relationship_id: FederationRelationshipId::from_bytes([1; 16])?,
            local_mesh_id: MeshId::from_bytes([2; 16])?,
            remote_mesh_id: MeshId::from_bytes([3; 16])?,
            authority_epoch: 4,
            identity_generation: 5,
            certificate_fingerprint: Sha256::digest(certificate).into(),
            verifying_key: signing_key.verifying_key().to_bytes(),
            valid_from: UnixMicros::new(10),
            valid_until: UnixMicros::new(100),
        })
    }

    fn context() -> Result<FederationHelloContext, TransportError> {
        FederationHelloContext::new(
            [6; 16],
            [7; 16],
            [8; 16],
            UnixMicros::new(90),
            [9; 32],
            [10; 32],
        )
    }

    fn config() -> Result<FederationHelloConfig, Box<dyn std::error::Error>> {
        Ok(FederationHelloConfig::new(
            vec![
                ProtocolVersion { major: 1, minor: 0 },
                ProtocolVersion { major: 1, minor: 1 },
            ],
            vec![1, 2],
            limits()?,
            8,
        )?)
    }

    fn limits() -> Result<WireLimits, meshspan_protocol::WireContractError> {
        WireLimits::new(8 * 1_024, 64 * 1_024, 8, 1_024)
    }
}
