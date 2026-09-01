// SPDX-License-Identifier: GPL-2.0-only

//! Certificate fingerprint to enrolled node/incarnation binding.

use std::collections::{BTreeMap, BTreeSet};

use meshspan_domain::{MeshId, NodeId};
use meshspan_protocol::v1::{NodeHello, NodeWelcome, ProtocolVersion};
use rustls::pki_types::CertificateDer;
use sha2::{Digest, Sha256};

use crate::TransportError;

/// One authoritative node certificate binding from committed topology.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerBinding {
    /// Enrolled node identity.
    pub node_id: NodeId,
    /// Exact active process incarnation.
    pub incarnation: u64,
    /// SHA-256 fingerprint of the node's leaf certificate DER.
    pub certificate_fingerprint: [u8; 32],
}

/// Immutable certificate lookup used after TLS validation and before protocol admission.
#[derive(Clone, Debug)]
pub struct PeerRegistry {
    by_fingerprint: BTreeMap<[u8; 32], PeerBinding>,
}

impl PeerRegistry {
    /// Creates a closed registry which authenticates no peers until authoritative bindings arrive.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            by_fingerprint: BTreeMap::new(),
        }
    }

    /// Builds an unambiguous registry from one binding per active node and certificate.
    ///
    /// # Errors
    ///
    /// Rejects zero incarnations, duplicate nodes or certificate fingerprints.
    pub fn new(bindings: impl IntoIterator<Item = PeerBinding>) -> Result<Self, TransportError> {
        let mut by_fingerprint = BTreeMap::new();
        let mut nodes = BTreeSet::new();
        for binding in bindings {
            if binding.incarnation == 0
                || binding.certificate_fingerprint == [0; 32]
                || !nodes.insert(binding.node_id)
                || by_fingerprint
                    .insert(binding.certificate_fingerprint, binding)
                    .is_some()
            {
                return Err(TransportError::InvalidConfiguration);
            }
        }
        if by_fingerprint.is_empty() {
            return Err(TransportError::InvalidConfiguration);
        }
        Ok(Self { by_fingerprint })
    }

    /// Resolves the TLS-authenticated leaf certificate to one enrolled node.
    ///
    /// # Errors
    ///
    /// Rejects absent, malformed, excessively deep or unregistered certificate chains.
    pub fn authenticate_connection(
        &self,
        connection: &quinn::Connection,
    ) -> Result<AuthenticatedPeer, TransportError> {
        let fingerprint = connection_certificate_fingerprint(connection)?;
        let binding = self
            .by_fingerprint
            .get(&fingerprint)
            .copied()
            .ok_or(TransportError::UntrustedPeer)?;
        Ok(AuthenticatedPeer(binding))
    }
}

pub(crate) fn connection_certificate_fingerprint(
    connection: &quinn::Connection,
) -> Result<[u8; 32], TransportError> {
    let identity = connection
        .peer_identity()
        .ok_or(TransportError::UntrustedPeer)?;
    let certificates = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| TransportError::UntrustedPeer)?;
    if certificates.is_empty() || certificates.len() > 8 {
        return Err(TransportError::UntrustedPeer);
    }
    Ok(certificate_fingerprint(&certificates[0]))
}

/// Proof that TLS and committed certificate enrolment resolved one exact peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedPeer(PeerBinding);

impl AuthenticatedPeer {
    /// Returns the certificate-bound node identity.
    #[must_use]
    pub const fn node_id(self) -> NodeId {
        self.0.node_id
    }

    /// Returns the certificate-bound process incarnation.
    #[must_use]
    pub const fn incarnation(self) -> u64 {
        self.0.incarnation
    }

    /// Returns the exact leaf-certificate fingerprint resolved by the registry.
    #[must_use]
    pub const fn certificate_fingerprint(self) -> [u8; 32] {
        self.0.certificate_fingerprint
    }

    /// Verifies that one already wire-validated hello claims this peer and expected mesh.
    ///
    /// # Errors
    ///
    /// Rejects any mesh, node or incarnation mismatch.
    pub fn verify_hello(self, mesh_id: MeshId, hello: &NodeHello) -> Result<(), TransportError> {
        if hello.mesh_id.as_slice() == mesh_id.as_bytes()
            && hello.node_id.as_slice() == self.0.node_id.as_bytes()
            && hello.incarnation == self.0.incarnation
        {
            Ok(())
        } else {
            Err(TransportError::UntrustedPeer)
        }
    }

    /// Negotiates the highest exact protocol version and lower resource limits for this peer.
    ///
    /// # Errors
    ///
    /// Rejects an identity mismatch, unsupported version, empty route set or invalid limits.
    pub fn negotiate(
        self,
        mesh_id: MeshId,
        hello: &NodeHello,
        local: &NegotiationConfig,
    ) -> Result<NodeWelcome, TransportError> {
        self.verify_hello(mesh_id, hello)?;
        local.validate()?;
        let selected_version = local
            .versions
            .iter()
            .filter(|supported| {
                hello.versions.iter().any(|offered| {
                    offered.major == supported.major && offered.minor == supported.minor
                })
            })
            .max_by_key(|version| (version.major, version.minor))
            .copied()
            .ok_or(TransportError::UnsupportedProtocol)?;
        let maximum_control_bytes = local.maximum_control_bytes.min(hello.maximum_control_bytes);
        let maximum_data_frame_bytes = local
            .maximum_data_frame_bytes
            .min(hello.maximum_data_frame_bytes);
        let maximum_streams = local.maximum_streams.min(hello.maximum_streams);
        if maximum_control_bytes == 0 || maximum_data_frame_bytes == 0 || maximum_streams == 0 {
            return Err(TransportError::InvalidConfiguration);
        }
        Ok(NodeWelcome {
            selected_version: Some(selected_version),
            peer_node_id: hello.node_id.clone(),
            peer_incarnation: hello.incarnation,
            partition_ids: local
                .partition_ids
                .iter()
                .map(|partition| partition.to_vec())
                .collect(),
            leader_node_id: local.leader_node_id.map(|node| node.as_bytes().to_vec()),
            routing_epoch: local.routing_epoch,
            maximum_control_bytes,
            maximum_data_frame_bytes,
            maximum_streams,
        })
    }
}

/// Local route and resource bounds used to answer an authenticated `NodeHello`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegotiationConfig {
    /// Exact protocol versions implemented locally.
    pub versions: Vec<ProtocolVersion>,
    /// Partition identifiers currently advertised to the peer.
    pub partition_ids: Vec<[u8; 16]>,
    /// Current leader hint, if known.
    pub leader_node_id: Option<NodeId>,
    /// Current signed-routing epoch.
    pub routing_epoch: u64,
    /// Local maximum control frame size.
    pub maximum_control_bytes: u64,
    /// Local maximum data frame size.
    pub maximum_data_frame_bytes: u64,
    /// Local maximum bidirectional stream count.
    pub maximum_streams: u32,
}

impl NegotiationConfig {
    fn validate(&self) -> Result<(), TransportError> {
        if self.versions.is_empty()
            || self.partition_ids.is_empty()
            || self.routing_epoch == 0
            || self.maximum_control_bytes == 0
            || self.maximum_data_frame_bytes == 0
            || self.maximum_streams == 0
            || self.versions.iter().any(|version| version.major == 0)
        {
            Err(TransportError::InvalidConfiguration)
        } else {
            Ok(())
        }
    }
}

/// Computes the committed fingerprint for one DER leaf certificate.
#[must_use]
pub fn certificate_fingerprint(certificate: &CertificateDer<'_>) -> [u8; 32] {
    Sha256::digest(certificate.as_ref()).into()
}
