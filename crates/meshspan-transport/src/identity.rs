// SPDX-License-Identifier: GPL-2.0-only

//! Certificate fingerprint to enrolled node/incarnation binding.

use std::collections::{BTreeMap, BTreeSet};

use meshspan_domain::{MeshId, NodeId};
use meshspan_protocol::v1::NodeHello;
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
        let identity = connection
            .peer_identity()
            .ok_or(TransportError::UntrustedPeer)?;
        let certificates = identity
            .downcast::<Vec<CertificateDer<'static>>>()
            .map_err(|_| TransportError::UntrustedPeer)?;
        if certificates.is_empty() || certificates.len() > 8 {
            return Err(TransportError::UntrustedPeer);
        }
        let fingerprint = certificate_fingerprint(&certificates[0]);
        let binding = self
            .by_fingerprint
            .get(&fingerprint)
            .copied()
            .ok_or(TransportError::UntrustedPeer)?;
        Ok(AuthenticatedPeer(binding))
    }
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
}

/// Computes the committed fingerprint for one DER leaf certificate.
#[must_use]
pub fn certificate_fingerprint(certificate: &CertificateDer<'_>) -> [u8; 32] {
    Sha256::digest(certificate.as_ref()).into()
}
