// SPDX-License-Identifier: GPL-2.0-only

//! Durable private-node certificate renewal inputs, separate from public HTTPS.

use meshspan_domain::{NodeId, Revision, UnixMicros};

/// Stages one same-key renewal after the exact current certificate generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StageNodeCertificate {
    /// Active enrolled node owning the private key.
    pub node_id: NodeId,
    /// Exact current node incarnation.
    pub incarnation: u64,
    /// Current active generation being renewed.
    pub previous_generation: u64,
    /// Next unused generation, which can skip expired uninstalled candidates.
    pub generation: u64,
    /// Exact authorised online signing-authority generation.
    pub issuer_generation: u64,
    /// Signed leaf DER for the explicit new generation.
    pub certificate_der: Vec<u8>,
    /// Inclusive validity start, aligned to a whole Unix second.
    pub valid_from: UnixMicros,
    /// Exclusive validity end, aligned to a whole Unix second.
    pub valid_until: UnixMicros,
}

/// The node's signed acknowledgement after selecting its staged TLS generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcknowledgeNodeCertificateInstallation {
    /// Node which performed the installation.
    pub node_id: NodeId,
    /// Current process incarnation.
    pub incarnation: u64,
    /// Staged generation actually selected.
    pub generation: u64,
    /// SHA-256 fingerprint of the installed leaf.
    pub certificate_fingerprint: [u8; 32],
    /// Exact immutable staging revision observed before installation.
    pub staged_revision: Revision,
    /// Canonical P-256 DER signature by the node-owned identity key.
    pub signature: Vec<u8>,
}

impl AcknowledgeNodeCertificateInstallation {
    /// Returns the domain-separated public installation statement to sign or verify.
    ///
    /// The signature is excluded. The fixed identity/generation/revision fields prevent
    /// replay as another node, incarnation or issuance; metadata enforces current state.
    #[must_use]
    pub fn signing_transcript(&self) -> Vec<u8> {
        let mut bytes = b"meshspan.node-certificate.installation.v1\0".to_vec();
        bytes.extend_from_slice(&self.node_id.as_bytes());
        bytes.extend_from_slice(&self.incarnation.to_be_bytes());
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.extend_from_slice(&self.certificate_fingerprint);
        bytes.extend_from_slice(&self.staged_revision.get().to_be_bytes());
        bytes
    }
}

/// Retires acknowledged overlap, or abandons an expired uninstalled candidate.
///
/// Abandonment never selects a candidate or retires the still-active previous leaf.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetireNodeCertificate {
    /// Active enrolled node.
    pub node_id: NodeId,
    /// Current process incarnation.
    pub incarnation: u64,
    /// Rotation generation whose overlap or expired staging is being retired.
    pub generation: u64,
}
