// SPDX-License-Identifier: GPL-2.0-only

//! Closed authoritative inputs for the mesh-local HTTPS certificate authority.

use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    MeshLocalCertificateAuthorityId, MeshLocalCertificateIssuanceId, NodeId, PublicCertificateId,
    Revision, UnixMicros,
};

use crate::{CommitSecretGeneration, SecretGenerationReference};

/// Maximum DER size accepted for one mesh-local CA trust anchor.
pub const MAXIMUM_MESH_LOCAL_CA_CERTIFICATE_BYTES: usize = 16 * 1_024;

/// Maximum canonical DNS names in one mesh-local endpoint generation.
pub const MAXIMUM_MESH_LOCAL_CERTIFICATE_NAMES: usize = 256;

/// Atomically persists the first encrypted mesh-local HTTPS signing authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateMeshLocalCertificateAuthority {
    /// Stable authority and encrypted-secret identity.
    pub authority_id: MeshLocalCertificateAuthorityId,
    /// Initial authority generation. The first implementation accepts generation one only.
    pub generation: u64,
    /// Self-signed public trust anchor in canonical DER form.
    pub certificate_der: Vec<u8>,
    /// Encrypted authority private key addressed to the exact current signer/recovery recipients.
    pub authority_key: Box<CommitSecretGeneration>,
    /// SHA-256 digest of the exact trust-anchor DER.
    pub certificate_digest: [u8; 32],
    /// Inclusive authority validity start.
    pub not_before: UnixMicros,
    /// Exclusive authority validity end.
    pub not_after: UnixMicros,
}

/// Atomically publishes one endpoint generation signed by the current mesh-local authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueMeshLocalCertificate {
    /// Stable issuance identity.
    pub issuance_id: MeshLocalCertificateIssuanceId,
    /// Exact signing authority identity.
    pub authority_id: MeshLocalCertificateAuthorityId,
    /// Exact signing authority generation.
    pub authority_generation: u64,
    /// Digest of the exact public trust anchor used to sign this generation.
    pub authority_certificate_digest: [u8; 32],
    /// Stable public-certificate and encrypted-secret identity.
    pub certificate_id: PublicCertificateId,
    /// Strictly increasing mesh-local endpoint generation.
    pub generation: u64,
    /// Canonical sorted lower-case DNS names.
    pub certificate_names: BoundedItems<String>,
    /// Encrypted leaf-first certificate chain and endpoint private key.
    pub certificate: Box<CommitSecretGeneration>,
    /// Digest of the complete canonical decrypted endpoint bundle.
    pub bundle_digest: [u8; 32],
    /// SHA-256 fingerprint of the endpoint public key.
    pub public_key_fingerprint: [u8; 32],
    /// Inclusive endpoint validity start.
    pub not_before: UnixMicros,
    /// Exclusive endpoint validity end.
    pub not_after: UnixMicros,
}

/// Records one gateway's proof that it selected a mesh-local endpoint generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcknowledgeMeshLocalCertificateInstallation {
    /// Mesh-local issuance whose bundle was installed.
    pub issuance_id: MeshLocalCertificateIssuanceId,
    /// Gateway reporting its own installation.
    pub gateway_node_id: NodeId,
    /// Exact current gateway process incarnation.
    pub gateway_incarnation: u64,
    /// Immutable encrypted certificate generation installed by the gateway.
    pub certificate: SecretGenerationReference,
    /// Digest of the canonical decrypted bundle.
    pub bundle_digest: [u8; 32],
    /// Issuance revision observed before loading the certificate.
    pub observed_issuance_revision: Revision,
}
