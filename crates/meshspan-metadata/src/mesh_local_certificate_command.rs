// SPDX-License-Identifier: GPL-2.0-only

//! Closed authoritative inputs for the mesh-local HTTPS certificate authority.

use meshspan_domain::{MeshLocalCertificateAuthorityId, UnixMicros};

use crate::CommitSecretGeneration;

/// Maximum DER size accepted for one mesh-local CA trust anchor.
pub const MAXIMUM_MESH_LOCAL_CA_CERTIFICATE_BYTES: usize = 16 * 1_024;

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
