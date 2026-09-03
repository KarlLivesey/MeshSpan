// SPDX-License-Identifier: GPL-2.0-only

//! Closed authoritative inputs for automated external-certificate publication.

use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    ExternalCertificatePublicationId, NodeId, PublicCertificateId, Revision, UnixMicros,
};

use crate::{CommitSecretGeneration, SecretGenerationReference};

/// Maximum number of canonical DNS names in one public certificate.
pub const MAXIMUM_EXTERNAL_CERTIFICATE_NAMES: usize = 256;

/// Atomically publishes one validated, encrypted certificate generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishExternalCertificate {
    /// Idempotent identity of this external publication.
    pub publication_id: ExternalCertificatePublicationId,
    /// Stable public-certificate identity used as the encrypted-secret identity.
    pub certificate_id: PublicCertificateId,
    /// Publisher-supplied strictly increasing generation.
    pub generation: u64,
    /// Canonical, sorted, lower-case DNS names from the validated certificate.
    pub certificate_names: BoundedItems<String>,
    /// Encrypted certificate and private-key bundle for every exact gateway recipient.
    pub certificate: Box<CommitSecretGeneration>,
    /// Digest of the complete canonical decrypted bundle.
    pub bundle_digest: [u8; 32],
    /// Digest of the canonical certificate chain alone.
    pub chain_digest: [u8; 32],
    /// SHA-256 fingerprint of the matching leaf public key.
    pub public_key_fingerprint: [u8; 32],
    /// Validated certificate lower validity bound.
    pub not_before: UnixMicros,
    /// Validated certificate upper validity bound.
    pub not_after: UnixMicros,
}

impl PublishExternalCertificate {
    /// Returns the exact encrypted generation selected by this publication.
    #[must_use]
    pub const fn certificate_reference(&self) -> SecretGenerationReference {
        SecretGenerationReference {
            secret_id: self.certificate_id.as_bytes(),
            generation: self.generation,
        }
    }
}

/// Records one gateway's proof that it selected an external certificate for new handshakes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcknowledgeExternalCertificateInstallation {
    /// Publication whose encrypted generation was installed.
    pub publication_id: ExternalCertificatePublicationId,
    /// Gateway reporting its own installation.
    pub gateway_node_id: NodeId,
    /// Exact current gateway process incarnation.
    pub gateway_incarnation: u64,
    /// Immutable encrypted generation decrypted and installed by the gateway.
    pub certificate: SecretGenerationReference,
    /// Digest of the canonical decrypted bundle installed by the gateway.
    pub bundle_digest: [u8; 32],
    /// Publication revision the gateway observed before loading the certificate.
    pub observed_publication_revision: Revision,
}
