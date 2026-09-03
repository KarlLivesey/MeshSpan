// SPDX-License-Identifier: GPL-2.0-only

//! Fail-closed installation of one encrypted public HTTPS certificate generation.

use std::sync::Arc;

use meshspan_certificates::PublicCertificateBundle;
use meshspan_metadata::{PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND, SecretGenerationReference};
use meshspan_secret_envelope::SecretContext;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use thiserror::Error;

use crate::volume_key_loading::load_secret_generation;
use crate::{SecretGenerationAuthority, SecretGenerationDecryptor, SecretGenerationLoadingError};

const HTTP_1_1_ALPN: &[u8] = b"http/1.1";

/// One cryptographically validated certificate generation ready for an HTTPS listener.
pub struct LoadedPublicCertificate {
    generation: SecretGenerationReference,
    bundle_digest: [u8; 32],
    server_config: Arc<ServerConfig>,
}

impl LoadedPublicCertificate {
    /// Returns the exact immutable encrypted-secret generation that produced this configuration.
    #[must_use]
    pub const fn generation(&self) -> SecretGenerationReference {
        self.generation
    }

    /// Returns the domain-separated digest of the decrypted canonical bundle.
    #[must_use]
    pub const fn bundle_digest(&self) -> [u8; 32] {
        self.bundle_digest
    }

    /// Clones the public HTTPS configuration without exposing private-key bytes.
    #[must_use]
    pub fn server_config(&self) -> Arc<ServerConfig> {
        Arc::clone(&self.server_config)
    }
}

/// Loads only certificate generations addressed to this node's local wrapping key.
pub struct PublicCertificateLoadingService<A, D> {
    authority: A,
    decryptor: D,
}

impl<A, D> PublicCertificateLoadingService<A, D> {
    /// Binds authoritative encrypted reads to one node-local private-key operation.
    #[must_use]
    pub const fn new(authority: A, decryptor: D) -> Self {
        Self {
            authority,
            decryptor,
        }
    }
}

impl<A, D> PublicCertificateLoadingService<A, D>
where
    A: SecretGenerationAuthority,
    D: SecretGenerationDecryptor,
{
    /// Decrypts, parses and proves one exact public HTTPS certificate generation.
    ///
    /// # Errors
    ///
    /// Rejects invalid identities or generations, missing local recipient access, malformed
    /// bundles, unsupported private keys and certificate/private-key mismatch.
    pub fn load(
        &self,
        generation: SecretGenerationReference,
    ) -> Result<LoadedPublicCertificate, PublicCertificateLoadingError> {
        let context = SecretContext::new(
            PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND,
            generation.secret_id,
            generation.generation,
        )
        .map_err(|_| PublicCertificateLoadingError::InvalidInput)?;
        let plaintext = load_secret_generation(&self.authority, &self.decryptor, context)?;
        let bundle = PublicCertificateBundle::decode(plaintext.expose())
            .map_err(|_| PublicCertificateLoadingError::Failed)?;
        let bundle_digest = bundle.digest();
        let certificate_chain = bundle
            .certificate_chain()
            .iter()
            .cloned()
            .map(CertificateDer::from)
            .collect();
        let private_key = PrivatePkcs8KeyDer::from(bundle.private_key_pkcs8().to_vec()).into();
        let provider = Arc::new(meshspan_rustls_provider::provider());
        let mut server_config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| PublicCertificateLoadingError::Failed)?
            .with_no_client_auth()
            .with_single_cert(certificate_chain, private_key)
            .map_err(|_| PublicCertificateLoadingError::Failed)?;
        server_config.alpn_protocols = vec![HTTP_1_1_ALPN.to_vec()];
        Ok(LoadedPublicCertificate {
            generation,
            bundle_digest,
            server_config: Arc::new(server_config),
        })
    }
}

/// Closed public-certificate loading failure without secret or certificate detail.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PublicCertificateLoadingError {
    /// The requested secret identity or generation is invalid.
    #[error("public certificate request is invalid")]
    InvalidInput,
    /// The committed certificate generation was not found.
    #[error("public certificate generation was not found")]
    NotFound,
    /// This node is not an authorised recipient for the certificate generation.
    #[error("public certificate generation does not authorise this node")]
    NotRecipient,
    /// Current replicated certificate authority is unavailable.
    #[error("public certificate loading is unavailable")]
    Unavailable,
    /// Encrypted evidence, bundle framing or TLS material failed closed.
    #[error("public certificate loading failed closed")]
    Failed,
}

impl From<SecretGenerationLoadingError> for PublicCertificateLoadingError {
    fn from(error: SecretGenerationLoadingError) -> Self {
        match error {
            SecretGenerationLoadingError::NotFound => Self::NotFound,
            SecretGenerationLoadingError::NotRecipient => Self::NotRecipient,
            SecretGenerationLoadingError::Unavailable => Self::Unavailable,
            SecretGenerationLoadingError::Failed => Self::Failed,
        }
    }
}
