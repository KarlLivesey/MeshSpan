// SPDX-License-Identifier: GPL-2.0-only

//! Protected restart-stable node identity and first-start HTTPS configuration.

use std::path::Path;
use std::sync::Arc;

use meshspan_certificates::{CertificateError, NodeIdentityKey};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use thiserror::Error;

use crate::protected_file::{self, ProtectedFileError, PublishMode};

const MINIMUM_PKCS8_BYTES: usize = 64;
const MAXIMUM_PKCS8_BYTES: usize = 512;

/// One private node identity loaded from or newly committed to owner-only local state.
///
/// The type implements neither `Clone`, `Debug` nor `Display` because it owns private-key
/// material. Its temporary self-signed certificate exists only to bring up first-start HTTPS;
/// mesh enrolment later installs a mesh-CA signature over this same public identity.
pub struct LocalNodeIdentity {
    key: NodeIdentityKey,
    bootstrap_certificate: Vec<u8>,
}

impl LocalNodeIdentity {
    /// Opens an existing identity or atomically creates one when the destination is absent.
    ///
    /// # Errors
    ///
    /// Rejects every existing unsafe or malformed value; only an exact missing-file result may
    /// enter creation.
    pub fn open_or_create(path: &Path, dns_name: &str) -> Result<Self, LocalNodeIdentityError> {
        match protected_file::read_bounded(path, MINIMUM_PKCS8_BYTES, MAXIMUM_PKCS8_BYTES) {
            Ok(private_key) => Self::from_private_key(&private_key, dns_name),
            Err(ProtectedFileError::Missing) => Self::create(path, dns_name),
            Err(error) => Err(error.into()),
        }
    }

    /// Creates one identity without overwriting any existing destination.
    ///
    /// # Errors
    ///
    /// Rejects unsafe/existing paths, unavailable entropy, invalid DNS names and durability
    /// failures.
    pub fn create(path: &Path, dns_name: &str) -> Result<Self, LocalNodeIdentityError> {
        let key = NodeIdentityKey::generate()?;
        let bootstrap_certificate = key.self_signed(dns_name)?;
        protected_file::publish(path, key.private_key_pkcs8(), PublishMode::Create)?;
        Ok(Self {
            key,
            bootstrap_certificate,
        })
    }

    /// Opens and validates one existing owner-only canonical P-256 identity.
    ///
    /// # Errors
    ///
    /// Rejects missing, replaced, permissive, malformed, wrong-algorithm or oversized key files
    /// and invalid certificate parameters.
    pub fn open(path: &Path, dns_name: &str) -> Result<Self, LocalNodeIdentityError> {
        let private_key =
            protected_file::read_bounded(path, MINIMUM_PKCS8_BYTES, MAXIMUM_PKCS8_BYTES)?;
        Self::from_private_key(&private_key, dns_name)
    }

    /// Returns the non-secret public identity fingerprint bound to claim and enrolment state.
    #[must_use]
    pub fn public_key_fingerprint(&self) -> [u8; 32] {
        self.key.public_key_fingerprint()
    }

    /// Builds the TLS 1.3-only first-start public HTTPS server configuration.
    ///
    /// Public HTTPS authenticates users at the application layer and therefore requests no client
    /// certificate. Private node transport has a distinct mandatory-mTLS configuration.
    ///
    /// # Errors
    ///
    /// Rejects any certificate/key mismatch or unsupported provider configuration.
    pub fn bootstrap_server_config(&self) -> Result<Arc<ServerConfig>, LocalNodeIdentityError> {
        let provider = Arc::new(meshspan_rustls_provider::provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(self.bootstrap_certificate.clone())],
                PrivatePkcs8KeyDer::from(self.key.private_key_pkcs8().to_vec()).into(),
            )?;
        Ok(Arc::new(config))
    }

    fn from_private_key(
        private_key: &[u8],
        dns_name: &str,
    ) -> Result<Self, LocalNodeIdentityError> {
        let key = NodeIdentityKey::from_pkcs8(private_key)?;
        let bootstrap_certificate = key.self_signed(dns_name)?;
        Ok(Self {
            key,
            bootstrap_certificate,
        })
    }
}

/// Stable local-node-identity failure without key or path contents.
#[derive(Debug, Error)]
pub enum LocalNodeIdentityError {
    /// Owner-only atomic local-file handling failed.
    #[error("protected node identity file failed")]
    File,
    /// Key generation, parsing or certificate construction failed.
    #[error("node certificate identity is invalid or unavailable")]
    Certificate(#[from] CertificateError),
    /// Rustls rejected the provider, certificate or private-key configuration.
    #[error("node HTTPS identity configuration failed")]
    Tls(#[from] rustls::Error),
}

impl From<ProtectedFileError> for LocalNodeIdentityError {
    fn from(_: ProtectedFileError) -> Self {
        Self::File
    }
}
