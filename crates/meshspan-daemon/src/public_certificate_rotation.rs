// SPDX-License-Identifier: GPL-2.0-only

//! Make-before-break HTTPS identity rotation for authoritative certificate revisions.

use std::fmt;
use std::sync::{Arc, RwLock};

use meshspan_domain::Revision;
use meshspan_metadata::SecretGenerationReference;
use rustls::ServerConfig;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use thiserror::Error;

use crate::public_certificate_loading::{HTTP_1_1_ALPN, LoadedPublicCertificate};

/// Public, non-secret identity of the certificate currently selected for new handshakes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstalledPublicCertificate {
    /// Authoritative metadata revision which selected this generation.
    pub revision: Revision,
    /// Exact immutable encrypted-secret generation installed by this gateway.
    pub generation: SecretGenerationReference,
    /// Domain-separated digest of the canonical decrypted certificate bundle.
    pub bundle_digest: [u8; 32],
}

/// Result of applying one authoritative certificate selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicCertificateInstallOutcome {
    /// A newer authoritative selection is active for subsequent TLS handshakes.
    Installed,
    /// The exact same revision and generation were already active.
    AlreadyCurrent,
}

/// One HTTPS configuration whose certificate can be replaced without rebinding its listener.
pub struct RotatingHttpsIdentity {
    state: Arc<CertificateResolverState>,
    server_config: Arc<ServerConfig>,
}

impl RotatingHttpsIdentity {
    /// Creates a resolver with one already decrypted and cryptographically validated identity.
    ///
    /// # Errors
    ///
    /// Fails if the TLS 1.3 configuration cannot be composed with the `MeshSpan` provider.
    pub fn new(
        revision: Revision,
        certificate: &LoadedPublicCertificate,
    ) -> Result<Self, PublicCertificateRotationError> {
        let installed = InstalledCertificate::new(revision, certificate);
        let state = Arc::new(CertificateResolverState {
            installed: RwLock::new(installed),
        });
        let provider = Arc::new(meshspan_rustls_provider::provider());
        let mut server_config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| PublicCertificateRotationError::Configuration)?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(RotatingCertificateResolver {
                state: Arc::clone(&state),
            }));
        server_config.alpn_protocols = vec![HTTP_1_1_ALPN.to_vec()];
        Ok(Self {
            state,
            server_config: Arc::new(server_config),
        })
    }

    /// Returns the stable server configuration used for the listener's entire lifetime.
    #[must_use]
    pub fn server_config(&self) -> Arc<ServerConfig> {
        Arc::clone(&self.server_config)
    }

    /// Returns the authoritative, non-secret identity currently selected for new handshakes.
    ///
    /// # Errors
    ///
    /// Fails closed if another thread panicked while changing the installed identity.
    pub fn current(&self) -> Result<InstalledPublicCertificate, PublicCertificateRotationError> {
        self.state
            .installed
            .read()
            .map(|installed| installed.public)
            .map_err(|_| PublicCertificateRotationError::Unavailable)
    }

    /// Atomically selects a newer authoritative identity for subsequent TLS handshakes.
    ///
    /// Existing TLS sessions retain the identity negotiated when they connected. A replay of the
    /// exact current selection is idempotent. Older revisions and conflicting content at one
    /// revision are rejected.
    ///
    /// # Errors
    ///
    /// Rejects stale or conflicting revisions and fails closed after lock poisoning.
    pub fn install(
        &self,
        revision: Revision,
        certificate: &LoadedPublicCertificate,
    ) -> Result<PublicCertificateInstallOutcome, PublicCertificateRotationError> {
        let replacement = InstalledCertificate::new(revision, certificate);
        let mut installed = self
            .state
            .installed
            .write()
            .map_err(|_| PublicCertificateRotationError::Unavailable)?;
        if replacement.public.revision < installed.public.revision {
            return Err(PublicCertificateRotationError::StaleRevision);
        }
        if replacement.public.revision == installed.public.revision {
            if replacement.public == installed.public {
                return Ok(PublicCertificateInstallOutcome::AlreadyCurrent);
            }
            return Err(PublicCertificateRotationError::ConflictingRevision);
        }
        *installed = replacement;
        Ok(PublicCertificateInstallOutcome::Installed)
    }
}

struct InstalledCertificate {
    public: InstalledPublicCertificate,
    certified_key: Arc<CertifiedKey>,
}

impl InstalledCertificate {
    fn new(revision: Revision, certificate: &LoadedPublicCertificate) -> Self {
        Self {
            public: InstalledPublicCertificate {
                revision,
                generation: certificate.generation(),
                bundle_digest: certificate.bundle_digest(),
            },
            certified_key: certificate.certified_key(),
        }
    }
}

struct CertificateResolverState {
    installed: RwLock<InstalledCertificate>,
}

struct RotatingCertificateResolver {
    state: Arc<CertificateResolverState>,
}

impl fmt::Debug for RotatingCertificateResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RotatingCertificateResolver([redacted])")
    }
}

impl ResolvesServerCert for RotatingCertificateResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.state
            .installed
            .read()
            .ok()
            .map(|installed| Arc::clone(&installed.certified_key))
    }
}

/// Closed certificate-rotation failure without key or certificate detail.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PublicCertificateRotationError {
    /// TLS 1.3 could not be composed with the configured cryptographic provider.
    #[error("public HTTPS identity configuration failed closed")]
    Configuration,
    /// The supplied selection predates the currently installed authoritative revision.
    #[error("public HTTPS identity revision is stale")]
    StaleRevision,
    /// The same authoritative revision identified different certificate content.
    #[error("public HTTPS identity revision conflicts with installed content")]
    ConflictingRevision,
    /// The atomic identity resolver is unavailable after an internal synchronization failure.
    #[error("public HTTPS identity rotation is unavailable")]
    Unavailable,
}
