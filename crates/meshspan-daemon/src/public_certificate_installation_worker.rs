// SPDX-License-Identifier: GPL-2.0-only

//! Restart-safe selection, decryption, live installation and acknowledgement of public HTTPS.

use meshspan_domain::{NodeId, UnixMicros};
use meshspan_metadata::PublicCertificateSelection;
use thiserror::Error;

use crate::{
    PublicCertificateInstallationAuthority, PublicCertificateInstallationCommit,
    PublicCertificateInstallationError, PublicCertificateInstallationRequest,
    PublicCertificateInstallationService, PublicCertificateLoadingError,
    PublicCertificateLoadingService, RotatingHttpsIdentity, SecretGenerationAuthority,
    SecretGenerationDecryptor,
};

/// Authoritative read required before a gateway may select a public certificate.
pub trait PublicCertificateSelectionAuthority {
    /// Returns the globally newest completed certificate generation.
    ///
    /// # Errors
    ///
    /// Fails closed when current authority is unavailable or persisted selection is malformed.
    fn latest_public_certificate(
        &self,
    ) -> Result<Option<PublicCertificateSelection>, PublicCertificateSelectionAuthorityError>;
}

/// Independently owned capabilities required by one gateway installation worker.
pub struct PublicCertificateInstallationWorkerComponents<S, G, A, D> {
    /// Reads the authoritative globally selected generation.
    pub selection: S,
    /// Reads its node-addressed encrypted secret envelope.
    pub generation: G,
    /// Decrypts only envelopes addressed to this node's private wrapping key.
    pub decryptor: D,
    /// Commits the post-installation acknowledgement.
    pub acknowledgement: A,
    /// Resolver shared with the live HTTPS listener.
    pub identity: RotatingHttpsIdentity,
    /// Exact local gateway node.
    pub gateway_node_id: NodeId,
    /// Current process incarnation fencing an old acknowledgement.
    pub gateway_incarnation: u64,
}

/// One gateway-local make-before-break public-certificate installation worker.
pub struct PublicCertificateInstallationWorker<S, G, A, D> {
    selection: S,
    loading: PublicCertificateLoadingService<G, D>,
    installation: PublicCertificateInstallationService<A>,
    identity: RotatingHttpsIdentity,
    gateway_node_id: NodeId,
    gateway_incarnation: u64,
    acknowledged: Option<PublicCertificateSelection>,
}

impl<S, G, A, D> PublicCertificateInstallationWorker<S, G, A, D> {
    /// Composes independent read, decrypt, resolver and commit capabilities.
    ///
    /// # Errors
    ///
    /// Rejects a zero gateway process incarnation.
    pub fn new(
        components: PublicCertificateInstallationWorkerComponents<S, G, A, D>,
    ) -> Result<Self, PublicCertificateInstallationWorkerError> {
        if components.gateway_incarnation == 0 {
            return Err(PublicCertificateInstallationWorkerError::InvalidInput);
        }
        Ok(Self {
            selection: components.selection,
            loading: PublicCertificateLoadingService::new(
                components.generation,
                components.decryptor,
            ),
            installation: PublicCertificateInstallationService::new(components.acknowledgement),
            identity: components.identity,
            gateway_node_id: components.gateway_node_id,
            gateway_incarnation: components.gateway_incarnation,
            acknowledged: None,
        })
    }
}

impl<S, G, A, D> PublicCertificateInstallationWorker<S, G, A, D>
where
    S: PublicCertificateSelectionAuthority,
    G: SecretGenerationAuthority,
    A: PublicCertificateInstallationAuthority,
    D: SecretGenerationDecryptor,
{
    /// Installs and acknowledges at most one new committed certificate generation.
    ///
    /// Missing local envelope or transient authority loss returns `Deferred`; corrupt or
    /// contradictory evidence fails closed before the resolver changes.
    ///
    /// # Errors
    ///
    /// Rejects malformed selection, decrypted bundle mismatch or conflicting installation state.
    pub fn run_once(
        &mut self,
        now: UnixMicros,
    ) -> Result<PublicCertificateInstallationWorkerOutcome, PublicCertificateInstallationWorkerError>
    {
        let selection = match self.selection.latest_public_certificate() {
            Ok(Some(selection)) => selection,
            Ok(None) => return Ok(PublicCertificateInstallationWorkerOutcome::Idle),
            Err(PublicCertificateSelectionAuthorityError::Unavailable) => {
                return Ok(PublicCertificateInstallationWorkerOutcome::Deferred);
            }
            Err(PublicCertificateSelectionAuthorityError::Failed) => {
                return Err(PublicCertificateInstallationWorkerError::Failed);
            }
        };
        if self.acknowledged == Some(selection) {
            return Ok(PublicCertificateInstallationWorkerOutcome::Current);
        }
        let loaded = match self.loading.load(selection.certificate) {
            Ok(loaded) => loaded,
            Err(
                PublicCertificateLoadingError::NotFound
                | PublicCertificateLoadingError::NotRecipient
                | PublicCertificateLoadingError::Unavailable,
            ) => return Ok(PublicCertificateInstallationWorkerOutcome::Deferred),
            Err(
                PublicCertificateLoadingError::InvalidInput | PublicCertificateLoadingError::Failed,
            ) => return Err(PublicCertificateInstallationWorkerError::Failed),
        };
        if loaded.generation() != selection.certificate
            || loaded.bundle_digest() != selection.bundle_digest
        {
            return Err(PublicCertificateInstallationWorkerError::Failed);
        }
        let request = PublicCertificateInstallationRequest {
            source: selection.source,
            source_revision: selection.source_revision,
            gateway_node_id: self.gateway_node_id,
            gateway_incarnation: self.gateway_incarnation,
            actor_principal_id: selection.configured_by,
            now,
        };
        let commit =
            match self
                .installation
                .install_and_acknowledge(&self.identity, &loaded, request)
            {
                Ok(commit) => commit,
                Err(PublicCertificateInstallationError::Unavailable) => {
                    return Ok(PublicCertificateInstallationWorkerOutcome::Deferred);
                }
                Err(_) => return Err(PublicCertificateInstallationWorkerError::Failed),
            };
        self.acknowledged = Some(selection);
        Ok(PublicCertificateInstallationWorkerOutcome::Installed(
            commit,
        ))
    }
}

/// Observable result of one bounded gateway installation pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicCertificateInstallationWorkerOutcome {
    /// No completed public certificate exists yet.
    Idle,
    /// The selected generation is waiting for authority, its local envelope or acknowledgement.
    Deferred,
    /// The exact selected generation is already installed and acknowledged in this process.
    Current,
    /// A new selection became live and its acknowledgement committed.
    Installed(PublicCertificateInstallationCommit),
}

/// Closed selection read failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PublicCertificateSelectionAuthorityError {
    /// Current replicated authority cannot answer safely.
    #[error("public certificate selection authority is unavailable")]
    Unavailable,
    /// Persisted selection evidence is malformed.
    #[error("public certificate selection authority failed closed")]
    Failed,
}

/// Closed worker failure without certificate or private-key material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PublicCertificateInstallationWorkerError {
    /// Gateway identity or incarnation is invalid.
    #[error("public certificate installation worker input is invalid")]
    InvalidInput,
    /// Selection, decryption, rotation or acknowledgement failed closed.
    #[error("public certificate installation worker failed closed")]
    Failed,
}
