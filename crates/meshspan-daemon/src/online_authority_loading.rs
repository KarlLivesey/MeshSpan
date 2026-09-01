// SPDX-License-Identifier: GPL-2.0-only

//! Request-time loading of the encrypted root-signed online node certificate authority.

use meshspan_certificates::OnlineCertificateAuthority;
use meshspan_domain::MeshId;
use meshspan_metadata::{ONLINE_AUTHORITY_KEY_SECRET_KIND, OnlineCertificateAuthorityRecord};
use meshspan_secret_envelope::SecretContext;
use thiserror::Error;

use crate::volume_key_loading::load_secret_generation;
use crate::{
    SecretGenerationAuthority, SecretGenerationAuthorityError, SecretGenerationDecryptor,
    SecretGenerationLoadingError,
};

/// Replicated public certificate and encrypted private-key head for the online authority.
pub trait OnlineAuthorityLoadingAuthority: SecretGenerationAuthority {
    /// Returns the one intrinsic mesh identity owned by this root partition.
    ///
    /// # Errors
    ///
    /// Fails closed when committed mesh identity is unavailable or malformed.
    fn local_mesh_id(&self) -> Result<Option<MeshId>, SecretGenerationAuthorityError>;

    /// Returns the current root-signed public online-authority certificate generation.
    ///
    /// # Errors
    ///
    /// Fails closed when committed certificate evidence is unavailable or malformed.
    fn online_certificate_authority(
        &self,
        mesh_id: MeshId,
    ) -> Result<Option<OnlineCertificateAuthorityRecord>, SecretGenerationAuthorityError>;
}

/// Loads one online authority only for the duration of a certificate issuance operation.
pub struct OnlineAuthorityLoadingService<A, D> {
    authority: A,
    decryptor: D,
}

impl<A, D> OnlineAuthorityLoadingService<A, D> {
    /// Binds replicated public/encrypted authority state to one node-local wrapping key.
    #[must_use]
    pub const fn new(authority: A, decryptor: D) -> Self {
        Self {
            authority,
            decryptor,
        }
    }
}

impl<A, D> OnlineAuthorityLoadingService<A, D>
where
    A: OnlineAuthorityLoadingAuthority,
    D: SecretGenerationDecryptor,
{
    /// Loads and proves the exact current certificate/private-key pair.
    ///
    /// # Errors
    ///
    /// Rejects missing authority, missing local recipient access, authenticated decryption
    /// failure and certificate/key mismatch or corruption.
    pub fn load_latest(
        &self,
    ) -> Result<(MeshId, OnlineCertificateAuthority), OnlineAuthorityLoadingError> {
        let mesh_id = self
            .authority
            .local_mesh_id()?
            .ok_or(OnlineAuthorityLoadingError::NotFound)?;
        let certificate = self
            .authority
            .online_certificate_authority(mesh_id)?
            .ok_or(OnlineAuthorityLoadingError::NotFound)?;
        let context = SecretContext::new(
            ONLINE_AUTHORITY_KEY_SECRET_KIND,
            mesh_id.as_bytes(),
            certificate.generation,
        )
        .map_err(|_| OnlineAuthorityLoadingError::Failed)?;
        let plaintext = load_secret_generation(&self.authority, &self.decryptor, context)?;
        let authority = OnlineCertificateAuthority::from_pkcs8_and_certificate(
            plaintext.expose(),
            &certificate.certificate_der,
        )
        .map_err(|_| OnlineAuthorityLoadingError::Failed)?;
        Ok((mesh_id, authority))
    }
}

/// Closed online-authority loading failure without secret or envelope detail.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum OnlineAuthorityLoadingError {
    /// No committed current authority generation exists.
    #[error("online certificate authority was not found")]
    NotFound,
    /// This node has no envelope in the current recipient set.
    #[error("online certificate authority does not authorise this node")]
    NotRecipient,
    /// Current replicated metadata cannot serve the read.
    #[error("online certificate authority is unavailable")]
    Unavailable,
    /// Persisted evidence, authenticated decryption or certificate construction failed closed.
    #[error("online certificate authority failed closed")]
    Failed,
}

impl From<SecretGenerationAuthorityError> for OnlineAuthorityLoadingError {
    fn from(error: SecretGenerationAuthorityError) -> Self {
        SecretGenerationLoadingError::from(error).into()
    }
}

impl From<SecretGenerationLoadingError> for OnlineAuthorityLoadingError {
    fn from(error: SecretGenerationLoadingError) -> Self {
        match error {
            SecretGenerationLoadingError::NotFound => Self::NotFound,
            SecretGenerationLoadingError::NotRecipient => Self::NotRecipient,
            SecretGenerationLoadingError::Unavailable => Self::Unavailable,
            SecretGenerationLoadingError::Failed => Self::Failed,
        }
    }
}
