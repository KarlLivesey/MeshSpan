// SPDX-License-Identifier: GPL-2.0-only

//! Fail-closed bridge from the replicated mesh secret to storage-permit capability.

use std::sync::Arc;

use meshspan_contracts::StoragePermitMacKey;
use meshspan_domain::MeshId;
use meshspan_metadata::STORAGE_PERMIT_KEY_SECRET_KIND;
use meshspan_secret_envelope::SecretContext;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::volume_key_loading::load_secret_generation;
use crate::{
    SecretGenerationAuthority, SecretGenerationAuthorityError, SecretGenerationDecryptor,
    SecretGenerationLoadingError,
};

const STORAGE_PERMIT_KEY_BYTES: usize = 32;

/// Authoritative encrypted-secret head needed to issue and verify storage permits.
pub trait StoragePermitAuthority: SecretGenerationAuthority {
    /// Returns the newest committed storage-permit generation for one mesh.
    ///
    /// # Errors
    ///
    /// Fails closed when replicated metadata is unavailable or invalid.
    fn latest_generation(
        &self,
        mesh_id: MeshId,
    ) -> Result<Option<u64>, SecretGenerationAuthorityError>;
}

impl<T> StoragePermitAuthority for &T
where
    T: StoragePermitAuthority + ?Sized,
{
    fn latest_generation(
        &self,
        mesh_id: MeshId,
    ) -> Result<Option<u64>, SecretGenerationAuthorityError> {
        (*self).latest_generation(mesh_id)
    }
}

impl<T> StoragePermitAuthority for Arc<T>
where
    T: StoragePermitAuthority + ?Sized,
{
    fn latest_generation(
        &self,
        mesh_id: MeshId,
    ) -> Result<Option<u64>, SecretGenerationAuthorityError> {
        self.as_ref().latest_generation(mesh_id)
    }
}

/// Loads storage-permit capability only from generations addressed to this node.
pub struct StoragePermitLoadingService<A, D> {
    authority: A,
    decryptor: D,
}

impl<A, D> StoragePermitLoadingService<A, D> {
    /// Binds replicated reads to one node-local private-key operation boundary.
    #[must_use]
    pub const fn new(authority: A, decryptor: D) -> Self {
        Self {
            authority,
            decryptor,
        }
    }
}

impl<A, D> StoragePermitLoadingService<A, D>
where
    A: StoragePermitAuthority,
    D: SecretGenerationDecryptor,
{
    /// Loads the newest committed key used by permit issuers and providers.
    ///
    /// # Errors
    ///
    /// Rejects absent authority and every exact-load failure.
    pub fn load_latest(
        &self,
        mesh_id: MeshId,
    ) -> Result<StoragePermitMacKey, StoragePermitLoadingError> {
        let generation = self
            .authority
            .latest_generation(mesh_id)?
            .ok_or(StoragePermitLoadingError::NotFound)?;
        self.load(mesh_id, generation)
    }

    /// Authenticates and unwraps one exact generation into a non-serialisable MAC capability.
    ///
    /// # Errors
    ///
    /// Rejects zero generations, absent or duplicate local envelopes, wrong plaintext length,
    /// all-zero key material and authenticated-decryption failure.
    pub fn load(
        &self,
        mesh_id: MeshId,
        generation: u64,
    ) -> Result<StoragePermitMacKey, StoragePermitLoadingError> {
        let context = SecretContext::new(
            STORAGE_PERMIT_KEY_SECRET_KIND,
            mesh_id.as_bytes(),
            generation,
        )
        .map_err(|_| StoragePermitLoadingError::InvalidInput)?;
        let plaintext = load_secret_generation(&self.authority, &self.decryptor, context)?;
        if plaintext.expose().len() != STORAGE_PERMIT_KEY_BYTES {
            return Err(StoragePermitLoadingError::Failed);
        }
        let mut bytes = Zeroizing::new([0_u8; STORAGE_PERMIT_KEY_BYTES]);
        bytes.copy_from_slice(plaintext.expose());
        StoragePermitMacKey::from_protected_bytes(bytes)
            .map_err(|_| StoragePermitLoadingError::Failed)
    }
}

/// Stable storage-permit capability loading failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum StoragePermitLoadingError {
    /// The requested generation is invalid.
    #[error("storage permit key request is invalid")]
    InvalidInput,
    /// No committed generation exists.
    #[error("storage permit key generation was not found")]
    NotFound,
    /// This node has no envelope in the committed recipient set.
    #[error("storage permit key generation does not authorise this node")]
    NotRecipient,
    /// Current replicated metadata cannot serve the read.
    #[error("storage permit key loading is unavailable")]
    Unavailable,
    /// Persisted evidence or authenticated decryption failed closed.
    #[error("storage permit key loading failed closed")]
    Failed,
}

impl From<SecretGenerationAuthorityError> for StoragePermitLoadingError {
    fn from(error: SecretGenerationAuthorityError) -> Self {
        SecretGenerationLoadingError::from(error).into()
    }
}

impl From<SecretGenerationLoadingError> for StoragePermitLoadingError {
    fn from(error: SecretGenerationLoadingError) -> Self {
        match error {
            SecretGenerationLoadingError::NotFound => Self::NotFound,
            SecretGenerationLoadingError::NotRecipient => Self::NotRecipient,
            SecretGenerationLoadingError::Unavailable => Self::Unavailable,
            SecretGenerationLoadingError::Failed => Self::Failed,
        }
    }
}
