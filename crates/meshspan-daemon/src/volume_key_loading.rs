// SPDX-License-Identifier: GPL-2.0-only

//! Fail-closed bridge from replicated encrypted volume secrets to filesystem key capability.

use std::sync::Arc;

use meshspan_domain::{ContentManifestId, RandomSource, VolumeId};
use meshspan_filesystem::{
    ContentEncryptionKey, ContentKeyEnvelopeCipher, ContentKeyError, VolumeContentKeys,
    VolumeKeyEncryptionKey, WrappedContentKey,
};
use meshspan_metadata::{SecretGenerationRecord, VOLUME_CONTENT_KEY_SECRET_KIND};
use meshspan_secret_envelope::{
    EncryptedSecret, RecipientKeyEnvelope, SecretContext, SecretPlaintext, WrappingPublicKey,
};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::LocalWrappingKey;

const VOLUME_CONTENT_KEY_BYTES: usize = 32;

/// Authoritative exact-generation read shared by protected runtime capabilities.
pub trait SecretGenerationAuthority {
    /// Returns one exact committed encrypted generation.
    ///
    /// # Errors
    ///
    /// Fails closed when replicated metadata is unavailable or invalid.
    fn secret_generation(
        &self,
        context: SecretContext,
    ) -> Result<Option<SecretGenerationRecord>, SecretGenerationAuthorityError>;
}

impl<T> SecretGenerationAuthority for &T
where
    T: SecretGenerationAuthority + ?Sized,
{
    fn secret_generation(
        &self,
        context: SecretContext,
    ) -> Result<Option<SecretGenerationRecord>, SecretGenerationAuthorityError> {
        (*self).secret_generation(context)
    }
}

impl<T> SecretGenerationAuthority for Arc<T>
where
    T: SecretGenerationAuthority + ?Sized,
{
    fn secret_generation(
        &self,
        context: SecretContext,
    ) -> Result<Option<SecretGenerationRecord>, SecretGenerationAuthorityError> {
        self.as_ref().secret_generation(context)
    }
}

/// Authoritative encrypted-secret head needed by one gateway volume-key load.
pub trait VolumeKeyAuthority: SecretGenerationAuthority {
    /// Returns the newest committed generation used to wrap new content keys.
    ///
    /// # Errors
    ///
    /// Fails closed when replicated metadata is unavailable or invalid.
    fn latest_generation(
        &self,
        volume_id: VolumeId,
    ) -> Result<Option<u64>, SecretGenerationAuthorityError>;
}

impl<T> VolumeKeyAuthority for &T
where
    T: VolumeKeyAuthority + ?Sized,
{
    fn latest_generation(
        &self,
        volume_id: VolumeId,
    ) -> Result<Option<u64>, SecretGenerationAuthorityError> {
        (*self).latest_generation(volume_id)
    }
}

impl<T> VolumeKeyAuthority for Arc<T>
where
    T: VolumeKeyAuthority + ?Sized,
{
    fn latest_generation(
        &self,
        volume_id: VolumeId,
    ) -> Result<Option<u64>, SecretGenerationAuthorityError> {
        self.as_ref().latest_generation(volume_id)
    }
}

/// Node-local private-key operation shared by protected runtime capabilities.
pub trait SecretGenerationDecryptor {
    /// Returns the public identity used to select one exact recipient envelope.
    fn public_key(&self) -> WrappingPublicKey;

    /// Opens the selected data-key envelope and decrypts its bound secret.
    ///
    /// # Errors
    ///
    /// Rejects recipient, context or authenticated-ciphertext substitution.
    fn decrypt_secret(
        &self,
        secret: &EncryptedSecret,
        recipient: &RecipientKeyEnvelope,
    ) -> Result<SecretPlaintext, SecretGenerationDecryptorError>;
}

impl SecretGenerationDecryptor for LocalWrappingKey {
    fn public_key(&self) -> WrappingPublicKey {
        LocalWrappingKey::public_key(self)
    }

    fn decrypt_secret(
        &self,
        secret: &EncryptedSecret,
        recipient: &RecipientKeyEnvelope,
    ) -> Result<SecretPlaintext, SecretGenerationDecryptorError> {
        LocalWrappingKey::decrypt_secret(self, secret, recipient)
            .map_err(|_| SecretGenerationDecryptorError::Failed)
    }
}

impl<T> SecretGenerationDecryptor for Arc<T>
where
    T: SecretGenerationDecryptor + ?Sized,
{
    fn public_key(&self) -> WrappingPublicKey {
        self.as_ref().public_key()
    }

    fn decrypt_secret(
        &self,
        secret: &EncryptedSecret,
        recipient: &RecipientKeyEnvelope,
    ) -> Result<SecretPlaintext, SecretGenerationDecryptorError> {
        self.as_ref().decrypt_secret(secret, recipient)
    }
}

impl<T> SecretGenerationDecryptor for &T
where
    T: SecretGenerationDecryptor + ?Sized,
{
    fn public_key(&self) -> WrappingPublicKey {
        (*self).public_key()
    }

    fn decrypt_secret(
        &self,
        secret: &EncryptedSecret,
        recipient: &RecipientKeyEnvelope,
    ) -> Result<SecretPlaintext, SecretGenerationDecryptorError> {
        (*self).decrypt_secret(secret, recipient)
    }
}

/// Loads only encrypted generations explicitly addressed to this gateway.
pub struct VolumeKeyLoadingService<A, D> {
    authority: A,
    decryptor: D,
}

impl<A, D> VolumeKeyLoadingService<A, D> {
    /// Binds replicated reads to one node-local private-key operation boundary.
    #[must_use]
    pub const fn new(authority: A, decryptor: D) -> Self {
        Self {
            authority,
            decryptor,
        }
    }
}

impl<A, D> VolumeKeyLoadingService<A, D>
where
    A: VolumeKeyAuthority,
    D: SecretGenerationDecryptor,
{
    /// Loads the newest committed generation used for new content-key envelopes.
    ///
    /// # Errors
    ///
    /// Rejects absent or invalid generation authority and every exact-load failure.
    pub fn load_latest(
        &self,
        volume_id: VolumeId,
    ) -> Result<VolumeKeyEncryptionKey, VolumeKeyLoadingError> {
        let generation = self
            .authority
            .latest_generation(volume_id)?
            .ok_or(VolumeKeyLoadingError::NotFound)?;
        self.load(volume_id, generation)
    }

    /// Authenticates and unwraps one exact volume key into a non-exportable filesystem capability.
    ///
    /// # Errors
    ///
    /// Rejects zero generations, missing authority, absent/duplicate local envelopes, wrong
    /// plaintext length, an all-zero key or any failed authenticated decryption.
    pub fn load(
        &self,
        volume_id: VolumeId,
        generation: u64,
    ) -> Result<VolumeKeyEncryptionKey, VolumeKeyLoadingError> {
        let context = SecretContext::new(
            VOLUME_CONTENT_KEY_SECRET_KIND,
            volume_id.as_bytes(),
            generation,
        )
        .map_err(|_| VolumeKeyLoadingError::InvalidInput)?;
        let plaintext = load_secret_generation(&self.authority, &self.decryptor, context)?;
        if plaintext.expose().len() != VOLUME_CONTENT_KEY_BYTES {
            return Err(VolumeKeyLoadingError::Failed);
        }
        let mut bytes = Zeroizing::new([0_u8; VOLUME_CONTENT_KEY_BYTES]);
        bytes.copy_from_slice(plaintext.expose());
        VolumeKeyEncryptionKey::from_protected_bytes(generation, bytes)
            .map_err(|_| VolumeKeyLoadingError::Failed)
    }
}

impl<A, D> VolumeContentKeys for VolumeKeyLoadingService<A, D>
where
    A: VolumeKeyAuthority,
    D: SecretGenerationDecryptor,
{
    fn wrap_content_key(
        &self,
        volume_id: VolumeId,
        manifest_id: ContentManifestId,
        content_key: &ContentEncryptionKey,
        random: &mut dyn RandomSource,
    ) -> Result<WrappedContentKey, ContentKeyError> {
        let key = self.load_latest(volume_id).map_err(map_content_key_load)?;
        ContentKeyEnvelopeCipher::new(key).wrap(manifest_id, content_key, random)
    }

    fn unwrap_content_key(
        &self,
        volume_id: VolumeId,
        manifest_id: ContentManifestId,
        envelope: WrappedContentKey,
    ) -> Result<ContentEncryptionKey, ContentKeyError> {
        let key = self
            .load(volume_id, envelope.key_generation)
            .map_err(map_content_key_load)?;
        ContentKeyEnvelopeCipher::new(key).unwrap(manifest_id, envelope)
    }
}

const fn map_content_key_load(error: VolumeKeyLoadingError) -> ContentKeyError {
    match error {
        VolumeKeyLoadingError::InvalidInput => ContentKeyError::InvalidInput,
        VolumeKeyLoadingError::NotFound
        | VolumeKeyLoadingError::NotRecipient
        | VolumeKeyLoadingError::Unavailable => ContentKeyError::Unavailable,
        VolumeKeyLoadingError::Failed => ContentKeyError::Corrupt,
    }
}

pub(crate) fn load_secret_generation<A, D>(
    authority: &A,
    decryptor: &D,
    context: SecretContext,
) -> Result<SecretPlaintext, SecretGenerationLoadingError>
where
    A: SecretGenerationAuthority,
    D: SecretGenerationDecryptor,
{
    let record = authority
        .secret_generation(context)?
        .ok_or(SecretGenerationLoadingError::NotFound)?;
    if record.secret.context() != context || record.revision == meshspan_domain::Revision::ZERO {
        return Err(SecretGenerationLoadingError::Failed);
    }
    let recipient = select_recipient(&record, decryptor.public_key())?;
    decryptor
        .decrypt_secret(&record.secret, recipient)
        .map_err(SecretGenerationLoadingError::from)
}

fn select_recipient(
    record: &SecretGenerationRecord,
    local_public_key: WrappingPublicKey,
) -> Result<&RecipientKeyEnvelope, SecretGenerationLoadingError> {
    let mut selected = None;
    for recipient in &record.recipients {
        let public_key = recipient
            .recipient_public_key()
            .map_err(|_| SecretGenerationLoadingError::Failed)?;
        if public_key == local_public_key && selected.replace(recipient).is_some() {
            return Err(SecretGenerationLoadingError::Failed);
        }
    }
    selected.ok_or(SecretGenerationLoadingError::NotRecipient)
}

/// Closed replicated-read failure with no secret or storage detail.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SecretGenerationAuthorityError {
    /// Current metadata authority cannot serve the read.
    #[error("secret generation authority is unavailable")]
    Unavailable,
    /// Persisted authoritative evidence failed validation.
    #[error("secret generation authority failed closed")]
    Failed,
}

/// Closed node-local decryption failure with no private-key or ciphertext detail.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SecretGenerationDecryptorError {
    /// Recipient binding or authenticated decryption failed.
    #[error("secret generation decryption failed closed")]
    Failed,
}

/// Shared exact-generation loading failure before capability-specific validation.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SecretGenerationLoadingError {
    /// No committed generation exists.
    #[error("secret generation was not found")]
    NotFound,
    /// This node has no envelope in the committed recipient set.
    #[error("secret generation does not authorise this node")]
    NotRecipient,
    /// Current replicated metadata cannot serve the read.
    #[error("secret generation loading is unavailable")]
    Unavailable,
    /// Persisted evidence or authenticated decryption failed closed.
    #[error("secret generation loading failed closed")]
    Failed,
}

/// Stable gateway volume-key loading failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum VolumeKeyLoadingError {
    /// The requested generation is invalid.
    #[error("volume key request is invalid")]
    InvalidInput,
    /// No committed generation exists.
    #[error("volume key generation was not found")]
    NotFound,
    /// This node has no envelope in the committed recipient set.
    #[error("volume key generation does not authorise this node")]
    NotRecipient,
    /// Current replicated metadata cannot serve the read.
    #[error("volume key loading is unavailable")]
    Unavailable,
    /// Persisted evidence or authenticated decryption failed closed.
    #[error("volume key loading failed closed")]
    Failed,
}

impl From<SecretGenerationAuthorityError> for SecretGenerationLoadingError {
    fn from(error: SecretGenerationAuthorityError) -> Self {
        match error {
            SecretGenerationAuthorityError::Unavailable => Self::Unavailable,
            SecretGenerationAuthorityError::Failed => Self::Failed,
        }
    }
}

impl From<SecretGenerationDecryptorError> for SecretGenerationLoadingError {
    fn from(_: SecretGenerationDecryptorError) -> Self {
        Self::Failed
    }
}

impl From<SecretGenerationLoadingError> for VolumeKeyLoadingError {
    fn from(error: SecretGenerationLoadingError) -> Self {
        match error {
            SecretGenerationLoadingError::NotFound => Self::NotFound,
            SecretGenerationLoadingError::NotRecipient => Self::NotRecipient,
            SecretGenerationLoadingError::Unavailable => Self::Unavailable,
            SecretGenerationLoadingError::Failed => Self::Failed,
        }
    }
}

impl From<SecretGenerationAuthorityError> for VolumeKeyLoadingError {
    fn from(error: SecretGenerationAuthorityError) -> Self {
        SecretGenerationLoadingError::from(error).into()
    }
}
