// SPDX-License-Identifier: GPL-2.0-only

//! Gateway-only loading and domain-separated expansion of the mesh authentication root.

use hmac::{Hmac, KeyInit, Mac};
use meshspan_domain::{ApiKeyIssuanceKey, MeshId, RecoveryCodeIssuanceKey};
use meshspan_metadata::AUTHENTICATION_ROOT_KEY_SECRET_KIND;
use meshspan_secret_envelope::{SecretContext, SecretPlaintext};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::volume_key_loading::load_secret_generation;
use crate::{
    SecretGenerationAuthority, SecretGenerationAuthorityError, SecretGenerationDecryptor,
    SecretGenerationLoadingError, TotpEnvelopeKey, TotpFactorVerifier, TotpSessionError,
    TotpSessionVerifier, VerifiedTotpFactor,
};

const AUTHENTICATION_ROOT_BYTES: usize = 32;
const API_KEY_ISSUANCE_DOMAIN: &[u8] = b"meshspan.authentication.api-key-issuance.v1";
const RECOVERY_CODE_ISSUANCE_DOMAIN: &[u8] = b"meshspan.authentication.recovery-code-issuance.v1";
const TOTP_ENVELOPE_DOMAIN: &[u8] = b"meshspan.authentication.totp-envelope.v1";

type HmacSha256 = Hmac<Sha256>;

/// Authoritative encrypted authentication-root head needed by one gateway.
pub trait AuthenticationRootAuthority: SecretGenerationAuthority {
    /// Returns the one intrinsic mesh identity owned by this root partition.
    ///
    /// # Errors
    ///
    /// Fails closed when replicated metadata is unavailable or structurally invalid.
    fn local_mesh_id(&self) -> Result<Option<MeshId>, SecretGenerationAuthorityError>;

    /// Returns the newest committed generation used for new authentication material.
    ///
    /// # Errors
    ///
    /// Fails closed when replicated metadata is unavailable or invalid.
    fn latest_authentication_root_generation(
        &self,
        mesh_id: MeshId,
    ) -> Result<Option<u64>, SecretGenerationAuthorityError>;
}

/// Independently typed operational keys derived from one protected authentication root.
pub struct AuthenticationRuntimeKeys {
    api_key_issuance: ApiKeyIssuanceKey,
    recovery_code_issuance: RecoveryCodeIssuanceKey,
    totp_envelope: TotpEnvelopeKey,
}

impl AuthenticationRuntimeKeys {
    /// Transfers each key directly into its single-purpose runtime service.
    #[must_use]
    pub fn into_parts(self) -> (ApiKeyIssuanceKey, RecoveryCodeIssuanceKey, TotpEnvelopeKey) {
        (
            self.api_key_issuance,
            self.recovery_code_issuance,
            self.totp_envelope,
        )
    }

    /// Transfers only the TOTP envelope capability into a verifier.
    #[must_use]
    pub fn into_totp_envelope_key(self) -> TotpEnvelopeKey {
        self.totp_envelope
    }
}

/// Loads a recipient-bound root and exposes only separately typed derived capabilities.
pub struct AuthenticationRootLoadingService<A, D> {
    authority: A,
    decryptor: D,
}

impl<A, D> AuthenticationRootLoadingService<A, D> {
    /// Binds replicated reads to one node-local private-key operation boundary.
    #[must_use]
    pub const fn new(authority: A, decryptor: D) -> Self {
        Self {
            authority,
            decryptor,
        }
    }
}

impl<A, D> AuthenticationRootLoadingService<A, D>
where
    A: AuthenticationRootAuthority,
    D: SecretGenerationDecryptor,
{
    /// Loads and expands the newest generation explicitly encrypted for this gateway.
    ///
    /// # Errors
    ///
    /// Rejects absent authority, a missing local recipient, malformed plaintext and invalid
    /// domain-separated key output.
    pub fn load_latest(&self) -> Result<AuthenticationRuntimeKeys, AuthenticationRootLoadingError> {
        let mesh_id = self
            .authority
            .local_mesh_id()?
            .ok_or(AuthenticationRootLoadingError::NotFound)?;
        let generation = self
            .authority
            .latest_authentication_root_generation(mesh_id)?
            .ok_or(AuthenticationRootLoadingError::NotFound)?;
        let context = SecretContext::new(
            AUTHENTICATION_ROOT_KEY_SECRET_KIND,
            mesh_id.as_bytes(),
            generation,
        )
        .map_err(|_| AuthenticationRootLoadingError::InvalidInput)?;
        let plaintext = load_secret_generation(&self.authority, &self.decryptor, context)?;
        derive_runtime_keys(&plaintext, context)
    }
}

/// Request-time TOTP verifier which never retains a decrypted root between calls.
pub struct ProtectedTotpFactorVerifier<A, D> {
    loader: AuthenticationRootLoadingService<A, D>,
}

impl<A, D> ProtectedTotpFactorVerifier<A, D> {
    /// Composes current replicated root authority with one node-local wrapping key.
    #[must_use]
    pub const fn new(authority: A, decryptor: D) -> Self {
        Self {
            loader: AuthenticationRootLoadingService::new(authority, decryptor),
        }
    }

    fn verifier(&self) -> Result<TotpSessionVerifier, TotpSessionError>
    where
        A: AuthenticationRootAuthority,
        D: SecretGenerationDecryptor,
    {
        let envelope_key = self
            .loader
            .load_latest()
            .map(AuthenticationRuntimeKeys::into_totp_envelope_key)
            .map_err(map_totp_loading_error)?;
        Ok(TotpSessionVerifier::new(crate::TotpSecretCipher::new(
            envelope_key,
        )))
    }
}

impl<A, D> TotpFactorVerifier for ProtectedTotpFactorVerifier<A, D>
where
    A: AuthenticationRootAuthority,
    D: SecretGenerationDecryptor,
{
    fn verify_current(
        &self,
        principal_id: meshspan_domain::PrincipalId,
        materials: &[meshspan_metadata::TotpVerificationMaterial],
        code: &str,
        now: meshspan_domain::UnixMicros,
    ) -> Result<VerifiedTotpFactor, TotpSessionError> {
        self.verifier()?
            .verify_current(principal_id, materials, code, now)
    }

    fn verify_replay(
        &self,
        principal_id: meshspan_domain::PrincipalId,
        materials: &[meshspan_metadata::TotpVerificationMaterial],
        method_id: meshspan_domain::AuthenticationMethodId,
        code: &str,
        accepted_step: u64,
    ) -> Result<(), TotpSessionError> {
        self.verifier()?
            .verify_replay(principal_id, materials, method_id, code, accepted_step)
    }
}

const fn map_totp_loading_error(error: AuthenticationRootLoadingError) -> TotpSessionError {
    match error {
        AuthenticationRootLoadingError::NotFound
        | AuthenticationRootLoadingError::NotRecipient
        | AuthenticationRootLoadingError::Unavailable => TotpSessionError::Unavailable,
        AuthenticationRootLoadingError::InvalidInput | AuthenticationRootLoadingError::Failed => {
            TotpSessionError::InvalidEvidence
        }
    }
}

fn derive_runtime_keys(
    plaintext: &SecretPlaintext,
    context: SecretContext,
) -> Result<AuthenticationRuntimeKeys, AuthenticationRootLoadingError> {
    if plaintext.expose().len() != AUTHENTICATION_ROOT_BYTES {
        return Err(AuthenticationRootLoadingError::Failed);
    }
    let root = Zeroizing::new(
        <[u8; AUTHENTICATION_ROOT_BYTES]>::try_from(plaintext.expose())
            .map_err(|_| AuthenticationRootLoadingError::Failed)?,
    );
    let api_key_issuance =
        ApiKeyIssuanceKey::from_bytes(derive(&root, context, API_KEY_ISSUANCE_DOMAIN)?)
            .map_err(|_| AuthenticationRootLoadingError::Failed)?;
    let recovery_code_issuance =
        RecoveryCodeIssuanceKey::from_bytes(derive(&root, context, RECOVERY_CODE_ISSUANCE_DOMAIN)?)
            .map_err(|_| AuthenticationRootLoadingError::Failed)?;
    let totp_envelope = TotpEnvelopeKey::from_bytes(derive(&root, context, TOTP_ENVELOPE_DOMAIN)?)
        .map_err(|_| AuthenticationRootLoadingError::Failed)?;
    Ok(AuthenticationRuntimeKeys {
        api_key_issuance,
        recovery_code_issuance,
        totp_envelope,
    })
}

fn derive(
    root: &[u8; AUTHENTICATION_ROOT_BYTES],
    context: SecretContext,
    domain: &[u8],
) -> Result<[u8; 32], AuthenticationRootLoadingError> {
    let mut mac =
        HmacSha256::new_from_slice(root).map_err(|_| AuthenticationRootLoadingError::Failed)?;
    mac.update(domain);
    mac.update(&context.kind().to_be_bytes());
    mac.update(&context.id());
    mac.update(&context.generation().to_be_bytes());
    let output: [u8; 32] = mac.finalize().into_bytes().into();
    if output == [0; 32] {
        Err(AuthenticationRootLoadingError::Failed)
    } else {
        Ok(output)
    }
}

/// Closed authentication-root load failure without secret or envelope detail.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AuthenticationRootLoadingError {
    /// The requested context was structurally invalid.
    #[error("authentication root request is invalid")]
    InvalidInput,
    /// No committed generation exists.
    #[error("authentication root generation was not found")]
    NotFound,
    /// This node has no envelope in the committed recipient set.
    #[error("authentication root generation does not authorise this node")]
    NotRecipient,
    /// Current replicated metadata cannot serve the read.
    #[error("authentication root loading is unavailable")]
    Unavailable,
    /// Persisted evidence, authenticated decryption or key expansion failed closed.
    #[error("authentication root loading failed closed")]
    Failed,
}

impl From<SecretGenerationAuthorityError> for AuthenticationRootLoadingError {
    fn from(error: SecretGenerationAuthorityError) -> Self {
        SecretGenerationLoadingError::from(error).into()
    }
}

impl From<SecretGenerationLoadingError> for AuthenticationRootLoadingError {
    fn from(error: SecretGenerationLoadingError) -> Self {
        match error {
            SecretGenerationLoadingError::NotFound => Self::NotFound,
            SecretGenerationLoadingError::NotRecipient => Self::NotRecipient,
            SecretGenerationLoadingError::Unavailable => Self::Unavailable,
            SecretGenerationLoadingError::Failed => Self::Failed,
        }
    }
}

impl<T> AuthenticationRootAuthority for &T
where
    T: AuthenticationRootAuthority + ?Sized,
{
    fn local_mesh_id(&self) -> Result<Option<MeshId>, SecretGenerationAuthorityError> {
        (*self).local_mesh_id()
    }

    fn latest_authentication_root_generation(
        &self,
        mesh_id: MeshId,
    ) -> Result<Option<u64>, SecretGenerationAuthorityError> {
        (*self).latest_authentication_root_generation(mesh_id)
    }
}

impl<T> AuthenticationRootAuthority for std::sync::Arc<T>
where
    T: AuthenticationRootAuthority + ?Sized,
{
    fn local_mesh_id(&self) -> Result<Option<MeshId>, SecretGenerationAuthorityError> {
        self.as_ref().local_mesh_id()
    }

    fn latest_authentication_root_generation(
        &self,
        mesh_id: MeshId,
    ) -> Result<Option<u64>, SecretGenerationAuthorityError> {
        self.as_ref().latest_authentication_root_generation(mesh_id)
    }
}
