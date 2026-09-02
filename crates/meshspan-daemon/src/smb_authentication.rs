// SPDX-License-Identifier: GPL-2.0-only

//! Shared-identity authentication boundary for embedded SMB sessions.

use std::collections::BTreeMap;

use meshspan_domain::{ApiKeyId, AuthenticationMethodId, PrincipalId, Revision, UnixMicros};
use meshspan_metadata::{
    AuthoritativeRepository, RecordName, RepositoryError, SmbVerificationMaterial,
};
use meshspan_smb::{
    EncryptionCipher, NtlmAuthenticate, NtlmChallenge, NtlmSessionBaseKey, Smb311PreauthHash,
    Smb311SessionKeys, SmbSessionAuthenticator,
};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    AuthenticationRootAuthority, AuthenticationRootLoadingService, AuthenticationRuntimeKeys,
    SecretGenerationDecryptor, SmbVerifierBinding, SmbVerifierCipher, SmbVerifierEnvelopeKey,
};

/// Current replicated SMB authentication-material query boundary.
pub trait SmbAuthenticationAuthority {
    /// Resolves a bounded set of current encrypted verifier candidates for one user.
    ///
    /// # Errors
    ///
    /// Fails closed when authoritative metadata is unavailable or malformed.
    fn smb_verification_materials(
        &self,
        user_name: &RecordName,
        now: UnixMicros,
    ) -> Result<Vec<SmbVerificationMaterial>, SmbAuthenticationAuthorityError>;
}

/// Historical authentication-root capability used only to decrypt one envelope generation.
pub trait SmbVerifierKeySource {
    /// Loads the key for one non-zero generation named by an untrusted envelope header.
    ///
    /// # Errors
    ///
    /// Fails closed for absent, unauthorised or malformed protected generations.
    fn smb_verifier_key(
        &self,
        generation: u64,
    ) -> Result<SmbVerifierEnvelopeKey, SmbAuthenticationError>;
}

/// Request-time historical-key source which retains no decrypted root between calls.
pub struct ProtectedSmbVerifierKeySource<R, D> {
    loader: AuthenticationRootLoadingService<R, D>,
}

impl<R, D> ProtectedSmbVerifierKeySource<R, D> {
    /// Binds replicated root authority to one node-local wrapping-key operation.
    #[must_use]
    pub const fn new(authority: R, decryptor: D) -> Self {
        Self {
            loader: AuthenticationRootLoadingService::new(authority, decryptor),
        }
    }
}

impl<R, D> SmbVerifierKeySource for ProtectedSmbVerifierKeySource<R, D>
where
    R: AuthenticationRootAuthority,
    D: SecretGenerationDecryptor,
{
    fn smb_verifier_key(
        &self,
        generation: u64,
    ) -> Result<SmbVerifierEnvelopeKey, SmbAuthenticationError> {
        self.loader
            .load_generation(generation)
            .map(AuthenticationRuntimeKeys::into_smb_verifier_envelope_key)
            .map_err(|error| match error {
                crate::AuthenticationRootLoadingError::NotFound
                | crate::AuthenticationRootLoadingError::NotRecipient
                | crate::AuthenticationRootLoadingError::Unavailable => {
                    SmbAuthenticationError::Unavailable
                }
                crate::AuthenticationRootLoadingError::InvalidInput
                | crate::AuthenticationRootLoadingError::Failed => SmbAuthenticationError::State,
            })
    }
}

/// Authenticated identity and fencing evidence attached to one SMB session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SmbAuthenticatedIdentity {
    /// Ordinary `MeshSpan` user principal.
    pub principal_id: PrincipalId,
    /// Authentication method which proved possession.
    pub method_id: AuthenticationMethodId,
    /// API-key identity which proved possession.
    pub key_id: ApiKeyId,
    /// API-key capabilities retained for later connector checks.
    pub scopes: u64,
    /// Credential generation used to fence revocation and rotation.
    pub credential_generation: u64,
    /// Method revision used to fence later identity changes.
    pub revision: Revision,
}

/// Successful proof plus the secret base key needed for SMB 3.1.1 session keys.
pub struct SmbAuthentication {
    identity: SmbAuthenticatedIdentity,
    session_base_key: NtlmSessionBaseKey,
    credential: SmbCredentialEvidence,
}

/// Credential evidence retained by an authenticated SMB session for common live authority checks.
///
/// This type deliberately implements neither `Debug`, `Clone`, `Copy` nor `Display`, and clears
/// its digest on drop.
pub struct SmbCredentialEvidence {
    digest: Zeroizing<[u8; 32]>,
}

/// Common identity and live credential evidence retained by one established SMB session.
pub struct SmbSessionAuthority {
    identity: SmbAuthenticatedIdentity,
    credential: SmbCredentialEvidence,
}

impl SmbSessionAuthority {
    /// Returns the non-secret authenticated principal and revision evidence.
    #[must_use]
    pub const fn identity(&self) -> SmbAuthenticatedIdentity {
        self.identity
    }

    /// Returns the credential digest for one short-lived common access context.
    #[must_use]
    pub fn credential_digest(&self) -> [u8; 32] {
        self.credential.digest()
    }
}

impl SmbCredentialEvidence {
    /// Copies the digest into one short-lived common filesystem access context.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        *self.digest
    }
}

impl SmbAuthentication {
    /// Returns the non-secret identity and fencing evidence.
    #[must_use]
    pub const fn identity(&self) -> SmbAuthenticatedIdentity {
        self.identity
    }

    /// Consumes the proof and derives transcript-bound signing and encryption keys.
    ///
    /// # Errors
    ///
    /// Fails closed when the negotiated cipher or key derivation is invalid.
    pub fn into_session_keys(
        self,
        preauth_hash: &Smb311PreauthHash,
        cipher: EncryptionCipher,
    ) -> Result<
        (
            SmbAuthenticatedIdentity,
            Smb311SessionKeys,
            SmbCredentialEvidence,
        ),
        SmbAuthenticationError,
    > {
        let keys = Smb311SessionKeys::derive(&self.session_base_key, preauth_hash, cipher)
            .map_err(|_| SmbAuthenticationError::State)?;
        Ok((self.identity, keys, self.credential))
    }
}

/// Complete NTLM proof verifier over replicated users and protected root generations.
pub struct SmbAuthenticationService<A, K> {
    authority: A,
    keys: K,
}

impl<A, K> SmbAuthenticationService<A, K> {
    /// Composes current identity reads with historical protected-key loading.
    #[must_use]
    pub const fn new(authority: A, keys: K) -> Self {
        Self { authority, keys }
    }
}

impl<A, K> SmbAuthenticationService<A, K>
where
    A: SmbAuthenticationAuthority,
    K: SmbVerifierKeySource,
{
    /// Verifies one already parsed NTLM authenticate message without a credential oracle.
    ///
    /// Every active candidate is evaluated. Zero or multiple matches are rejected, and ordinary
    /// proof failure never reveals whether the user, method, generation or key was absent.
    ///
    /// # Errors
    ///
    /// Returns one opaque credential rejection or a closed authority/state failure.
    pub fn authenticate(
        &self,
        authenticate: &NtlmAuthenticate<'_>,
        challenge: &NtlmChallenge,
        now: UnixMicros,
    ) -> Result<SmbAuthentication, SmbAuthenticationError> {
        let user_name =
            RecordName::new(&authenticate.username).map_err(|_| SmbAuthenticationError::Denied)?;
        let materials = self
            .authority
            .smb_verification_materials(&user_name, now)
            .map_err(Into::<SmbAuthenticationError>::into)?;
        let grouped = group_by_generation(&materials)?;
        let mut matched = None;
        let mut invalid_envelope = false;
        for (generation, candidates) in grouped {
            let cipher =
                SmbVerifierCipher::new(self.keys.smb_verifier_key(generation)?, generation)
                    .map_err(|_| SmbAuthenticationError::State)?;
            for material in candidates {
                let binding = SmbVerifierBinding {
                    method_id: material.method_id,
                    principal_id: material.principal_id,
                    key_id: material.key_id,
                    service_scope: material.service_scope,
                    scopes: material.scopes,
                };
                let Ok(verifier) = cipher.decrypt(binding, &material.verifier_ciphertext) else {
                    invalid_envelope = true;
                    continue;
                };
                let Ok(session_base_key) = authenticate.verify(verifier.verifier(), challenge)
                else {
                    continue;
                };
                if matched.is_some() {
                    return Err(SmbAuthenticationError::State);
                }
                matched = Some(SmbAuthentication {
                    identity: identity(material),
                    session_base_key,
                    credential: SmbCredentialEvidence {
                        digest: Zeroizing::new(verifier.credential_digest()),
                    },
                });
            }
        }
        matched.ok_or(if invalid_envelope {
            SmbAuthenticationError::State
        } else {
            SmbAuthenticationError::Denied
        })
    }
}

impl<A, K> SmbSessionAuthenticator for SmbAuthenticationService<A, K>
where
    A: SmbAuthenticationAuthority,
    K: SmbVerifierKeySource,
{
    type Identity = SmbSessionAuthority;
    type Verified = SmbAuthentication;
    type Error = SmbAuthenticationError;

    fn verify(
        &mut self,
        authenticate: &NtlmAuthenticate<'_>,
        challenge: &NtlmChallenge,
        observed_at: UnixMicros,
    ) -> Result<Self::Verified, Self::Error> {
        self.authenticate(authenticate, challenge, observed_at)
    }

    fn establish(
        &mut self,
        verified: Self::Verified,
        preauth: &Smb311PreauthHash,
        cipher: EncryptionCipher,
    ) -> Result<(Self::Identity, Smb311SessionKeys), Self::Error> {
        let (identity, keys, credential) = verified.into_session_keys(preauth, cipher)?;
        Ok((
            SmbSessionAuthority {
                identity,
                credential,
            },
            keys,
        ))
    }
}

fn group_by_generation(
    materials: &[SmbVerificationMaterial],
) -> Result<BTreeMap<u64, Vec<&SmbVerificationMaterial>>, SmbAuthenticationError> {
    let mut grouped = BTreeMap::<u64, Vec<_>>::new();
    for material in materials {
        let generation = SmbVerifierCipher::envelope_generation(&material.verifier_ciphertext)
            .map_err(|_| SmbAuthenticationError::State)?;
        grouped.entry(generation).or_default().push(material);
    }
    Ok(grouped)
}

fn identity(material: &SmbVerificationMaterial) -> SmbAuthenticatedIdentity {
    SmbAuthenticatedIdentity {
        principal_id: material.principal_id,
        method_id: material.method_id,
        key_id: material.key_id,
        scopes: material.scopes,
        credential_generation: material.credential_generation,
        revision: material.revision,
    }
}

/// Opaque replicated-authority failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SmbAuthenticationAuthorityError {
    /// Current replicated metadata cannot serve the bounded read.
    #[error("SMB authentication authority is unavailable")]
    Unavailable,
    /// Persisted authentication evidence is malformed.
    #[error("SMB authentication authority failed closed")]
    Failed,
}

/// Opaque SMB authentication result safe to map to protocol status.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SmbAuthenticationError {
    /// The complete proof was not accepted without disclosing which fact disagreed.
    #[error("SMB authentication was not accepted")]
    Denied,
    /// Current replicated or protected authority cannot serve authentication.
    #[error("SMB authentication is temporarily unavailable")]
    Unavailable,
    /// Protected or replicated authentication state failed closed.
    #[error("SMB authentication state failed closed")]
    State,
}

impl From<SmbAuthenticationAuthorityError> for SmbAuthenticationError {
    fn from(error: SmbAuthenticationAuthorityError) -> Self {
        match error {
            SmbAuthenticationAuthorityError::Unavailable => Self::Unavailable,
            SmbAuthenticationAuthorityError::Failed => Self::State,
        }
    }
}

impl SmbAuthenticationAuthority for AuthoritativeRepository {
    fn smb_verification_materials(
        &self,
        user_name: &RecordName,
        now: UnixMicros,
    ) -> Result<Vec<SmbVerificationMaterial>, SmbAuthenticationAuthorityError> {
        self.smb_verification_materials(user_name, now)
            .map_err(|error| map_repository_error(&error))
    }
}

impl SmbAuthenticationAuthority for crate::ConsensusAuthenticationAuthority {
    fn smb_verification_materials(
        &self,
        user_name: &RecordName,
        now: UnixMicros,
    ) -> Result<Vec<SmbVerificationMaterial>, SmbAuthenticationAuthorityError> {
        self.reader()
            .smb_verification_materials(user_name, now)
            .map_err(|error| map_repository_error(&error))
    }
}

fn map_repository_error(error: &RepositoryError) -> SmbAuthenticationAuthorityError {
    if matches!(
        error,
        RepositoryError::Store(_)
            | RepositoryError::Sqlite(_)
            | RepositoryError::Io(_)
            | RepositoryError::CapacityExceeded
    ) {
        SmbAuthenticationAuthorityError::Unavailable
    } else {
        SmbAuthenticationAuthorityError::Failed
    }
}

#[cfg(test)]
mod tests {
    use meshspan_domain::{ApiKeyId, AuthenticationMethodId, PrincipalId, Revision, UnixMicros};
    use meshspan_metadata::{RecordName, SmbVerificationMaterial};
    use meshspan_smb::{
        EncryptionCipher, NtlmAuthenticate, NtlmChallenge, NtlmChallengeConfig, NtlmNegotiate,
        NtlmPasswordVerifier, Smb311PreauthHash,
    };

    use super::{
        SmbAuthenticationAuthority, SmbAuthenticationAuthorityError, SmbAuthenticationService,
        SmbVerifierKeySource,
    };
    use crate::{SmbVerifierBinding, SmbVerifierCipher, SmbVerifierEnvelopeKey};

    #[test]
    fn official_ntlm_proof_resolves_shared_user_and_historical_root_generation()
    -> Result<(), Box<dyn std::error::Error>> {
        let binding = binding()?;
        let cipher = SmbVerifierCipher::new(key()?, 7)?;
        let ciphertext =
            cipher.encrypt(binding, &NtlmPasswordVerifier::derive("Password")?, [8; 32])?;
        let service = SmbAuthenticationService::new(
            FakeAuthority {
                material: material(binding, ciphertext),
            },
            FakeKeys,
        );
        let negotiate = NtlmNegotiate::parse(&negotiate_message())?;
        let challenge = NtlmChallenge::encode(
            negotiate,
            NtlmChallengeConfig {
                server_challenge: hex8("0123456789abcdef"),
                computer_name: "Server",
                domain_name: "Domain",
                dns_computer_name: None,
                dns_domain_name: None,
            },
        )?;
        let message = authenticate_message();
        let authenticate = NtlmAuthenticate::parse(&message, &challenge)?;
        let authenticated = service.authenticate(&authenticate, &challenge, UnixMicros::new(10))?;
        assert_eq!(authenticated.identity().principal_id, binding.principal_id);
        let mut preauth = Smb311PreauthHash::new();
        preauth.update(b"exact negotiate and session transcript");
        let (identity, keys, credential) =
            authenticated.into_session_keys(&preauth, EncryptionCipher::Aes128Gcm)?;
        assert_eq!(identity.method_id, binding.method_id);
        assert_eq!(credential.digest(), [8; 32]);
        assert_eq!(keys.signing_key().len(), 16);
        assert_eq!(keys.outgoing_encryption_key().len(), 16);
        Ok(())
    }

    struct FakeAuthority {
        material: SmbVerificationMaterial,
    }

    impl SmbAuthenticationAuthority for FakeAuthority {
        fn smb_verification_materials(
            &self,
            user_name: &RecordName,
            _now: UnixMicros,
        ) -> Result<Vec<SmbVerificationMaterial>, SmbAuthenticationAuthorityError> {
            if user_name.canonical() == "user" {
                Ok(vec![self.material.clone()])
            } else {
                Ok(Vec::new())
            }
        }
    }

    struct FakeKeys;

    impl SmbVerifierKeySource for FakeKeys {
        fn smb_verifier_key(
            &self,
            generation: u64,
        ) -> Result<SmbVerifierEnvelopeKey, super::SmbAuthenticationError> {
            if generation != 7 {
                return Err(super::SmbAuthenticationError::State);
            }
            key().map_err(|_| super::SmbAuthenticationError::State)
        }
    }

    fn key() -> Result<SmbVerifierEnvelopeKey, crate::SmbVerifierSecretError> {
        SmbVerifierEnvelopeKey::from_parts([1; 32], [2; 32])
    }

    fn binding() -> Result<SmbVerifierBinding, meshspan_domain::IdentifierError> {
        Ok(SmbVerifierBinding {
            method_id: AuthenticationMethodId::from_bytes([3; 16])?,
            principal_id: PrincipalId::from_bytes([4; 16])?,
            key_id: ApiKeyId::from_bytes([5; 16])?,
            service_scope: 7,
            scopes: 7,
        })
    }

    fn material(binding: SmbVerifierBinding, ciphertext: Vec<u8>) -> SmbVerificationMaterial {
        SmbVerificationMaterial {
            principal_id: binding.principal_id,
            method_id: binding.method_id,
            key_id: binding.key_id,
            service_scope: binding.service_scope,
            scopes: binding.scopes,
            credential_generation: 1,
            revision: Revision::new(1),
            verifier_ciphertext: ciphertext,
        }
    }

    fn negotiate_message() -> Vec<u8> {
        let mut message = vec![0; 32];
        message[..8].copy_from_slice(b"NTLMSSP\0");
        message[8..12].copy_from_slice(&1_u32.to_le_bytes());
        message[12..16].copy_from_slice(&0x008a_8205_u32.to_le_bytes());
        message
    }

    fn authenticate_message() -> Vec<u8> {
        let mut response = Vec::from(hex16("68cd0ab851e51c96aabc927bebef6a1c"));
        let mut client = vec![1, 1, 0, 0, 0, 0, 0, 0];
        client.extend_from_slice(&[0; 8]);
        client.extend_from_slice(&[0xaa; 8]);
        client.extend_from_slice(&[0; 4]);
        append_av_pair(&mut client, 2, "Domain");
        append_av_pair(&mut client, 1, "Server");
        client.extend_from_slice(&[0; 8]);
        response.extend_from_slice(&client);

        let domain = utf16("Domain");
        let user = utf16("User");
        let mut message = vec![0; 64];
        message[..8].copy_from_slice(b"NTLMSSP\0");
        message[8..12].copy_from_slice(&3_u32.to_le_bytes());
        let domain_offset = 64;
        let user_offset = domain_offset + domain.len();
        let response_offset = user_offset + user.len();
        set_buffer(&mut message, 28, domain.len(), domain_offset);
        set_buffer(&mut message, 36, user.len(), user_offset);
        set_buffer(&mut message, 20, response.len(), response_offset);
        message[60..64].copy_from_slice(&0x008a_8205_u32.to_le_bytes());
        message.extend_from_slice(&domain);
        message.extend_from_slice(&user);
        message.extend_from_slice(&response);
        message
    }

    fn set_buffer(message: &mut [u8], offset: usize, length: usize, payload_offset: usize) {
        let length = u16::try_from(length).unwrap_or_default();
        message[offset..offset + 2].copy_from_slice(&length.to_le_bytes());
        message[offset + 2..offset + 4].copy_from_slice(&length.to_le_bytes());
        message[offset + 4..offset + 8].copy_from_slice(
            &u32::try_from(payload_offset)
                .unwrap_or_default()
                .to_le_bytes(),
        );
    }

    fn append_av_pair(output: &mut Vec<u8>, identifier: u16, value: &str) {
        let encoded = utf16(value);
        output.extend_from_slice(&identifier.to_le_bytes());
        output.extend_from_slice(&(u16::try_from(encoded.len()).unwrap_or_default()).to_le_bytes());
        output.extend_from_slice(&encoded);
    }

    fn utf16(value: &str) -> Vec<u8> {
        value.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    fn hex16(value: &str) -> [u8; 16] {
        decode_hex(value).try_into().unwrap_or_default()
    }

    fn hex8(value: &str) -> [u8; 8] {
        decode_hex(value).try_into().unwrap_or_default()
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let text = std::str::from_utf8(pair).unwrap_or_default();
                u8::from_str_radix(text, 16).unwrap_or_default()
            })
            .collect()
    }
}
