// SPDX-License-Identifier: GPL-2.0-only

//! SMB 3.1.1 pre-authentication transcript and session-key derivation.

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

use crate::{EncryptionCipher, NtlmSessionBaseKey};

const PREAUTH_HASH_LENGTH: usize = 64;
const SIGNING_KEY_LENGTH: usize = 16;
const APPLICATION_KEY_LENGTH: usize = 16;
const AES_128_KEY_LENGTH: usize = 16;
const AES_256_KEY_LENGTH: usize = 32;
const MAXIMUM_DERIVED_KEY_LENGTH: usize = AES_256_KEY_LENGTH;

const SIGNING_LABEL: &[u8] = b"SMBSigningKey";
const APPLICATION_LABEL: &[u8] = b"SMBAppKey";
const SERVER_TO_CLIENT_LABEL: &[u8] = b"SMBS2CCipherKey";
const CLIENT_TO_SERVER_LABEL: &[u8] = b"SMBC2SCipherKey";

/// SHA-512 transcript binding the exact SMB 3.1.1 negotiate and session-setup bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct Smb311PreauthHash([u8; PREAUTH_HASH_LENGTH]);

impl Smb311PreauthHash {
    /// Creates the all-zero initial transcript value mandated by SMB 3.1.1.
    #[must_use]
    pub const fn new() -> Self {
        Self([0; PREAUTH_HASH_LENGTH])
    }

    /// Appends one exact SMB message, excluding Direct TCP framing.
    pub fn update(&mut self, message: &[u8]) {
        let mut digest = Sha512::new();
        digest.update(self.0);
        digest.update(message);
        self.0 = digest.finalize().into();
    }

    /// Exposes the non-secret transcript value for protocol diagnostics and derivation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PREAUTH_HASH_LENGTH] {
        &self.0
    }
}

impl Default for Smb311PreauthHash {
    fn default() -> Self {
        Self::new()
    }
}

/// Directional keys for one authenticated SMB 3.1.1 server session.
///
/// Encryption directions are deliberately named from the server's perspective.
/// The type implements neither `Clone`, `Debug` nor `Display` and zeroises all
/// key material on drop.
pub struct Smb311SessionKeys {
    signing: Zeroizing<[u8; SIGNING_KEY_LENGTH]>,
    application: Zeroizing<[u8; APPLICATION_KEY_LENGTH]>,
    outgoing_encryption: Zeroizing<[u8; MAXIMUM_DERIVED_KEY_LENGTH]>,
    incoming_decryption: Zeroizing<[u8; MAXIMUM_DERIVED_KEY_LENGTH]>,
    encryption_length: usize,
}

impl Smb311SessionKeys {
    /// Derives all SMB 3.1.1 keys from the authentication session key and final transcript.
    ///
    /// # Errors
    ///
    /// Fails closed if the negotiated output length or underlying PRF setup is invalid.
    pub fn derive(
        session_key: &NtlmSessionBaseKey,
        preauth_hash: &Smb311PreauthHash,
        cipher: EncryptionCipher,
    ) -> Result<Self, SmbSessionKeyError> {
        let key = session_key.expose_for_derivation();
        let context = preauth_hash.as_bytes();
        let signing = kdf::<SIGNING_KEY_LENGTH>(key, SIGNING_LABEL, context)?;
        let application = kdf::<APPLICATION_KEY_LENGTH>(key, APPLICATION_LABEL, context)?;
        let encryption_length = match cipher {
            EncryptionCipher::Aes128Gcm => AES_128_KEY_LENGTH,
            EncryptionCipher::Aes256Gcm => AES_256_KEY_LENGTH,
        };
        let outgoing_encryption =
            derive_padded_key(key, SERVER_TO_CLIENT_LABEL, context, encryption_length)?;
        let incoming_decryption =
            derive_padded_key(key, CLIENT_TO_SERVER_LABEL, context, encryption_length)?;
        Ok(Self {
            signing: Zeroizing::new(signing),
            application: Zeroizing::new(application),
            outgoing_encryption: Zeroizing::new(outgoing_encryption),
            incoming_decryption: Zeroizing::new(incoming_decryption),
            encryption_length,
        })
    }

    /// Exposes the 128-bit key only to the packet-signing boundary.
    #[must_use]
    pub fn signing_key(&self) -> &[u8; SIGNING_KEY_LENGTH] {
        &self.signing
    }

    /// Exposes the 128-bit application key only to authenticated higher-layer protocols.
    #[must_use]
    pub fn application_key(&self) -> &[u8; APPLICATION_KEY_LENGTH] {
        &self.application
    }

    /// Exposes the server-to-client key only to the SMB transform encoder.
    #[must_use]
    pub fn outgoing_encryption_key(&self) -> &[u8] {
        &self.outgoing_encryption[..self.encryption_length]
    }

    /// Exposes the client-to-server key only to the SMB transform decoder.
    #[must_use]
    pub fn incoming_decryption_key(&self) -> &[u8] {
        &self.incoming_decryption[..self.encryption_length]
    }
}

fn derive_padded_key(
    key: &[u8],
    label: &[u8],
    context: &[u8],
    output_length: usize,
) -> Result<[u8; MAXIMUM_DERIVED_KEY_LENGTH], SmbSessionKeyError> {
    let mut output = [0; MAXIMUM_DERIVED_KEY_LENGTH];
    match output_length {
        AES_128_KEY_LENGTH => {
            output[..AES_128_KEY_LENGTH]
                .copy_from_slice(&kdf::<AES_128_KEY_LENGTH>(key, label, context)?);
        }
        AES_256_KEY_LENGTH => {
            output.copy_from_slice(&kdf::<AES_256_KEY_LENGTH>(key, label, context)?);
        }
        _ => return Err(SmbSessionKeyError::InvalidOutputLength),
    }
    Ok(output)
}

fn kdf<const LENGTH: usize>(
    key: &[u8],
    label: &[u8],
    context: &[u8],
) -> Result<[u8; LENGTH], SmbSessionKeyError> {
    if LENGTH == 0 || LENGTH > MAXIMUM_DERIVED_KEY_LENGTH {
        return Err(SmbSessionKeyError::InvalidOutputLength);
    }
    let output_bits = u32::try_from(
        LENGTH
            .checked_mul(8)
            .ok_or(SmbSessionKeyError::InvalidOutputLength)?,
    )
    .map_err(|_| SmbSessionKeyError::InvalidOutputLength)?;
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key)
        .map_err(|_| SmbSessionKeyError::InvalidSessionKey)?;
    mac.update(&1_u32.to_be_bytes());
    mac.update(label);
    mac.update(&[0]);
    mac.update(context);
    mac.update(&output_bits.to_be_bytes());
    let block = mac.finalize().into_bytes();
    let mut output = [0; LENGTH];
    output.copy_from_slice(&block[..LENGTH]);
    Ok(output)
}

/// SMB 3.1.1 session-key derivation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SmbSessionKeyError {
    /// The authenticated session key cannot initialise the specified PRF.
    #[error("SMB authentication session key is invalid")]
    InvalidSessionKey,
    /// A requested key length is unsupported or cannot be encoded safely.
    #[error("SMB derived key length is invalid")]
    InvalidOutputLength,
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha512};

    use crate::{EncryptionCipher, NtlmPasswordVerifier, NtlmVerificationError};

    use super::{Smb311PreauthHash, Smb311SessionKeys};

    #[test]
    fn preauth_hash_chains_exact_messages_from_zero() {
        let mut transcript = Smb311PreauthHash::new();
        transcript.update(b"negotiate-request");
        let first = Sha512::digest([&[0_u8; 64][..], b"negotiate-request".as_slice()].concat());
        assert_eq!(transcript.as_bytes().as_slice(), first.as_slice());
        transcript.update(b"negotiate-response");
        let second = Sha512::digest([first.as_slice(), b"negotiate-response".as_slice()].concat());
        assert_eq!(transcript.as_bytes().as_slice(), second.as_slice());
        assert_eq!(
            transcript.as_bytes(),
            &hex64(
                "7ccb29a874c2786dbac47e2244e741fde2d37a9fbb12e9f1ef7c85897e3171cbf590a2d3f0f78e271e9e88dadf73f89e19f633913bed1a1bcb39d46d951c7ece"
            )
        );
    }

    #[test]
    fn derives_directional_and_domain_separated_aes128_keys()
    -> Result<(), Box<dyn std::error::Error>> {
        let session_key = microsoft_ntlm_session_key()?;
        let mut transcript = Smb311PreauthHash::new();
        transcript.update(b"complete SMB transcript");
        let keys =
            Smb311SessionKeys::derive(&session_key, &transcript, EncryptionCipher::Aes128Gcm)?;
        assert_eq!(keys.signing_key().len(), 16);
        assert_eq!(keys.application_key().len(), 16);
        assert_eq!(keys.outgoing_encryption_key().len(), 16);
        assert_eq!(keys.incoming_decryption_key().len(), 16);
        assert_eq!(
            keys.signing_key(),
            &hex16("11a46c4cc9c14599e5ab7d1a048293ca")
        );
        assert_eq!(
            keys.application_key(),
            &hex16("183b22b880fa0252bebe99e33dad7f6e")
        );
        assert_eq!(
            keys.outgoing_encryption_key(),
            &hex16("ff09715fe1199c169efe43fe9f647dcc")
        );
        assert_eq!(
            keys.incoming_decryption_key(),
            &hex16("d9de928bf980a0197b72ea35f57ed2ee")
        );
        Ok(())
    }

    #[test]
    fn aes256_selection_derives_full_width_directional_keys()
    -> Result<(), Box<dyn std::error::Error>> {
        let session_key = microsoft_ntlm_session_key()?;
        let mut transcript = Smb311PreauthHash::new();
        transcript.update(b"complete SMB transcript");
        let keys =
            Smb311SessionKeys::derive(&session_key, &transcript, EncryptionCipher::Aes256Gcm)?;
        assert_eq!(keys.outgoing_encryption_key().len(), 32);
        assert_eq!(keys.incoming_decryption_key().len(), 32);
        assert_eq!(
            keys.outgoing_encryption_key(),
            &hex32("5d0fbd5c21e0bcd5d09a4decd4dead5eec082de1375316a35a8c5f52d6f05e2d")
        );
        assert_eq!(
            keys.incoming_decryption_key(),
            &hex32("a44af7e805bd583773b616d546973df18c545a22bcbf16ab93fd9fea1510ecf2")
        );
        Ok(())
    }

    fn microsoft_ntlm_session_key() -> Result<crate::NtlmSessionBaseKey, NtlmVerificationError> {
        let verifier = NtlmPasswordVerifier::derive("Password")?;
        let mut response = Vec::from(hex16("68cd0ab851e51c96aabc927bebef6a1c"));
        let mut challenge = vec![1, 1, 0, 0, 0, 0, 0, 0];
        challenge.extend_from_slice(&[0; 8]);
        challenge.extend_from_slice(&[0xaa; 8]);
        challenge.extend_from_slice(&[0; 4]);
        append_av_pair(&mut challenge, 2, "Domain");
        append_av_pair(&mut challenge, 1, "Server");
        challenge.extend_from_slice(&[0; 8]);
        response.extend_from_slice(&challenge);
        verifier.verify_ntlm_v2("User", "Domain", hex8("0123456789abcdef"), &response)
    }

    fn append_av_pair(output: &mut Vec<u8>, identifier: u16, value: &str) {
        let encoded = value
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        output.extend_from_slice(&identifier.to_le_bytes());
        output.extend_from_slice(&(u16::try_from(encoded.len()).unwrap_or_default()).to_le_bytes());
        output.extend_from_slice(&encoded);
    }

    fn hex16(value: &str) -> [u8; 16] {
        decode_hex(value).try_into().unwrap_or_default()
    }

    fn hex32(value: &str) -> [u8; 32] {
        decode_hex(value).try_into().unwrap_or_default()
    }

    fn hex64(value: &str) -> [u8; 64] {
        decode_hex(value).try_into().unwrap_or([0; 64])
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
