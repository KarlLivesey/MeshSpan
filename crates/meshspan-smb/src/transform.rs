// SPDX-License-Identifier: GPL-2.0-only

//! SMB 3.1.1 authenticated-encryption transform framing.

use aes_gcm::aead::{AeadInOut, KeyInit};

use crate::{EncryptionCipher, Smb311SessionKeys};

const TRANSFORM_HEADER_LENGTH: usize = 52;
const TRANSFORM_PROTOCOL_ID: [u8; 4] = [0xfd, b'S', b'M', b'B'];
const SMB2_PROTOCOL_ID: [u8; 4] = [0xfe, b'S', b'M', b'B'];
const SIGNATURE_OFFSET: usize = 4;
const NONCE_OFFSET: usize = 20;
const ORIGINAL_SIZE_OFFSET: usize = 36;
const FLAGS_OFFSET: usize = 42;
const SESSION_ID_OFFSET: usize = 44;
const AUTHENTICATED_DATA_OFFSET: usize = NONCE_OFFSET;
const TRANSFORM_FLAG_ENCRYPTED: u16 = 0x0001;
const MAXIMUM_DIRECT_TCP_PAYLOAD: usize = 0x00ff_ffff;
const MAXIMUM_PLAINTEXT_LENGTH: usize = MAXIMUM_DIRECT_TCP_PAYLOAD - TRANSFORM_HEADER_LENGTH;
const SMB2_HEADER_LENGTH: usize = 64;
const INNER_SESSION_ID_OFFSET: usize = 40;

/// Authenticated transform boundary for one SMB 3.1.1 session.
///
/// The encryption keys remain owned by the session-key object. Outgoing nonces
/// are generated directly from operating-system cryptographic randomness and
/// are never accepted from application callers.
pub struct Smb311Transform<'a> {
    keys: &'a Smb311SessionKeys,
    cipher: EncryptionCipher,
    session_id: u64,
}

impl<'a> Smb311Transform<'a> {
    /// Binds a negotiated cipher and non-zero session identity to its directional keys.
    ///
    /// # Errors
    ///
    /// Rejects the reserved zero session identifier or a key/cipher width mismatch.
    pub fn new(
        keys: &'a Smb311SessionKeys,
        cipher: EncryptionCipher,
        session_id: u64,
    ) -> Result<Self, SmbTransformError> {
        if session_id == 0 {
            return Err(SmbTransformError::InvalidSessionId);
        }
        validate_key_length(keys.outgoing_encryption_key(), cipher)?;
        validate_key_length(keys.incoming_decryption_key(), cipher)?;
        Ok(Self {
            keys,
            cipher,
            session_id,
        })
    }

    /// Encrypts one complete SMB2/3 packet using a fresh OS-generated nonce.
    ///
    /// # Errors
    ///
    /// Rejects malformed, oversized or session-confused plaintext and random or
    /// authenticated-encryption failures.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, SmbTransformError> {
        let mut nonce = [0; 12];
        getrandom::fill(&mut nonce).map_err(|_| SmbTransformError::RandomNonceFailed)?;
        self.encrypt_with_nonce(plaintext, nonce)
    }

    /// Authenticates and decrypts one complete SMB 3.1.1 transform packet.
    ///
    /// # Errors
    ///
    /// Rejects malformed headers, wrong sessions, size confusion, nested
    /// transforms, altered ciphertext or authenticated-encryption failures.
    pub fn decrypt(&self, packet: &[u8]) -> Result<Vec<u8>, SmbTransformError> {
        validate_transform_header(packet, self.session_id)?;
        let nonce: [u8; 12] = packet[NONCE_OFFSET..NONCE_OFFSET + 12]
            .try_into()
            .map_err(|_| SmbTransformError::Truncated)?;
        let tag = aes_gcm::Tag::try_from(
            packet
                .get(SIGNATURE_OFFSET..SIGNATURE_OFFSET + 16)
                .ok_or(SmbTransformError::Truncated)?,
        )
        .map_err(|_| SmbTransformError::Truncated)?;
        let mut plaintext = packet[TRANSFORM_HEADER_LENGTH..].to_vec();
        decrypt_payload(
            self.cipher,
            self.keys.incoming_decryption_key(),
            nonce,
            &packet[AUTHENTICATED_DATA_OFFSET..TRANSFORM_HEADER_LENGTH],
            &mut plaintext,
            &tag,
        )?;
        validate_plaintext(&plaintext, self.session_id)?;
        Ok(plaintext)
    }

    fn encrypt_with_nonce(
        &self,
        plaintext: &[u8],
        nonce: [u8; 12],
    ) -> Result<Vec<u8>, SmbTransformError> {
        self.encrypt_with_key(plaintext, nonce, self.keys.outgoing_encryption_key())
    }

    fn encrypt_with_key(
        &self,
        plaintext: &[u8],
        nonce: [u8; 12],
        key: &[u8],
    ) -> Result<Vec<u8>, SmbTransformError> {
        validate_plaintext(plaintext, self.session_id)?;
        if plaintext.len() > MAXIMUM_PLAINTEXT_LENGTH {
            return Err(SmbTransformError::MessageTooLarge);
        }
        let original_size =
            u32::try_from(plaintext.len()).map_err(|_| SmbTransformError::MessageTooLarge)?;
        let mut packet = vec![0; TRANSFORM_HEADER_LENGTH];
        packet[..4].copy_from_slice(&TRANSFORM_PROTOCOL_ID);
        packet[NONCE_OFFSET..NONCE_OFFSET + 12].copy_from_slice(&nonce);
        packet[ORIGINAL_SIZE_OFFSET..ORIGINAL_SIZE_OFFSET + 4]
            .copy_from_slice(&original_size.to_le_bytes());
        packet[FLAGS_OFFSET..FLAGS_OFFSET + 2]
            .copy_from_slice(&TRANSFORM_FLAG_ENCRYPTED.to_le_bytes());
        packet[SESSION_ID_OFFSET..TRANSFORM_HEADER_LENGTH]
            .copy_from_slice(&self.session_id.to_le_bytes());
        let mut ciphertext = plaintext.to_vec();
        let signature = encrypt_payload(
            self.cipher,
            key,
            nonce,
            &packet[AUTHENTICATED_DATA_OFFSET..TRANSFORM_HEADER_LENGTH],
            &mut ciphertext,
        )?;
        packet[SIGNATURE_OFFSET..SIGNATURE_OFFSET + 16].copy_from_slice(&signature);
        packet.extend_from_slice(&ciphertext);
        Ok(packet)
    }
}

fn encrypt_payload(
    cipher: EncryptionCipher,
    key: &[u8],
    nonce: [u8; 12],
    authenticated_data: &[u8],
    payload: &mut [u8],
) -> Result<[u8; 16], SmbTransformError> {
    match cipher {
        EncryptionCipher::Aes128Gcm => aes_gcm::Aes128Gcm::new_from_slice(key)
            .map_err(|_| SmbTransformError::InvalidKey)?
            .encrypt_inout_detached(&nonce.into(), authenticated_data, payload.into())
            .map(Into::into)
            .map_err(|_| SmbTransformError::EncryptionFailed),
        EncryptionCipher::Aes256Gcm => aes_gcm::Aes256Gcm::new_from_slice(key)
            .map_err(|_| SmbTransformError::InvalidKey)?
            .encrypt_inout_detached(&nonce.into(), authenticated_data, payload.into())
            .map(Into::into)
            .map_err(|_| SmbTransformError::EncryptionFailed),
    }
}

fn decrypt_payload(
    cipher: EncryptionCipher,
    key: &[u8],
    nonce: [u8; 12],
    authenticated_data: &[u8],
    payload: &mut [u8],
    tag: &aes_gcm::Tag,
) -> Result<(), SmbTransformError> {
    match cipher {
        EncryptionCipher::Aes128Gcm => aes_gcm::Aes128Gcm::new_from_slice(key)
            .map_err(|_| SmbTransformError::InvalidKey)?
            .decrypt_inout_detached(&nonce.into(), authenticated_data, payload.into(), tag)
            .map_err(|_| SmbTransformError::AuthenticationFailed),
        EncryptionCipher::Aes256Gcm => aes_gcm::Aes256Gcm::new_from_slice(key)
            .map_err(|_| SmbTransformError::InvalidKey)?
            .decrypt_inout_detached(&nonce.into(), authenticated_data, payload.into(), tag)
            .map_err(|_| SmbTransformError::AuthenticationFailed),
    }
}

fn validate_transform_header(packet: &[u8], session_id: u64) -> Result<(), SmbTransformError> {
    if packet.len() <= TRANSFORM_HEADER_LENGTH || packet.len() > MAXIMUM_DIRECT_TCP_PAYLOAD {
        return Err(if packet.len() <= TRANSFORM_HEADER_LENGTH {
            SmbTransformError::Truncated
        } else {
            SmbTransformError::MessageTooLarge
        });
    }
    if packet[..4] != TRANSFORM_PROTOCOL_ID {
        return Err(SmbTransformError::InvalidProtocol);
    }
    if packet[NONCE_OFFSET + 12..NONCE_OFFSET + 16]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(SmbTransformError::InvalidNonce);
    }
    if read_u16(packet, FLAGS_OFFSET)? != TRANSFORM_FLAG_ENCRYPTED {
        return Err(SmbTransformError::InvalidFlags);
    }
    if read_u64(packet, SESSION_ID_OFFSET)? != session_id {
        return Err(SmbTransformError::SessionMismatch);
    }
    let original_size = usize::try_from(read_u32(packet, ORIGINAL_SIZE_OFFSET)?)
        .map_err(|_| SmbTransformError::MessageTooLarge)?;
    if original_size != packet.len() - TRANSFORM_HEADER_LENGTH {
        return Err(SmbTransformError::SizeMismatch);
    }
    Ok(())
}

fn validate_plaintext(plaintext: &[u8], session_id: u64) -> Result<(), SmbTransformError> {
    if plaintext.len() < SMB2_HEADER_LENGTH {
        return Err(SmbTransformError::InvalidPlaintext);
    }
    if plaintext[..4] != SMB2_PROTOCOL_ID {
        return Err(SmbTransformError::NestedTransform);
    }
    if read_u64(plaintext, INNER_SESSION_ID_OFFSET)? != session_id {
        return Err(SmbTransformError::SessionMismatch);
    }
    Ok(())
}

fn validate_key_length(key: &[u8], cipher: EncryptionCipher) -> Result<(), SmbTransformError> {
    let required = match cipher {
        EncryptionCipher::Aes128Gcm => 16,
        EncryptionCipher::Aes256Gcm => 32,
    };
    if key.len() == required {
        Ok(())
    } else {
        Err(SmbTransformError::InvalidKey)
    }
}

fn read_u16(packet: &[u8], offset: usize) -> Result<u16, SmbTransformError> {
    packet
        .get(offset..offset + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(SmbTransformError::Truncated)
}

fn read_u32(packet: &[u8], offset: usize) -> Result<u32, SmbTransformError> {
    packet
        .get(offset..offset + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(SmbTransformError::Truncated)
}

fn read_u64(packet: &[u8], offset: usize) -> Result<u64, SmbTransformError> {
    packet
        .get(offset..offset + 8)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(SmbTransformError::Truncated)
}

/// SMB 3.1.1 transform framing or authenticated-encryption failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SmbTransformError {
    /// Session zero is reserved for packets without an established session.
    #[error("SMB encrypted transform session identifier is invalid")]
    InvalidSessionId,
    /// A complete transform header and ciphertext are absent.
    #[error("SMB encrypted transform is truncated")]
    Truncated,
    /// The packet is not an SMB encrypted transform.
    #[error("SMB encrypted transform protocol identifier is invalid")]
    InvalidProtocol,
    /// The four reserved GCM nonce bytes were non-zero.
    #[error("SMB encrypted transform nonce is invalid")]
    InvalidNonce,
    /// The transform is not marked with the SMB 3.1.1 encrypted flag.
    #[error("SMB encrypted transform flags are invalid")]
    InvalidFlags,
    /// The transform or plaintext belongs to a different authenticated session.
    #[error("SMB encrypted transform session does not match")]
    SessionMismatch,
    /// The declared plaintext size does not match the ciphertext length.
    #[error("SMB encrypted transform size does not match")]
    SizeMismatch,
    /// The complete transform cannot fit the Direct TCP wire limit.
    #[error("SMB encrypted transform exceeds the wire limit")]
    MessageTooLarge,
    /// The plaintext is not a complete SMB2/3 packet.
    #[error("SMB encrypted transform plaintext is invalid")]
    InvalidPlaintext,
    /// Nested encryption or unsupported compression was detected after decryption.
    #[error("nested SMB transform is forbidden")]
    NestedTransform,
    /// The directional key does not match the negotiated cipher width.
    #[error("SMB encrypted transform key is invalid")]
    InvalidKey,
    /// Operating-system randomness could not produce a fresh nonce.
    #[error("SMB encrypted transform nonce generation failed")]
    RandomNonceFailed,
    /// Authenticated encryption failed before transmission.
    #[error("SMB encrypted transform encryption failed")]
    EncryptionFailed,
    /// Ciphertext or authenticated header data did not verify.
    #[error("SMB encrypted transform authentication failed")]
    AuthenticationFailed,
}

#[cfg(test)]
mod tests {
    use crate::{
        EncryptionCipher, NtlmPasswordVerifier, NtlmVerificationError, Smb311PreauthHash,
        Smb311SessionKeys,
    };

    use super::{Smb311Transform, SmbTransformError};

    #[test]
    fn aes128_transform_matches_fixed_wire_and_rejects_tampering()
    -> Result<(), Box<dyn std::error::Error>> {
        let keys = session_keys(EncryptionCipher::Aes128Gcm)?;
        let transform = Smb311Transform::new(&keys, EncryptionCipher::Aes128Gcm, 9)?;
        let encrypted = transform.encrypt_with_nonce(&plaintext(), [0x33; 12])?;
        assert_eq!(encrypted.len(), 132);
        assert_eq!(&encrypted[..4], &[0xfd, b'S', b'M', b'B']);
        assert_eq!(
            &encrypted[4..20],
            &hex16("7921d6a65445e6717f539835d2925285")
        );
        assert_eq!(&encrypted[20..32], &[0x33; 12]);
        assert_eq!(&encrypted[32..36], &[0; 4]);
        assert_eq!(
            &encrypted[52..],
            decode_hex(
                "803853b063477598e63c745e96e1fcafd50c3acaf9b1136daa9c6e8a4ab95f7262b12b725480abf69b4c5c02a26fdb2af52bb43e2cf8010a1546de299c636bfb7f87f416e559aa813acef0974a6e3087"
            )
        );

        let request =
            transform.encrypt_with_key(&plaintext(), [0x44; 12], keys.incoming_decryption_key())?;
        assert_eq!(transform.decrypt(&request)?, plaintext());

        let mut changed = request;
        changed[70] ^= 1;
        assert_eq!(
            transform.decrypt(&changed),
            Err(SmbTransformError::AuthenticationFailed)
        );
        Ok(())
    }

    #[test]
    fn header_size_session_and_nested_transform_fail_before_dispatch()
    -> Result<(), Box<dyn std::error::Error>> {
        let keys = session_keys(EncryptionCipher::Aes256Gcm)?;
        let transform = Smb311Transform::new(&keys, EncryptionCipher::Aes256Gcm, 9)?;
        let encrypted =
            transform.encrypt_with_key(&plaintext(), [0x44; 12], keys.incoming_decryption_key())?;

        let mut wrong_size = encrypted.clone();
        wrong_size[36] ^= 1;
        assert_eq!(
            transform.decrypt(&wrong_size),
            Err(SmbTransformError::SizeMismatch)
        );
        let wrong_session = Smb311Transform::new(&keys, EncryptionCipher::Aes256Gcm, 10)?;
        assert_eq!(
            wrong_session.decrypt(&encrypted),
            Err(SmbTransformError::SessionMismatch)
        );
        let mut nested = plaintext();
        nested[..4].copy_from_slice(&[0xfd, b'S', b'M', b'B']);
        assert_eq!(
            transform.encrypt_with_nonce(&nested, [1; 12]),
            Err(SmbTransformError::NestedTransform)
        );
        Ok(())
    }

    fn session_keys(
        cipher: EncryptionCipher,
    ) -> Result<Smb311SessionKeys, Box<dyn std::error::Error>> {
        let verifier = NtlmPasswordVerifier::derive("Password")?;
        let session = microsoft_ntlm_session_key(&verifier)?;
        let mut transcript = Smb311PreauthHash::new();
        transcript.update(b"complete SMB transcript");
        Ok(Smb311SessionKeys::derive(&session, &transcript, cipher)?)
    }

    fn microsoft_ntlm_session_key(
        verifier: &NtlmPasswordVerifier,
    ) -> Result<crate::NtlmSessionBaseKey, NtlmVerificationError> {
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

    fn plaintext() -> Vec<u8> {
        let mut packet = vec![0; 80];
        packet[..4].copy_from_slice(&[0xfe, b'S', b'M', b'B']);
        packet[4..6].copy_from_slice(&64_u16.to_le_bytes());
        packet[12..14].copy_from_slice(&0x000d_u16.to_le_bytes());
        packet[16..20].copy_from_slice(&1_u32.to_le_bytes());
        packet[24..32].copy_from_slice(&42_u64.to_le_bytes());
        packet[40..48].copy_from_slice(&9_u64.to_le_bytes());
        packet[64..].copy_from_slice(b"encrypted packet");
        packet
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
