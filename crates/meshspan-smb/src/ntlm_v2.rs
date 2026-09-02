// SPDX-License-Identifier: GPL-2.0-only

//! Narrow `NTLMv2` proof verification required by ordinary SMB clients.
//!
//! NTLM's legacy hashes are used only to prove possession of the same scoped
//! high-entropy API key. They never weaken the API key's canonical verifier or
//! become a separate authentication method.

use hmac::{Hmac, KeyInit, Mac};
use md4::{Digest, Md4};
use md5::Md5;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const VERIFIER_LENGTH: usize = 16;
const PROOF_LENGTH: usize = 16;
const MINIMUM_CLIENT_CHALLENGE_LENGTH: usize = 32;
const MAXIMUM_UTF16_UNITS: usize = 256;

/// Password-equivalent NTLM verifier derived from one ordinary `MeshSpan` API key.
///
/// The type deliberately implements neither `Clone`, `Debug` nor `Display` and
/// clears its bytes on drop. Persisted instances must be encrypted by the
/// replicated authentication-material protector.
pub struct NtlmPasswordVerifier(Zeroizing<[u8; VERIFIER_LENGTH]>);

impl NtlmPasswordVerifier {
    /// Derives the verifier from the exact API-key text entered as the SMB password.
    ///
    /// # Errors
    ///
    /// Rejects blank or excessively long input before allocating its UTF-16 form.
    pub fn derive(password: &str) -> Result<Self, NtlmVerificationError> {
        let encoded = utf16_le(password, MAXIMUM_UTF16_UNITS)?;
        if encoded.is_empty() {
            return Err(NtlmVerificationError::InvalidIdentity);
        }
        let digest: [u8; VERIFIER_LENGTH] = Md4::digest(&encoded).into();
        Self::from_bytes(digest)
    }

    /// Restores one decrypted non-zero verifier.
    ///
    /// # Errors
    ///
    /// Rejects the reserved all-zero value.
    pub fn from_bytes(bytes: [u8; VERIFIER_LENGTH]) -> Result<Self, NtlmVerificationError> {
        if bytes == [0; VERIFIER_LENGTH] {
            Err(NtlmVerificationError::InvalidVerifier)
        } else {
            Ok(Self(Zeroizing::new(bytes)))
        }
    }

    /// Exposes the verifier only for immediate authenticated encryption.
    #[must_use]
    pub fn expose_for_encryption(&self) -> &[u8; VERIFIER_LENGTH] {
        &self.0
    }

    /// Verifies one `NTLMv2` challenge response and derives its session base key.
    ///
    /// # Errors
    ///
    /// Rejects malformed identities, malformed client-challenge blobs or a proof
    /// that does not bind the supplied server challenge.
    pub fn verify_ntlm_v2(
        &self,
        username: &str,
        domain: &str,
        server_challenge: [u8; 8],
        nt_challenge_response: &[u8],
    ) -> Result<NtlmSessionBaseKey, NtlmVerificationError> {
        let response_key = self.response_key(username, domain)?;
        let (proof, client_challenge) = split_response(nt_challenge_response)?;
        validate_client_challenge(client_challenge)?;
        let expected = hmac_md5(&response_key, &[&server_challenge, client_challenge])?;
        if expected.ct_eq(proof).unwrap_u8() != 1 {
            return Err(NtlmVerificationError::ProofMismatch);
        }
        let session_base_key = hmac_md5(&response_key, &[proof])?;
        NtlmSessionBaseKey::from_bytes(session_base_key)
    }

    fn response_key(
        &self,
        username: &str,
        domain: &str,
    ) -> Result<[u8; VERIFIER_LENGTH], NtlmVerificationError> {
        if username.is_empty() {
            return Err(NtlmVerificationError::InvalidIdentity);
        }
        let uppercase = username.to_uppercase();
        let mut identity = utf16_le(&uppercase, MAXIMUM_UTF16_UNITS)?;
        let domain = utf16_le(domain, MAXIMUM_UTF16_UNITS)?;
        identity
            .len()
            .checked_add(domain.len())
            .filter(|length| *length <= MAXIMUM_UTF16_UNITS * 4)
            .ok_or(NtlmVerificationError::InvalidIdentity)?;
        identity.extend_from_slice(&domain);
        hmac_md5(self.0.as_ref(), &[&identity])
    }
}

/// Secret NTLM session base key from which SMB 3.1.1 session keys are derived.
///
/// The type deliberately exposes bytes only to the session-key derivation boundary.
pub struct NtlmSessionBaseKey(Zeroizing<[u8; VERIFIER_LENGTH]>);

impl NtlmSessionBaseKey {
    fn from_bytes(bytes: [u8; VERIFIER_LENGTH]) -> Result<Self, NtlmVerificationError> {
        if bytes == [0; VERIFIER_LENGTH] {
            Err(NtlmVerificationError::InvalidSessionKey)
        } else {
            Ok(Self(Zeroizing::new(bytes)))
        }
    }

    /// Exposes the key only for immediate SMB session-key derivation.
    #[must_use]
    pub fn expose_for_derivation(&self) -> &[u8; VERIFIER_LENGTH] {
        &self.0
    }
}

fn split_response(response: &[u8]) -> Result<(&[u8; 16], &[u8]), NtlmVerificationError> {
    let proof = response
        .get(..PROOF_LENGTH)
        .ok_or(NtlmVerificationError::InvalidResponse)?
        .try_into()
        .map_err(|_| NtlmVerificationError::InvalidResponse)?;
    let client_challenge = response
        .get(PROOF_LENGTH..)
        .filter(|challenge| challenge.len() >= MINIMUM_CLIENT_CHALLENGE_LENGTH)
        .ok_or(NtlmVerificationError::InvalidResponse)?;
    Ok((proof, client_challenge))
}

fn validate_client_challenge(challenge: &[u8]) -> Result<(), NtlmVerificationError> {
    if challenge[0] != 1
        || challenge[1] != 1
        || challenge[2..8].iter().any(|byte| *byte != 0)
        || challenge[24..28].iter().any(|byte| *byte != 0)
        || challenge[challenge.len() - 4..]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(NtlmVerificationError::InvalidResponse);
    }
    Ok(())
}

fn utf16_le(value: &str, maximum_units: usize) -> Result<Vec<u8>, NtlmVerificationError> {
    let units = value.encode_utf16().collect::<Vec<_>>();
    if units.len() > maximum_units {
        return Err(NtlmVerificationError::InvalidIdentity);
    }
    let mut encoded = Vec::with_capacity(units.len() * 2);
    for unit in units {
        encoded.extend_from_slice(&unit.to_le_bytes());
    }
    Ok(encoded)
}

fn hmac_md5(key: &[u8], messages: &[&[u8]]) -> Result<[u8; 16], NtlmVerificationError> {
    let mut mac = <Hmac<Md5> as KeyInit>::new_from_slice(key)
        .map_err(|_| NtlmVerificationError::InvalidVerifier)?;
    for message in messages {
        mac.update(message);
    }
    Ok(mac.finalize().into_bytes().into())
}

/// `NTLMv2` verifier or proof failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NtlmVerificationError {
    /// Username, domain or API-key text violates the bounded string contract.
    #[error("NTLM identity input is invalid")]
    InvalidIdentity,
    /// Decrypted verifier material is reserved or malformed.
    #[error("NTLM verifier is invalid")]
    InvalidVerifier,
    /// The NT challenge response is truncated or structurally invalid.
    #[error("NTLMv2 challenge response is invalid")]
    InvalidResponse,
    /// The response does not prove possession of this API key.
    #[error("NTLMv2 proof does not match")]
    ProofMismatch,
    /// The derived session key used a reserved value.
    #[error("NTLMv2 session key is invalid")]
    InvalidSessionKey,
}

#[cfg(test)]
mod tests {
    use super::{NtlmPasswordVerifier, NtlmVerificationError};

    #[test]
    fn microsoft_ntlmv2_vector_derives_and_verifies_exactly() -> Result<(), NtlmVerificationError> {
        let verifier = NtlmPasswordVerifier::derive("Password")?;
        assert_eq!(
            verifier.expose_for_encryption(),
            &hex16("a4f49c406510bdcab6824ee7c30fd852")
        );
        let mut response = Vec::from(hex16("68cd0ab851e51c96aabc927bebef6a1c"));
        response.extend_from_slice(&microsoft_client_challenge());
        let session =
            verifier.verify_ntlm_v2("User", "Domain", hex8("0123456789abcdef"), &response)?;
        assert_eq!(
            session.expose_for_derivation(),
            &hex16("8de40ccadbc14a82f15cb0ad0de95ca3")
        );
        Ok(())
    }

    #[test]
    fn changed_challenge_proof_and_shape_fail_closed() -> Result<(), NtlmVerificationError> {
        let verifier = NtlmPasswordVerifier::derive("Password")?;
        let mut response = Vec::from(hex16("68cd0ab851e51c96aabc927bebef6a1c"));
        response.extend_from_slice(&microsoft_client_challenge());
        assert!(matches!(
            verifier.verify_ntlm_v2("User", "Domain", [0; 8], &response),
            Err(NtlmVerificationError::ProofMismatch)
        ));
        response[16] = 2;
        assert!(matches!(
            verifier.verify_ntlm_v2("User", "Domain", hex8("0123456789abcdef"), &response),
            Err(NtlmVerificationError::InvalidResponse)
        ));
        Ok(())
    }

    fn microsoft_client_challenge() -> Vec<u8> {
        let mut challenge = vec![1, 1, 0, 0, 0, 0, 0, 0];
        challenge.extend_from_slice(&[0; 8]);
        challenge.extend_from_slice(&[0xaa; 8]);
        challenge.extend_from_slice(&[0; 4]);
        append_av_pair(&mut challenge, 2, "Domain");
        append_av_pair(&mut challenge, 1, "Server");
        challenge.extend_from_slice(&[0; 8]);
        challenge
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
