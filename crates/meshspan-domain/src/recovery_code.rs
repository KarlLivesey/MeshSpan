// SPDX-License-Identifier: GPL-2.0-only

//! Canonical high-entropy, single-use recovery-code material.

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::secret_text::{SECRET_BYTES, decode, encode};
use crate::{OperationId, PrincipalId, RecoveryCodeId};

const PREFIX: &str = "meshspan-recovery-v1.";
const CODE_ID_DOMAIN: &[u8] = b"meshspan.authentication.recovery-code-id.v1\0";
const CODE_SECRET_DOMAIN: &[u8] = b"meshspan.authentication.recovery-code-secret.v1\0";

/// Exact byte length of one canonical encoded recovery code.
pub const ENCODED_RECOVERY_CODE_LENGTH: usize = PREFIX.len() + 97;

/// Secret-bearing single-use recovery code.
///
/// The type deliberately implements neither `Debug` nor `Display`.
pub struct RecoveryCodeBundle {
    code_id: RecoveryCodeId,
    secret: Zeroizing<[u8; SECRET_BYTES]>,
}

impl RecoveryCodeBundle {
    /// Derives one exact code for an idempotent set-issuance operation.
    ///
    /// # Errors
    ///
    /// Rejects an out-of-range sequence or invalid derived material.
    pub fn derive_issued(
        issuance_key: &RecoveryCodeIssuanceKey,
        principal_id: PrincipalId,
        operation_id: OperationId,
        sequence: u8,
    ) -> Result<Self, RecoveryCodeBundleError> {
        if sequence == 0 || sequence > 32 {
            return Err(RecoveryCodeBundleError::InvalidSequence);
        }
        let mut code_id =
            issuance_key.derive(CODE_ID_DOMAIN, principal_id, operation_id, sequence)?;
        code_id[6] = (code_id[6] & 0x0f) | 0x40;
        code_id[8] = (code_id[8] & 0x3f) | 0x80;
        let secret = Zeroizing::new(issuance_key.derive(
            CODE_SECRET_DOMAIN,
            principal_id,
            operation_id,
            sequence,
        )?);
        Self::from_parts(
            code_id[..16]
                .try_into()
                .map_err(|_| RecoveryCodeBundleError::Invalid)?,
            secret,
        )
    }

    /// Parses one exact lowercase canonical recovery code.
    ///
    /// # Errors
    ///
    /// Rejects another version, whitespace, uppercase/non-hex material or zero values.
    pub fn parse(value: &str) -> Result<Self, RecoveryCodeBundleError> {
        let (code_id, secret) =
            decode(value, PREFIX).ok_or(RecoveryCodeBundleError::InvalidEncoding)?;
        Self::from_parts(code_id, Zeroizing::new(secret))
    }

    /// Returns the public identity included in the code text.
    #[must_use]
    pub const fn code_id(&self) -> RecoveryCodeId {
        self.code_id
    }

    /// Returns the verifier persisted in replicated authentication metadata.
    #[must_use]
    pub fn secret_digest(&self) -> [u8; 32] {
        Sha256::digest(self.secret.as_ref()).into()
    }

    /// Explicitly exposes the secret-bearing text for its one-time response boundary.
    #[must_use]
    pub fn expose_encoded(&self) -> Zeroizing<String> {
        encode(PREFIX, &self.code_id.as_bytes(), &self.secret)
    }

    fn from_parts(
        code_id: [u8; 16],
        secret: Zeroizing<[u8; SECRET_BYTES]>,
    ) -> Result<Self, RecoveryCodeBundleError> {
        let code_id =
            RecoveryCodeId::from_bytes(code_id).map_err(|_| RecoveryCodeBundleError::Invalid)?;
        if secret.as_ref() == [0; SECRET_BYTES] {
            return Err(RecoveryCodeBundleError::Invalid);
        }
        Ok(Self { code_id, secret })
    }
}

/// Mesh-wide non-exportable key for exactly replayable recovery-code issuance.
pub struct RecoveryCodeIssuanceKey(Zeroizing<[u8; 32]>);

impl RecoveryCodeIssuanceKey {
    /// Takes ownership of one loaded non-zero issuance key.
    ///
    /// # Errors
    ///
    /// Rejects the reserved all-zero value.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, RecoveryCodeIssuanceKeyError> {
        if bytes == [0; 32] {
            Err(RecoveryCodeIssuanceKeyError::Invalid)
        } else {
            Ok(Self(Zeroizing::new(bytes)))
        }
    }

    fn derive(
        &self,
        domain: &[u8],
        principal_id: PrincipalId,
        operation_id: OperationId,
        sequence: u8,
    ) -> Result<[u8; 32], RecoveryCodeBundleError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.0.as_ref())
            .map_err(|_| RecoveryCodeBundleError::Invalid)?;
        mac.update(domain);
        mac.update(&principal_id.as_bytes());
        mac.update(&operation_id.as_bytes());
        mac.update(&[sequence]);
        Ok(mac.finalize().into_bytes().into())
    }
}

/// Failure to load the non-exportable recovery-code issuance key.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RecoveryCodeIssuanceKeyError {
    /// The reserved zero key was supplied.
    #[error("recovery-code issuance key is invalid")]
    Invalid,
}

/// Failure to create or parse recovery-code material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RecoveryCodeBundleError {
    /// Derived values violated the non-zero contract.
    #[error("recovery-code material is invalid")]
    Invalid,
    /// Presented text was not the exact canonical recovery-code encoding.
    #[error("recovery-code encoding is invalid")]
    InvalidEncoding,
    /// The one-based set sequence was outside the supported bound.
    #[error("recovery-code sequence is invalid")]
    InvalidSequence,
}

#[cfg(test)]
mod tests {
    use super::{
        ENCODED_RECOVERY_CODE_LENGTH, RecoveryCodeBundle, RecoveryCodeBundleError,
        RecoveryCodeIssuanceKey, RecoveryCodeIssuanceKeyError,
    };
    use crate::{OperationId, PrincipalId};

    #[test]
    fn issued_codes_are_exactly_replayable_and_domain_separated()
    -> Result<(), Box<dyn std::error::Error>> {
        let key = RecoveryCodeIssuanceKey::from_bytes([7; 32])?;
        let principal = PrincipalId::from_bytes([8; 16])?;
        let operation = OperationId::from_bytes([9; 16])?;
        let first = RecoveryCodeBundle::derive_issued(&key, principal, operation, 1)?;
        let replay = RecoveryCodeBundle::derive_issued(&key, principal, operation, 1)?;
        let second = RecoveryCodeBundle::derive_issued(&key, principal, operation, 2)?;
        assert_eq!(first.expose_encoded(), replay.expose_encoded());
        assert_ne!(first.expose_encoded(), second.expose_encoded());
        assert_ne!(first.code_id(), second.code_id());
        assert_eq!(first.expose_encoded().len(), ENCODED_RECOVERY_CODE_LENGTH);
        let parsed = RecoveryCodeBundle::parse(&first.expose_encoded())?;
        assert_eq!(parsed.code_id(), first.code_id());
        assert_eq!(parsed.secret_digest(), first.secret_digest());
        Ok(())
    }

    #[test]
    fn invalid_keys_sequences_and_encodings_fail_closed() -> Result<(), Box<dyn std::error::Error>>
    {
        assert!(matches!(
            RecoveryCodeIssuanceKey::from_bytes([0; 32]),
            Err(RecoveryCodeIssuanceKeyError::Invalid)
        ));
        let key = RecoveryCodeIssuanceKey::from_bytes([7; 32])?;
        let principal = PrincipalId::from_bytes([8; 16])?;
        let operation = OperationId::from_bytes([9; 16])?;
        for sequence in [0, 33] {
            assert_eq!(
                RecoveryCodeBundle::derive_issued(&key, principal, operation, sequence).map(|_| ()),
                Err(RecoveryCodeBundleError::InvalidSequence)
            );
        }
        for value in ["", "meshspan-recovery-v2.invalid", " meshspan-recovery-v1."] {
            assert!(matches!(
                RecoveryCodeBundle::parse(value),
                Err(RecoveryCodeBundleError::InvalidEncoding)
            ));
        }
        Ok(())
    }
}
