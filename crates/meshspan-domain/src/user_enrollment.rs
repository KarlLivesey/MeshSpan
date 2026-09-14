// SPDX-License-Identifier: GPL-2.0-only

//! Short-lived first-credential capability, deliberately distinct from a login key.

use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::secret_text::{decode, encode};
use crate::{ApiKeyIssuanceKey, OperationId, PrincipalId};

const PREFIX: &str = "meshspan-user-enrollment-v1.";
const SECRET_DOMAIN: &[u8] = b"meshspan.authentication.user-enrollment-secret.v1\0";

/// Exact byte length of the canonical secret-bearing invitation.
pub const ENCODED_USER_ENROLLMENT_LENGTH: usize = PREFIX.len() + 97;

/// One first-credential invitation; it is never accepted as a login credential.
///
/// This type deliberately implements neither `Debug` nor `Display`.
pub struct UserEnrollmentBundle {
    issuance_operation_id: OperationId,
    secret: Zeroizing<[u8; 32]>,
}

impl UserEnrollmentBundle {
    /// Derives the same invitation for one authorised principal and issuance operation.
    ///
    /// # Errors
    ///
    /// Rejects invalid derived material. Authoritative consent must precede returning it.
    pub fn derive_issued(
        key: &ApiKeyIssuanceKey,
        principal_id: PrincipalId,
        issuance_operation_id: OperationId,
    ) -> Result<Self, UserEnrollmentError> {
        let secret = key
            .derive(SECRET_DOMAIN, principal_id, issuance_operation_id)
            .map_err(|_| UserEnrollmentError)?;
        Self::from_parts(issuance_operation_id, Zeroizing::new(secret))
    }

    /// Parses only this canonical invitation family, with no whitespace or alternate case.
    ///
    /// # Errors
    ///
    /// Rejects malformed, unsupported, zero or non-canonical capability material.
    pub fn parse(encoded: &str) -> Result<Self, UserEnrollmentError> {
        let (operation, secret) = decode(encoded, PREFIX).ok_or(UserEnrollmentError)?;
        let operation = OperationId::from_bytes(operation).map_err(|_| UserEnrollmentError)?;
        Self::from_parts(operation, Zeroizing::new(secret))
    }

    /// Returns the issuing operation used to locate authoritative consent.
    #[must_use]
    pub const fn issuance_operation_id(&self) -> OperationId {
        self.issuance_operation_id
    }

    /// Returns the digest persisted with the bounded consent and lifecycle record.
    #[must_use]
    pub fn secret_digest(&self) -> [u8; 32] {
        Sha256::digest(self.secret.as_ref()).into()
    }

    /// Exposes material solely at the one-time response or recipient request boundary.
    #[must_use]
    pub fn expose_encoded(&self) -> Zeroizing<String> {
        encode(PREFIX, &self.issuance_operation_id.as_bytes(), &self.secret)
    }

    fn from_parts(
        issuance_operation_id: OperationId,
        secret: Zeroizing<[u8; 32]>,
    ) -> Result<Self, UserEnrollmentError> {
        if secret.as_ref() == [0; 32] {
            return Err(UserEnrollmentError);
        }
        Ok(Self {
            issuance_operation_id,
            secret,
        })
    }
}

/// Invalid invitation material; never includes the submitted token.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("user enrollment capability is invalid")]
pub struct UserEnrollmentError;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ApiKeyBundle;

    #[test]
    fn invitations_are_exactly_replayable_and_never_login_keys()
    -> Result<(), Box<dyn std::error::Error>> {
        let key = ApiKeyIssuanceKey::from_bytes([7; 32])?;
        let principal = PrincipalId::from_bytes([8; 16])?;
        let operation = OperationId::from_bytes([9; 16])?;
        let first = UserEnrollmentBundle::derive_issued(&key, principal, operation)?;
        let replay = UserEnrollmentBundle::derive_issued(&key, principal, operation)?;
        let other = UserEnrollmentBundle::derive_issued(
            &key,
            PrincipalId::from_bytes([10; 16])?,
            operation,
        )?;
        assert_eq!(first.expose_encoded(), replay.expose_encoded());
        assert_ne!(first.secret_digest(), other.secret_digest());
        assert_eq!(first.expose_encoded().len(), ENCODED_USER_ENROLLMENT_LENGTH);
        let parsed = UserEnrollmentBundle::parse(&first.expose_encoded())?;
        assert_eq!(parsed.issuance_operation_id(), operation);
        assert_eq!(parsed.secret_digest(), first.secret_digest());
        assert!(ApiKeyBundle::parse(&first.expose_encoded()).is_err());
        let login = ApiKeyBundle::derive_issued(&key, principal, operation)?;
        assert!(UserEnrollmentBundle::parse(&login.expose_encoded()).is_err());
        assert_ne!(first.secret_digest(), login.secret_digest());
        Ok(())
    }
}
