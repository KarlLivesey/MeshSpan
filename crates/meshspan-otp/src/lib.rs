// SPDX-License-Identifier: GPL-2.0-only

//! Small, bounded RFC 6238 TOTP verifier with no application or persistence dependency.

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use subtle::ConstantTimeEq;
use thiserror::Error;

const MINIMUM_SECRET_BYTES: usize = 16;
const MAXIMUM_SECRET_BYTES: usize = 128;
const MINIMUM_PERIOD_SECONDS: u16 = 15;
const MAXIMUM_PERIOD_SECONDS: u16 = 300;
const MAXIMUM_STEP_WINDOW: u8 = 10;

/// Hash algorithm used by one TOTP credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TotpAlgorithm {
    /// HMAC-SHA-1 for compatibility with the default TOTP ecosystem profile.
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-512.
    Sha512,
}

/// Validated immutable parameters for one TOTP credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TotpProfile {
    algorithm: TotpAlgorithm,
    digits: u8,
    period_seconds: u16,
    accepted_step_window: u8,
}

impl TotpProfile {
    /// Validates exact TOTP parameters before any secret or presented code is processed.
    ///
    /// # Errors
    ///
    /// Rejects unsupported digit counts, periods and excessively permissive clock windows.
    pub const fn new(
        algorithm: TotpAlgorithm,
        digits: u8,
        period_seconds: u16,
        accepted_step_window: u8,
    ) -> Result<Self, TotpError> {
        if digits < 6
            || digits > 8
            || period_seconds < MINIMUM_PERIOD_SECONDS
            || period_seconds > MAXIMUM_PERIOD_SECONDS
            || accepted_step_window > MAXIMUM_STEP_WINDOW
        {
            return Err(TotpError::InvalidConfiguration);
        }
        Ok(Self {
            algorithm,
            digits,
            period_seconds,
            accepted_step_window,
        })
    }

    /// Verifies a presented decimal code over the configured bounded time-step window.
    ///
    /// The returned time step is the exact value that replicated authority must consume
    /// monotonically to prevent replay. A well-formed but incorrect code returns `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Rejects malformed codes and secrets outside the bounded interoperability profile.
    pub fn verify(
        self,
        secret: &[u8],
        code: &str,
        unix_seconds: u64,
    ) -> Result<Option<AcceptedTotp>, TotpError> {
        validate_secret(secret)?;
        let presented = validate_code(code, self.digits)?;
        let current_step = unix_seconds / u64::from(self.period_seconds);
        let first_step = current_step.saturating_sub(u64::from(self.accepted_step_window));
        let last_step = current_step.saturating_add(u64::from(self.accepted_step_window));
        let mut accepted = None;
        for step in first_step..=last_step {
            let expected = self.code(secret, step)?;
            let matches = expected.to_be_bytes().ct_eq(&presented.to_be_bytes());
            if bool::from(matches) {
                accepted = Some(AcceptedTotp { step });
            }
        }
        Ok(accepted)
    }

    /// Verifies a code against one exact retained step without applying a freshness window.
    ///
    /// This is only for validating an idempotent replay whose step was already consumed
    /// atomically by authority. It must not be used to admit a new authentication attempt.
    ///
    /// # Errors
    ///
    /// Rejects malformed codes and secrets outside the bounded interoperability profile.
    pub fn verify_step(self, secret: &[u8], code: &str, step: u64) -> Result<bool, TotpError> {
        validate_secret(secret)?;
        let presented = validate_code(code, self.digits)?;
        let expected = self.code(secret, step)?;
        Ok(bool::from(
            expected.to_be_bytes().ct_eq(&presented.to_be_bytes()),
        ))
    }

    fn code(self, secret: &[u8], step: u64) -> Result<u32, TotpError> {
        let counter = step.to_be_bytes();
        let binary = match self.algorithm {
            TotpAlgorithm::Sha1 => dynamic_truncate(&mac::<Sha1>(secret, counter)?),
            TotpAlgorithm::Sha256 => dynamic_truncate(&mac::<Sha256>(secret, counter)?),
            TotpAlgorithm::Sha512 => dynamic_truncate(&mac::<Sha512>(secret, counter)?),
        }?;
        Ok(binary % 10_u32.pow(u32::from(self.digits)))
    }
}

/// Exact accepted TOTP time step used for authoritative replay prevention.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptedTotp {
    step: u64,
}

impl AcceptedTotp {
    /// Returns the accepted counter value derived from authoritative known time.
    #[must_use]
    pub const fn step(self) -> u64 {
        self.step
    }
}

/// Closed TOTP verification failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TotpError {
    /// Credential parameters are outside the bounded profile.
    #[error("TOTP configuration is invalid")]
    InvalidConfiguration,
    /// The presented code is not exact canonical decimal text.
    #[error("TOTP code is invalid")]
    InvalidCode,
    /// Secret length is outside the bounded profile.
    #[error("TOTP secret is invalid")]
    InvalidSecret,
    /// The selected maintained cryptographic primitive rejected the key.
    #[error("TOTP cryptographic operation failed closed")]
    Cryptographic,
}

fn validate_secret(secret: &[u8]) -> Result<(), TotpError> {
    if !(MINIMUM_SECRET_BYTES..=MAXIMUM_SECRET_BYTES).contains(&secret.len()) {
        return Err(TotpError::InvalidSecret);
    }
    Ok(())
}

fn validate_code(code: &str, digits: u8) -> Result<u32, TotpError> {
    if code.len() != usize::from(digits) || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(TotpError::InvalidCode);
    }
    code.parse().map_err(|_| TotpError::InvalidCode)
}

fn mac<D>(secret: &[u8], counter: [u8; 8]) -> Result<Vec<u8>, TotpError>
where
    D: hmac::digest::block_api::EagerHash,
{
    let mut hmac = Hmac::<D>::new_from_slice(secret).map_err(|_| TotpError::Cryptographic)?;
    hmac.update(&counter);
    Ok(hmac.finalize().into_bytes().to_vec())
}

fn dynamic_truncate(output: &[u8]) -> Result<u32, TotpError> {
    let offset = usize::from(*output.last().ok_or(TotpError::Cryptographic)? & 0x0f);
    let selected = output
        .get(offset..offset.saturating_add(4))
        .ok_or(TotpError::Cryptographic)?;
    Ok((u32::from(selected[0] & 0x7f) << 24)
        | (u32::from(selected[1]) << 16)
        | (u32::from(selected[2]) << 8)
        | u32::from(selected[3]))
}

#[cfg(test)]
mod tests {
    use super::{TotpAlgorithm, TotpError, TotpProfile};

    const SHA1_SECRET: &[u8] = b"12345678901234567890";
    const SHA256_SECRET: &[u8] = b"12345678901234567890123456789012";
    const SHA512_SECRET: &[u8] =
        b"1234567890123456789012345678901234567890123456789012345678901234";

    #[test]
    fn rfc_6238_vectors_match_every_supported_algorithm() -> Result<(), TotpError> {
        let vectors = [
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_111_111_111, "14050471", "67062674", "99943326"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ];
        for (time, sha1, sha256, sha512) in vectors {
            assert_code(TotpAlgorithm::Sha1, SHA1_SECRET, time, sha1)?;
            assert_code(TotpAlgorithm::Sha256, SHA256_SECRET, time, sha256)?;
            assert_code(TotpAlgorithm::Sha512, SHA512_SECRET, time, sha512)?;
        }
        Ok(())
    }

    #[test]
    fn verification_returns_exact_window_step_for_replay_prevention() -> Result<(), TotpError> {
        let profile = TotpProfile::new(TotpAlgorithm::Sha1, 8, 30, 1)?;
        let accepted = profile
            .verify(SHA1_SECRET, "94287082", 89)?
            .ok_or(TotpError::InvalidCode)?;
        assert_eq!(accepted.step(), 1);
        assert_eq!(profile.verify(SHA1_SECRET, "94287082", 90)?, None);
        assert!(profile.verify_step(SHA1_SECRET, "94287082", 1)?);
        assert!(!profile.verify_step(SHA1_SECRET, "94287082", 2)?);
        Ok(())
    }

    #[test]
    fn malformed_configuration_secret_and_code_fail_before_authentication() {
        assert_eq!(
            TotpProfile::new(TotpAlgorithm::Sha1, 5, 30, 1),
            Err(TotpError::InvalidConfiguration)
        );
        assert_eq!(
            TotpProfile::new(TotpAlgorithm::Sha1, 6, 14, 1),
            Err(TotpError::InvalidConfiguration)
        );
        assert_eq!(
            TotpProfile::new(TotpAlgorithm::Sha1, 6, 30, 11),
            Err(TotpError::InvalidConfiguration)
        );
        let profile = TotpProfile::new(TotpAlgorithm::Sha1, 6, 30, 1)
            .unwrap_or_else(|error| unreachable!("constant profile failed: {error}"));
        assert_eq!(
            profile.verify(&[1; 15], "123456", 0),
            Err(TotpError::InvalidSecret)
        );
        for code in ["", "12345", "1234567", "12345a", "１２３４５６"] {
            assert_eq!(
                profile.verify(SHA1_SECRET, code, 0),
                Err(TotpError::InvalidCode)
            );
        }
    }

    fn assert_code(
        algorithm: TotpAlgorithm,
        secret: &[u8],
        unix_seconds: u64,
        code: &str,
    ) -> Result<(), TotpError> {
        let accepted = TotpProfile::new(algorithm, 8, 30, 0)?
            .verify(secret, code, unix_seconds)?
            .ok_or(TotpError::InvalidCode)?;
        assert_eq!(accepted.step(), unix_seconds / 30);
        Ok(())
    }
}
