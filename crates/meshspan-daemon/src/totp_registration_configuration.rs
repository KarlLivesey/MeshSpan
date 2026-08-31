// SPDX-License-Identifier: GPL-2.0-only

//! Validated policy for current-user TOTP registration.

use meshspan_domain::DurationMicros;
use sha2::{Digest, Sha256};
use thiserror::Error;

const MINIMUM_LIFETIME_MICROS: u64 = 30_000_000;
const MAXIMUM_LIFETIME_MICROS: u64 = 600_000_000;
const MAXIMUM_ISSUER_CHARACTERS: usize = 128;

/// Server-owned TOTP issuer and short-lived registration lifetime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TotpRegistrationConfiguration {
    issuer: String,
    lifetime: DurationMicros,
}

impl TotpRegistrationConfiguration {
    /// Validates one authenticator-visible issuer and ceremony lifetime.
    ///
    /// # Errors
    ///
    /// Rejects blank, untrimmed, control-containing or excessive issuers and lifetimes outside
    /// the public 30-second to ten-minute range.
    pub fn new(
        issuer: String,
        lifetime: DurationMicros,
    ) -> Result<Self, TotpRegistrationConfigurationError> {
        let characters = issuer.chars().count();
        if characters == 0
            || characters > MAXIMUM_ISSUER_CHARACTERS
            || issuer.trim() != issuer
            || issuer.chars().any(char::is_control)
            || !(MINIMUM_LIFETIME_MICROS..=MAXIMUM_LIFETIME_MICROS).contains(&lifetime.get())
        {
            return Err(TotpRegistrationConfigurationError);
        }
        Ok(Self { issuer, lifetime })
    }

    #[must_use]
    pub(crate) fn issuer(&self) -> &str {
        &self.issuer
    }

    #[must_use]
    pub(crate) const fn lifetime(&self) -> DurationMicros {
        self.lifetime
    }

    pub(crate) fn digest(&self) -> Result<[u8; 32], TotpRegistrationConfigurationError> {
        let mut digest = Sha256::new();
        digest.update(b"meshspan.authentication.totp-registration-configuration.v1\0");
        digest.update(
            u16::try_from(self.issuer.len())
                .map_err(|_| TotpRegistrationConfigurationError)?
                .to_be_bytes(),
        );
        digest.update(self.issuer.as_bytes());
        digest.update(self.lifetime.get().to_be_bytes());
        Ok(digest.finalize().into())
    }
}

/// Invalid TOTP-registration policy.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("TOTP registration configuration is invalid")]
pub struct TotpRegistrationConfigurationError;

#[cfg(test)]
mod tests {
    use meshspan_domain::DurationMicros;

    use super::{TotpRegistrationConfiguration, TotpRegistrationConfigurationError};

    #[test]
    fn configuration_validates_and_digests_all_policy() -> Result<(), Box<dyn std::error::Error>> {
        let configuration = TotpRegistrationConfiguration::new(
            "MeshSpan Home".to_owned(),
            DurationMicros::new(120_000_000),
        )?;
        assert_eq!(configuration.issuer(), "MeshSpan Home");
        assert_ne!(configuration.digest()?, [0; 32]);
        assert_eq!(
            TotpRegistrationConfiguration::new(
                " MeshSpan".to_owned(),
                DurationMicros::new(120_000_000),
            ),
            Err(TotpRegistrationConfigurationError)
        );
        Ok(())
    }
}
