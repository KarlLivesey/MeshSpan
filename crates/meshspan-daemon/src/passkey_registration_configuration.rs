// SPDX-License-Identifier: GPL-2.0-only

//! Validated relying-party policy for current-user passkey registration.

use meshspan_domain::DurationMicros;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{PasskeyChallengeConfiguration, PasskeyChallengeConfigurationError};

const MAXIMUM_RELYING_PARTY_NAME_CHARACTERS: usize = 128;

/// Registration-specific relying-party settings composed over common challenge policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasskeyRegistrationConfiguration {
    common: PasskeyChallengeConfiguration,
    relying_party_name: String,
}

impl PasskeyRegistrationConfiguration {
    /// Validates one HTTPS relying party and its authenticator-visible display name.
    ///
    /// # Errors
    ///
    /// Rejects malformed common challenge policy or a blank, untrimmed, control-containing or
    /// excessive display name.
    pub fn new(
        relying_party_id: String,
        relying_party_name: String,
        allowed_origins: Vec<String>,
        lifetime: DurationMicros,
    ) -> Result<Self, PasskeyRegistrationConfigurationError> {
        let common =
            PasskeyChallengeConfiguration::new(relying_party_id, allowed_origins, lifetime)?;
        let characters = relying_party_name.chars().count();
        if characters == 0
            || characters > MAXIMUM_RELYING_PARTY_NAME_CHARACTERS
            || relying_party_name.trim() != relying_party_name
            || relying_party_name.chars().any(char::is_control)
        {
            return Err(PasskeyRegistrationConfigurationError);
        }
        Ok(Self {
            common,
            relying_party_name,
        })
    }

    #[must_use]
    pub(crate) fn relying_party_id(&self) -> &str {
        self.common.relying_party_id()
    }

    #[must_use]
    pub(crate) fn relying_party_name(&self) -> &str {
        &self.relying_party_name
    }

    #[must_use]
    pub(crate) fn allowed_origins(&self) -> &[String] {
        self.common.allowed_origins()
    }

    #[must_use]
    pub(crate) const fn lifetime(&self) -> DurationMicros {
        self.common.lifetime()
    }

    pub(crate) fn digest(&self) -> Result<[u8; 32], PasskeyRegistrationConfigurationError> {
        let mut digest = Sha256::new();
        digest.update(b"meshspan.authentication.passkey-registration-configuration.v1\0");
        digest.update(self.common.digest()?);
        digest.update(
            u16::try_from(self.relying_party_name.len())
                .map_err(|_| PasskeyRegistrationConfigurationError)?
                .to_be_bytes(),
        );
        digest.update(self.relying_party_name.as_bytes());
        Ok(digest.finalize().into())
    }
}

/// Invalid passkey-registration relying-party configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("passkey registration configuration is invalid")]
pub struct PasskeyRegistrationConfigurationError;

impl From<PasskeyChallengeConfigurationError> for PasskeyRegistrationConfigurationError {
    fn from(_: PasskeyChallengeConfigurationError) -> Self {
        Self
    }
}

#[cfg(test)]
mod tests {
    use meshspan_domain::DurationMicros;

    use super::{PasskeyRegistrationConfiguration, PasskeyRegistrationConfigurationError};

    #[test]
    fn registration_configuration_validates_and_digests_all_public_policy()
    -> Result<(), Box<dyn std::error::Error>> {
        let configuration = PasskeyRegistrationConfiguration::new(
            "mesh.example".to_owned(),
            "MeshSpan".to_owned(),
            vec!["https://mesh.example".to_owned()],
            DurationMicros::new(120_000_000),
        )?;
        assert_eq!(configuration.relying_party_id(), "mesh.example");
        assert_eq!(configuration.relying_party_name(), "MeshSpan");
        assert_ne!(configuration.digest()?, [0; 32]);
        assert_eq!(
            PasskeyRegistrationConfiguration::new(
                "mesh.example".to_owned(),
                " MeshSpan".to_owned(),
                vec!["https://mesh.example".to_owned()],
                DurationMicros::new(120_000_000),
            ),
            Err(PasskeyRegistrationConfigurationError)
        );
        Ok(())
    }
}
