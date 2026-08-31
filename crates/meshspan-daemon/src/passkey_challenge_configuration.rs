// SPDX-License-Identifier: GPL-2.0-only

//! Validated passkey relying-party configuration.

use meshspan_domain::DurationMicros;
use thiserror::Error;

pub(crate) const MINIMUM_LIFETIME_MICROS: u64 = 30_000_000;
pub(crate) const MAXIMUM_LIFETIME_MICROS: u64 = 600_000_000;
pub(crate) const MICROS_PER_MILLISECOND: u64 = 1_000;
const MAXIMUM_ORIGINS: usize = 16;

/// Validated relying-party settings frozen into every generated challenge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasskeyChallengeConfiguration {
    relying_party_id: String,
    allowed_origins: Vec<String>,
    lifetime: DurationMicros,
}

impl PasskeyChallengeConfiguration {
    /// Validates one simple HTTPS relying-party configuration.
    ///
    /// Each origin must be a complete HTTPS origin without a path, query, fragment or user
    /// information. Its host must equal or be a subdomain of the relying-party identifier.
    ///
    /// # Errors
    ///
    /// Rejects malformed identifiers/origins, duplicates, excess origins, or a lifetime outside
    /// the public 30-second to ten-minute range.
    pub fn new(
        relying_party_id: String,
        allowed_origins: Vec<String>,
        lifetime: DurationMicros,
    ) -> Result<Self, PasskeyChallengeConfigurationError> {
        if !valid_relying_party_id(&relying_party_id)
            || allowed_origins.is_empty()
            || allowed_origins.len() > MAXIMUM_ORIGINS
            || allowed_origins
                .iter()
                .any(|origin| !valid_origin(origin, &relying_party_id))
            || contains_duplicate(&allowed_origins)
            || !(MINIMUM_LIFETIME_MICROS..=MAXIMUM_LIFETIME_MICROS).contains(&lifetime.get())
            || !lifetime.get().is_multiple_of(MICROS_PER_MILLISECOND)
        {
            return Err(PasskeyChallengeConfigurationError);
        }
        Ok(Self {
            relying_party_id,
            allowed_origins,
            lifetime,
        })
    }

    /// Returns the exact relying-party identifier supplied to browsers.
    #[must_use]
    pub fn relying_party_id(&self) -> &str {
        &self.relying_party_id
    }

    /// Returns every exact HTTPS origin accepted for this relying party.
    #[must_use]
    pub fn allowed_origins(&self) -> &[String] {
        &self.allowed_origins
    }

    /// Returns the authoritative challenge lifetime.
    #[must_use]
    pub const fn lifetime(&self) -> DurationMicros {
        self.lifetime
    }
}

/// Invalid passkey relying-party configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("passkey challenge configuration is invalid")]
pub struct PasskeyChallengeConfigurationError;

fn valid_relying_party_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.is_ascii()
        && value.split('.').all(valid_dns_label)
}

fn valid_dns_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && label
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && label
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_origin(origin: &str, relying_party_id: &str) -> bool {
    let Some(authority) = origin.strip_prefix("https://") else {
        return false;
    };
    if authority.is_empty()
        || authority.len() > 2_048
        || authority.contains(['/', '?', '#', '@'])
        || !authority.is_ascii()
    {
        return false;
    }
    let host = match authority.rsplit_once(':') {
        Some((host, port)) => {
            if host.is_empty()
                || port.is_empty()
                || port
                    .parse::<u16>()
                    .ok()
                    .as_ref()
                    .is_none_or(|port| *port == 0)
            {
                return false;
            }
            host
        }
        None => authority,
    };
    host == relying_party_id
        || host
            .strip_suffix(relying_party_id)
            .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1)
}

fn contains_duplicate(values: &[String]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, value)| values[index + 1..].contains(value))
}
