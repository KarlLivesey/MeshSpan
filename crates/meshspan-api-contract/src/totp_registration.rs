// SPDX-License-Identifier: GPL-2.0-only

//! Public current-user TOTP registration ceremony models.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{AuthenticationMethodId, AuthenticationMethodLabel, OperationId};

/// Stable identity of one short-lived TOTP registration ceremony.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct TotpRegistrationChallengeId(
    #[schemars(
        length(equal = 36),
        pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    )]
    String,
);

impl TotpRegistrationChallengeId {
    /// Constructs canonical UUID text from already validated versioned UUID bytes.
    #[must_use]
    pub fn from_uuid_bytes(value: [u8; 16]) -> Option<Self> {
        let version = value[6] >> 4;
        if !(1..=8).contains(&version) || value[8] >> 6 != 2 {
            return None;
        }
        Some(Self(crate::model::format_uuid(value)))
    }

    /// Returns the canonical UUID text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// TOTP algorithm profile exposed to authenticator applications.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub enum TotpRegistrationAlgorithm {
    /// Interoperable HMAC-SHA-1 TOTP profile; SHA-1 is not used as a general digest.
    #[serde(rename = "SHA1")]
    Sha1,
}

/// One idempotent request to create TOTP registration material.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateTotpRegistrationChallengeRequest {
    /// Client-generated identity making creation exactly replayable on this gateway.
    pub operation_id: OperationId,
    /// Human-readable independently revocable method label.
    pub label: AuthenticationMethodLabel,
}

/// One exactly replayable TOTP seed presentation.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateTotpRegistrationChallengeResponse {
    /// Challenge-creation operation whose exact result this response represents.
    pub operation_id: OperationId,
    /// Stable gateway-local ceremony identity supplied with confirmation.
    pub challenge_id: TotpRegistrationChallengeId,
    /// Canonical RFC 4648 base32 seed without padding.
    #[schemars(
        length(equal = 32),
        pattern(r"^[A-Z2-7]{32}$"),
        extend("readOnly" = true),
        extend("x-meshspan-sensitive" = true)
    )]
    pub secret: String,
    /// Standard authenticator provisioning URI encoding the same seed and parameters.
    #[schemars(
        length(min = 1, max = 1_024),
        pattern(r"^otpauth://totp/[^\x00-\x20\x7f]+$"),
        extend("readOnly" = true),
        extend("x-meshspan-sensitive" = true)
    )]
    pub provisioning_uri: String,
    /// Exact algorithm used by this seed.
    pub algorithm: TotpRegistrationAlgorithm,
    /// Exact decimal code width.
    #[schemars(range(min = 6, max = 6))]
    pub digits: u8,
    /// Exact TOTP timestep in seconds.
    #[schemars(range(min = 30, max = 30))]
    pub period_seconds: u16,
    /// Exclusive ceremony expiry as epoch microseconds.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub expires_at_epoch_micros: i64,
}

/// One idempotent request confirming a newly presented TOTP seed.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateTotpRegistrationRequest {
    /// Client-generated identity binding exact confirmation retries.
    pub operation_id: OperationId,
    /// Exact short-lived registration ceremony being confirmed.
    pub challenge_id: TotpRegistrationChallengeId,
    /// Current six-digit code proving the authenticator stored the seed.
    #[schemars(
        length(equal = 6),
        pattern(r"^\d{6}$"),
        extend("writeOnly" = true)
    )]
    pub code: String,
}

/// Durable result of confirming one independently revocable TOTP method.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateTotpRegistrationResponse {
    /// Exact confirmation operation whose result was resolved.
    pub operation_id: OperationId,
    /// Newly created common authentication-method identity.
    pub method_id: AuthenticationMethodId,
    /// Authoritative creation instant as epoch microseconds.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub created_at_epoch_micros: i64,
}
