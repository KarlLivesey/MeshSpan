// SPDX-License-Identifier: GPL-2.0-only

//! Public current-user recovery-code management models.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{AuthenticationMethodId, AuthenticationMethodLabel, OperationId};

/// Fixed initial number of independently consumable codes in one replacement set.
pub const RECOVERY_CODES_PER_SET: usize = 10;

/// One idempotent request to replace the current user's recovery-code set.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateRecoveryCodesRequest {
    /// Client-generated identity binding exact retries.
    pub operation_id: OperationId,
    /// Human-readable independently revocable method label.
    pub label: AuthenticationMethodLabel,
}

/// One exactly replayable recovery-code set returned only by its issuance operation.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateRecoveryCodesResponse {
    /// Exact idempotency identity whose committed result was resolved.
    pub operation_id: OperationId,
    /// Independently revocable common authentication-method identity.
    pub method_id: AuthenticationMethodId,
    /// Ten independent, single-use secret-bearing recovery codes.
    #[schemars(length(equal = 10))]
    pub codes: Vec<RecoveryCode>,
    /// Authoritative creation instant as epoch microseconds.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub created_at_epoch_micros: i64,
}

/// One canonical secret-bearing recovery code.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RecoveryCode(
    #[schemars(
        length(equal = 118),
        pattern(r"^meshspan-recovery-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$"),
        extend("readOnly" = true),
        extend("x-meshspan-sensitive" = true)
    )]
    String,
);

impl RecoveryCode {
    /// Constructs a response value after domain-level canonical material validation.
    #[must_use]
    pub fn from_canonical(value: String) -> Self {
        Self(value)
    }

    /// Returns the secret only to the one-time response encoder.
    #[must_use]
    pub fn expose_for_delivery(&self) -> &str {
        &self.0
    }
}
