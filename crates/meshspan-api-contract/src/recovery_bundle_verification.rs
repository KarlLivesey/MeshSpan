// SPDX-License-Identifier: GPL-2.0-only

//! Public administrator proof that an exact offline recovery bundle was saved.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::OperationId;

/// One authenticated idempotent save-verification request.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfirmRecoveryBundleRequest {
    /// Client-generated idempotency identity.
    pub operation_id: OperationId,
    /// Exact mesh returned by first-mesh setup.
    #[schemars(
        length(equal = 36),
        pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    )]
    pub mesh_id: String,
    /// Short proof derived from the separately saved code and exact bundle.
    #[schemars(
        length(equal = 34),
        pattern(r"^meshspan-check-v1\.[0-9a-f]{16}$"),
        extend("x-meshspan-sensitive" = true)
    )]
    pub recovery_challenge: String,
}

/// Durable proof that the offline recovery bundle may no longer remain on the daemon.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfirmRecoveryBundleResponse {
    /// Exact operation which committed or replayed verification.
    pub operation_id: OperationId,
    /// Verified mesh.
    #[schemars(
        length(equal = 36),
        pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    )]
    pub mesh_id: String,
    /// Authoritative verification instant.
    pub verified_at_epoch_micros: i64,
    /// Authoritative revision which verified the bundle.
    #[schemars(range(min = 1))]
    pub revision: u64,
}
