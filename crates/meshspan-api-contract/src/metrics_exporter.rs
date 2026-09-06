// SPDX-License-Identifier: GPL-2.0-only

//! Explicit exporter opt-in and consumer grants, never operational measurement authority.

use crate::{OperationId, PrincipalId};

/// Maximum encoded metrics text response, shared by the `OpenAPI` contract and encoder.
pub const MAX_METRICS_EXPORT_BYTES: usize = 64 * 1024;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Complete desired metrics-export policy, without tokens or external destinations.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsExporterPolicy {
    /// Disabled by default, including before the first configuration exists.
    pub enabled: bool,
    /// Existing users permitted to scrape with current HTTPS-capable API keys.
    /// Order has no meaning; the server canonicalises it and rejects duplicate identities.
    #[schemars(length(max = 64))]
    pub allowed_principals: Vec<PrincipalId>,
}

/// Exact-retry replacement of one mesh-wide exporter configuration.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigureMetricsExporterRequest {
    /// Retained logical mutation identity.
    pub operation_id: OperationId,
    /// Zero for initial configuration; otherwise the current immutable policy sequence.
    #[schemars(range(min = 0, max = 9_007_199_254_740_990_u64))]
    pub expected_sequence: u64,
    /// Complete replacement, not a patch.
    pub policy: MetricsExporterPolicy,
}

/// Active exporter configuration, not evidence that a collector is available.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsExporterStatus {
    /// Exact active policy sequence.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub sequence: u64,
    /// Complete non-secret policy.
    pub policy: MetricsExporterPolicy,
    /// Metadata revision which committed this configuration.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub committed_revision: u64,
}

/// Current mesh policy; null explicitly means never configured and disabled.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsExporterResponse {
    /// Current configuration if explicitly committed.
    pub configuration: Option<MetricsExporterStatus>,
}

/// Original durable mutation receipt, even after a later policy supersedes it.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigureMetricsExporterResponse {
    /// Original operation identity.
    pub operation_id: OperationId,
    /// Policy sequence created by the original operation.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub sequence: u64,
    /// Metadata revision of the original operation.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub committed_revision: u64,
}
