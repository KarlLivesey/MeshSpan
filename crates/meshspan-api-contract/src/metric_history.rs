// SPDX-License-Identifier: GPL-2.0-only

//! Downsampled process-local observations, not durable events or distributed telemetry.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::DiagnosticCounter;

/// Maximum encoded history page; selection is separately limited to 30 buckets.
pub const MAX_METRIC_HISTORY_BYTES: usize = 1024 * 1024;

/// Last-observation sampling interval, not a mean or an integral.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricHistoryResolution {
    /// One sample per minute, retaining six hours.
    Minute,
    /// Last minute sample in each hour, retaining seven days.
    Hour,
}

/// Exact non-negative seconds, with nanosecond precision and no floating-point coercion.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct MetricSeconds(
    #[schemars(length(max = 30), pattern(r"^(0|[1-9][0-9]{0,19})\.[0-9]{9}$"))] pub String,
);

/// Numeric representation of a fixed catalogue family. Missing families remain absent.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoricalMetricValue {
    /// Process-lifetime count; consumers must not bridge different history identities.
    Counter {
        /// Exact accumulated event count.
        value: DiagnosticCounter,
    },
    /// Unitless observed quantity.
    Gauge {
        /// Exact observed unitless quantity.
        value: DiagnosticCounter,
    },
    /// Byte count, not implicitly filesystem free space.
    Bytes {
        /// Exact observed byte quantity.
        value: DiagnosticCounter,
    },
    /// Observed duration in seconds.
    Seconds {
        /// Exact non-negative duration in seconds.
        value: MetricSeconds,
    },
    /// Process-lifetime cumulative latency histogram using the exporter bucket schema.
    Histogram {
        /// Complete count, also the implicit positive-infinity bucket.
        count: DiagnosticCounter,
        /// Exact total duration.
        sum_seconds: MetricSeconds,
        /// Inclusive counts at 0.001, 0.005, 0.025, 0.1, 0.5, 1, 5 and 30 seconds.
        #[schemars(length(equal = 8))]
        bucket_counts: Vec<DiagnosticCounter>,
    },
}

/// One existing exporter family, with no user-derived labels or identities.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalMetric {
    /// Versioned family name, excluding the counter sample's `_total` suffix.
    #[schemars(length(max = 96), pattern(r"^meshspan_v1_[a-z_]+$"))]
    pub name: String,
    /// Exact observation, not authority or health certification.
    pub measurement: HistoricalMetricValue,
}

/// Latest sampled observation in one monotonic bucket; gaps are not filled with zeros.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetricHistoryPoint {
    /// Bucket start relative to the observation store, not wall-clock ordering.
    pub bucket_start_seconds: DiagnosticCounter,
    /// Actual observation time relative to the same store.
    pub sampled_uptime_seconds: DiagnosticCounter,
    /// Host wall clock for display only; null if unavailable or outside representation.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub observed_at_epoch_micros: Option<i64>,
    /// Null means the sampling attempt failed; an empty vector is a valid empty source.
    #[schemars(length(max = 64))]
    pub metrics: Option<Vec<HistoricalMetric>>,
}

/// Newest-first bounded page. History is local, best-effort and cleared on daemon restart.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetricHistoryResponse {
    /// Random process-local history identity; not a node identity or an access credential.
    #[schemars(length(equal = 32), pattern(r"^[0-9a-f]{32}$"))]
    pub history_id: String,
    /// Selected downsampling interval.
    pub resolution: MetricHistoryResolution,
    /// Maximum retained window for this resolution, not a promise of complete observations.
    pub retention_seconds: DiagnosticCounter,
    /// Monotonic age of this process's observation store at collection.
    pub uptime_seconds: DiagnosticCounter,
    /// Whether earlier buckets have expired from the selected local window.
    pub older_samples_expired: bool,
    /// At most 30 buckets; unavailable samples and time gaps remain explicit.
    #[schemars(length(max = 30))]
    pub points: Vec<MetricHistoryPoint>,
    /// Same-gateway continuation, or null when no older retained page exists.
    #[schemars(length(max = 180), pattern(r"^/api/latest/admin/metrics/history\?resolution=(minute|hour)&history_id=[0-9a-f]{32}&before=(0|[1-9][0-9]*)$"))]
    pub next_page_url: Option<String>,
}
