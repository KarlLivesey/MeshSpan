// SPDX-License-Identifier: GPL-2.0-only

//! Administration history, explicitly distinct from present restore readiness.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Bounded newest-first history. Continuations preserve position, not stale authority.
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListBackupRunsQuery {
    /// Maximum records; defaults to 25.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "u16", range(min = 1, max = 100))]
    pub limit: Option<u16>,
    /// Opaque caller-bound continuation from the preceding page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(
        with = "String",
        length(min = 1, max = 256),
        pattern(r"^[a-zA-Z0-9._-]+$")
    )]
    pub cursor: Option<String>,
}

/// Recorded execution state; no variant proves present provider availability.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupRunStatus {
    /// An occurrence has been queued.
    Queued,
    /// A worker claim exists; it may need recovery after expiry.
    Claimed,
    /// Encrypted bytes and their first receipt were recorded.
    Recorded,
    /// Required protection was met at completion, not necessarily now.
    Protected,
    /// The occurrence ended without its required protection.
    Incomplete,
}

/// Historical run and the protection requirements captured when it was queued.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupRunSummary {
    /// Exact immutable backup identity.
    #[schemars(
        length(equal = 36),
        pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    )]
    pub backup_id: String,
    /// Lossless monotonic occurrence number, not wall-clock ordering.
    #[schemars(length(min = 1, max = 19), pattern(r"^[1-9][0-9]*$"))]
    pub run_sequence: String,
    /// Exact policy revision used by this occurrence.
    #[schemars(length(min = 1, max = 19), pattern(r"^[1-9][0-9]*$"))]
    pub schedule_sequence: String,
    /// Scheduled occurrence time in Unix microseconds.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub scheduled_for_epoch_micros: i64,
    /// Null until terminal; never inferred from a worker lease or timeout.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub completed_at_epoch_micros: Option<i64>,
    /// Historical execution outcome, not current safety.
    pub state: BackupRunStatus,
    /// Verified-copy requirement at queue time.
    #[schemars(range(min = 1))]
    pub minimum_verified_copies: u8,
    /// Independent-copy requirement at queue time.
    pub minimum_independent_copies: u8,
}

/// One live, newest-first page. Refresh starts at the newest occurrence.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListBackupRunsResponse {
    /// Bounded records, ordered by decreasing run sequence.
    #[schemars(length(max = 100))]
    pub runs: Vec<BackupRunSummary>,
    /// Exact relative continuation, or null at the end.
    #[schemars(
        length(max = 512),
        pattern(r"^/api/latest/admin/backups/runs\?limit=[0-9]+&cursor=[a-zA-Z0-9._-]+$")
    )]
    pub next_page_url: Option<String>,
}
