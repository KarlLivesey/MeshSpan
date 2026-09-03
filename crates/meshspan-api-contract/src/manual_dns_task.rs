// SPDX-License-Identifier: GPL-2.0-only

//! Public manager-only manual DNS challenge task inventory.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Opaque continuation for the deadline-ordered manual DNS task queue.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ManualDnsTaskCursor(
    #[schemars(length(min = 1, max = 256), pattern(r"^[A-Za-z0-9._~-]+$"))] String,
);

impl ManualDnsTaskCursor {
    /// Constructs a cursor after public alphabet and length validation.
    #[must_use]
    pub fn from_encoded(value: String) -> Option<Self> {
        ((1..=256).contains(&value.len())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._~-".contains(&byte)))
        .then_some(Self(value))
    }

    /// Returns the opaque cursor text for server-side decoding.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Bounded administrator query for actionable manual DNS work.
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListManualDnsTasksQuery {
    /// Exact continuation returned by the preceding page.
    pub cursor: Option<ManualDnsTaskCursor>,
    /// Requested page size; omission applies the server default.
    #[schemars(range(min = 1, max = 200))]
    pub limit: Option<u16>,
}

/// Action an administrator must perform for one exact fenced TXT record.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManualDnsTaskAction {
    /// Publish the exact TXT owner and value.
    Publish,
    /// Remove only the exact TXT owner and value after issuance.
    Remove,
}

/// One durable, currently actionable manual DNS task.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManualDnsTaskSummary {
    /// Lower-case SHA-256 identity of this exact fenced task.
    #[schemars(length(equal = 64), pattern(r"^[0-9a-f]{64}$"))]
    pub task_digest: String,
    /// Certificate order owning the task.
    #[schemars(
        length(equal = 36),
        pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    )]
    pub order_id: String,
    /// Exact positive order fence represented without JavaScript precision loss.
    #[schemars(length(min = 1, max = 20), pattern(r"^[1-9][0-9]{0,19}$"))]
    pub order_fence: String,
    /// Canonical TXT owner name without a trailing dot.
    #[schemars(
        length(min = 1, max = 253),
        pattern(r"^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+$")
    )]
    pub record_name: String,
    /// Exact unquoted ACME TXT value.
    #[schemars(length(min = 1, max = 512), pattern(r"^[A-Za-z0-9_-]+$"))]
    pub record_value: String,
    /// Required operator action.
    pub action: ManualDnsTaskAction,
    /// Exclusive challenge deadline as epoch microseconds.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_i64))]
    pub expires_at_epoch_micros: i64,
    /// Original authoritative task creation instant.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_i64))]
    pub created_at_epoch_micros: i64,
    /// Most recent authoritative task transition.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_i64))]
    pub transitioned_at_epoch_micros: i64,
    /// Current authoritative revision.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub revision: u64,
}

/// One bounded deadline-ordered page of current manual DNS work.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListManualDnsTasksResponse {
    /// Tasks ordered by deadline, creation time and digest.
    #[schemars(length(max = 200))]
    pub tasks: Vec<ManualDnsTaskSummary>,
    /// Ready-to-follow same-origin URL, or null when the page is terminal.
    #[schemars(
        length(min = 1, max = 16_384),
        pattern(r"^/api/latest/admin/certificate-tasks/manual-dns")
    )]
    pub next_page_url: Option<String>,
}
