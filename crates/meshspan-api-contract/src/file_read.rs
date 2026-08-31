// SPDX-License-Identifier: GPL-2.0-only

//! Public contract for bounded reads from one logical regular file.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::NamespacePath;

/// Largest byte range returned by one native file-content request.
pub const MAX_FILE_READ_BYTES: u32 = 8 * 1_024 * 1_024;

/// Largest exact integer safely represented by generated JavaScript clients.
pub const MAX_SAFE_FILE_OFFSET: u64 = 9_007_199_254_740_991;

/// One bounded logical-file byte-range query.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReadFileQuery {
    /// Required root-relative logical regular-file path.
    pub path: NamespacePath,
    /// First logical byte; omission selects byte zero.
    #[schemars(range(max = 9_007_199_254_740_991_u64))]
    pub offset: Option<u64>,
    /// Maximum response bytes; omission selects the 8 MiB operation limit.
    #[schemars(range(min = 1, max = 8_388_608))]
    pub length: Option<u32>,
}
