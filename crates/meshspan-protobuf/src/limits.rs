// SPDX-License-Identifier: GPL-2.0-only

//! Hostile-input allocation, work and recursion limits.

/// Bounds applied before and during Protocol Buffers decoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeLimits {
    /// Maximum complete encoded message size.
    pub maximum_message_bytes: usize,
    /// Maximum size of one length-delimited value.
    pub maximum_field_bytes: usize,
    /// Maximum number of encoded field occurrences.
    pub maximum_fields: usize,
    /// Maximum number of values accepted by any one repeated field.
    pub maximum_repeated_items: usize,
    /// Maximum nested message or deprecated-group depth.
    pub maximum_depth: usize,
}

impl DecodeLimits {
    /// Conservative defaults for control and moderately sized data records.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            maximum_message_bytes: 16 * 1_024 * 1_024,
            maximum_field_bytes: 16 * 1_024 * 1_024,
            maximum_fields: 65_536,
            maximum_repeated_items: 65_536,
            maximum_depth: 64,
        }
    }
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self::new()
    }
}
