// SPDX-License-Identifier: GPL-2.0-only

use crate::LatencyHistogram;

/// Coding boundary operation, independent of which gateway or repair worker requested it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodingOperation {
    /// Encode an encrypted stripe into systematic and recovery slices.
    Encode,
    /// Verify and reconstruct a stripe from supplied slices.
    Reconstruct,
}

/// Process-lifetime coding measurements; none implies namespace publication or read availability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CodingMetric {
    /// Returned coding calls, including failures.
    Calls(u64),
    /// Calls returning an error.
    Failures(u64),
    /// Bytes supplied to completed calls, including failed calls and replay.
    InputBytes(u64),
    /// Bytes returned by successful calls, including replay and recovery slices.
    OutputBytes(u64),
    /// Calls supplied without every systematic slice; always zero for encode.
    MissingDataCalls(u64),
    /// Time inside the coding implementation, excluding storage and network IO.
    Duration(LatencyHistogram),
}
