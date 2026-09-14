// SPDX-License-Identifier: GPL-2.0-only

//! Target-operation observations, not physical disk traffic or file publication receipts.

use crate::LatencyHistogram;
use std::time::Duration;

/// Closed provider operation categories, without target or request labels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageIoKind {
    /// An exact authenticated shard read.
    Read,
    /// An exact shard installation, including idempotent replay.
    Write,
    /// An exact scrub or a bounded scrub page.
    Scrub,
}

impl StorageIoKind {
    /// Fixed collector order; not a wire identifier.
    pub const ALL: [Self; 3] = [Self::Read, Self::Write, Self::Scrub];
}

/// Successfully returned payload accounting, not physical IO amplification.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StorageIoCounts {
    /// Bytes returned by reads, acknowledged by writes, or observed by scrub.
    pub payload_bytes: u64,
    /// Corrupt results, including explicitly corrupt scrub records.
    pub corruption_reports: u64,
}

/// One completed synchronous provider call, including target-lock residence.
#[derive(Clone, Copy, Debug)]
pub struct StorageIoObservation {
    /// Provider operation category.
    pub kind: StorageIoKind,
    /// Monotonic operation duration, not subsequent response delivery.
    pub duration: Duration,
    /// The call returned an error or unwound before returning.
    pub failed: bool,
    /// None means aggregation overflow; the observation must be dropped, not clamped.
    pub counts: Option<StorageIoCounts>,
}

/// Best-effort in-process observer, never a provider or permission authority.
pub trait StorageIoObserver: Send + Sync {
    /// Records or counts a dropped sample without IO, blocking, or changing domain outcomes.
    fn observe_storage_io(&self, observation: StorageIoObservation);
}

/// Process-local cumulative measurements for one provider operation kind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StorageIoMetric {
    /// Ended provider calls, including failures and unwinds.
    Calls(u64),
    /// Calls which failed or unwound; not all unhealthy scrub records.
    Failures(u64),
    /// Cumulative returned/acknowledged/observed payload bytes, including replay.
    PayloadBytes(u64),
    /// Corrupt call results and explicitly corrupt scrub records, not unique damaged shards.
    CorruptionReports(u64),
    /// Provider-call duration including target-lock residence.
    Duration(LatencyHistogram),
}
