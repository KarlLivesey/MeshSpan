// SPDX-License-Identifier: GPL-2.0-only

//! Fixed-cardinality observations of the local committed-content catalogue.

use std::time::Duration;

/// Last completed paged assessment, not mesh-wide health or live read availability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtectionMetric {
    /// Age since the completed pass began; includes collection time.
    ObservationAge(Duration),
    /// Time spent collecting that pass across bounded pages.
    PassDuration(Duration),
    /// Collection passes abandoned after a read or accounting failure.
    ObservationFailures(u64),
    /// Stripes whose receipts and current policy were assessable in that pass.
    AssessedStripes(u64),
    /// Stripes not assessable against the available current policy/topology.
    UnassessableStripes(u64),
    /// Planned slices without a retained receipt in the sampled catalogue.
    MissingShardReceipts(u64),
    /// Assessed stripes with fewer receipts than their decode threshold.
    InsufficientReceiptsStripes(u64),
    /// Assessed stripes not satisfying the requested failure scenarios.
    ProtectionDebtStripes(u64),
    /// Assessed stripes not satisfying all configured cell predicates.
    LocalityDebtStripes(u64),
}
