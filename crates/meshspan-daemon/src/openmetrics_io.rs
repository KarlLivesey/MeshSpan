// SPDX-License-Identifier: GPL-2.0-only

//! Closed target-operation vocabulary, shared by the text exporter and JSON history.

use super::Measurement;
use meshspan_contracts::{StorageIoKind, StorageIoMetric};

pub(super) fn name_and_help(
    kind: StorageIoKind,
    value: &StorageIoMetric,
) -> (&'static str, &'static str) {
    use StorageIoKind::{Read, Scrub, Write};
    use StorageIoMetric::{Calls, CorruptionReports, Duration, Failures, PayloadBytes};
    let name = match (kind, value) {
        (Read, Calls(_)) => "storage_io_read_calls",
        (Read, Failures(_)) => "storage_io_read_failures",
        (Read, PayloadBytes(_)) => "storage_io_read_payload_bytes",
        (Read, CorruptionReports(_)) => "storage_io_read_corruption_reports",
        (Read, Duration(_)) => "storage_io_read_duration_seconds",
        (Write, Calls(_)) => "storage_io_write_calls",
        (Write, Failures(_)) => "storage_io_write_failures",
        (Write, PayloadBytes(_)) => "storage_io_write_payload_bytes",
        (Write, CorruptionReports(_)) => "storage_io_write_corruption_reports",
        (Write, Duration(_)) => "storage_io_write_duration_seconds",
        (Scrub, Calls(_)) => "storage_io_scrub_calls",
        (Scrub, Failures(_)) => "storage_io_scrub_failures",
        (Scrub, PayloadBytes(_)) => "storage_io_scrub_payload_bytes",
        (Scrub, CorruptionReports(_)) => "storage_io_scrub_corruption_reports",
        (Scrub, Duration(_)) => "storage_io_scrub_duration_seconds",
    };
    let help = match value {
        Calls(_) => "Ended provider calls, including failures and unwinds.",
        Failures(_) => "Failed or unwound provider calls, not every unhealthy scrub record.",
        PayloadBytes(_) => {
            "Returned, acknowledged or scrub-observed payload bytes including replay; not physical disk traffic."
        }
        CorruptionReports(_) => {
            "Corrupt call results and explicitly corrupt scrub records; not unique damaged shards."
        }
        Duration(_) => {
            "Provider operation duration including target-lock residence, excluding network delivery."
        }
    };
    (name, help)
}

pub(super) fn measurement(value: &StorageIoMetric) -> Measurement<'_> {
    match value {
        StorageIoMetric::Calls(value)
        | StorageIoMetric::Failures(value)
        | StorageIoMetric::PayloadBytes(value)
        | StorageIoMetric::CorruptionReports(value) => Measurement::Counter(*value),
        StorageIoMetric::Duration(value) => Measurement::Latency(value),
    }
}
