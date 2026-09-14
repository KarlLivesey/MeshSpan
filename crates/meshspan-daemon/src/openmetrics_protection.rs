// SPDX-License-Identifier: GPL-2.0-only

//! Recorded-layout measurements deliberately do not claim current mesh or provider health.

use super::Measurement;
use meshspan_contracts::ProtectionMetric;

pub(super) fn name_and_help(value: &ProtectionMetric) -> (&'static str, &'static str) {
    match value {
        ProtectionMetric::ObservationAge(_) => (
            "protection_catalogue_age_seconds",
            "Age since the completed local catalogue pass began; not a health lease.",
        ),
        ProtectionMetric::PassDuration(_) => (
            "protection_catalogue_pass_duration_seconds",
            "Duration of the completed paged local catalogue assessment.",
        ),
        ProtectionMetric::ObservationFailures(_) => (
            "protection_catalogue_observation_failures",
            "Local catalogue passes abandoned after collection failure.",
        ),
        ProtectionMetric::AssessedStripes(_) => (
            "protection_catalogue_assessed_stripes",
            "Local committed stripes assessed against recorded receipts and current policy; not verified live reads.",
        ),
        ProtectionMetric::UnassessableStripes(_) => (
            "protection_catalogue_unassessable_stripes",
            "Local committed stripes without usable current policy or topology evidence.",
        ),
        ProtectionMetric::MissingShardReceipts(_) => (
            "protection_catalogue_missing_shard_receipts",
            "Planned slices missing recorded receipts in the sampled local catalogue.",
        ),
        ProtectionMetric::InsufficientReceiptsStripes(_) => (
            "protection_catalogue_insufficient_receipts_stripes",
            "Assessed stripes with fewer recorded receipts than the decode threshold.",
        ),
        ProtectionMetric::ProtectionDebtStripes(_) => (
            "protection_catalogue_protection_debt_stripes",
            "Assessed stripes whose recorded locations do not satisfy requested failure scenarios.",
        ),
        ProtectionMetric::LocalityDebtStripes(_) => (
            "protection_catalogue_locality_debt_stripes",
            "Assessed stripes whose recorded locations do not satisfy all cell predicates.",
        ),
    }
}

pub(super) fn measurement(value: &ProtectionMetric) -> Measurement<'_> {
    match value {
        ProtectionMetric::ObservationAge(value) | ProtectionMetric::PassDuration(value) => {
            Measurement::Seconds(*value)
        }
        ProtectionMetric::ObservationFailures(value) => Measurement::Counter(*value),
        ProtectionMetric::AssessedStripes(value)
        | ProtectionMetric::UnassessableStripes(value)
        | ProtectionMetric::MissingShardReceipts(value)
        | ProtectionMetric::InsufficientReceiptsStripes(value)
        | ProtectionMetric::ProtectionDebtStripes(value)
        | ProtectionMetric::LocalityDebtStripes(value) => Measurement::Gauge(*value),
    }
}
