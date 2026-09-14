// SPDX-License-Identifier: GPL-2.0-only

//! Fixed names for owned worker outcomes; neither subjects nor raw failures are accepted.

use super::Measurement;
use meshspan_contracts::{LifecycleKind, LifecycleMetric};

// Prefixes and suffixes are literals: the exported vocabulary is closed at compilation.
macro_rules! names {
    ($prefix:literal, $metric:expr) => {
        match $metric {
            LifecycleMetric::Idle(_) => (
                concat!($prefix, "_idle_passes"),
                "Worker passes with no new work; not an inventory count.",
            ),
            LifecycleMetric::Pending(_) => (
                concat!($prefix, "_pending_passes"),
                "Worker passes awaiting external or authoritative progress.",
            ),
            LifecycleMetric::Progress(_) => (
                concat!($prefix, "_progress_passes"),
                "Worker passes recording non-terminal progress.",
            ),
            LifecycleMetric::Completed(_) => (
                concat!($prefix, "_completed_passes"),
                "Worker passes completing their named unit; retries may count again.",
            ),
            LifecycleMetric::Retried(_) => (
                concat!($prefix, "_retried_passes"),
                "Worker passes explicitly returned for retry.",
            ),
            LifecycleMetric::Failed(_) => (
                concat!($prefix, "_failed_passes"),
                "Worker passes returning errors; no failure detail is exported.",
            ),
            LifecycleMetric::Duration(_) => (
                concat!($prefix, "_pass_duration_seconds"),
                "Monotonic duration of observed worker passes, including errors.",
            ),
            LifecycleMetric::ObservationAge(_) => (
                concat!($prefix, "_observation_age_seconds"),
                "Age of the last observed worker pass; absent until first observation.",
            ),
        }
    };
}

pub(super) fn name_and_help(
    kind: LifecycleKind,
    value: &LifecycleMetric,
) -> (&'static str, &'static str) {
    match kind {
        LifecycleKind::CertificateAutomation => names!("certificate_automation", value),
        LifecycleKind::CertificateInstallation => names!("certificate_installation", value),
        LifecycleKind::Backup => names!("backup", value),
        LifecycleKind::UpdatePreparation => names!("update_preparation", value),
        LifecycleKind::FederationSessions => names!("federation_sessions", value),
    }
}

pub(super) const fn measurement(value: &LifecycleMetric) -> Measurement<'_> {
    match value {
        LifecycleMetric::Idle(value)
        | LifecycleMetric::Pending(value)
        | LifecycleMetric::Progress(value)
        | LifecycleMetric::Completed(value)
        | LifecycleMetric::Retried(value)
        | LifecycleMetric::Failed(value) => Measurement::Counter(*value),
        LifecycleMetric::Duration(value) => Measurement::Latency(value),
        LifecycleMetric::ObservationAge(value) => Measurement::Seconds(*value),
    }
}
