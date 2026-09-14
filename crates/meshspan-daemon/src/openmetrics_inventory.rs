// SPDX-License-Identifier: GPL-2.0-only

use super::Measurement;
use meshspan_contracts::InventoryMetric as Metric;

#[expect(
    clippy::too_many_lines,
    reason = "exhaustive declarative metric vocabulary keeps each public name beside its meaning"
)]
pub(super) fn name_and_help(value: &Metric) -> (&'static str, &'static str) {
    match value {
        Metric::CertificateSelected(_) => (
            "certificate_selected",
            "A public certificate was selected at observation time.",
        ),
        Metric::CertificateRemainingValidity(_) => (
            "certificate_remaining_validity_seconds",
            "Selected certificate validity remaining at sample time, using the host wall clock.",
        ),
        Metric::CertificateNotYetValid(_) => (
            "certificate_not_yet_valid",
            "Selected certificate validity had not begun at sample time.",
        ),
        Metric::CertificateExpired(_) => (
            "certificate_expired",
            "Selected certificate had expired at sample time.",
        ),
        Metric::CertificateRequiredGateways(_) => (
            "certificate_required_gateways",
            "Gateways in the selected encrypted delivery generation.",
        ),
        Metric::CertificateInstalledGateways(_) => (
            "certificate_installed_gateways",
            "Exact-generation durable installation acknowledgements, not current reachability.",
        ),
        Metric::CertificateObservationAge(_) => (
            "certificate_observation_age_seconds",
            "Monotonic age of the last completed certificate observation.",
        ),
        Metric::CertificateObservationFailures(_) => (
            "certificate_observation_failures",
            "Failed certificate observation attempts in this process.",
        ),
        Metric::BackupsQueued(_) => (
            "backup_queued_occurrences",
            "Retained backup occurrences awaiting a worker in the completed inventory.",
        ),
        Metric::BackupsClaimed(_) => (
            "backup_claimed_occurrences",
            "Retained backup occurrences with a claimed worker in the completed inventory.",
        ),
        Metric::BackupsRecorded(_) => (
            "backup_recorded_occurrences",
            "Retained backup occurrences with admitted bytes and unfinished protection.",
        ),
        Metric::BackupsProtected(_) => (
            "backup_protected_occurrences",
            "Retained backup occurrences historically meeting thresholds, not current copy protection.",
        ),
        Metric::BackupsIncomplete(_) => (
            "backup_incomplete_occurrences",
            "Retained backup occurrences ending without their thresholds.",
        ),
        Metric::BackupObservationAge(_) => (
            "backup_inventory_age_seconds",
            "Monotonic age of the start of the last completed paged backup inventory.",
        ),
        Metric::BackupObservationFailures(_) => (
            "backup_inventory_failures",
            "Failed backup inventory passes in this process.",
        ),
        Metric::UpdatesRunning(_) => (
            "update_running_rollouts",
            "Retained running rollouts in the completed inventory.",
        ),
        Metric::UpdatesPaused(_) => (
            "update_paused_rollouts",
            "Retained paused rollouts in the completed inventory.",
        ),
        Metric::UpdatesCompleted(_) => (
            "update_completed_rollouts",
            "Retained completed rollouts in the completed inventory.",
        ),
        Metric::UpdatesCancelled(_) => (
            "update_cancelled_rollouts",
            "Retained cancelled rollouts in the completed inventory.",
        ),
        Metric::UpdateSelected(_) => (
            "update_selected",
            "A running or paused rollout was selected at observation time.",
        ),
        Metric::UpdatePendingNodes(_) => (
            "update_pending_nodes",
            "Selected rollout nodes awaiting staging, not a live process census.",
        ),
        Metric::UpdateStagedNodes(_) => (
            "update_staged_nodes",
            "Selected rollout nodes with staged bytes, including preparation in progress.",
        ),
        Metric::UpdateRestartingNodes(_) => (
            "update_restarting_nodes",
            "Selected rollout nodes in restart phase.",
        ),
        Metric::UpdateVerifiedNodes(_) => (
            "update_verified_nodes",
            "Selected rollout nodes with verified replacement checkpoints.",
        ),
        Metric::UpdateFailedNodes(_) => (
            "update_failed_nodes",
            "Selected rollout nodes with failed checkpoints.",
        ),
        Metric::UpdateUnresolvedRestarts(_) => (
            "update_unresolved_restarts",
            "Selected rollout restart outcomes still requiring reconciliation.",
        ),
        Metric::UpdateObservationAge(_) => (
            "update_inventory_age_seconds",
            "Monotonic age of the start of the last completed paged update inventory.",
        ),
        Metric::UpdateObservationFailures(_) => (
            "update_inventory_failures",
            "Failed update inventory passes in this process.",
        ),
    }
}

pub(super) fn measurement(value: &Metric) -> Measurement<'_> {
    match value {
        Metric::CertificateObservationFailures(value)
        | Metric::BackupObservationFailures(value)
        | Metric::UpdateObservationFailures(value) => Measurement::Counter(*value),
        Metric::CertificateRemainingValidity(value)
        | Metric::CertificateObservationAge(value)
        | Metric::BackupObservationAge(value)
        | Metric::UpdateObservationAge(value) => Measurement::Seconds(*value),
        Metric::CertificateSelected(value)
        | Metric::CertificateNotYetValid(value)
        | Metric::CertificateExpired(value)
        | Metric::UpdateSelected(value) => Measurement::Gauge(u64::from(*value)),
        Metric::CertificateRequiredGateways(value)
        | Metric::CertificateInstalledGateways(value)
        | Metric::BackupsQueued(value)
        | Metric::BackupsClaimed(value)
        | Metric::BackupsRecorded(value)
        | Metric::BackupsProtected(value)
        | Metric::BackupsIncomplete(value)
        | Metric::UpdatesRunning(value)
        | Metric::UpdatesPaused(value)
        | Metric::UpdatesCompleted(value)
        | Metric::UpdatesCancelled(value)
        | Metric::UpdatePendingNodes(value)
        | Metric::UpdateStagedNodes(value)
        | Metric::UpdateRestartingNodes(value)
        | Metric::UpdateVerifiedNodes(value)
        | Metric::UpdateFailedNodes(value)
        | Metric::UpdateUnresolvedRestarts(value) => Measurement::Gauge(*value),
    }
}
