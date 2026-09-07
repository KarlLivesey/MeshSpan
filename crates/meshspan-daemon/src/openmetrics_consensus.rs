// SPDX-License-Identifier: GPL-2.0-only

//! Public vocabulary and units for the closed local consensus measurement family.

use meshspan_contracts::ConsensusMetric;

use super::Measurement;

pub(super) fn name_and_help(sample: &ConsensusMetric) -> (&'static str, &'static str) {
    match sample {
        ConsensusMetric::ObservationAge(_) => (
            "consensus_observation_age_seconds",
            "Age of the last local reactor observation; not a quorum lease.",
        ),
        ConsensusMetric::ObservationFailures(_) => (
            "consensus_observation_failures",
            "Local reactor observations which failed or exceeded their budget.",
        ),
        ConsensusMetric::Role(_) => (
            "consensus_role",
            "Observed role: 1 follower, 2 candidate, 3 leader; not current write authority.",
        ),
        ConsensusMetric::Term(_) => ("consensus_term", "Last observed local election term."),
        ConsensusMetric::CommittedIndex(_) => (
            "consensus_committed_index",
            "Last observed committed log index.",
        ),
        ConsensusMetric::AppliedIndex(_) => (
            "consensus_applied_index",
            "Last observed locally applied log index.",
        ),
        ConsensusMetric::PendingOperations(_) => (
            "consensus_pending_operations",
            "Pending authoritative operations at the last local observation.",
        ),
        ConsensusMetric::QueuedOperations(_) => (
            "consensus_queued_operations",
            "Queued authoritative operations at the last local observation.",
        ),
        ConsensusMetric::PersistenceBlocked(_) => (
            "consensus_persistence_blocked",
            "Whether local persistence was blocked at the last observation.",
        ),
        ConsensusMetric::LeaderKnown(_) => (
            "consensus_leader_known",
            "Whether a leader identity was known; not leader reachability.",
        ),
    }
}

pub(super) fn measurement(sample: &ConsensusMetric) -> Measurement<'_> {
    match sample {
        ConsensusMetric::ObservationAge(value) => Measurement::Seconds(*value),
        ConsensusMetric::ObservationFailures(value) => Measurement::Counter(*value),
        ConsensusMetric::Role(value) => Measurement::Gauge(u64::from(*value as u8)),
        ConsensusMetric::PersistenceBlocked(value) | ConsensusMetric::LeaderKnown(value) => {
            Measurement::Gauge(u64::from(*value))
        }
        ConsensusMetric::Term(value)
        | ConsensusMetric::CommittedIndex(value)
        | ConsensusMetric::AppliedIndex(value)
        | ConsensusMetric::PendingOperations(value)
        | ConsensusMetric::QueuedOperations(value) => Measurement::Gauge(*value),
    }
}
