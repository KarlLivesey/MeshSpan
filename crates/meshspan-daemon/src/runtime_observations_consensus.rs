// SPDX-License-Identifier: GPL-2.0-only

//! One coherent local reactor observation; no peer identities or authority conclusions.

use std::time::Instant;

use meshspan_cluster::MetadataAuthorityObservation;
use meshspan_contracts::{ConsensusMetric, ConsensusObservedRole, RuntimeMetric};
use meshspan_domain::UnixMicros;

use super::RuntimeObservations;

#[derive(Clone)]
pub(super) struct ObservedConsensus {
    captured: Instant,
    role: ConsensusObservedRole,
    term: u64,
    committed: u64,
    applied: u64,
    pending: u64,
    queued: u64,
    persistence_blocked: bool,
    leader_known: bool,
    remote_members: u64,
    replication: Option<ReplicationCounts>,
}

#[derive(Clone)]
struct ReplicationCounts {
    unknown: u64,
    lagging: u64,
    maximum_gap: u64,
}

impl RuntimeObservations {
    pub(crate) fn record_consensus(&self, value: MetadataAuthorityObservation, now: UnixMicros) {
        if value.applied_index > value.commit_index {
            self.drop_update();
            return;
        }
        if let Some(replication) = value.replication
            && (value.role != meshspan_consensus::Role::Leader
                || replication.unknown_members > value.remote_members
                || replication.lagging_members > value.remote_members - replication.unknown_members
                || replication.maximum_committed_gap > value.commit_index
                || (replication.maximum_committed_gap == 0) != (replication.lagging_members == 0))
        {
            self.drop_update();
            return;
        }
        self.update(Some(now), |state, time| {
            state.consensus = Some(ObservedConsensus {
                captured: time.monotonic,
                role: match value.role {
                    meshspan_consensus::Role::Follower => ConsensusObservedRole::Follower,
                    meshspan_consensus::Role::Candidate => ConsensusObservedRole::Candidate,
                    meshspan_consensus::Role::Leader => ConsensusObservedRole::Leader,
                },
                term: value.term,
                committed: value.commit_index,
                applied: value.applied_index,
                pending: u64::try_from(value.pending_operations).map_err(|_| ())?,
                queued: u64::try_from(value.queued_operations).map_err(|_| ())?,
                persistence_blocked: value.persistence_blocked,
                leader_known: value.known_leader.is_some(),
                remote_members: u64::try_from(value.remote_members).map_err(|_| ())?,
                replication: value
                    .replication
                    .map(|replication| {
                        Ok(ReplicationCounts {
                            unknown: u64::try_from(replication.unknown_members).map_err(|_| ())?,
                            lagging: u64::try_from(replication.lagging_members).map_err(|_| ())?,
                            maximum_gap: replication.maximum_committed_gap,
                        })
                    })
                    .transpose()?,
            });
            Ok(())
        });
    }

    pub(crate) fn record_consensus_unavailable(&self, now: UnixMicros) {
        self.update(Some(now), |state, _time| {
            state.consensus_failures = state.consensus_failures.checked_add(1).ok_or(())?;
            Ok(())
        });
    }
}

impl ObservedConsensus {
    pub(super) fn append_metrics(&self, now: Instant, samples: &mut Vec<RuntimeMetric>) {
        samples.extend(
            [
                ConsensusMetric::ObservationAge(now.saturating_duration_since(self.captured)),
                ConsensusMetric::Role(self.role),
                ConsensusMetric::Term(self.term),
                ConsensusMetric::CommittedIndex(self.committed),
                ConsensusMetric::AppliedIndex(self.applied),
                ConsensusMetric::PendingOperations(self.pending),
                ConsensusMetric::QueuedOperations(self.queued),
                ConsensusMetric::PersistenceBlocked(self.persistence_blocked),
                ConsensusMetric::LeaderKnown(self.leader_known),
                ConsensusMetric::RemoteMembers(self.remote_members),
                ConsensusMetric::ApplyGap(self.committed - self.applied),
            ]
            .into_iter()
            .map(RuntimeMetric::Consensus),
        );
        if let Some(replication) = &self.replication {
            samples.extend(
                [
                    ConsensusMetric::ReplicationUnknownMembers(replication.unknown),
                    ConsensusMetric::ReplicationLaggingMembers(replication.lagging),
                    ConsensusMetric::ReplicationMaximumCommittedGap(replication.maximum_gap),
                ]
                .into_iter()
                .map(RuntimeMetric::Consensus),
            );
        }
    }
}
