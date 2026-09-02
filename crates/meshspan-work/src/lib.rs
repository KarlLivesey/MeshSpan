// SPDX-License-Identifier: GPL-2.0-only

//! Deterministic policy for bounded repair, scrub, drain and reconciliation work.
//!
//! This crate owns no threads, storage or metadata. It turns committed health signals into a
//! stable priority and admits work against an explicit resource budget, allowing the daemon and
//! future embedders to supply their own persistence and execution runtimes.

use std::fmt;

use meshspan_domain::{
    ContentManifestId, DurationMicros, FaultGroupId, NodeId, Revision, TargetId, UnixMicros,
    VolumeId,
};

/// Maximum canonical bytes occupied by any supported work subject.
pub const MAXIMUM_WORK_SUBJECT_BYTES: usize = 128;

/// Closed maintenance families sharing the durable work coordinator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WorkKind {
    /// Reconstructs or relocates immutable shards to restore a protection promise.
    Repair = 1,
    /// Revalidates complete stored shard bytes against committed integrity metadata.
    Scrub = 2,
    /// Moves authoritative data away from a target, node or shared-failure group.
    Drain = 3,
    /// Improves a safe layout after capacity or topology changes.
    Rebalance = 4,
    /// Reconciles a returning target's journal-known inventory with authoritative metadata.
    Reconcile = 5,
}

/// Exact authoritative subject of one durable maintenance job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkSubject {
    /// One immutable stripe generation whose placement no longer satisfies policy.
    Repair {
        /// Volume whose current policy controls replacement placement.
        volume_id: VolumeId,
        /// Immutable content manifest containing the stripe.
        manifest_id: ContentManifestId,
        /// Zero-based stripe index inside the manifest.
        stripe_index: u64,
        /// Exact shard position requiring reconstruction or relocation.
        shard_index: u16,
        /// Exact immutable generation whose catalogue entry is the compare-and-swap base.
        source_generation: u64,
    },
    /// One target generation requiring a bounded page of full-byte verification.
    Scrub {
        /// Target to inspect.
        target_id: TargetId,
        /// Exact target generation; path reuse cannot inherit the job.
        target_generation: u64,
    },
    /// One target, node or shared-failure group being evacuated.
    Drain(DrainScope),
    /// One volume whose safe placement may improve after a topology change.
    Rebalance {
        /// Volume to evaluate.
        volume_id: VolumeId,
        /// Exact authoritative topology revision that produced the candidate work.
        topology_revision: Revision,
    },
    /// One returning target generation whose journal inventory must be reconciled.
    Reconcile {
        /// Returning target.
        target_id: TargetId,
        /// Exact marker generation admitted by authority.
        target_generation: u64,
    },
}

impl WorkSubject {
    /// Returns the maintenance family implied by the closed subject.
    #[must_use]
    pub const fn kind(self) -> WorkKind {
        match self {
            Self::Repair { .. } => WorkKind::Repair,
            Self::Scrub { .. } => WorkKind::Scrub,
            Self::Drain(_) => WorkKind::Drain,
            Self::Rebalance { .. } => WorkKind::Rebalance,
            Self::Reconcile { .. } => WorkKind::Reconcile,
        }
    }

    /// Encodes the closed subject into deterministic versioned bytes for durable metadata.
    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(MAXIMUM_WORK_SUBJECT_BYTES);
        bytes.push(1);
        match self {
            Self::Repair {
                volume_id,
                manifest_id,
                stripe_index,
                shard_index,
                source_generation,
            } => {
                bytes.push(1);
                bytes.extend_from_slice(&volume_id.as_bytes());
                bytes.extend_from_slice(&manifest_id.as_bytes());
                bytes.extend_from_slice(&stripe_index.to_be_bytes());
                bytes.extend_from_slice(&shard_index.to_be_bytes());
                bytes.extend_from_slice(&source_generation.to_be_bytes());
            }
            Self::Scrub {
                target_id,
                target_generation,
            } => encode_target_subject(&mut bytes, 2, target_id, target_generation),
            Self::Drain(scope) => encode_drain_subject(&mut bytes, scope),
            Self::Rebalance {
                volume_id,
                topology_revision,
            } => {
                bytes.push(6);
                bytes.extend_from_slice(&volume_id.as_bytes());
                bytes.extend_from_slice(&topology_revision.get().to_be_bytes());
            }
            Self::Reconcile {
                target_id,
                target_generation,
            } => encode_target_subject(&mut bytes, 7, target_id, target_generation),
        }
        bytes
    }

    /// Decodes and validates one exact canonical subject representation.
    ///
    /// # Errors
    ///
    /// Rejects unknown versions or variants, nil identities, zero generations and trailing or
    /// truncated bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, WorkSubjectError> {
        if bytes.len() > MAXIMUM_WORK_SUBJECT_BYTES {
            return Err(WorkSubjectError::Invalid);
        }
        let mut decoder = SubjectDecoder::new(bytes);
        if decoder.byte()? != 1 {
            return Err(WorkSubjectError::Invalid);
        }
        let subject = match decoder.byte()? {
            1 => Self::Repair {
                volume_id: VolumeId::from_bytes(decoder.identifier()?)?,
                manifest_id: ContentManifestId::from_bytes(decoder.identifier()?)?,
                stripe_index: decoder.u64()?,
                shard_index: decoder.u16()?,
                source_generation: nonzero(decoder.u64()?)?,
            },
            2 => Self::Scrub {
                target_id: TargetId::from_bytes(decoder.identifier()?)?,
                target_generation: nonzero(decoder.u64()?)?,
            },
            3 => Self::Drain(DrainScope::Target {
                target_id: TargetId::from_bytes(decoder.identifier()?)?,
                target_generation: nonzero(decoder.u64()?)?,
            }),
            4 => Self::Drain(DrainScope::Node {
                node_id: NodeId::from_bytes(decoder.identifier()?)?,
                node_incarnation: nonzero(decoder.u64()?)?,
            }),
            5 => Self::Drain(DrainScope::FaultGroup {
                fault_group_id: FaultGroupId::from_bytes(decoder.identifier()?)?,
            }),
            6 => Self::Rebalance {
                volume_id: VolumeId::from_bytes(decoder.identifier()?)?,
                topology_revision: Revision::new(nonzero(decoder.u64()?)?),
            },
            7 => Self::Reconcile {
                target_id: TargetId::from_bytes(decoder.identifier()?)?,
                target_generation: nonzero(decoder.u64()?)?,
            },
            _ => return Err(WorkSubjectError::Invalid),
        };
        decoder.finish()?;
        Ok(subject)
    }
}

fn encode_target_subject(
    bytes: &mut Vec<u8>,
    kind: u8,
    target_id: TargetId,
    target_generation: u64,
) {
    bytes.push(kind);
    bytes.extend_from_slice(&target_id.as_bytes());
    bytes.extend_from_slice(&target_generation.to_be_bytes());
}

fn encode_drain_subject(bytes: &mut Vec<u8>, scope: DrainScope) {
    match scope {
        DrainScope::Target {
            target_id,
            target_generation,
        } => encode_target_subject(bytes, 3, target_id, target_generation),
        DrainScope::Node {
            node_id,
            node_incarnation,
        } => {
            bytes.push(4);
            bytes.extend_from_slice(&node_id.as_bytes());
            bytes.extend_from_slice(&node_incarnation.to_be_bytes());
        }
        DrainScope::FaultGroup { fault_group_id } => {
            bytes.push(5);
            bytes.extend_from_slice(&fault_group_id.as_bytes());
        }
    }
}

fn nonzero(value: u64) -> Result<u64, WorkSubjectError> {
    if value == 0 {
        Err(WorkSubjectError::Invalid)
    } else {
        Ok(value)
    }
}

struct SubjectDecoder<'a> {
    remaining: &'a [u8],
}

impl<'a> SubjectDecoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn byte(&mut self) -> Result<u8, WorkSubjectError> {
        Ok(self.take::<1>()?[0])
    }

    fn identifier(&mut self) -> Result<[u8; 16], WorkSubjectError> {
        self.take()
    }

    fn u64(&mut self) -> Result<u64, WorkSubjectError> {
        self.take().map(u64::from_be_bytes)
    }

    fn u16(&mut self) -> Result<u16, WorkSubjectError> {
        self.take().map(u16::from_be_bytes)
    }

    fn take<const LENGTH: usize>(&mut self) -> Result<[u8; LENGTH], WorkSubjectError> {
        let Some((value, remaining)) = self.remaining.split_first_chunk::<LENGTH>() else {
            return Err(WorkSubjectError::Invalid);
        };
        self.remaining = remaining;
        Ok(*value)
    }

    fn finish(self) -> Result<(), WorkSubjectError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(WorkSubjectError::Invalid)
        }
    }
}

/// Invalid or non-canonical durable work subject.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkSubjectError {
    /// The version, variant, bounds or required positive values were invalid.
    Invalid,
}

impl fmt::Display for WorkSubjectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid maintenance-work subject")
    }
}

impl std::error::Error for WorkSubjectError {}

impl From<meshspan_domain::IdentifierError> for WorkSubjectError {
    fn from(_: meshspan_domain::IdentifierError) -> Self {
        Self::Invalid
    }
}

/// Authoritative scope evacuated by one drain job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DrainScope {
    /// One registered storage target generation.
    Target {
        /// Target to stop using for new placement and evacuate.
        target_id: TargetId,
        /// Exact generation being drained.
        target_generation: u64,
    },
    /// Every storage target owned by one daemon node incarnation.
    Node {
        /// Node to evacuate.
        node_id: NodeId,
        /// Exact incarnation that accepted the drain.
        node_incarnation: u64,
    },
    /// Every storage target within one administrator-defined shared-failure group.
    FaultGroup {
        /// Failure group to evacuate.
        fault_group_id: FaultGroupId,
    },
}

/// Safety consequence that primarily orders background work.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum WorkUrgency {
    /// Preventive verification or a safe placement improvement.
    Routine = 1,
    /// A required locality copy or administrator-requested drain is incomplete.
    Required = 2,
    /// Current data survives, but the promised failure protection is not met.
    UnderProtected = 3,
    /// One further independent failure would make some committed data unreadable.
    LastRecoveryMargin = 4,
    /// Committed data is presently unreadable or a destructive integrity failure is active.
    Unavailable = 5,
}

impl WorkUrgency {
    const fn code(self) -> u8 {
        match self {
            Self::Routine => 1,
            Self::Required => 2,
            Self::UnderProtected => 3,
            Self::LastRecoveryMargin => 4,
            Self::Unavailable => 5,
        }
    }
}

/// Committed and observed signals used to order one job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkSignals {
    /// Whether the affected committed data is presently unreadable.
    pub data_unavailable: bool,
    /// Remaining independent failures that may occur before data becomes unreadable.
    pub remaining_recovery_margin: u16,
    /// Number of currently unmet protection predicates.
    pub protection_debt: u16,
    /// Number of currently unmet required-locality predicates.
    pub locality_debt: u16,
    /// Bounded recent failure/return instability score.
    pub instability: u16,
    /// Bounded recent access-heat score.
    pub access_heat: u16,
    /// Authoritative instant at which the job first became necessary.
    pub created_at: UnixMicros,
    /// Optional authoritative deadline, including a scrub maximum age or drain deadline.
    pub due_at: Option<UnixMicros>,
}

impl WorkSignals {
    /// Classifies the job's primary safety consequence without consulting local wall time.
    #[must_use]
    pub const fn urgency(self) -> WorkUrgency {
        if self.data_unavailable {
            WorkUrgency::Unavailable
        } else if self.remaining_recovery_margin == 0 {
            WorkUrgency::LastRecoveryMargin
        } else if self.protection_debt > 0 {
            WorkUrgency::UnderProtected
        } else if self.locality_debt > 0 || self.due_at.is_some() {
            WorkUrgency::Required
        } else {
            WorkUrgency::Routine
        }
    }

    /// Produces a deterministic sortable priority at one authority-agreed instant.
    ///
    /// Higher values are more urgent. Age and lateness are bounded so an old routine scrub cannot
    /// outrank actual data loss, while still preventing safe work from starving forever.
    #[must_use]
    pub fn priority(self, now: UnixMicros) -> WorkPriority {
        const MICROS_PER_SECOND: u64 = 1_000_000;
        const MAXIMUM_TIME_SCORE: u64 = (1 << 20) - 1;

        let age = elapsed_micros(self.created_at, now) / MICROS_PER_SECOND;
        let lateness = self
            .due_at
            .map_or(0, |due_at| elapsed_micros(due_at, now) / MICROS_PER_SECOND);
        let urgency = u64::from(self.urgency().code());
        let debt = u64::from(self.protection_debt.saturating_add(self.locality_debt)).min(0x0fff);
        let instability = u64::from(self.instability).min(0x03ff);
        let heat = u64::from(self.access_heat).min(0x03ff);
        let time = age.saturating_add(lateness).min(MAXIMUM_TIME_SCORE);
        WorkPriority((urgency << 60) | (debt << 48) | (instability << 38) | (heat << 28) | time)
    }
}

fn elapsed_micros(earlier: UnixMicros, later: UnixMicros) -> u64 {
    later
        .get()
        .checked_sub(earlier.get())
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or(0)
}

/// Stable descending queue priority derived from [`WorkSignals`].
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WorkPriority(u64);

impl WorkPriority {
    /// Returns the portable integer persisted by the work queue.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Administrator-controlled ceiling for background work on one worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkBudget {
    concurrent_jobs: u16,
    in_flight_bytes: u64,
    bytes_per_second: Option<u64>,
}

impl WorkBudget {
    /// Constructs a positive bounded budget.
    ///
    /// `maximum_bytes_per_second = None` means no explicit transfer-rate ceiling; concurrency and
    /// in-flight memory remain bounded.
    ///
    /// # Errors
    ///
    /// Rejects zero concurrency, zero in-flight capacity or an explicit zero transfer rate.
    pub const fn new(
        maximum_concurrent_jobs: u16,
        maximum_in_flight_bytes: u64,
        maximum_bytes_per_second: Option<u64>,
    ) -> Result<Self, WorkBudgetError> {
        if maximum_concurrent_jobs == 0 || maximum_in_flight_bytes == 0 {
            return Err(WorkBudgetError::InvalidLimit);
        }
        if matches!(maximum_bytes_per_second, Some(0)) {
            return Err(WorkBudgetError::InvalidLimit);
        }
        Ok(Self {
            concurrent_jobs: maximum_concurrent_jobs,
            in_flight_bytes: maximum_in_flight_bytes,
            bytes_per_second: maximum_bytes_per_second,
        })
    }

    /// Returns whether the next bounded demand fits without oversubscribing either hard ceiling.
    #[must_use]
    pub fn admits(self, usage: WorkUsage, demand: WorkDemand) -> bool {
        demand.in_flight_bytes > 0
            && usage.active_jobs < self.concurrent_jobs
            && usage
                .in_flight_bytes
                .checked_add(demand.in_flight_bytes)
                .is_some_and(|bytes| bytes <= self.in_flight_bytes)
    }

    /// Returns the configured maximum number of concurrently claimed jobs.
    #[must_use]
    pub const fn maximum_concurrent_jobs(self) -> u16 {
        self.concurrent_jobs
    }

    /// Returns the configured maximum bytes retained across concurrent work.
    #[must_use]
    pub const fn maximum_in_flight_bytes(self) -> u64 {
        self.in_flight_bytes
    }

    /// Returns the optional administrator-selected transfer-rate ceiling.
    #[must_use]
    pub const fn maximum_bytes_per_second(self) -> Option<u64> {
        self.bytes_per_second
    }
}

/// Current resource use attributed to background work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkUsage {
    /// Jobs currently executing under live leases.
    pub active_jobs: u16,
    /// Bytes currently retained across bounded work buffers and transfers.
    pub in_flight_bytes: u64,
}

/// Bounded resource demand of one candidate job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkDemand {
    /// Positive maximum bytes this job may retain at once.
    pub in_flight_bytes: u64,
}

/// Invalid background-resource policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkBudgetError {
    /// A mandatory resource ceiling was zero.
    InvalidLimit,
}

impl fmt::Display for WorkBudgetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid maintenance-work resource limit")
    }
}

impl std::error::Error for WorkBudgetError {}

/// Calculates the first time a safe repair should become eligible.
///
/// With no remaining recovery margin the answer is always `now`. Otherwise a recent absence may
/// debounce until `absence_grace`, but repeated flapping reduces that grace and `maximum_deferral`
/// prevents an unstable target from postponing necessary repair forever.
#[must_use]
pub fn repair_due_at(
    now: UnixMicros,
    absent_since: UnixMicros,
    remaining_recovery_margin: u16,
    instability: u16,
    absence_grace: DurationMicros,
    maximum_deferral: DurationMicros,
) -> UnixMicros {
    if remaining_recovery_margin == 0 {
        return now;
    }
    let divisor = u64::from(instability).saturating_add(1);
    let adjusted_grace = DurationMicros::new(absence_grace.get() / divisor);
    let grace_end = absent_since.checked_add(adjusted_grace).unwrap_or(now);
    let final_end = absent_since.checked_add(maximum_deferral).unwrap_or(now);
    if grace_end < final_end {
        grace_end
    } else {
        final_end
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_subject_has_one_exact_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let subjects = [
            WorkSubject::Repair {
                volume_id: VolumeId::from_bytes([1; 16])?,
                manifest_id: ContentManifestId::from_bytes([2; 16])?,
                stripe_index: 3,
                shard_index: 4,
                source_generation: 5,
            },
            WorkSubject::Scrub {
                target_id: TargetId::from_bytes([5; 16])?,
                target_generation: 6,
            },
            WorkSubject::Drain(DrainScope::Target {
                target_id: TargetId::from_bytes([7; 16])?,
                target_generation: 8,
            }),
            WorkSubject::Drain(DrainScope::Node {
                node_id: NodeId::from_bytes([9; 16])?,
                node_incarnation: 10,
            }),
            WorkSubject::Drain(DrainScope::FaultGroup {
                fault_group_id: FaultGroupId::from_bytes([11; 16])?,
            }),
            WorkSubject::Rebalance {
                volume_id: VolumeId::from_bytes([12; 16])?,
                topology_revision: Revision::new(13),
            },
            WorkSubject::Reconcile {
                target_id: TargetId::from_bytes([14; 16])?,
                target_generation: 15,
            },
        ];

        for subject in subjects {
            let encoded = subject.encode();
            assert!(encoded.len() <= MAXIMUM_WORK_SUBJECT_BYTES);
            assert_eq!(WorkSubject::decode(&encoded)?, subject);
            let mut with_trailing_byte = encoded;
            with_trailing_byte.push(0);
            assert_eq!(
                WorkSubject::decode(&with_trailing_byte),
                Err(WorkSubjectError::Invalid)
            );
        }
        Ok(())
    }

    #[test]
    fn actual_unavailability_outranks_age_heat_and_debt() {
        let now = UnixMicros::new(10_000_000_000);
        let routine = WorkSignals {
            data_unavailable: false,
            remaining_recovery_margin: 9,
            protection_debt: u16::MAX,
            locality_debt: u16::MAX,
            instability: u16::MAX,
            access_heat: u16::MAX,
            created_at: UnixMicros::new(1),
            due_at: Some(UnixMicros::new(1)),
        };
        let unavailable = WorkSignals {
            data_unavailable: true,
            remaining_recovery_margin: 0,
            protection_debt: 0,
            locality_debt: 0,
            instability: 0,
            access_heat: 0,
            created_at: now,
            due_at: None,
        };

        assert!(unavailable.priority(now) > routine.priority(now));
    }

    #[test]
    fn no_recovery_margin_bypasses_flap_debounce() {
        let now = UnixMicros::new(1_000);
        assert_eq!(
            repair_due_at(
                now,
                UnixMicros::new(900),
                0,
                u16::MAX,
                DurationMicros::new(500),
                DurationMicros::new(5_000),
            ),
            now
        );
    }

    #[test]
    fn repeated_flapping_shortens_but_cannot_extend_safe_debounce() {
        let absent_since = UnixMicros::new(1_000);
        let quiet = repair_due_at(
            UnixMicros::new(1_100),
            absent_since,
            2,
            0,
            DurationMicros::new(1_000),
            DurationMicros::new(5_000),
        );
        let unstable = repair_due_at(
            UnixMicros::new(1_100),
            absent_since,
            2,
            9,
            DurationMicros::new(1_000),
            DurationMicros::new(5_000),
        );

        assert_eq!(quiet, UnixMicros::new(2_000));
        assert_eq!(unstable, UnixMicros::new(1_100));
    }

    #[test]
    fn resource_admission_checks_jobs_bytes_and_overflow() -> Result<(), WorkBudgetError> {
        let budget = WorkBudget::new(2, 1_024, None)?;
        assert!(budget.admits(
            WorkUsage {
                active_jobs: 1,
                in_flight_bytes: 512,
            },
            WorkDemand {
                in_flight_bytes: 512,
            },
        ));
        assert!(!budget.admits(
            WorkUsage {
                active_jobs: 2,
                in_flight_bytes: 0,
            },
            WorkDemand { in_flight_bytes: 1 },
        ));
        assert!(!budget.admits(
            WorkUsage {
                active_jobs: 0,
                in_flight_bytes: u64::MAX,
            },
            WorkDemand { in_flight_bytes: 1 },
        ));
        Ok(())
    }
}
