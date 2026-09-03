// SPDX-License-Identifier: GPL-2.0-only

use std::cell::Cell;

use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_domain::{
    BackupId, DurationMicros, EntropyError, NodeId, PartitionId, PrincipalId, RandomSource,
    Revision, UnixMicros,
};
use meshspan_metadata::{
    ApplyDisposition, AuthoritativeCommand, CommandContext, CommandReceipt, EntityKind,
    EntityReference, LogPosition, MetadataBackupRun, MetadataBackupRunClaimRecord,
    MetadataBackupRunState, MetadataBackupSchedule, RepositoryError,
};

use crate::{
    MetadataBackupDispatchAuthority, MetadataBackupDispatchError, MetadataBackupDispatchOutcome,
    MetadataBackupDispatcher,
};

#[test]
fn dispatch_materialises_resumes_fences_and_surfaces_recorded_work()
-> Result<(), Box<dyn std::error::Error>> {
    let authority = MemoryAuthority::new(schedule()?);
    let first_node = NodeId::from_bytes([2; 16])?;
    let second_node = NodeId::from_bytes([3; 16])?;
    let actor = PrincipalId::from_bytes([4; 16])?;
    let mut random = CounterRandom::default();
    let first = MetadataBackupDispatcher::new(&authority, &mut random, first_node, 1, actor)
        .dispatch(UnixMicros::new(100), DurationMicros::new(100))?;
    let MetadataBackupDispatchOutcome::Claimed {
        run,
        claim: first_claim,
    } = first
    else {
        return Err("due run was not claimed".into());
    };
    assert_eq!(authority.commit_count.get(), 2);
    assert_eq!(first_claim.claim.claim_generation, 1);

    let resumed = MetadataBackupDispatcher::new(&authority, &mut random, first_node, 1, actor)
        .dispatch(UnixMicros::new(150), DurationMicros::new(100))?;
    assert_eq!(resumed, first);
    assert_eq!(authority.commit_count.get(), 2);

    let contended = MetadataBackupDispatcher::new(&authority, &mut random, second_node, 1, actor)
        .dispatch(UnixMicros::new(150), DurationMicros::new(100))?;
    assert_eq!(contended, MetadataBackupDispatchOutcome::Idle);
    assert_eq!(authority.commit_count.get(), 2);

    let replacement = MetadataBackupDispatcher::new(&authority, &mut random, second_node, 1, actor)
        .dispatch(UnixMicros::new(200), DurationMicros::new(100))?;
    let MetadataBackupDispatchOutcome::Claimed {
        claim: replacement_claim,
        ..
    } = replacement
    else {
        return Err("expired run was not reclaimed".into());
    };
    assert_eq!(replacement_claim.claim.claim_generation, 2);
    assert_eq!(replacement_claim.claim.worker_node_id, second_node);
    assert_ne!(replacement_claim.claim.fence, first_claim.claim.fence);
    assert_eq!(authority.commit_count.get(), 3);

    authority.run.set(Some(MetadataBackupRun {
        state: MetadataBackupRunState::Recorded,
        revision: Revision::new(4),
        ..run
    }));
    authority.claim.set(None);
    let recorded = MetadataBackupDispatcher::new(&authority, &mut random, second_node, 1, actor)
        .dispatch(UnixMicros::new(210), DurationMicros::new(100))?;
    assert!(matches!(
        recorded,
        MetadataBackupDispatchOutcome::AwaitingProtection { run: current }
            if current.backup_id == run.backup_id
    ));
    assert_eq!(authority.commit_count.get(), 3);
    Ok(())
}

#[test]
fn dispatch_rejects_unbounded_or_unfenced_work() -> Result<(), Box<dyn std::error::Error>> {
    let authority = MemoryAuthority::new(schedule()?);
    let node = NodeId::from_bytes([5; 16])?;
    let actor = PrincipalId::from_bytes([6; 16])?;
    let mut random = CounterRandom::default();
    assert!(matches!(
        MetadataBackupDispatcher::new(&authority, &mut random, node, 0, actor)
            .dispatch(UnixMicros::new(100), DurationMicros::new(100)),
        Err(MetadataBackupDispatchError::InvalidInput)
    ));
    assert!(matches!(
        MetadataBackupDispatcher::new(&authority, &mut random, node, 1, actor).dispatch(
            UnixMicros::new(100),
            DurationMicros::new(30 * 60 * 1_000_000 + 1)
        ),
        Err(MetadataBackupDispatchError::InvalidInput)
    ));
    assert_eq!(authority.commit_count.get(), 0);

    let mut future_schedule = schedule()?;
    future_schedule.next_due_at = UnixMicros::new(101);
    let future_authority = MemoryAuthority::new(future_schedule);
    future_authority.return_schedule_without_due_check.set(true);
    assert!(matches!(
        MetadataBackupDispatcher::new(&future_authority, &mut random, node, 1, actor)
            .dispatch(UnixMicros::new(100), DurationMicros::new(100)),
        Err(MetadataBackupDispatchError::InvalidProjection)
    ));
    assert_eq!(future_authority.commit_count.get(), 0);
    Ok(())
}

struct MemoryAuthority {
    schedule: Cell<Option<MetadataBackupSchedule>>,
    run: Cell<Option<MetadataBackupRun>>,
    claim: Cell<Option<MetadataBackupRunClaimRecord>>,
    commit_count: Cell<u64>,
    return_schedule_without_due_check: Cell<bool>,
}

impl MemoryAuthority {
    const fn new(schedule: MetadataBackupSchedule) -> Self {
        Self {
            schedule: Cell::new(Some(schedule)),
            run: Cell::new(None),
            claim: Cell::new(None),
            commit_count: Cell::new(0),
            return_schedule_without_due_check: Cell::new(false),
        }
    }

    fn commit_queue(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
        value: meshspan_metadata::QueueMetadataBackupRun,
    ) -> Result<CommandReceipt, MetadataAuthorityRequestError> {
        let schedule = self
            .schedule
            .get()
            .ok_or(MetadataAuthorityRequestError::Rejected)?;
        if self.run.get().is_some()
            || schedule.partition_id != value.partition_id
            || schedule.sequence != value.expected_schedule_sequence
            || schedule.next_due_at != value.scheduled_for
        {
            return Err(MetadataAuthorityRequestError::Rejected);
        }
        let revision = self.next_revision();
        self.run.set(Some(MetadataBackupRun {
            backup_id: value.backup_id,
            partition_id: value.partition_id,
            schedule_sequence: value.expected_schedule_sequence,
            run_sequence: schedule.run_sequence + 1,
            scheduled_for: value.scheduled_for,
            minimum_verified_copies: schedule.minimum_verified_copies,
            minimum_independent_copies: schedule.minimum_independent_copies,
            state: MetadataBackupRunState::Queued,
            completed_at: None,
            result_digest: None,
            revision,
        }));
        self.schedule.set(None);
        Ok(receipt(context, command, value.backup_id, revision))
    }

    fn commit_claim(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
        value: meshspan_metadata::ClaimMetadataBackupRun,
    ) -> Result<CommandReceipt, MetadataAuthorityRequestError> {
        let mut run = self
            .run
            .get()
            .ok_or(MetadataAuthorityRequestError::Rejected)?;
        let current = self.claim.get();
        let expected_generation = current.map_or(1, |stored| stored.claim.claim_generation + 1);
        if value.claim.claim_generation != expected_generation
            || current.is_some_and(|stored| stored.lease_expires_at > context.occurred_at)
        {
            return Err(MetadataAuthorityRequestError::Rejected);
        }
        let revision = self.next_revision();
        run.state = MetadataBackupRunState::Claimed;
        run.revision = revision;
        self.run.set(Some(run));
        self.claim.set(Some(MetadataBackupRunClaimRecord {
            backup_id: value.backup_id,
            claim: value.claim,
            lease_expires_at: value.lease_expires_at,
            revision,
        }));
        Ok(receipt(context, command, value.backup_id, revision))
    }

    fn next_revision(&self) -> Revision {
        let next = self.commit_count.get() + 1;
        self.commit_count.set(next);
        Revision::new(next)
    }
}

impl MetadataBackupDispatchAuthority for MemoryAuthority {
    fn due_metadata_backup_schedule(
        &self,
        now: UnixMicros,
    ) -> Result<Option<MetadataBackupSchedule>, RepositoryError> {
        Ok(self.schedule.get().filter(|value| {
            self.return_schedule_without_due_check.get()
                || (value.enabled && value.next_due_at <= now && self.run.get().is_none())
        }))
    }

    fn unfinished_metadata_backup_run(&self) -> Result<Option<MetadataBackupRun>, RepositoryError> {
        Ok(self.run.get())
    }

    fn metadata_backup_run_claim(
        &self,
        backup_id: BackupId,
    ) -> Result<Option<MetadataBackupRunClaimRecord>, RepositoryError> {
        Ok(self
            .claim
            .get()
            .filter(|value| value.backup_id == backup_id))
    }

    fn commit_metadata_backup_dispatch(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, MetadataAuthorityRequestError> {
        match command {
            AuthoritativeCommand::QueueMetadataBackupRun(value) => {
                self.commit_queue(context, command, *value)
            }
            AuthoritativeCommand::ClaimMetadataBackupRun(value) => {
                self.commit_claim(context, command, *value)
            }
            _ => Err(MetadataAuthorityRequestError::Rejected),
        }
    }
}

fn receipt(
    context: CommandContext,
    command: &AuthoritativeCommand,
    backup_id: BackupId,
    revision: Revision,
) -> CommandReceipt {
    let position = LogPosition {
        index: revision.get(),
        term: 1,
    };
    CommandReceipt {
        disposition: ApplyDisposition::Applied,
        operation_id: context.operation_id,
        request_digest: command.request_digest(context),
        result_digest: [7; 32],
        committed_revision: revision,
        committed_position: position,
        applied_position: position,
        entity: EntityReference {
            kind: EntityKind::MetadataBackupRun,
            id: backup_id.as_bytes(),
        },
    }
}

fn schedule() -> Result<MetadataBackupSchedule, meshspan_domain::IdentifierError> {
    Ok(MetadataBackupSchedule {
        partition_id: PartitionId::from_bytes([1; 16])?,
        sequence: 1,
        interval: DurationMicros::new(1_000),
        retained_generations: 4,
        minimum_verified_copies: 2,
        minimum_independent_copies: 1,
        enabled: true,
        next_due_at: UnixMicros::new(100),
        run_sequence: 0,
        revision: Revision::new(1),
    })
}

#[derive(Default)]
struct CounterRandom(u8);

impl RandomSource for CounterRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        self.0 = self.0.wrapping_add(1);
        for (index, byte) in destination.iter_mut().enumerate() {
            *byte = self.0.wrapping_add(u8::try_from(index).unwrap_or(u8::MAX));
        }
        Ok(())
    }
}
