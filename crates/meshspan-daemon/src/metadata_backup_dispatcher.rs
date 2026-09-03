// SPDX-License-Identifier: GPL-2.0-only

//! Restart-safe admission of due metadata backups to one fenced daemon worker.

use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_domain::{
    AuditEventId, BackupId, DurationMicros, EntropyError, NodeId, OperationId, PrincipalId,
    RandomSource, UnixMicros, uuid_v8,
};
use meshspan_metadata::{
    AuthoritativeCommand, ClaimMetadataBackupRun, CommandContext, CommandReceipt, EntityKind,
    MetadataBackupRun, MetadataBackupRunClaim, MetadataBackupRunClaimRecord,
    MetadataBackupRunState, MetadataBackupSchedule, QueueMetadataBackupRun, RepositoryError,
};
use thiserror::Error;

use crate::ConsensusAuthenticationAuthority;

const MAXIMUM_CLAIM_LEASE_MICROS: u64 = 30 * 60 * 1_000_000;

/// Replicated reads and mutations required to discover and fence automatic backup work.
pub trait MetadataBackupDispatchAuthority {
    /// Returns the current due schedule when no unfinished run exists.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed or unavailable replicated state.
    fn due_metadata_backup_schedule(
        &self,
        now: UnixMicros,
    ) -> Result<Option<MetadataBackupSchedule>, RepositoryError>;

    /// Returns the partition's sole non-terminal run.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed or unavailable replicated state.
    fn unfinished_metadata_backup_run(&self) -> Result<Option<MetadataBackupRun>, RepositoryError>;

    /// Returns the current active claim, including an expired claim awaiting supersession.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed or unavailable replicated state.
    fn metadata_backup_run_claim(
        &self,
        backup_id: BackupId,
    ) -> Result<Option<MetadataBackupRunClaimRecord>, RepositoryError>;

    /// Commits or resolves one exact queue or claim command through consensus.
    ///
    /// # Errors
    ///
    /// Never reports success without a durable authoritative receipt.
    fn commit_metadata_backup_dispatch(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, MetadataAuthorityRequestError>;
}

impl MetadataBackupDispatchAuthority for ConsensusAuthenticationAuthority {
    fn due_metadata_backup_schedule(
        &self,
        now: UnixMicros,
    ) -> Result<Option<MetadataBackupSchedule>, RepositoryError> {
        self.reader().due_metadata_backup_schedule(now)
    }

    fn unfinished_metadata_backup_run(&self) -> Result<Option<MetadataBackupRun>, RepositoryError> {
        self.reader().unfinished_metadata_backup_run()
    }

    fn metadata_backup_run_claim(
        &self,
        backup_id: BackupId,
    ) -> Result<Option<MetadataBackupRunClaimRecord>, RepositoryError> {
        self.reader().metadata_backup_run_claim(backup_id)
    }

    fn commit_metadata_backup_dispatch(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, MetadataAuthorityRequestError> {
        self.commit_authoritative(context, command)
    }
}

/// Exact work selected by one bounded dispatcher pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataBackupDispatchOutcome {
    /// No run is due or another worker owns the live claim.
    Idle,
    /// This exact daemon incarnation owns a live run claim.
    Claimed {
        /// Current run projection.
        run: MetadataBackupRun,
        /// Exact live claim and lease.
        claim: MetadataBackupRunClaimRecord,
    },
    /// Backup bytes exist and the run needs further copy verification or terminal completion.
    AwaitingProtection {
        /// Current recorded run projection.
        run: MetadataBackupRun,
    },
}

/// Bounded due-run dispatcher for one daemon incarnation.
pub struct MetadataBackupDispatcher<'a, Authority, Random> {
    authority: &'a Authority,
    random: &'a mut Random,
    worker_node_id: NodeId,
    worker_incarnation: u64,
    actor_principal_id: PrincipalId,
}

impl<'a, Authority, Random> MetadataBackupDispatcher<'a, Authority, Random> {
    /// Binds dispatch to one exact local daemon incarnation and automation principal.
    #[must_use]
    pub const fn new(
        authority: &'a Authority,
        random: &'a mut Random,
        worker_node_id: NodeId,
        worker_incarnation: u64,
        actor_principal_id: PrincipalId,
    ) -> Self {
        Self {
            authority,
            random,
            worker_node_id,
            worker_incarnation,
            actor_principal_id,
        }
    }
}

impl<Authority, Random> MetadataBackupDispatcher<'_, Authority, Random>
where
    Authority: MetadataBackupDispatchAuthority,
    Random: RandomSource,
{
    /// Discovers, materialises and claims at most one automatic backup occurrence.
    ///
    /// A restart first discovers the unfinished authoritative run. It never creates a second
    /// generation while an earlier one is queued, claimed or awaiting protection.
    ///
    /// # Errors
    ///
    /// Rejects invalid worker identity or lease bounds, entropy failure, unavailable consensus,
    /// contradictory projections and malformed durable receipts.
    pub fn dispatch(
        &mut self,
        now: UnixMicros,
        lease_duration: DurationMicros,
    ) -> Result<MetadataBackupDispatchOutcome, MetadataBackupDispatchError> {
        validate_request(now, self.worker_incarnation, lease_duration)?;
        let run = match self.authority.unfinished_metadata_backup_run()? {
            Some(run) => run,
            None => match self.materialise_due_run(now)? {
                Some(run) => run,
                None => return Ok(MetadataBackupDispatchOutcome::Idle),
            },
        };
        self.dispatch_run(now, lease_duration, run)
    }

    fn materialise_due_run(
        &mut self,
        now: UnixMicros,
    ) -> Result<Option<MetadataBackupRun>, MetadataBackupDispatchError> {
        let Some(schedule) = self.authority.due_metadata_backup_schedule(now)? else {
            return Ok(None);
        };
        if !schedule.enabled
            || schedule.sequence == 0
            || schedule.interval.get() == 0
            || schedule.retained_generations == 0
            || schedule.minimum_verified_copies == 0
            || schedule.minimum_independent_copies > schedule.minimum_verified_copies
            || schedule.next_due_at > now
        {
            return Err(MetadataBackupDispatchError::InvalidProjection);
        }
        let expected_run_sequence = schedule
            .run_sequence
            .checked_add(1)
            .ok_or(MetadataBackupDispatchError::Capacity)?;
        let (backup_id, operation_id, audit_event_id) = queue_identities(self.random)?;
        let context = CommandContext {
            operation_id,
            actor_principal_id: self.actor_principal_id,
            audit_event_id,
            occurred_at: now,
            expected_revision: None,
        };
        let command = AuthoritativeCommand::QueueMetadataBackupRun(QueueMetadataBackupRun {
            backup_id,
            partition_id: schedule.partition_id,
            expected_schedule_sequence: schedule.sequence,
            scheduled_for: schedule.next_due_at,
        });
        match self
            .authority
            .commit_metadata_backup_dispatch(context, &command)
        {
            Ok(receipt) => validate_receipt(
                receipt,
                context,
                &command,
                backup_id,
                EntityKind::MetadataBackupRun,
            )?,
            Err(MetadataAuthorityRequestError::Rejected) => {
                return self
                    .authority
                    .unfinished_metadata_backup_run()
                    .map_err(Into::into);
            }
            Err(error) => return Err(error.into()),
        }
        let run = self
            .authority
            .unfinished_metadata_backup_run()?
            .ok_or(MetadataBackupDispatchError::InvalidProjection)?;
        if run.backup_id != backup_id
            || run.partition_id != schedule.partition_id
            || run.schedule_sequence != schedule.sequence
            || run.run_sequence != expected_run_sequence
            || run.scheduled_for != schedule.next_due_at
            || run.minimum_verified_copies != schedule.minimum_verified_copies
            || run.minimum_independent_copies != schedule.minimum_independent_copies
            || run.state != MetadataBackupRunState::Queued
        {
            return Err(MetadataBackupDispatchError::InvalidProjection);
        }
        Ok(Some(run))
    }

    fn dispatch_run(
        &mut self,
        now: UnixMicros,
        lease_duration: DurationMicros,
        run: MetadataBackupRun,
    ) -> Result<MetadataBackupDispatchOutcome, MetadataBackupDispatchError> {
        match run.state {
            MetadataBackupRunState::Recorded => {
                Ok(MetadataBackupDispatchOutcome::AwaitingProtection { run })
            }
            MetadataBackupRunState::Queued | MetadataBackupRunState::Claimed => {
                self.claim_run(now, lease_duration, run)
            }
            MetadataBackupRunState::Protected | MetadataBackupRunState::Incomplete => {
                Err(MetadataBackupDispatchError::InvalidProjection)
            }
        }
    }

    fn claim_run(
        &mut self,
        now: UnixMicros,
        lease_duration: DurationMicros,
        run: MetadataBackupRun,
    ) -> Result<MetadataBackupDispatchOutcome, MetadataBackupDispatchError> {
        let current = self.authority.metadata_backup_run_claim(run.backup_id)?;
        if let Some(claim) = current {
            validate_claim_projection(run.backup_id, claim)?;
            if claim.lease_expires_at > now {
                return self.resolve_live_claim(run, claim);
            }
        }
        let generation = current.map_or(Ok(1), |value| {
            value
                .claim
                .claim_generation
                .checked_add(1)
                .ok_or(MetadataBackupDispatchError::Capacity)
        })?;
        self.commit_claim(now, lease_duration, run, generation)
    }

    fn commit_claim(
        &mut self,
        now: UnixMicros,
        lease_duration: DurationMicros,
        run: MetadataBackupRun,
        claim_generation: u64,
    ) -> Result<MetadataBackupDispatchOutcome, MetadataBackupDispatchError> {
        let lease_expires_at = now
            .checked_add(lease_duration)
            .ok_or(MetadataBackupDispatchError::InvalidInput)?;
        let (operation_id, audit_event_id, fence) = claim_identities(self.random)?;
        let claim = MetadataBackupRunClaim {
            claim_generation,
            worker_node_id: self.worker_node_id,
            worker_incarnation: self.worker_incarnation,
            fence,
        };
        let context = CommandContext {
            operation_id,
            actor_principal_id: self.actor_principal_id,
            audit_event_id,
            occurred_at: now,
            expected_revision: None,
        };
        let command = AuthoritativeCommand::ClaimMetadataBackupRun(ClaimMetadataBackupRun {
            backup_id: run.backup_id,
            claim,
            lease_expires_at,
        });
        match self
            .authority
            .commit_metadata_backup_dispatch(context, &command)
        {
            Ok(receipt) => validate_receipt(
                receipt,
                context,
                &command,
                run.backup_id,
                EntityKind::MetadataBackupRun,
            )?,
            Err(MetadataAuthorityRequestError::Rejected) => {
                return self.resolve_claim_race(now, run);
            }
            Err(error) => return Err(error.into()),
        }
        let current_run = self
            .authority
            .unfinished_metadata_backup_run()?
            .ok_or(MetadataBackupDispatchError::InvalidProjection)?;
        let current_claim = self
            .authority
            .metadata_backup_run_claim(run.backup_id)?
            .ok_or(MetadataBackupDispatchError::InvalidProjection)?;
        if current_run.backup_id != run.backup_id
            || current_run.state != MetadataBackupRunState::Claimed
            || current_claim.claim != claim
            || current_claim.lease_expires_at != lease_expires_at
        {
            return Err(MetadataBackupDispatchError::InvalidProjection);
        }
        Ok(MetadataBackupDispatchOutcome::Claimed {
            run: current_run,
            claim: current_claim,
        })
    }

    fn resolve_claim_race(
        &self,
        now: UnixMicros,
        prior: MetadataBackupRun,
    ) -> Result<MetadataBackupDispatchOutcome, MetadataBackupDispatchError> {
        let current = self
            .authority
            .unfinished_metadata_backup_run()?
            .ok_or(MetadataBackupDispatchError::InvalidProjection)?;
        if current.backup_id != prior.backup_id {
            return Err(MetadataBackupDispatchError::InvalidProjection);
        }
        if current.state == MetadataBackupRunState::Recorded {
            return Ok(MetadataBackupDispatchOutcome::AwaitingProtection { run: current });
        }
        let claim = self
            .authority
            .metadata_backup_run_claim(current.backup_id)?
            .ok_or(MetadataBackupDispatchError::InvalidProjection)?;
        if claim.lease_expires_at <= now {
            return Err(MetadataBackupDispatchError::InvalidProjection);
        }
        self.resolve_live_claim(current, claim)
    }

    fn resolve_live_claim(
        &self,
        run: MetadataBackupRun,
        claim: MetadataBackupRunClaimRecord,
    ) -> Result<MetadataBackupDispatchOutcome, MetadataBackupDispatchError> {
        if run.state != MetadataBackupRunState::Claimed || claim.backup_id != run.backup_id {
            return Err(MetadataBackupDispatchError::InvalidProjection);
        }
        if claim.claim.worker_node_id == self.worker_node_id
            && claim.claim.worker_incarnation == self.worker_incarnation
        {
            Ok(MetadataBackupDispatchOutcome::Claimed { run, claim })
        } else {
            Ok(MetadataBackupDispatchOutcome::Idle)
        }
    }
}

fn validate_request(
    now: UnixMicros,
    worker_incarnation: u64,
    lease_duration: DurationMicros,
) -> Result<(), MetadataBackupDispatchError> {
    if now.get() < 0
        || worker_incarnation == 0
        || lease_duration.get() == 0
        || lease_duration.get() > MAXIMUM_CLAIM_LEASE_MICROS
    {
        Err(MetadataBackupDispatchError::InvalidInput)
    } else {
        Ok(())
    }
}

fn validate_receipt(
    receipt: CommandReceipt,
    context: CommandContext,
    command: &AuthoritativeCommand,
    backup_id: BackupId,
    entity_kind: EntityKind,
) -> Result<(), MetadataBackupDispatchError> {
    if receipt.operation_id != context.operation_id
        || receipt.request_digest != command.request_digest(context)
        || receipt.result_digest == [0; 32]
        || receipt.entity.kind != entity_kind
        || receipt.entity.id != backup_id.as_bytes()
    {
        Err(MetadataBackupDispatchError::InvalidReceipt)
    } else {
        Ok(())
    }
}

fn validate_claim_projection(
    backup_id: BackupId,
    claim: MetadataBackupRunClaimRecord,
) -> Result<(), MetadataBackupDispatchError> {
    if claim.backup_id != backup_id
        || claim.claim.claim_generation == 0
        || claim.claim.worker_incarnation == 0
        || claim.claim.fence == 0
    {
        Err(MetadataBackupDispatchError::InvalidProjection)
    } else {
        Ok(())
    }
}

fn queue_identities(
    random: &mut impl RandomSource,
) -> Result<(BackupId, OperationId, AuditEventId), MetadataBackupDispatchError> {
    let mut bytes = [0_u8; 48];
    random.fill_bytes(&mut bytes)?;
    let backup = BackupId::from_bytes(uuid_v8(identifier(&bytes[..16])?))?;
    let operation = OperationId::from_bytes(uuid_v8(identifier(&bytes[16..32])?))?;
    let audit = AuditEventId::from_bytes(uuid_v8(identifier(&bytes[32..])?))?;
    if backup.as_bytes() == operation.as_bytes()
        || backup.as_bytes() == audit.as_bytes()
        || operation.as_bytes() == audit.as_bytes()
    {
        return Err(MetadataBackupDispatchError::InvalidInput);
    }
    Ok((backup, operation, audit))
}

fn claim_identities(
    random: &mut impl RandomSource,
) -> Result<(OperationId, AuditEventId, u64), MetadataBackupDispatchError> {
    let mut bytes = [0_u8; 40];
    random.fill_bytes(&mut bytes)?;
    let operation = OperationId::from_bytes(uuid_v8(identifier(&bytes[..16])?))?;
    let audit = AuditEventId::from_bytes(uuid_v8(identifier(&bytes[16..32])?))?;
    let fence = u64::from_be_bytes(identifier8(&bytes[32..])?);
    if operation.as_bytes() == audit.as_bytes() || fence == 0 {
        return Err(MetadataBackupDispatchError::InvalidInput);
    }
    Ok((operation, audit, fence))
}

fn identifier(value: &[u8]) -> Result<[u8; 16], MetadataBackupDispatchError> {
    value
        .try_into()
        .map_err(|_| MetadataBackupDispatchError::InvalidInput)
}

fn identifier8(value: &[u8]) -> Result<[u8; 8], MetadataBackupDispatchError> {
    value
        .try_into()
        .map_err(|_| MetadataBackupDispatchError::InvalidInput)
}

/// Closed failure from one bounded metadata-backup dispatch pass.
#[derive(Debug, Error)]
pub enum MetadataBackupDispatchError {
    /// Worker identity, time or lease bounds are invalid.
    #[error("metadata backup dispatch input is invalid")]
    InvalidInput,
    /// Replicated schedule, run or claim state contradicted itself.
    #[error("metadata backup dispatch projection is invalid")]
    InvalidProjection,
    /// A durable receipt did not exactly identify the attempted transition.
    #[error("metadata backup dispatch receipt is invalid")]
    InvalidReceipt,
    /// A monotonic generation cannot advance safely.
    #[error("metadata backup dispatch capacity was exceeded")]
    Capacity,
    /// Replicated metadata could not be read safely.
    #[error("metadata backup dispatch metadata failed")]
    Repository(#[from] RepositoryError),
    /// Consensus could not durably resolve the requested transition.
    #[error("metadata backup dispatch authority failed")]
    Authority(#[from] MetadataAuthorityRequestError),
    /// Cryptographically unpredictable identities could not be generated.
    #[error("metadata backup dispatch entropy failed")]
    Entropy(#[from] EntropyError),
    /// A generated typed identifier was invalid.
    #[error("metadata backup dispatch identifier was invalid")]
    Identifier(#[from] meshspan_domain::IdentifierError),
}
