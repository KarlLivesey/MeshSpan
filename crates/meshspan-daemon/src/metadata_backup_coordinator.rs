// SPDX-License-Identifier: GPL-2.0-only

//! Bounded composition of automatic metadata-backup lifecycle services.

use std::path::Path;

use meshspan_domain::{BackupId, DurationMicros, NodeId, PrincipalId, RandomSource, UnixMicros};
use meshspan_metadata::{
    BackupDestinationCursor, LocalDatabase, MetadataBackupProtectionEvidence, MetadataBackupRun,
    MetadataBackupRunClaimRecord,
};
use thiserror::Error;

use crate::{
    BackupPublicationAuthority, MetadataBackupCompletionAuthority, MetadataBackupCompletionError,
    MetadataBackupCompletionOutcome, MetadataBackupCompletionService,
    MetadataBackupDispatchAuthority, MetadataBackupDispatchError, MetadataBackupDispatchOutcome,
    MetadataBackupDispatcher, MetadataBackupPlacementAuthority, MetadataBackupPlacementError,
    MetadataBackupPlacementInput, MetadataBackupPlacementPage, MetadataBackupPlacementService,
    MetadataBackupPreparationAuthority, MetadataBackupPreparationError,
    MetadataBackupPreparationService, MetadataBackupProviderResolver, PreparedMetadataBackup,
    ResolvingMetadataBackupDestinationWriter,
};

/// Bounded timing and page limits for one backup-worker pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataBackupWorkerLimits {
    /// Authority lease retained across snapshot and placement work.
    pub lease_duration: DurationMicros,
    /// Maximum wall-clock authority interval for provider IO in this pass.
    pub provider_timeout: DurationMicros,
    /// Maximum destinations attempted in one pass.
    pub destination_page_items: usize,
}

/// Observable result of one finite automatic backup-worker pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataBackupWorkerOutcome {
    /// No work belongs to this daemon now.
    Idle,
    /// One page completed and an exact continuation remains.
    Progress {
        /// Backup generation being protected.
        backup_id: BackupId,
        /// Copies published during this pass.
        published: usize,
        /// Exact next destination seek position.
        next: BackupDestinationCursor,
        /// Current authority-recomputed protection evidence.
        evidence: MetadataBackupProtectionEvidence,
    },
    /// Every configured destination was considered but current policy is not yet protected.
    AwaitingDestinations {
        /// Backup generation awaiting another eligible destination or retry.
        backup_id: BackupId,
        /// Current authority-recomputed protection evidence.
        evidence: MetadataBackupProtectionEvidence,
    },
    /// The captured protection policy committed and local staging was released.
    Protected {
        /// Protected backup generation.
        backup_id: BackupId,
        /// Terminal authority revision.
        revision: meshspan_domain::Revision,
        /// Exact committed protection evidence.
        evidence: MetadataBackupProtectionEvidence,
    },
}

/// Lifecycle seam used by the stateful bounded worker.
pub trait MetadataBackupCycle {
    /// Discovers and fences at most one run.
    ///
    /// # Errors
    ///
    /// Fails closed when schedule, claim or consensus state cannot be resolved.
    fn dispatch(
        &mut self,
        now: UnixMicros,
        lease_duration: DurationMicros,
    ) -> Result<MetadataBackupDispatchOutcome, MetadataBackupCycleError>;

    /// Creates or resumes exact local encrypted bytes.
    ///
    /// # Errors
    ///
    /// Fails closed when exact encrypted staging cannot be proven durable.
    fn prepare(
        &mut self,
        run: MetadataBackupRun,
        now: UnixMicros,
    ) -> Result<PreparedMetadataBackup, MetadataBackupCycleError>;

    /// Publishes one bounded page of destinations.
    ///
    /// # Errors
    ///
    /// Fails closed when provider or replicated-copy evidence cannot be reconciled.
    fn place(
        &mut self,
        input: MetadataBackupCyclePlacement<'_>,
    ) -> Result<MetadataBackupPlacementPage, MetadataBackupCycleError>;

    /// Attempts evidence-bound terminal completion.
    ///
    /// # Errors
    ///
    /// Fails closed when current protection evidence or consensus is unavailable.
    fn complete(
        &mut self,
        backup_id: BackupId,
        now: UnixMicros,
    ) -> Result<MetadataBackupCompletionOutcome, MetadataBackupCycleError>;

    /// Releases exact local staging after authoritative protection.
    ///
    /// # Errors
    ///
    /// Fails closed when exact local ownership or durable deletion cannot be proven.
    fn release(
        &mut self,
        prepared: &PreparedMetadataBackup,
    ) -> Result<(), MetadataBackupCycleError>;
}

/// Placement inputs retained independently of provider implementation.
#[derive(Clone, Copy, Debug)]
pub struct MetadataBackupCyclePlacement<'a> {
    /// Current fenced run.
    pub run: MetadataBackupRun,
    /// Sole live worker claim.
    pub claim: MetadataBackupRunClaimRecord,
    /// Exact durable local bytes.
    pub prepared: &'a PreparedMetadataBackup,
    /// Seek continuation within the active destination inventory.
    pub after: Option<BackupDestinationCursor>,
    /// Authority time for this pass.
    pub now: UnixMicros,
    /// Strict provider IO deadline.
    pub deadline: UnixMicros,
    /// Maximum destinations attempted.
    pub page_items: usize,
}

/// Small stateful worker retaining only a best-effort in-process seek cursor.
#[derive(Default)]
pub struct MetadataBackupWorker {
    continuation: Option<(BackupId, BackupDestinationCursor)>,
}

impl MetadataBackupWorker {
    /// Executes at most one finite destination page and one terminal transition.
    ///
    /// # Errors
    ///
    /// Rejects invalid bounds and contradictory lifecycle outcomes. Component failures remain
    /// typed by phase; a retry can safely start from no cursor after process restart.
    pub fn run_once<Cycle: MetadataBackupCycle>(
        &mut self,
        cycle: &mut Cycle,
        now: UnixMicros,
        limits: MetadataBackupWorkerLimits,
    ) -> Result<MetadataBackupWorkerOutcome, MetadataBackupWorkerError> {
        validate_limits(now, limits)?;
        let (run, claim) = match cycle.dispatch(now, limits.lease_duration)? {
            MetadataBackupDispatchOutcome::Idle => {
                self.continuation = None;
                return Ok(MetadataBackupWorkerOutcome::Idle);
            }
            MetadataBackupDispatchOutcome::Claimed { run, claim }
            | MetadataBackupDispatchOutcome::AwaitingProtection { run, claim } => (run, claim),
        };
        let prepared = cycle.prepare(run, now)?;
        let after = self
            .continuation
            .filter(|(backup_id, _)| *backup_id == run.backup_id)
            .map(|(_, cursor)| cursor);
        let deadline = now
            .checked_add(limits.provider_timeout)
            .ok_or(MetadataBackupWorkerError::InvalidInput)?;
        let page = cycle.place(MetadataBackupCyclePlacement {
            run,
            claim,
            prepared: &prepared,
            after,
            now,
            deadline,
            page_items: limits.destination_page_items,
        })?;
        self.resolve_page(cycle, run.backup_id, &prepared, page, now)
    }

    fn resolve_page<Cycle: MetadataBackupCycle>(
        &mut self,
        cycle: &mut Cycle,
        backup_id: BackupId,
        prepared: &PreparedMetadataBackup,
        page: MetadataBackupPlacementPage,
        now: UnixMicros,
    ) -> Result<MetadataBackupWorkerOutcome, MetadataBackupWorkerError> {
        if let Some(next) = page.next {
            self.continuation = Some((backup_id, next));
            return Ok(MetadataBackupWorkerOutcome::Progress {
                backup_id,
                published: page.published,
                next,
                evidence: page.evidence,
            });
        }
        self.continuation = None;
        match cycle.complete(backup_id, now)? {
            MetadataBackupCompletionOutcome::AwaitingCopies { evidence } => {
                Ok(MetadataBackupWorkerOutcome::AwaitingDestinations {
                    backup_id,
                    evidence,
                })
            }
            MetadataBackupCompletionOutcome::Protected {
                backup_id: completed,
                revision,
                evidence,
                ..
            } if completed == backup_id => {
                cycle.release(prepared)?;
                Ok(MetadataBackupWorkerOutcome::Protected {
                    backup_id,
                    revision,
                    evidence,
                })
            }
            MetadataBackupCompletionOutcome::Protected { .. } => {
                Err(MetadataBackupWorkerError::InvalidProjection)
            }
        }
    }
}

/// Production composition of durable lifecycle services behind [`MetadataBackupCycle`].
pub struct ComposedMetadataBackupCycle<'a, Authority, Resolver, Random> {
    /// Shared replicated read/mutation authority.
    pub authority: &'a Authority,
    /// Identity-bound daemon-local journal.
    pub local: &'a mut LocalDatabase,
    /// Runtime provider resolver.
    pub resolver: &'a mut Resolver,
    /// Cryptographic entropy source.
    pub random: &'a mut Random,
    /// Canonical private daemon-state root.
    pub state_directory: &'a Path,
    /// Local node executing work.
    pub worker_node_id: NodeId,
    /// Current process incarnation.
    pub worker_incarnation: u64,
    /// Authoritative automation principal.
    pub actor_principal_id: PrincipalId,
}

impl<Authority, Resolver, Random> MetadataBackupCycle
    for ComposedMetadataBackupCycle<'_, Authority, Resolver, Random>
where
    Authority: MetadataBackupDispatchAuthority
        + MetadataBackupPreparationAuthority
        + MetadataBackupPlacementAuthority
        + MetadataBackupCompletionAuthority
        + BackupPublicationAuthority,
    Resolver: MetadataBackupProviderResolver,
    Random: RandomSource,
{
    fn dispatch(
        &mut self,
        now: UnixMicros,
        lease_duration: DurationMicros,
    ) -> Result<MetadataBackupDispatchOutcome, MetadataBackupCycleError> {
        MetadataBackupDispatcher::new(
            self.authority,
            self.random,
            self.worker_node_id,
            self.worker_incarnation,
            self.actor_principal_id,
        )
        .dispatch(now, lease_duration)
        .map_err(Into::into)
    }

    fn prepare(
        &mut self,
        run: MetadataBackupRun,
        now: UnixMicros,
    ) -> Result<PreparedMetadataBackup, MetadataBackupCycleError> {
        MetadataBackupPreparationService::open(
            self.authority,
            self.local,
            self.random,
            self.state_directory,
        )?
        .prepare(run, now)
        .map_err(Into::into)
    }

    fn place(
        &mut self,
        input: MetadataBackupCyclePlacement<'_>,
    ) -> Result<MetadataBackupPlacementPage, MetadataBackupCycleError> {
        let mut writer =
            ResolvingMetadataBackupDestinationWriter::new(self.authority, self.resolver);
        MetadataBackupPlacementService::new(self.authority, &mut writer)
            .publish_page(MetadataBackupPlacementInput {
                run: input.run,
                claim: input.claim.claim,
                encrypted_source: &input.prepared.encrypted_path,
                backup: input.prepared.staging.evidence,
                actor_principal_id: self.actor_principal_id,
                now: input.now,
                deadline: input.deadline,
                after: input.after,
                page_items: input.page_items,
            })
            .map_err(Into::into)
    }

    fn complete(
        &mut self,
        backup_id: BackupId,
        now: UnixMicros,
    ) -> Result<MetadataBackupCompletionOutcome, MetadataBackupCycleError> {
        MetadataBackupCompletionService::new(self.authority, self.random, self.actor_principal_id)
            .complete_if_protected(backup_id, now)
            .map_err(Into::into)
    }

    fn release(
        &mut self,
        prepared: &PreparedMetadataBackup,
    ) -> Result<(), MetadataBackupCycleError> {
        MetadataBackupPreparationService::open(
            self.authority,
            self.local,
            self.random,
            self.state_directory,
        )?
        .release(prepared)
        .map_err(Into::into)
    }
}

fn validate_limits(
    now: UnixMicros,
    limits: MetadataBackupWorkerLimits,
) -> Result<(), MetadataBackupWorkerError> {
    if now.get() < 0
        || limits.lease_duration.get() == 0
        || limits.provider_timeout.get() == 0
        || limits.destination_page_items == 0
    {
        Err(MetadataBackupWorkerError::InvalidInput)
    } else {
        Ok(())
    }
}

/// Failure inside one composed backup lifecycle phase.
#[derive(Debug, Error)]
pub enum MetadataBackupCycleError {
    /// Dispatch or fencing failed.
    #[error("metadata backup dispatch failed")]
    Dispatch(#[from] MetadataBackupDispatchError),
    /// Encrypted staging failed.
    #[error("metadata backup preparation failed")]
    Preparation(#[from] MetadataBackupPreparationError),
    /// Destination placement failed.
    #[error("metadata backup placement failed")]
    Placement(#[from] MetadataBackupPlacementError),
    /// Evidence-bound completion failed.
    #[error("metadata backup completion failed")]
    Completion(#[from] MetadataBackupCompletionError),
}

/// Closed failure from one bounded backup-worker pass.
#[derive(Debug, Error)]
pub enum MetadataBackupWorkerError {
    /// Time or worker limits were invalid.
    #[error("metadata backup worker input was invalid")]
    InvalidInput,
    /// Lifecycle components returned contradictory identities.
    #[error("metadata backup worker projection was invalid")]
    InvalidProjection,
    /// One lifecycle phase failed closed.
    #[error("metadata backup worker cycle failed")]
    Cycle(#[from] MetadataBackupCycleError),
}
