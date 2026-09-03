// SPDX-License-Identifier: GPL-2.0-only

//! Evidence-bound terminal completion of protected metadata-backup runs.

use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_domain::{
    AuditEventId, BackupId, EntropyError, OperationId, PrincipalId, RandomSource, UnixMicros,
    uuid_v8,
};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, CommandReceipt, CompleteMetadataBackupRun, EntityKind,
    MetadataBackupProtectionEvidence, MetadataBackupRecord, MetadataBackupRun,
    MetadataBackupRunCompletion, MetadataBackupRunState, MetadataBackupState, RepositoryError,
};
use thiserror::Error;

use crate::ConsensusAuthenticationAuthority;

/// Replicated reads and mutation needed to complete one protected backup run.
pub trait MetadataBackupCompletionAuthority {
    /// Loads the current run projection.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed or unavailable replicated state.
    fn metadata_backup_run(
        &self,
        backup_id: BackupId,
    ) -> Result<Option<MetadataBackupRun>, RepositoryError>;

    /// Recomputes canonical evidence for current verified copies.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed copy, destination or provider-generation state.
    fn metadata_backup_protection_evidence(
        &self,
        backup_id: BackupId,
    ) -> Result<MetadataBackupProtectionEvidence, RepositoryError>;

    /// Loads the admitted backup generation after terminal completion.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed or unavailable replicated state.
    fn metadata_backup(
        &self,
        backup_id: BackupId,
    ) -> Result<Option<MetadataBackupRecord>, RepositoryError>;

    /// Commits or resolves one exact terminal transition through consensus.
    ///
    /// # Errors
    ///
    /// Never reports success without a durable authoritative receipt.
    fn commit_metadata_backup_completion(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, MetadataAuthorityRequestError>;
}

impl MetadataBackupCompletionAuthority for ConsensusAuthenticationAuthority {
    fn metadata_backup_run(
        &self,
        backup_id: BackupId,
    ) -> Result<Option<MetadataBackupRun>, RepositoryError> {
        self.reader().metadata_backup_run(backup_id)
    }

    fn metadata_backup_protection_evidence(
        &self,
        backup_id: BackupId,
    ) -> Result<MetadataBackupProtectionEvidence, RepositoryError> {
        self.reader().metadata_backup_protection_evidence(backup_id)
    }

    fn metadata_backup(
        &self,
        backup_id: BackupId,
    ) -> Result<Option<MetadataBackupRecord>, RepositoryError> {
        self.reader().metadata_backup(backup_id)
    }

    fn commit_metadata_backup_completion(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, MetadataAuthorityRequestError> {
        self.commit_authoritative(context, command)
    }
}

/// Result of checking one recorded run against its captured protection threshold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataBackupCompletionOutcome {
    /// Current verified copies do not yet satisfy the run's captured policy.
    AwaitingCopies {
        /// Exact canonical evidence evaluated by this pass.
        evidence: MetadataBackupProtectionEvidence,
    },
    /// Authority committed the run and backup generation as protected.
    Protected {
        /// Protected generation.
        backup_id: BackupId,
        /// Authoritative completion instant.
        completed_at: UnixMicros,
        /// Terminal authoritative revision.
        revision: meshspan_domain::Revision,
        /// Exact copy evidence committed by the transition.
        evidence: MetadataBackupProtectionEvidence,
    },
}

/// Completes recorded runs only after authority-derived copy evidence satisfies policy.
pub struct MetadataBackupCompletionService<'a, Authority, Random> {
    authority: &'a Authority,
    random: &'a mut Random,
    actor_principal_id: PrincipalId,
}

impl<'a, Authority, Random> MetadataBackupCompletionService<'a, Authority, Random> {
    /// Binds completion to one authority and automation principal.
    #[must_use]
    pub const fn new(
        authority: &'a Authority,
        random: &'a mut Random,
        actor_principal_id: PrincipalId,
    ) -> Self {
        Self {
            authority,
            random,
            actor_principal_id,
        }
    }
}

impl<Authority, Random> MetadataBackupCompletionService<'_, Authority, Random>
where
    Authority: MetadataBackupCompletionAuthority,
    Random: RandomSource,
{
    /// Completes `backup_id` if and only if current verified-copy evidence meets captured policy.
    ///
    /// # Errors
    ///
    /// Rejects invalid time, absent or contradictory state, entropy failure, unavailable
    /// consensus, substituted receipts and any terminal projection that does not match evidence.
    pub fn complete_if_protected(
        &mut self,
        backup_id: BackupId,
        now: UnixMicros,
    ) -> Result<MetadataBackupCompletionOutcome, MetadataBackupCompletionError> {
        if now.get() < 0 {
            return Err(MetadataBackupCompletionError::InvalidInput);
        }
        let run = self
            .authority
            .metadata_backup_run(backup_id)?
            .ok_or(MetadataBackupCompletionError::InvalidProjection)?;
        if run.backup_id != backup_id || run.state != MetadataBackupRunState::Recorded {
            return Err(MetadataBackupCompletionError::InvalidProjection);
        }
        let evidence = self
            .authority
            .metadata_backup_protection_evidence(backup_id)?;
        if evidence.backup_id != backup_id {
            return Err(MetadataBackupCompletionError::InvalidProjection);
        }
        if evidence.verified_copies < u64::from(run.minimum_verified_copies)
            || evidence.independent_copies < u64::from(run.minimum_independent_copies)
        {
            return Ok(MetadataBackupCompletionOutcome::AwaitingCopies { evidence });
        }
        self.commit_protected(run, evidence, now)
    }

    fn commit_protected(
        &mut self,
        run: MetadataBackupRun,
        evidence: MetadataBackupProtectionEvidence,
        now: UnixMicros,
    ) -> Result<MetadataBackupCompletionOutcome, MetadataBackupCompletionError> {
        let (operation_id, audit_event_id) = random_identities(self.random)?;
        let context = CommandContext {
            operation_id,
            actor_principal_id: self.actor_principal_id,
            audit_event_id,
            occurred_at: now,
            expected_revision: None,
        };
        let command = AuthoritativeCommand::CompleteMetadataBackupRun(CompleteMetadataBackupRun {
            backup_id: run.backup_id,
            outcome: MetadataBackupRunCompletion::Protected {
                result_digest: evidence.digest,
            },
        });
        let receipt = self
            .authority
            .commit_metadata_backup_completion(context, &command)?;
        validate_receipt(receipt, context, &command, run.backup_id)?;
        let completed = self
            .authority
            .metadata_backup_run(run.backup_id)?
            .ok_or(MetadataBackupCompletionError::InvalidProjection)?;
        let backup = self
            .authority
            .metadata_backup(run.backup_id)?
            .ok_or(MetadataBackupCompletionError::InvalidProjection)?;
        if completed.state != MetadataBackupRunState::Protected
            || completed.completed_at != Some(now)
            || completed.result_digest != Some(evidence.digest)
            || completed.revision != receipt.committed_revision
            || backup.backup_id != run.backup_id
            || backup.state != MetadataBackupState::Verified
        {
            return Err(MetadataBackupCompletionError::InvalidProjection);
        }
        Ok(MetadataBackupCompletionOutcome::Protected {
            backup_id: run.backup_id,
            completed_at: now,
            revision: completed.revision,
            evidence,
        })
    }
}

fn validate_receipt(
    receipt: CommandReceipt,
    context: CommandContext,
    command: &AuthoritativeCommand,
    backup_id: BackupId,
) -> Result<(), MetadataBackupCompletionError> {
    if receipt.operation_id != context.operation_id
        || receipt.request_digest != command.request_digest(context)
        || receipt.result_digest == [0; 32]
        || receipt.entity.kind != EntityKind::MetadataBackupRun
        || receipt.entity.id != backup_id.as_bytes()
    {
        Err(MetadataBackupCompletionError::InvalidReceipt)
    } else {
        Ok(())
    }
}

fn random_identities(
    random: &mut impl RandomSource,
) -> Result<(OperationId, AuditEventId), MetadataBackupCompletionError> {
    let mut bytes = [0_u8; 32];
    random.fill_bytes(&mut bytes)?;
    let operation = OperationId::from_bytes(uuid_v8(identifier(&bytes[..16])?))?;
    let audit = AuditEventId::from_bytes(uuid_v8(identifier(&bytes[16..])?))?;
    if operation.as_bytes() == audit.as_bytes() {
        return Err(MetadataBackupCompletionError::InvalidInput);
    }
    Ok((operation, audit))
}

fn identifier(value: &[u8]) -> Result<[u8; 16], MetadataBackupCompletionError> {
    value
        .try_into()
        .map_err(|_| MetadataBackupCompletionError::InvalidInput)
}

/// Closed failure from evidence-bound backup completion.
#[derive(Debug, Error)]
pub enum MetadataBackupCompletionError {
    /// Time or generated identity input is invalid.
    #[error("metadata backup completion input is invalid")]
    InvalidInput,
    /// Run, evidence or terminal backup state contradicted itself.
    #[error("metadata backup completion projection is invalid")]
    InvalidProjection,
    /// A durable receipt did not exactly identify the attempted completion.
    #[error("metadata backup completion receipt is invalid")]
    InvalidReceipt,
    /// Replicated metadata could not be read safely.
    #[error("metadata backup completion metadata failed")]
    Repository(#[from] RepositoryError),
    /// Consensus could not durably resolve terminal completion.
    #[error("metadata backup completion authority failed")]
    Authority(#[from] MetadataAuthorityRequestError),
    /// Cryptographically unpredictable operation identities could not be generated.
    #[error("metadata backup completion entropy failed")]
    Entropy(#[from] EntropyError),
    /// A generated typed identifier was invalid.
    #[error("metadata backup completion identifier was invalid")]
    Identifier(#[from] meshspan_domain::IdentifierError),
}
