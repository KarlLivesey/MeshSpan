// SPDX-License-Identifier: GPL-2.0-only

//! Bounded automatic retirement and receipt-backed provider space reclamation.

mod authority;
mod deletion;

use meshspan_domain::{AuditEventId, OperationId, PrincipalId, RandomSource, UnixMicros, uuid_v8};
use meshspan_metadata::{
    AuthoritativeCommand, BackupReclamationCursor, CommandContext, CommandReceipt, EntityKind,
    PageLimit,
};
use thiserror::Error;

use crate::{MetadataBackupProviderResolver, MetadataBackupWorkerLimits};
pub(crate) use authority::BackupRetentionAuthority;

/// Only a fairness cursor is volatile; unfinished cleanup remains in replicated metadata.
#[derive(Default)]
pub(crate) struct MetadataBackupRetentionWorker {
    cursor: Option<BackupReclamationCursor>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BackupRetentionOutcome {
    pub retired: bool,
    pub reclaimed: usize,
    pub failed: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct BackupRetentionInput {
    pub actor: PrincipalId,
    pub now: UnixMicros,
    pub limits: MetadataBackupWorkerLimits,
}

impl MetadataBackupRetentionWorker {
    /// One candidate and one bounded cleanup page; a failed provider cannot starve later pages.
    pub(crate) fn run_once(
        &mut self,
        authority: &impl BackupRetentionAuthority,
        resolver: &mut impl MetadataBackupProviderResolver,
        random: &mut impl RandomSource,
        input: BackupRetentionInput,
    ) -> Result<BackupRetentionOutcome, BackupRetentionError> {
        let limit = PageLimit::new(input.limits.destination_page_items)?;
        if input.now.get() < 0 || input.limits.provider_timeout.get() == 0 {
            return Err(BackupRetentionError::Invalid);
        }
        let retired = retire_one(authority, random, &input);
        // Reclaim already retired copies even when a fresh retirement races a policy edit.
        let page = authority.pending(self.cursor, limit)?;
        self.cursor = page.next;
        let mut outcome = BackupRetentionOutcome {
            retired: false,
            reclaimed: 0,
            failed: 0,
        };
        for copy in page.items {
            match deletion::reclaim(authority, resolver, random, &input, &copy) {
                Ok(()) => outcome.reclaimed += 1,
                Err(_) => outcome.failed += 1,
            }
        }
        outcome.retired = retired?;
        Ok(outcome)
    }
}

fn retire_one(
    authority: &impl BackupRetentionAuthority,
    random: &mut impl RandomSource,
    input: &BackupRetentionInput,
) -> Result<bool, BackupRetentionError> {
    let Some(candidate) = authority.candidate()? else {
        return Ok(false);
    };
    let backup_id = candidate.backup_id;
    let context = context(random, input)?;
    let command = AuthoritativeCommand::RetireMetadataBackup(candidate);
    let receipt = authority.commit(context, &command)?;
    validate_receipt(receipt, context, &command, backup_id)?;
    Ok(true)
}

fn context(
    random: &mut impl RandomSource,
    input: &BackupRetentionInput,
) -> Result<CommandContext, BackupRetentionError> {
    let mut operation = [0; 16];
    let mut audit = [0; 16];
    random.fill_bytes(&mut operation)?;
    random.fill_bytes(&mut audit)?;
    if operation == audit {
        return Err(BackupRetentionError::Invalid);
    }
    Ok(CommandContext {
        operation_id: OperationId::from_bytes(uuid_v8(operation))?,
        actor_principal_id: input.actor,
        audit_event_id: AuditEventId::from_bytes(uuid_v8(audit))?,
        occurred_at: input.now,
        expected_revision: None,
    })
}

fn validate_receipt(
    receipt: CommandReceipt,
    context: CommandContext,
    command: &AuthoritativeCommand,
    backup_id: meshspan_domain::BackupId,
) -> Result<(), BackupRetentionError> {
    if receipt.operation_id != context.operation_id
        || receipt.request_digest != command.request_digest(context)
        || receipt.result_digest == [0; 32]
        || receipt.committed_revision.get() == 0
        || receipt.entity.kind != EntityKind::MetadataBackup
        || receipt.entity.id != backup_id.as_bytes()
    {
        return Err(BackupRetentionError::Invalid);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub(crate) enum BackupRetentionError {
    #[error("backup retention identity or receipt is invalid")]
    Invalid,
    #[error("backup retention metadata is unavailable")]
    Repository(#[from] meshspan_metadata::RepositoryError),
    #[error("backup retention authority is unavailable")]
    Authority(#[from] meshspan_cluster::MetadataAuthorityRequestError),
    #[error("backup retention provider resolution failed")]
    Resolution(#[from] crate::MetadataBackupProviderResolutionError),
    #[error("backup retention provider operation failed")]
    Provider(#[from] meshspan_contracts::ContractError),
    #[error("backup retention entropy unavailable")]
    Entropy(#[from] meshspan_domain::EntropyError),
    #[error("backup retention identifier invalid")]
    Identifier(#[from] meshspan_domain::IdentifierError),
}
