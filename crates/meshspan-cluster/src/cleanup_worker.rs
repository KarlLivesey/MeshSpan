// SPDX-License-Identifier: GPL-2.0-only

//! Bounded, restart-safe execution of exact physical-cleanup transitions.

use meshspan_contracts::{ContractError, ReclamationReceipt, RemovalPermit, TombstoneReceipt};
use meshspan_domain::{NodeId, OperationId, Revision, TargetId, UnixMicros};
use meshspan_metadata::{
    AuthoritativeCommand, AuthoritativeRepository, PageLimit, RepositoryError,
    VersionCleanupInventoryState, VersionCleanupItem, VersionCleanupItemCompletion,
    VersionCleanupItemCursor, VersionCleanupItemReclamation, VersionCleanupPermitAttempt,
    VersionCleanupPermitAuthority,
};

use crate::{
    CleanupCompletionError, CleanupReclamationError, version_cleanup_reclamation,
    version_cleanup_tombstone_completion,
};

/// Maximum independently dispatchable cleanup items returned in one page.
pub const MAXIMUM_CLEANUP_WORK_PAGE_ITEMS: usize = 1_000;

/// One exact independently executable cleanup transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupWorkAction {
    /// No current unexpired permit exists; the leader must commit the supplied next authority.
    AcquirePermit(VersionCleanupPermitAuthority),
    /// Apply or exactly replay one current provider tombstone.
    Tombstone {
        /// Exact immutable inventory seal accepted by completion.
        inventory_sealed_revision: Revision,
        /// Exact already-committed provider permit attempt.
        attempt: VersionCleanupPermitAttempt,
    },
    /// Physically unlink or exactly replay one completed provider tombstone.
    Reclaim(VersionCleanupItemCompletion),
    /// Both durable provider and replicated reclamation transitions already completed.
    Complete(VersionCleanupItemReclamation),
}

/// One sealed inventory item plus its exact next transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CleanupWorkEntry {
    /// Owning authorised cleanup proposal.
    pub cleanup_operation_id: OperationId,
    /// Stable sealed physical item.
    pub item: VersionCleanupItem,
    /// Exact transition safe to dispatch now.
    pub action: CleanupWorkAction,
}

/// Bounded keyset page of independently dispatchable cleanup work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CleanupWorkPage {
    /// Work entries safe to execute concurrently.
    pub entries: Vec<CleanupWorkEntry>,
    /// Opaque next-page cursor, or `None` when this pass reached the end.
    pub next: Option<VersionCleanupItemCursor>,
}

/// Read-only authority used to recover exact work state after restart or lost responses.
pub trait CleanupWorkCatalogue {
    /// Returns one bounded page derived only from validated replicated cleanup records.
    ///
    /// # Errors
    ///
    /// Rejects invalid bounds, incomplete inventories and corrupt authority state.
    fn cleanup_work_page(
        &self,
        cleanup_operation_id: OperationId,
        after: Option<&VersionCleanupItemCursor>,
        limit: PageLimit,
        observed_at: UnixMicros,
    ) -> Result<CleanupWorkPage, RepositoryError>;
}

impl CleanupWorkCatalogue for AuthoritativeRepository {
    fn cleanup_work_page(
        &self,
        cleanup_operation_id: OperationId,
        after: Option<&VersionCleanupItemCursor>,
        limit: PageLimit,
        observed_at: UnixMicros,
    ) -> Result<CleanupWorkPage, RepositoryError> {
        let inventory = self
            .version_cleanup_inventory(cleanup_operation_id)?
            .ok_or(RepositoryError::InvalidCommand)?;
        if inventory.state != VersionCleanupInventoryState::Sealed {
            return Err(RepositoryError::InvalidCommand);
        }
        let sealed_revision = inventory
            .sealed_revision
            .ok_or(RepositoryError::CorruptState)?;
        let page = self.version_cleanup_items(cleanup_operation_id, after, limit)?;
        let mut entries = Vec::with_capacity(page.items.len());
        for item in page.items {
            let action = work_action(
                self,
                cleanup_operation_id,
                item,
                sealed_revision,
                observed_at,
            )?;
            entries.push(CleanupWorkEntry {
                cleanup_operation_id,
                item,
                action,
            });
        }
        Ok(CleanupWorkPage {
            entries,
            next: page.next,
        })
    }
}

fn work_action(
    repository: &AuthoritativeRepository,
    cleanup_operation_id: OperationId,
    item: VersionCleanupItem,
    sealed_revision: Revision,
    observed_at: UnixMicros,
) -> Result<CleanupWorkAction, RepositoryError> {
    if let Some(completion) =
        repository.version_cleanup_item_completion(cleanup_operation_id, item.item_index)?
    {
        return Ok(repository
            .version_cleanup_item_reclamation(cleanup_operation_id, item.item_index)?
            .map_or(
                CleanupWorkAction::Reclaim(completion),
                CleanupWorkAction::Complete,
            ));
    }
    if let Some(attempt) =
        repository.version_cleanup_permit_attempt(cleanup_operation_id, item.item_index)?
        && attempt.permit.expires_at > observed_at
    {
        return Ok(CleanupWorkAction::Tombstone {
            inventory_sealed_revision: sealed_revision,
            attempt,
        });
    }
    Ok(CleanupWorkAction::AcquirePermit(
        repository.version_cleanup_permit_authority(cleanup_operation_id, item.item_index)?,
    ))
}

/// Replaceable local or remote provider dispatch used by cleanup workers.
pub trait CleanupProviderDispatch {
    /// Applies or resolves one exact provider tombstone.
    ///
    /// # Errors
    ///
    /// Returns a typed contract failure without claiming metadata completion.
    fn tombstone(
        &mut self,
        target_id: TargetId,
        permit: RemovalPermit,
        observed_at: UnixMicros,
    ) -> Result<TombstoneReceipt, ContractError>;

    /// Applies or resolves one exact physical unlink.
    ///
    /// # Errors
    ///
    /// Returns a typed contract failure without claiming byte reclamation.
    fn reclaim(
        &mut self,
        target_id: TargetId,
        receipt: TombstoneReceipt,
        observed_at: UnixMicros,
    ) -> Result<ReclamationReceipt, ContractError>;
}

/// Honest result of executing at most one durable transition for one work item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CleanupWorkerOutcome {
    /// The current leader must construct and commit the next short-lived permit.
    PermitRequired(VersionCleanupPermitAuthority),
    /// Provider work is durable; this exact command must enter consensus before further work.
    CommandReady(AuthoritativeCommand),
    /// Physical reclamation was already both durable and replicated.
    Complete(VersionCleanupItemReclamation),
}

/// Stable cleanup worker failures that never manufacture completion.
#[derive(Debug, thiserror::Error)]
pub enum CleanupWorkerError {
    /// Page state substituted a different cleanup item, shard or target.
    #[error("cleanup worker authority is inconsistent")]
    InconsistentAuthority,
    /// Provider rejected or could not durably execute the exact transition.
    #[error("cleanup provider dispatch failed")]
    Provider(#[from] ContractError),
    /// Tombstone completion construction rejected the provider result.
    #[error("cleanup tombstone completion construction failed")]
    Completion(#[from] CleanupCompletionError),
    /// Physical-reclamation construction rejected the provider result.
    #[error("cleanup reclamation construction failed")]
    Reclamation(#[from] CleanupReclamationError),
}

/// Executes no more than one durable provider transition for one independently dispatchable item.
///
/// Calling this again after a crash or lost response is safe: provider operations replay their
/// exact receipts, while a refreshed work page observes any command already committed to metadata.
/// Separate entries carry no shared mutable worker state and may execute concurrently.
///
/// # Errors
///
/// Rejects substituted page authority and propagates typed provider or command validation errors.
pub fn execute_cleanup_work<D: CleanupProviderDispatch>(
    dispatch: &mut D,
    entry: CleanupWorkEntry,
    reporter_node_id: NodeId,
    reporter_incarnation: u64,
    observed_at: UnixMicros,
) -> Result<CleanupWorkerOutcome, CleanupWorkerError> {
    match entry.action {
        CleanupWorkAction::AcquirePermit(authority) => {
            validate_item_authority(entry.cleanup_operation_id, entry.item, authority)?;
            Ok(CleanupWorkerOutcome::PermitRequired(authority))
        }
        CleanupWorkAction::Tombstone {
            inventory_sealed_revision,
            attempt,
        } => {
            validate_attempt(entry.cleanup_operation_id, entry.item, attempt)?;
            validate_reporter(entry.item, reporter_node_id)?;
            let receipt = dispatch.tombstone(entry.item.target_id, attempt.permit, observed_at)?;
            Ok(CleanupWorkerOutcome::CommandReady(
                version_cleanup_tombstone_completion(
                    inventory_sealed_revision,
                    attempt,
                    receipt,
                    reporter_node_id,
                    reporter_incarnation,
                )?,
            ))
        }
        CleanupWorkAction::Reclaim(completion) => {
            validate_completion(entry.cleanup_operation_id, entry.item, completion)?;
            validate_reporter(entry.item, reporter_node_id)?;
            let receipt =
                dispatch.reclaim(entry.item.target_id, completion.receipt, observed_at)?;
            Ok(CleanupWorkerOutcome::CommandReady(
                version_cleanup_reclamation(
                    completion,
                    receipt,
                    reporter_node_id,
                    reporter_incarnation,
                )?,
            ))
        }
        CleanupWorkAction::Complete(reclamation) => {
            validate_reclamation(entry.cleanup_operation_id, entry.item, &reclamation)?;
            Ok(CleanupWorkerOutcome::Complete(reclamation))
        }
    }
}

fn validate_reporter(
    item: VersionCleanupItem,
    reporter_node_id: NodeId,
) -> Result<(), CleanupWorkerError> {
    if item.storage_node_id == reporter_node_id {
        Ok(())
    } else {
        Err(CleanupWorkerError::InconsistentAuthority)
    }
}

fn validate_item_authority(
    cleanup_operation_id: OperationId,
    item: VersionCleanupItem,
    authority: VersionCleanupPermitAuthority,
) -> Result<(), CleanupWorkerError> {
    if cleanup_operation_id == authority.cleanup_operation_id && item == authority.item {
        Ok(())
    } else {
        Err(CleanupWorkerError::InconsistentAuthority)
    }
}

fn validate_attempt(
    cleanup_operation_id: OperationId,
    item: VersionCleanupItem,
    attempt: VersionCleanupPermitAttempt,
) -> Result<(), CleanupWorkerError> {
    let permit = attempt.permit;
    if attempt.cleanup_operation_id == cleanup_operation_id
        && attempt.item_index == item.item_index
        && permit.shard == item.shard
        && permit.target_id == item.target_id
        && permit.target_generation == item.target_generation
    {
        Ok(())
    } else {
        Err(CleanupWorkerError::InconsistentAuthority)
    }
}

fn validate_completion(
    cleanup_operation_id: OperationId,
    item: VersionCleanupItem,
    completion: VersionCleanupItemCompletion,
) -> Result<(), CleanupWorkerError> {
    let receipt = completion.receipt;
    if completion.cleanup_operation_id == cleanup_operation_id
        && completion.item_index == item.item_index
        && receipt.shard == item.shard
        && receipt.target_id == item.target_id
        && receipt.target_generation == item.target_generation
    {
        Ok(())
    } else {
        Err(CleanupWorkerError::InconsistentAuthority)
    }
}

fn validate_reclamation(
    cleanup_operation_id: OperationId,
    item: VersionCleanupItem,
    reclamation: &VersionCleanupItemReclamation,
) -> Result<(), CleanupWorkerError> {
    let receipt = reclamation.receipt.tombstone;
    if reclamation.cleanup_operation_id == cleanup_operation_id
        && reclamation.item_index == item.item_index
        && receipt.shard == item.shard
        && receipt.target_id == item.target_id
        && receipt.target_generation == item.target_generation
    {
        Ok(())
    } else {
        Err(CleanupWorkerError::InconsistentAuthority)
    }
}
