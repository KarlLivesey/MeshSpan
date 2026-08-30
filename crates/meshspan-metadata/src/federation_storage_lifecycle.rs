// SPDX-License-Identifier: GPL-2.0-only

//! Crash-safe logical retirement, physical reclamation and quota release for federated shards.

use meshspan_contracts::{
    FederatedShardPermit, ReclamationReceipt, ShardIdentity, TombstoneReceipt,
    federated_provider_shard_identity, federated_shard_reclamation_result_digest,
    federated_shard_retirement_result_digest, reclamation_receipt_digest,
};
use meshspan_domain::{
    FederationStorageAction, FederationStorageAllocationId, MeshId, OperationId, TargetId,
    UnixMicros,
};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use thiserror::Error;

use crate::{FederationStorageCapabilityLedgerError, LocalDatabase};

const RETIRED: i64 = 1;
const RECLAIMED: i64 = 2;

/// Durable retirement input after the provider has committed its physical tombstone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationStorageRetirementCompletion {
    /// Current exact remote lifecycle permit.
    pub permit: FederatedShardPermit,
    /// Exact signed capability presentation used by the remote swarm.
    pub capability_digest: [u8; 32],
    /// Provider-local tombstone over the namespaced physical shard.
    pub provider_tombstone: TombstoneReceipt,
    /// Quorum-derived completion instant retained across retries.
    pub completed_at: UnixMicros,
}

/// Durable reclamation input after the provider has physically unlinked the shard.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationStorageReclamationCompletion {
    /// Current exact remote lifecycle permit.
    pub permit: FederatedShardPermit,
    /// Exact signed capability presentation used by the remote swarm.
    pub capability_digest: [u8; 32],
    /// Earlier logical tombstone returned to the remote swarm.
    pub logical_tombstone: TombstoneReceipt,
    /// Provider-local physical-unlink receipt.
    pub provider_reclamation: ReclamationReceipt,
}

/// Terminal state of one exact remote-scope shard lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FederationStorageLifecycleState {
    /// Reads are fenced but physical bytes remain charged.
    Retired,
    /// Physical bytes are unlinked and their exact allocation charge is released.
    Reclaimed,
}

/// Complete validated lifecycle evidence retained for replay and audit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationStorageLifecycle {
    /// Stable remote swarm namespace.
    pub remote_mesh_id: MeshId,
    /// Stable signed logical scope namespace.
    pub scope_digest: [u8; 32],
    /// Exact logical shard identity.
    pub shard: ShardIdentity,
    /// Provider target identity.
    pub target_id: TargetId,
    /// Provider target incarnation.
    pub target_generation: u64,
    /// Allocation whose physical charge owns these bytes.
    pub allocation_id: FederationStorageAllocationId,
    /// Exact charged physical bytes.
    pub charged_bytes: u64,
    /// Exact logical tombstone returned to the remote swarm.
    pub logical_tombstone: TombstoneReceipt,
    /// Exact provider-local tombstone needed for physical unlink.
    pub provider_tombstone: TombstoneReceipt,
    /// Original durable retirement instant.
    pub retired_at: UnixMicros,
    /// Current terminal state.
    pub state: FederationStorageLifecycleState,
    /// Exact reclaim operation after physical unlink.
    pub reclaim_operation_id: Option<OperationId>,
    /// First exact signed reclaim-capability presentation retained for audit.
    pub reclaim_capability_digest: Option<[u8; 32]>,
    /// Exact provider-issued reclaim permit retained across response retries.
    pub reclaim_permit_digest: Option<[u8; 32]>,
    /// Logical reclamation receipt after physical unlink.
    pub logical_reclamation: Option<ReclamationReceipt>,
    /// Provider-local reclamation evidence after physical unlink.
    pub provider_reclamation: Option<ReclamationReceipt>,
}

/// Idempotent local lifecycle transition result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FederationStorageLifecycleDisposition {
    /// New durable evidence was applied.
    Applied,
    /// The exact previously durable evidence was returned.
    Replayed,
}

impl LocalDatabase {
    /// Records the exact provider tombstone before remote retirement success may be signed.
    ///
    /// # Errors
    ///
    /// Rejects malformed, stale or conflicting capability and shard evidence, corrupt local state
    /// and SQLite failures.
    pub fn record_federated_storage_retirement(
        &mut self,
        completion: &FederationStorageRetirementCompletion,
    ) -> Result<
        (
            FederationStorageLifecycleDisposition,
            FederationStorageLifecycle,
        ),
        FederationStorageLifecycleError,
    > {
        retire(self, completion)
    }

    /// Loads current exact logical and provider tombstone evidence for one scope shard.
    ///
    /// # Errors
    ///
    /// Rejects malformed identities, contradictory persisted evidence and SQLite failures.
    pub fn federated_storage_lifecycle(
        &self,
        remote_mesh_id: MeshId,
        scope_digest: [u8; 32],
        target_id: TargetId,
        target_generation: u64,
        shard: ShardIdentity,
    ) -> Result<Option<FederationStorageLifecycle>, FederationStorageLifecycleError> {
        load(
            self.connection(),
            remote_mesh_id,
            scope_digest,
            target_id,
            target_generation,
            shard,
        )
    }

    /// Records physical unlink and atomically releases only the original allocation charge.
    ///
    /// # Errors
    ///
    /// Rejects malformed, stale or conflicting capability, tombstone and reclamation evidence,
    /// corrupt quota state and SQLite failures.
    pub fn record_federated_storage_reclamation(
        &mut self,
        completion: &FederationStorageReclamationCompletion,
    ) -> Result<
        (
            FederationStorageLifecycleDisposition,
            FederationStorageLifecycle,
        ),
        FederationStorageLifecycleError,
    > {
        reclaim(self, completion)
    }
}

fn retire(
    database: &mut LocalDatabase,
    completion: &FederationStorageRetirementCompletion,
) -> Result<
    (
        FederationStorageLifecycleDisposition,
        FederationStorageLifecycle,
    ),
    FederationStorageLifecycleError,
> {
    validate_capability(database, &completion.permit, completion.capability_digest)?;
    validate_retirement(completion)?;
    let transaction = database
        .connection_mut()
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(stored) = load_for_permit(&transaction, &completion.permit)? {
        validate_retirement_replay(&stored, completion)?;
        transaction.commit()?;
        return Ok((FederationStorageLifecycleDisposition::Replayed, stored));
    }
    let shard = load_active_shard(&transaction, &completion.permit)?;
    let logical_tombstone = logical_tombstone(completion);
    insert_retirement(&transaction, completion, shard, logical_tombstone)?;
    let stored = load_for_permit(&transaction, &completion.permit)?
        .ok_or(FederationStorageLifecycleError::CorruptState)?;
    transaction.commit()?;
    Ok((FederationStorageLifecycleDisposition::Applied, stored))
}

fn reclaim(
    database: &mut LocalDatabase,
    completion: &FederationStorageReclamationCompletion,
) -> Result<
    (
        FederationStorageLifecycleDisposition,
        FederationStorageLifecycle,
    ),
    FederationStorageLifecycleError,
> {
    validate_capability(database, &completion.permit, completion.capability_digest)?;
    validate_reclamation(completion)?;
    let transaction = database
        .connection_mut()
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let stored = load_for_permit(&transaction, &completion.permit)?
        .ok_or(FederationStorageLifecycleError::Conflict)?;
    let logical_reclamation = logical_reclamation(completion);
    if stored.state == FederationStorageLifecycleState::Reclaimed {
        validate_reclamation_replay(&stored, completion, logical_reclamation)?;
        transaction.commit()?;
        return Ok((FederationStorageLifecycleDisposition::Replayed, stored));
    }
    validate_reclamation_transition(&stored, completion)?;
    apply_reclamation(&transaction, &stored, completion, logical_reclamation)?;
    let completed = load_for_permit(&transaction, &completion.permit)?
        .ok_or(FederationStorageLifecycleError::CorruptState)?;
    transaction.commit()?;
    Ok((FederationStorageLifecycleDisposition::Applied, completed))
}

fn validate_capability(
    database: &LocalDatabase,
    permit: &FederatedShardPermit,
    capability_digest: [u8; 32],
) -> Result<(), FederationStorageLifecycleError> {
    let presentation = database
        .federated_storage_capability(capability_digest)?
        .ok_or(FederationStorageLifecycleError::Conflict)?;
    if presentation.permit == *permit {
        Ok(())
    } else {
        Err(FederationStorageLifecycleError::Conflict)
    }
}

fn validate_retirement(
    completion: &FederationStorageRetirementCompletion,
) -> Result<(), FederationStorageLifecycleError> {
    let permit = completion.permit;
    let provider_shard =
        federated_provider_shard_identity(permit.remote_mesh_id, permit.scope_digest, permit.shard);
    let tombstone = completion.provider_tombstone;
    let valid = permit.action == FederationStorageAction::Retire
        && completion.capability_digest != [0; 32]
        && completion.completed_at >= permit.issued_at
        && completion.completed_at < permit.expires_at
        && tombstone.operation_id == permit.operation_id
        && tombstone.target_id == permit.target_id
        && tombstone.target_generation == permit.target_generation
        && tombstone.shard == provider_shard
        && tombstone.permit_digest != [0; 32]
        && tombstone.tombstone_digest != [0; 32];
    valid
        .then_some(())
        .ok_or(FederationStorageLifecycleError::Invalid)
}

fn validate_reclamation(
    completion: &FederationStorageReclamationCompletion,
) -> Result<(), FederationStorageLifecycleError> {
    let permit = completion.permit;
    let provider = completion.provider_reclamation;
    let valid = permit.action == FederationStorageAction::Reclaim
        && completion.capability_digest != [0; 32]
        && completion.logical_tombstone.shard == permit.shard
        && completion.logical_tombstone.target_id == permit.target_id
        && completion.logical_tombstone.target_generation == permit.target_generation
        && provider.reclamation_digest
            == reclamation_receipt_digest(
                provider.tombstone,
                provider.bytes_unlinked_at,
                provider.reclaimed_bytes,
            );
    valid
        .then_some(())
        .ok_or(FederationStorageLifecycleError::Invalid)
}

#[derive(Clone, Copy)]
struct ActiveShard {
    allocation_id: FederationStorageAllocationId,
    length: u64,
}

fn load_active_shard(
    transaction: &Transaction<'_>,
    permit: &FederatedShardPermit,
) -> Result<ActiveShard, FederationStorageLifecycleError> {
    let remote_mesh_id = permit.remote_mesh_id.as_bytes();
    let target_id = permit.target_id.as_bytes();
    let target_generation = to_i64(permit.target_generation)?;
    let stripe_index = to_i64(permit.shard.stripe_index)?;
    let row = transaction
        .query_row(
            "SELECT allocation_id, length FROM local_federation_storage_shards AS shard
             WHERE remote_mesh_id = ?1 AND scope_digest = ?2 AND target_id = ?3
               AND target_generation = ?4 AND manifest_digest = ?5 AND stripe_index = ?6
               AND shard_index = ?7 AND shard_generation = ?8
               AND NOT EXISTS(
                   SELECT 1 FROM local_federation_storage_lifecycle AS lifecycle
                   WHERE lifecycle.remote_mesh_id = shard.remote_mesh_id
                     AND lifecycle.scope_digest = shard.scope_digest
                     AND lifecycle.target_id = shard.target_id
                     AND lifecycle.target_generation = shard.target_generation
                     AND lifecycle.manifest_digest = shard.manifest_digest
                     AND lifecycle.stripe_index = shard.stripe_index
                     AND lifecycle.shard_index = shard.shard_index
                     AND lifecycle.shard_generation = shard.shard_generation
               )",
            params![
                remote_mesh_id.as_slice(),
                permit.scope_digest.as_slice(),
                target_id.as_slice(),
                target_generation,
                permit.shard.manifest_digest.as_slice(),
                stripe_index,
                i64::from(permit.shard.shard_index),
                i64::from(permit.shard.generation),
            ],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?
        .ok_or(FederationStorageLifecycleError::Conflict)?;
    let shard = ActiveShard {
        allocation_id: FederationStorageAllocationId::from_bytes(exact(&row.0)?)
            .map_err(|_| FederationStorageLifecycleError::CorruptState)?,
        length: positive(row.1)?,
    };
    (shard.length <= permit.maximum_bytes)
        .then_some(shard)
        .ok_or(FederationStorageLifecycleError::Conflict)
}

fn insert_retirement(
    transaction: &Transaction<'_>,
    completion: &FederationStorageRetirementCompletion,
    shard: ActiveShard,
    logical: TombstoneReceipt,
) -> Result<(), FederationStorageLifecycleError> {
    let permit = completion.permit;
    let provider = completion.provider_tombstone;
    let provider_shard =
        federated_provider_shard_identity(permit.remote_mesh_id, permit.scope_digest, permit.shard);
    transaction.execute(
        "INSERT INTO local_federation_storage_lifecycle(
            retire_operation_id, remote_mesh_id, scope_digest, target_id, target_generation,
            manifest_digest, stripe_index, shard_index, shard_generation, allocation_id,
            charged_bytes, retire_capability_digest, retire_permit_digest,
            provider_manifest_digest, provider_permit_digest, provider_tombstone_digest,
            logical_tombstone_digest, retired_at, state
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                   ?14, ?15, ?16, ?17, ?18, 1)",
        params![
            permit.operation_id.as_bytes().as_slice(),
            permit.remote_mesh_id.as_bytes().as_slice(),
            permit.scope_digest.as_slice(),
            permit.target_id.as_bytes().as_slice(),
            to_i64(permit.target_generation)?,
            permit.shard.manifest_digest.as_slice(),
            to_i64(permit.shard.stripe_index)?,
            i64::from(permit.shard.shard_index),
            i64::from(permit.shard.generation),
            shard.allocation_id.as_bytes().as_slice(),
            to_i64(shard.length)?,
            completion.capability_digest.as_slice(),
            permit.permit_digest.as_slice(),
            provider_shard.manifest_digest.as_slice(),
            provider.permit_digest.as_slice(),
            provider.tombstone_digest.as_slice(),
            logical.tombstone_digest.as_slice(),
            completion.completed_at.get(),
        ],
    )?;
    Ok(())
}

fn apply_reclamation(
    transaction: &Transaction<'_>,
    stored: &FederationStorageLifecycle,
    completion: &FederationStorageReclamationCompletion,
    logical: ReclamationReceipt,
) -> Result<(), FederationStorageLifecycleError> {
    let permit = completion.permit;
    let provider = completion.provider_reclamation;
    let usage_rows = transaction.execute(
        "UPDATE local_federation_storage_usage
         SET committed_bytes = committed_bytes - ?1, updated_at = ?2
         WHERE allocation_id = ?3 AND committed_bytes >= ?1",
        params![
            to_i64(stored.charged_bytes)?,
            provider.bytes_unlinked_at.get(),
            stored.allocation_id.as_bytes().as_slice()
        ],
    )?;
    if usage_rows != 1 {
        return Err(FederationStorageLifecycleError::CorruptState);
    }
    let lifecycle_rows = transaction.execute(
        "UPDATE local_federation_storage_lifecycle SET
            state = 2, reclaim_operation_id = ?1, reclaim_capability_digest = ?2,
            reclaim_permit_digest = ?3, bytes_unlinked_at = ?4, reclaimed_bytes = ?5,
            provider_reclamation_digest = ?6, logical_reclamation_digest = ?7
         WHERE retire_operation_id = ?8 AND state = 1",
        params![
            permit.operation_id.as_bytes().as_slice(),
            completion.capability_digest.as_slice(),
            permit.permit_digest.as_slice(),
            provider.bytes_unlinked_at.get(),
            to_i64(provider.reclaimed_bytes)?,
            provider.reclamation_digest.as_slice(),
            logical.reclamation_digest.as_slice(),
            stored.logical_tombstone.operation_id.as_bytes().as_slice(),
        ],
    )?;
    if lifecycle_rows == 1 {
        Ok(())
    } else {
        Err(FederationStorageLifecycleError::Conflict)
    }
}

fn logical_tombstone(completion: &FederationStorageRetirementCompletion) -> TombstoneReceipt {
    let permit = completion.permit;
    TombstoneReceipt {
        operation_id: permit.operation_id,
        shard: permit.shard,
        target_id: permit.target_id,
        target_generation: permit.target_generation,
        permit_digest: permit.permit_digest,
        tombstone_digest: federated_shard_retirement_result_digest(
            &permit,
            completion.provider_tombstone,
            completion.completed_at,
        ),
    }
}

fn logical_reclamation(completion: &FederationStorageReclamationCompletion) -> ReclamationReceipt {
    let provider = completion.provider_reclamation;
    ReclamationReceipt {
        tombstone: completion.logical_tombstone,
        bytes_unlinked_at: provider.bytes_unlinked_at,
        reclaimed_bytes: provider.reclaimed_bytes,
        reclamation_digest: federated_shard_reclamation_result_digest(
            &completion.permit,
            completion.logical_tombstone,
            provider,
        ),
    }
}

fn validate_retirement_replay(
    stored: &FederationStorageLifecycle,
    completion: &FederationStorageRetirementCompletion,
) -> Result<(), FederationStorageLifecycleError> {
    let permit = completion.permit;
    let exact = stored.logical_tombstone.operation_id == permit.operation_id
        && stored.logical_tombstone.shard == permit.shard
        && stored.logical_tombstone.permit_digest == permit.permit_digest
        && stored.provider_tombstone == completion.provider_tombstone
        && stored.charged_bytes <= permit.maximum_bytes
        && stored.retired_at >= permit.issued_at
        && stored.retired_at <= completion.completed_at;
    exact
        .then_some(())
        .ok_or(FederationStorageLifecycleError::Conflict)
}

fn validate_reclamation_transition(
    stored: &FederationStorageLifecycle,
    completion: &FederationStorageReclamationCompletion,
) -> Result<(), FederationStorageLifecycleError> {
    let provider = completion.provider_reclamation;
    let valid = stored.state == FederationStorageLifecycleState::Retired
        && stored.logical_tombstone == completion.logical_tombstone
        && stored.provider_tombstone == provider.tombstone
        && provider.reclaimed_bytes == stored.charged_bytes
        && stored.charged_bytes <= completion.permit.maximum_bytes
        && provider.bytes_unlinked_at >= stored.retired_at;
    valid
        .then_some(())
        .ok_or(FederationStorageLifecycleError::Conflict)
}

fn validate_reclamation_replay(
    stored: &FederationStorageLifecycle,
    completion: &FederationStorageReclamationCompletion,
    logical: ReclamationReceipt,
) -> Result<(), FederationStorageLifecycleError> {
    let exact = stored.reclaim_operation_id == Some(completion.permit.operation_id)
        && stored.reclaim_permit_digest == Some(completion.permit.permit_digest)
        && stored.logical_tombstone == completion.logical_tombstone
        && stored.provider_reclamation == Some(completion.provider_reclamation)
        && stored.logical_reclamation == Some(logical);
    exact
        .then_some(())
        .ok_or(FederationStorageLifecycleError::Conflict)
}

fn load_for_permit(
    connection: &rusqlite::Connection,
    permit: &FederatedShardPermit,
) -> Result<Option<FederationStorageLifecycle>, FederationStorageLifecycleError> {
    load(
        connection,
        permit.remote_mesh_id,
        permit.scope_digest,
        permit.target_id,
        permit.target_generation,
        permit.shard,
    )
}

fn load(
    connection: &rusqlite::Connection,
    remote_mesh_id: MeshId,
    scope_digest: [u8; 32],
    target_id: TargetId,
    target_generation: u64,
    shard: ShardIdentity,
) -> Result<Option<FederationStorageLifecycle>, FederationStorageLifecycleError> {
    let row = connection
        .query_row(
            "SELECT allocation_id, charged_bytes, retire_operation_id, retire_permit_digest,
                    provider_manifest_digest, provider_permit_digest, provider_tombstone_digest,
                    logical_tombstone_digest, retired_at, state, reclaim_operation_id,
                    reclaim_capability_digest, reclaim_permit_digest, bytes_unlinked_at,
                    reclaimed_bytes, provider_reclamation_digest, logical_reclamation_digest
             FROM local_federation_storage_lifecycle
             WHERE remote_mesh_id = ?1 AND scope_digest = ?2 AND target_id = ?3
               AND target_generation = ?4 AND manifest_digest = ?5 AND stripe_index = ?6
               AND shard_index = ?7 AND shard_generation = ?8",
            params![
                remote_mesh_id.as_bytes().as_slice(),
                scope_digest.as_slice(),
                target_id.as_bytes().as_slice(),
                to_i64(target_generation)?,
                shard.manifest_digest.as_slice(),
                to_i64(shard.stripe_index)?,
                i64::from(shard.shard_index),
                i64::from(shard.generation),
            ],
            |row| {
                Ok(StoredLifecycle {
                    allocation_id: row.get(0)?,
                    charged_bytes: row.get(1)?,
                    retire_operation_id: row.get(2)?,
                    retire_permit_digest: row.get(3)?,
                    provider_manifest_digest: row.get(4)?,
                    provider_permit_digest: row.get(5)?,
                    provider_tombstone_digest: row.get(6)?,
                    logical_tombstone_digest: row.get(7)?,
                    retired_at: row.get(8)?,
                    state: row.get(9)?,
                    reclaim_operation_id: row.get(10)?,
                    reclaim_capability_digest: row.get(11)?,
                    reclaim_permit_digest: row.get(12)?,
                    bytes_unlinked_at: row.get(13)?,
                    reclaimed_bytes: row.get(14)?,
                    provider_reclamation_digest: row.get(15)?,
                    logical_reclamation_digest: row.get(16)?,
                })
            },
        )
        .optional()?;
    row.as_ref()
        .map(|row| {
            decode(
                remote_mesh_id,
                scope_digest,
                target_id,
                target_generation,
                shard,
                row,
            )
        })
        .transpose()
}

struct StoredLifecycle {
    allocation_id: Vec<u8>,
    charged_bytes: i64,
    retire_operation_id: Vec<u8>,
    retire_permit_digest: Vec<u8>,
    provider_manifest_digest: Vec<u8>,
    provider_permit_digest: Vec<u8>,
    provider_tombstone_digest: Vec<u8>,
    logical_tombstone_digest: Vec<u8>,
    retired_at: i64,
    state: i64,
    reclaim_operation_id: Option<Vec<u8>>,
    reclaim_capability_digest: Option<Vec<u8>>,
    reclaim_permit_digest: Option<Vec<u8>>,
    bytes_unlinked_at: Option<i64>,
    reclaimed_bytes: Option<i64>,
    provider_reclamation_digest: Option<Vec<u8>>,
    logical_reclamation_digest: Option<Vec<u8>>,
}

fn decode(
    remote_mesh_id: MeshId,
    scope_digest: [u8; 32],
    target_id: TargetId,
    target_generation: u64,
    shard: ShardIdentity,
    row: &StoredLifecycle,
) -> Result<FederationStorageLifecycle, FederationStorageLifecycleError> {
    let retire_operation_id = OperationId::from_bytes(exact(&row.retire_operation_id)?)
        .map_err(|_| FederationStorageLifecycleError::CorruptState)?;
    let provider_shard = ShardIdentity {
        manifest_digest: exact(&row.provider_manifest_digest)?,
        ..shard
    };
    let provider_tombstone = TombstoneReceipt {
        operation_id: retire_operation_id,
        shard: provider_shard,
        target_id,
        target_generation,
        permit_digest: exact(&row.provider_permit_digest)?,
        tombstone_digest: exact(&row.provider_tombstone_digest)?,
    };
    let logical_tombstone = TombstoneReceipt {
        operation_id: retire_operation_id,
        shard,
        target_id,
        target_generation,
        permit_digest: exact(&row.retire_permit_digest)?,
        tombstone_digest: exact(&row.logical_tombstone_digest)?,
    };
    let reclamation = decode_reclamation(row, logical_tombstone, provider_tombstone)?;
    let lifecycle = FederationStorageLifecycle {
        remote_mesh_id,
        scope_digest,
        shard,
        target_id,
        target_generation,
        allocation_id: FederationStorageAllocationId::from_bytes(exact(&row.allocation_id)?)
            .map_err(|_| FederationStorageLifecycleError::CorruptState)?,
        charged_bytes: positive(row.charged_bytes)?,
        logical_tombstone,
        provider_tombstone,
        retired_at: UnixMicros::new(row.retired_at),
        state: reclamation.state,
        reclaim_operation_id: reclamation.operation_id,
        reclaim_capability_digest: reclamation.capability_digest,
        reclaim_permit_digest: reclamation.permit_digest,
        logical_reclamation: reclamation.logical_receipt,
        provider_reclamation: reclamation.provider_receipt,
    };
    validate_stored(&lifecycle)?;
    Ok(lifecycle)
}

struct DecodedReclamation {
    state: FederationStorageLifecycleState,
    operation_id: Option<OperationId>,
    capability_digest: Option<[u8; 32]>,
    permit_digest: Option<[u8; 32]>,
    logical_receipt: Option<ReclamationReceipt>,
    provider_receipt: Option<ReclamationReceipt>,
}

fn decode_reclamation(
    row: &StoredLifecycle,
    logical_tombstone: TombstoneReceipt,
    provider_tombstone: TombstoneReceipt,
) -> Result<DecodedReclamation, FederationStorageLifecycleError> {
    if row.state == RETIRED {
        let empty = row.reclaim_operation_id.is_none()
            && row.reclaim_capability_digest.is_none()
            && row.reclaim_permit_digest.is_none()
            && row.bytes_unlinked_at.is_none()
            && row.reclaimed_bytes.is_none()
            && row.provider_reclamation_digest.is_none()
            && row.logical_reclamation_digest.is_none();
        return empty
            .then_some(DecodedReclamation {
                state: FederationStorageLifecycleState::Retired,
                operation_id: None,
                capability_digest: None,
                permit_digest: None,
                logical_receipt: None,
                provider_receipt: None,
            })
            .ok_or(FederationStorageLifecycleError::CorruptState);
    }
    if row.state != RECLAIMED {
        return Err(FederationStorageLifecycleError::CorruptState);
    }
    let operation_id = OperationId::from_bytes(exact(
        row.reclaim_operation_id
            .as_deref()
            .ok_or(FederationStorageLifecycleError::CorruptState)?,
    )?)
    .map_err(|_| FederationStorageLifecycleError::CorruptState)?;
    let capability_digest = exact(
        row.reclaim_capability_digest
            .as_deref()
            .ok_or(FederationStorageLifecycleError::CorruptState)?,
    )?;
    let permit_digest = exact(
        row.reclaim_permit_digest
            .as_deref()
            .ok_or(FederationStorageLifecycleError::CorruptState)?,
    )?;
    let bytes_unlinked_at = UnixMicros::new(
        row.bytes_unlinked_at
            .ok_or(FederationStorageLifecycleError::CorruptState)?,
    );
    let reclaimed_bytes = positive(
        row.reclaimed_bytes
            .ok_or(FederationStorageLifecycleError::CorruptState)?,
    )?;
    let provider = ReclamationReceipt {
        tombstone: provider_tombstone,
        bytes_unlinked_at,
        reclaimed_bytes,
        reclamation_digest: exact(
            row.provider_reclamation_digest
                .as_deref()
                .ok_or(FederationStorageLifecycleError::CorruptState)?,
        )?,
    };
    let logical = ReclamationReceipt {
        tombstone: logical_tombstone,
        bytes_unlinked_at,
        reclaimed_bytes,
        reclamation_digest: exact(
            row.logical_reclamation_digest
                .as_deref()
                .ok_or(FederationStorageLifecycleError::CorruptState)?,
        )?,
    };
    Ok(DecodedReclamation {
        state: FederationStorageLifecycleState::Reclaimed,
        operation_id: Some(operation_id),
        capability_digest: Some(capability_digest),
        permit_digest: Some(permit_digest),
        logical_receipt: Some(logical),
        provider_receipt: Some(provider),
    })
}

fn validate_stored(
    lifecycle: &FederationStorageLifecycle,
) -> Result<(), FederationStorageLifecycleError> {
    let provider_shard = federated_provider_shard_identity(
        lifecycle.remote_mesh_id,
        lifecycle.scope_digest,
        lifecycle.shard,
    );
    let base = lifecycle.target_generation > 0
        && lifecycle.charged_bytes > 0
        && lifecycle.retired_at.get() > 0
        && lifecycle.logical_tombstone.shard == lifecycle.shard
        && lifecycle.provider_tombstone.shard == provider_shard;
    let terminal = match lifecycle.state {
        FederationStorageLifecycleState::Retired => {
            lifecycle.reclaim_operation_id.is_none()
                && lifecycle.reclaim_capability_digest.is_none()
                && lifecycle.reclaim_permit_digest.is_none()
                && lifecycle.logical_reclamation.is_none()
                && lifecycle.provider_reclamation.is_none()
        }
        FederationStorageLifecycleState::Reclaimed => lifecycle
            .reclaim_operation_id
            .zip(lifecycle.reclaim_capability_digest)
            .zip(lifecycle.reclaim_permit_digest)
            .zip(lifecycle.logical_reclamation)
            .zip(lifecycle.provider_reclamation)
            .is_some_and(
                |((((operation_id, capability_digest), permit_digest), logical), provider)| {
                    operation_id != lifecycle.logical_tombstone.operation_id
                        && capability_digest != [0; 32]
                        && permit_digest != [0; 32]
                        && logical.tombstone == lifecycle.logical_tombstone
                        && provider.tombstone == lifecycle.provider_tombstone
                        && logical.reclaimed_bytes == lifecycle.charged_bytes
                        && provider.reclaimed_bytes == lifecycle.charged_bytes
                        && provider.reclamation_digest
                            == reclamation_receipt_digest(
                                provider.tombstone,
                                provider.bytes_unlinked_at,
                                provider.reclaimed_bytes,
                            )
                },
            ),
    };
    if base && terminal {
        Ok(())
    } else {
        Err(FederationStorageLifecycleError::CorruptState)
    }
}

fn exact<const LENGTH: usize>(
    value: &[u8],
) -> Result<[u8; LENGTH], FederationStorageLifecycleError> {
    value
        .try_into()
        .map_err(|_| FederationStorageLifecycleError::CorruptState)
}

fn positive(value: i64) -> Result<u64, FederationStorageLifecycleError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(FederationStorageLifecycleError::CorruptState)
}

fn to_i64(value: u64) -> Result<i64, FederationStorageLifecycleError> {
    i64::try_from(value).map_err(|_| FederationStorageLifecycleError::Invalid)
}

/// Stable node-local federated storage lifecycle failures.
#[derive(Debug, Error)]
pub enum FederationStorageLifecycleError {
    /// Input evidence is malformed or contradictory.
    #[error("federated storage lifecycle input is invalid")]
    Invalid,
    /// Input conflicts with current durable lifecycle or shard evidence.
    #[error("federated storage lifecycle evidence conflicts")]
    Conflict,
    /// Persisted lifecycle, quota or receipt evidence is contradictory.
    #[error("federated storage lifecycle state is corrupt")]
    CorruptState,
    /// Signed capability evidence was unavailable or malformed.
    #[error("federated storage lifecycle capability evidence failed")]
    Capability(#[from] FederationStorageCapabilityLedgerError),
    /// SQLite rejected an atomic lifecycle transition.
    #[error("federated storage lifecycle database operation failed")]
    Database(#[from] rusqlite::Error),
}
