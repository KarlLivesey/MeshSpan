// SPDX-License-Identifier: GPL-2.0-only

//! Crash-safe exact federated shard scrub preparation, completion and replay.

use meshspan_contracts::{
    FederatedShardPermit, InventoryEntry, ScrubObservation, ScrubOutcome,
    federated_provider_shard_identity, federated_shard_scrub_result_digest,
    validate_exact_scrub_observation,
};
use meshspan_domain::{
    FederationGrantId, FederationStorageAction, FederationStorageAllocationId, MeshId, OperationId,
    TargetId, UnixMicros,
};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use thiserror::Error;

use crate::{FederationStorageCapabilityLedgerError, LocalDatabase};

/// Provider work required for a fresh operation, or immutable evidence for an exact retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FederationStorageScrubPreparation {
    /// The provider must inspect this exact independently catalogued physical shard.
    Pending(InventoryEntry),
    /// The operation already committed and must return this original observation.
    Replayed(FederationStorageScrubEvidence),
}

/// Durable exact scrub completion input after complete provider-byte inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationStorageScrubCompletion {
    /// Current exact remote scrub permit.
    pub permit: FederatedShardPermit,
    /// Exact signed capability presentation used by the remote swarm.
    pub capability_digest: [u8; 32],
    /// Provider observation over the namespaced physical shard.
    pub provider_observation: ScrubObservation,
    /// Quorum-derived completion instant retained across retries.
    pub completed_at: UnixMicros,
}

/// Immutable logical scrub evidence retained for signed response replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationStorageScrubEvidence {
    /// Logical remote-swarm shard observation.
    pub observation: ScrubObservation,
    /// Digest binding the exact permit, observation and original completion instant.
    pub result_digest: [u8; 32],
    /// Original provider completion instant.
    pub completed_at: UnixMicros,
}

impl LocalDatabase {
    /// Resolves an exact scrub retry or returns the provider-local shard expectation.
    ///
    /// # Errors
    ///
    /// Rejects non-scrub, missing, retired, substituted or corrupt shard evidence.
    pub fn prepare_federated_storage_scrub(
        &self,
        permit: &FederatedShardPermit,
    ) -> Result<FederationStorageScrubPreparation, FederationStorageScrubError> {
        prepare(self, permit)
    }

    /// Commits one immutable logical observation before signed success may leave the provider.
    ///
    /// # Errors
    ///
    /// Rejects stale capability, conflicting replay, provider substitution or corrupt state.
    pub fn record_federated_storage_scrub(
        &mut self,
        completion: &FederationStorageScrubCompletion,
    ) -> Result<FederationStorageScrubEvidence, FederationStorageScrubError> {
        complete(self, completion)
    }
}

fn prepare(
    database: &LocalDatabase,
    permit: &FederatedShardPermit,
) -> Result<FederationStorageScrubPreparation, FederationStorageScrubError> {
    validate_permit(permit)?;
    if let Some(stored) = load_scrub(database.connection(), permit.operation_id)? {
        validate_replay(permit, &stored)?;
        return Ok(FederationStorageScrubPreparation::Replayed(stored.evidence));
    }
    let active = load_active_shard(database.connection(), permit)?;
    Ok(FederationStorageScrubPreparation::Pending(
        active.provider_entry(permit),
    ))
}

fn complete(
    database: &mut LocalDatabase,
    completion: &FederationStorageScrubCompletion,
) -> Result<FederationStorageScrubEvidence, FederationStorageScrubError> {
    validate_capability(database, completion)?;
    validate_permit(&completion.permit)?;
    let transaction = database
        .connection_mut()
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(stored) = load_scrub(&transaction, completion.permit.operation_id)? {
        validate_replay(&completion.permit, &stored)?;
        transaction.commit()?;
        return Ok(stored.evidence);
    }
    let active = load_active_shard(&transaction, &completion.permit)?;
    validate_provider_observation(completion, active)?;
    let observation = logical_observation(completion.provider_observation, &completion.permit);
    let result_digest = federated_shard_scrub_result_digest(
        &completion.permit,
        observation,
        completion.completed_at,
    );
    insert_scrub(&transaction, completion, observation, result_digest)?;
    let stored = load_scrub(&transaction, completion.permit.operation_id)?
        .ok_or(FederationStorageScrubError::CorruptState)?;
    transaction.commit()?;
    Ok(stored.evidence)
}

fn validate_capability(
    database: &LocalDatabase,
    completion: &FederationStorageScrubCompletion,
) -> Result<(), FederationStorageScrubError> {
    let presentation = database
        .federated_storage_capability(completion.capability_digest)?
        .ok_or(FederationStorageScrubError::Conflict)?;
    if presentation.permit == completion.permit {
        Ok(())
    } else {
        Err(FederationStorageScrubError::Conflict)
    }
}

fn validate_permit(permit: &FederatedShardPermit) -> Result<(), FederationStorageScrubError> {
    let valid = permit.action == FederationStorageAction::Scrub
        && permit.maximum_bytes > 0
        && permit.permit_digest != [0; 32];
    valid
        .then_some(())
        .ok_or(FederationStorageScrubError::Invalid)
}

#[derive(Clone, Copy)]
struct ActiveShard {
    grant_id: FederationGrantId,
    allocation_id: FederationStorageAllocationId,
    length: u64,
    digest: [u8; 32],
}

impl ActiveShard {
    fn provider_entry(self, permit: &FederatedShardPermit) -> InventoryEntry {
        InventoryEntry {
            shard: federated_provider_shard_identity(
                permit.remote_mesh_id,
                permit.scope_digest,
                permit.shard,
            ),
            length: self.length,
            digest: self.digest,
            bytes_verified: false,
        }
    }
}

fn load_active_shard(
    connection: &rusqlite::Connection,
    permit: &FederatedShardPermit,
) -> Result<ActiveShard, FederationStorageScrubError> {
    let row = connection
        .query_row(
            "SELECT grant_id, allocation_id, length, content_digest
             FROM local_federation_storage_shards AS shard
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
                permit.remote_mesh_id.as_bytes().as_slice(),
                permit.scope_digest.as_slice(),
                permit.target_id.as_bytes().as_slice(),
                to_i64(permit.target_generation)?,
                permit.shard.manifest_digest.as_slice(),
                to_i64(permit.shard.stripe_index)?,
                i64::from(permit.shard.shard_index),
                i64::from(permit.shard.generation),
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or(FederationStorageScrubError::Conflict)?;
    let active = ActiveShard {
        grant_id: FederationGrantId::from_bytes(exact(&row.0)?)
            .map_err(|_| FederationStorageScrubError::CorruptState)?,
        allocation_id: FederationStorageAllocationId::from_bytes(exact(&row.1)?)
            .map_err(|_| FederationStorageScrubError::CorruptState)?,
        length: positive(row.2)?,
        digest: exact(&row.3)?,
    };
    let exact = active.grant_id == permit.grant_id
        && active.allocation_id == permit.allocation_id
        && active.length <= permit.maximum_bytes;
    exact
        .then_some(active)
        .ok_or(FederationStorageScrubError::Conflict)
}

fn validate_provider_observation(
    completion: &FederationStorageScrubCompletion,
    active: ActiveShard,
) -> Result<(), FederationStorageScrubError> {
    let observation = completion.provider_observation;
    let expected = active.provider_entry(&completion.permit);
    let valid = observation.shard == expected.shard
        && observation.expected_length == Some(expected.length)
        && observation.expected_digest == Some(expected.digest)
        && completion.completed_at >= completion.permit.issued_at
        && completion.completed_at < completion.permit.expires_at
        && validate_exact_scrub_observation(observation).is_ok();
    valid
        .then_some(())
        .ok_or(FederationStorageScrubError::Conflict)
}

fn logical_observation(
    provider: ScrubObservation,
    permit: &FederatedShardPermit,
) -> ScrubObservation {
    ScrubObservation {
        shard: permit.shard,
        ..provider
    }
}

fn insert_scrub(
    transaction: &Transaction<'_>,
    completion: &FederationStorageScrubCompletion,
    observation: ScrubObservation,
    result_digest: [u8; 32],
) -> Result<(), FederationStorageScrubError> {
    let permit = completion.permit;
    transaction.execute(
        "INSERT INTO local_federation_storage_scrubs(
            operation_id, remote_mesh_id, scope_digest, grant_id, allocation_id, target_id,
            target_generation, manifest_digest, stripe_index, shard_index, shard_generation,
            capability_digest, permit_digest, capability_action, expected_length,
            expected_digest, observed_length, observed_digest, outcome, result_digest,
            completed_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                   ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)",
        params![
            permit.operation_id.as_bytes().as_slice(),
            permit.remote_mesh_id.as_bytes().as_slice(),
            permit.scope_digest.as_slice(),
            permit.grant_id.as_bytes().as_slice(),
            permit.allocation_id.as_bytes().as_slice(),
            permit.target_id.as_bytes().as_slice(),
            to_i64(permit.target_generation)?,
            permit.shard.manifest_digest.as_slice(),
            to_i64(permit.shard.stripe_index)?,
            i64::from(permit.shard.shard_index),
            i64::from(permit.shard.generation),
            completion.capability_digest.as_slice(),
            permit.permit_digest.as_slice(),
            i64::from(FederationStorageAction::Scrub.code()),
            to_i64(
                observation
                    .expected_length
                    .ok_or(FederationStorageScrubError::Invalid)?
            )?,
            observation
                .expected_digest
                .ok_or(FederationStorageScrubError::Invalid)?
                .as_slice(),
            observation.observed_length.map(to_i64).transpose()?,
            observation
                .observed_digest
                .as_ref()
                .map(<[u8; 32]>::as_slice),
            i64::from(scrub_outcome_code(observation.outcome)),
            result_digest.as_slice(),
            completion.completed_at.get(),
        ],
    )?;
    Ok(())
}

struct StoredScrub {
    remote_mesh_id: MeshId,
    scope_digest: [u8; 32],
    grant_id: FederationGrantId,
    allocation_id: FederationStorageAllocationId,
    target_id: TargetId,
    target_generation: u64,
    permit_digest: [u8; 32],
    evidence: FederationStorageScrubEvidence,
}

fn load_scrub(
    connection: &rusqlite::Connection,
    operation_id: OperationId,
) -> Result<Option<StoredScrub>, FederationStorageScrubError> {
    let row = connection
        .query_row(
            "SELECT remote_mesh_id, scope_digest, grant_id, allocation_id, target_id,
                    target_generation, manifest_digest, stripe_index, shard_index,
                    shard_generation, permit_digest, expected_length, expected_digest,
                    observed_length, observed_digest, outcome, result_digest, completed_at
             FROM local_federation_storage_scrubs WHERE operation_id = ?1",
            [operation_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, Vec<u8>>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, Vec<u8>>(12)?,
                    row.get::<_, Option<i64>>(13)?,
                    row.get::<_, Option<Vec<u8>>>(14)?,
                    row.get::<_, i64>(15)?,
                    row.get::<_, Vec<u8>>(16)?,
                    row.get::<_, i64>(17)?,
                ))
            },
        )
        .optional()?;
    row.as_ref().map(decode_scrub).transpose()
}

type ScrubRow = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    Vec<u8>,
    i64,
    i64,
    i64,
    Vec<u8>,
    i64,
    Vec<u8>,
    Option<i64>,
    Option<Vec<u8>>,
    i64,
    Vec<u8>,
    i64,
);

fn decode_scrub(row: &ScrubRow) -> Result<StoredScrub, FederationStorageScrubError> {
    let outcome = scrub_outcome(row.15)?;
    let observation = ScrubObservation {
        shard: meshspan_contracts::ShardIdentity {
            manifest_digest: exact(&row.6)?,
            stripe_index: nonnegative(row.7)?,
            shard_index: u16::try_from(row.8)
                .map_err(|_| FederationStorageScrubError::CorruptState)?,
            generation: u32::try_from(row.9)
                .map_err(|_| FederationStorageScrubError::CorruptState)?,
        },
        expected_length: Some(positive(row.11)?),
        expected_digest: Some(exact(&row.12)?),
        observed_length: row.13.map(nonnegative).transpose()?,
        observed_digest: row.14.as_deref().map(exact).transpose()?,
        outcome,
    };
    validate_stored_observation(&observation)?;
    Ok(StoredScrub {
        remote_mesh_id: MeshId::from_bytes(exact(&row.0)?)
            .map_err(|_| FederationStorageScrubError::CorruptState)?,
        scope_digest: exact(&row.1)?,
        grant_id: FederationGrantId::from_bytes(exact(&row.2)?)
            .map_err(|_| FederationStorageScrubError::CorruptState)?,
        allocation_id: FederationStorageAllocationId::from_bytes(exact(&row.3)?)
            .map_err(|_| FederationStorageScrubError::CorruptState)?,
        target_id: TargetId::from_bytes(exact(&row.4)?)
            .map_err(|_| FederationStorageScrubError::CorruptState)?,
        target_generation: positive(row.5)?,
        permit_digest: exact(&row.10)?,
        evidence: FederationStorageScrubEvidence {
            observation,
            result_digest: exact(&row.16)?,
            completed_at: UnixMicros::new(row.17),
        },
    })
}

fn validate_stored_observation(
    observation: &ScrubObservation,
) -> Result<(), FederationStorageScrubError> {
    validate_exact_scrub_observation(*observation)
        .map_err(|_| FederationStorageScrubError::CorruptState)
}

fn validate_replay(
    permit: &FederatedShardPermit,
    stored: &StoredScrub,
) -> Result<(), FederationStorageScrubError> {
    let exact = stored.remote_mesh_id == permit.remote_mesh_id
        && stored.scope_digest == permit.scope_digest
        && stored.grant_id == permit.grant_id
        && stored.allocation_id == permit.allocation_id
        && stored.target_id == permit.target_id
        && stored.target_generation == permit.target_generation
        && stored.evidence.observation.shard == permit.shard
        && stored.permit_digest == permit.permit_digest
        && stored
            .evidence
            .observation
            .expected_length
            .is_some_and(|length| length <= permit.maximum_bytes)
        && stored.evidence.completed_at >= permit.issued_at
        && stored.evidence.completed_at < permit.expires_at
        && stored.evidence.result_digest
            == federated_shard_scrub_result_digest(
                permit,
                stored.evidence.observation,
                stored.evidence.completed_at,
            );
    exact
        .then_some(())
        .ok_or(FederationStorageScrubError::Conflict)
}

const fn scrub_outcome_code(outcome: ScrubOutcome) -> u8 {
    match outcome {
        ScrubOutcome::Healthy => 1,
        ScrubOutcome::Missing => 2,
        ScrubOutcome::Corrupt => 3,
        ScrubOutcome::Unreadable => 4,
        ScrubOutcome::Unexpected => 5,
        ScrubOutcome::Deferred => 6,
    }
}

fn scrub_outcome(value: i64) -> Result<ScrubOutcome, FederationStorageScrubError> {
    match value {
        1 => Ok(ScrubOutcome::Healthy),
        2 => Ok(ScrubOutcome::Missing),
        3 => Ok(ScrubOutcome::Corrupt),
        4 => Ok(ScrubOutcome::Unreadable),
        6 => Ok(ScrubOutcome::Deferred),
        _ => Err(FederationStorageScrubError::CorruptState),
    }
}

fn exact<const LENGTH: usize>(value: &[u8]) -> Result<[u8; LENGTH], FederationStorageScrubError> {
    value
        .try_into()
        .map_err(|_| FederationStorageScrubError::CorruptState)
}

fn positive(value: i64) -> Result<u64, FederationStorageScrubError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(FederationStorageScrubError::CorruptState)
}

fn nonnegative(value: i64) -> Result<u64, FederationStorageScrubError> {
    u64::try_from(value).map_err(|_| FederationStorageScrubError::CorruptState)
}

fn to_i64(value: u64) -> Result<i64, FederationStorageScrubError> {
    i64::try_from(value).map_err(|_| FederationStorageScrubError::Invalid)
}

/// Stable node-local exact federated scrub failures.
#[derive(Debug, Error)]
pub enum FederationStorageScrubError {
    /// Input evidence is malformed or contradictory.
    #[error("federated storage scrub input is invalid")]
    Invalid,
    /// Input conflicts with current durable shard or prior scrub evidence.
    #[error("federated storage scrub evidence conflicts")]
    Conflict,
    /// Persisted scrub, shard or receipt evidence is contradictory.
    #[error("federated storage scrub state is corrupt")]
    CorruptState,
    /// Signed capability evidence was unavailable or malformed.
    #[error("federated storage scrub capability evidence failed")]
    Capability(#[from] FederationStorageCapabilityLedgerError),
    /// SQLite rejected an atomic scrub transition.
    #[error("federated storage scrub database operation failed")]
    Database(#[from] rusqlite::Error),
}
