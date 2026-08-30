// SPDX-License-Identifier: GPL-2.0-only

//! Immutable node-local evidence for every signed federated storage capability presentation.

use meshspan_contracts::{FederatedShardPermit, ShardIdentity};
use meshspan_domain::{
    FederationGrantId, FederationRelationshipId, FederationStorageAction,
    FederationStorageAllocationId, MeshId, NodeId, OperationId, Revision, TargetId, UnixMicros,
};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use thiserror::Error;

use crate::LocalDatabase;

/// Complete immutable correlation between one signed wire capability and its provider permit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationStorageCapabilityPresentation {
    /// SHA-256 digest of the exact signed wire capability returned to the remote swarm.
    pub capability_digest: [u8; 32],
    /// Provider-only permit carried inside that capability.
    pub permit: FederatedShardPermit,
    /// Federation protocol major used by the original capability request.
    pub protocol_major: u32,
    /// Federation protocol minor used by the original capability request.
    pub protocol_minor: u32,
    /// Original request correlation identity.
    pub request_id: [u8; 16],
    /// Original distributed trace identity.
    pub trace_id: [u8; 16],
    /// Original request deadline, which also fences any later receipt.
    pub request_deadline: UnixMicros,
    /// Provider response nonce which a later receipt must not reflect.
    pub response_replay_nonce: [u8; 32],
    /// Local durable-recording instant before the capability could be sent.
    pub recorded_at: UnixMicros,
}

/// Idempotent presentation-recording outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FederationStorageCapabilityDisposition {
    /// New immutable presentation evidence was committed.
    Applied,
    /// The exact presentation already existed.
    Replayed,
}

impl LocalDatabase {
    /// Persists one signed capability presentation before its bytes may cross the network.
    ///
    /// # Errors
    ///
    /// Rejects malformed evidence, digest/nonce reuse and SQLite failure atomically.
    pub fn record_federated_storage_capability(
        &mut self,
        presentation: &FederationStorageCapabilityPresentation,
    ) -> Result<FederationStorageCapabilityDisposition, FederationStorageCapabilityLedgerError>
    {
        record(self, presentation)
    }

    /// Loads one independently validated presentation by its exact signed capability digest.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed persisted identity, authority, bounds or correlation fields.
    pub fn federated_storage_capability(
        &self,
        capability_digest: [u8; 32],
    ) -> Result<
        Option<FederationStorageCapabilityPresentation>,
        FederationStorageCapabilityLedgerError,
    > {
        if !valid_digest(capability_digest) {
            return Err(FederationStorageCapabilityLedgerError::Invalid);
        }
        load(self.connection(), capability_digest)
    }

    /// Loads the exact provider permit already issued for one idempotent operation.
    ///
    /// Multiple outer signed responses may exist after lost replies, but every response for one
    /// operation must carry the same inner permit. A conflicting persisted permit fails closed.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed identity, conflicting permit evidence or corrupt rows.
    pub fn federated_storage_capability_for_operation(
        &self,
        operation_id: OperationId,
    ) -> Result<
        Option<FederationStorageCapabilityPresentation>,
        FederationStorageCapabilityLedgerError,
    > {
        load_for_operation(self.connection(), operation_id)
    }
}

fn load_for_operation(
    connection: &rusqlite::Connection,
    operation_id: OperationId,
) -> Result<Option<FederationStorageCapabilityPresentation>, FederationStorageCapabilityLedgerError>
{
    let capability_digest = connection
        .query_row(
            "SELECT capability_digest FROM local_federation_storage_capabilities
             WHERE operation_id = ?1 ORDER BY recorded_at, capability_digest LIMIT 1",
            [operation_id.as_bytes().as_slice()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?
        .map(|value| exact(&value))
        .transpose()?;
    let Some(capability_digest) = capability_digest else {
        return Ok(None);
    };
    let presentation = load(connection, capability_digest)?
        .ok_or(FederationStorageCapabilityLedgerError::CorruptState)?;
    let conflicting: bool = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM local_federation_storage_capabilities
             WHERE operation_id = ?1 AND permit_digest != ?2
         )",
        params![
            operation_id.as_bytes().as_slice(),
            presentation.permit.permit_digest.as_slice()
        ],
        |row| row.get(0),
    )?;
    if conflicting {
        Err(FederationStorageCapabilityLedgerError::CorruptState)
    } else {
        Ok(Some(presentation))
    }
}

fn record(
    database: &mut LocalDatabase,
    presentation: &FederationStorageCapabilityPresentation,
) -> Result<FederationStorageCapabilityDisposition, FederationStorageCapabilityLedgerError> {
    validate(presentation)?;
    let transaction = database
        .connection_mut()
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(stored) = load(&transaction, presentation.capability_digest)? {
        if stored == *presentation {
            transaction.commit()?;
            return Ok(FederationStorageCapabilityDisposition::Replayed);
        }
        return Err(FederationStorageCapabilityLedgerError::Conflict);
    }
    reject_nonce_substitution(&transaction, presentation)?;
    insert(&transaction, presentation)?;
    let stored = load(&transaction, presentation.capability_digest)?
        .ok_or(FederationStorageCapabilityLedgerError::CorruptState)?;
    if stored != *presentation {
        return Err(FederationStorageCapabilityLedgerError::CorruptState);
    }
    transaction.commit()?;
    Ok(FederationStorageCapabilityDisposition::Applied)
}

fn reject_nonce_substitution(
    transaction: &Transaction<'_>,
    presentation: &FederationStorageCapabilityPresentation,
) -> Result<(), FederationStorageCapabilityLedgerError> {
    let exists: bool = transaction.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM local_federation_storage_capabilities
             WHERE operation_id = ?1 AND response_replay_nonce = ?2
         )",
        params![
            presentation.permit.operation_id.as_bytes().as_slice(),
            presentation.response_replay_nonce.as_slice(),
        ],
        |row| row.get(0),
    )?;
    if exists {
        Err(FederationStorageCapabilityLedgerError::Conflict)
    } else {
        Ok(())
    }
}

fn insert(
    transaction: &Transaction<'_>,
    presentation: &FederationStorageCapabilityPresentation,
) -> Result<(), FederationStorageCapabilityLedgerError> {
    let permit = presentation.permit;
    transaction.execute(
        "INSERT INTO local_federation_storage_capabilities(
            capability_digest, operation_id, permit_digest, relationship_id, remote_mesh_id,
            provider_mesh_id, allocation_id, grant_id, provider_node_id, target_id,
            target_generation, manifest_digest, stripe_index, shard_index, shard_generation,
            action, maximum_bytes, relationship_authority_epoch, grant_revision,
            allocation_revision, capability_nonce, scope_digest, request_digest, issued_at,
            expires_at, protocol_major, protocol_minor, request_id, trace_id, request_deadline,
            response_replay_nonce, recorded_at
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
            ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20,
            ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30,
            ?31, ?32
         )",
        params![
            presentation.capability_digest.as_slice(),
            permit.operation_id.as_bytes().as_slice(),
            permit.permit_digest.as_slice(),
            permit.relationship_id.as_bytes().as_slice(),
            permit.remote_mesh_id.as_bytes().as_slice(),
            permit.provider_mesh_id.as_bytes().as_slice(),
            permit.allocation_id.as_bytes().as_slice(),
            permit.grant_id.as_bytes().as_slice(),
            permit.provider_node_id.as_bytes().as_slice(),
            permit.target_id.as_bytes().as_slice(),
            to_i64(permit.target_generation)?,
            permit.shard.manifest_digest.as_slice(),
            to_i64(permit.shard.stripe_index)?,
            i64::from(permit.shard.shard_index),
            i64::from(permit.shard.generation),
            i64::from(permit.action.code()),
            to_i64(permit.maximum_bytes)?,
            to_i64(permit.relationship_authority_epoch)?,
            to_i64(permit.grant_revision.get())?,
            to_i64(permit.allocation_revision.get())?,
            permit.capability_nonce.as_slice(),
            permit.scope_digest.as_slice(),
            permit.request_digest.as_slice(),
            permit.issued_at.get(),
            permit.expires_at.get(),
            i64::from(presentation.protocol_major),
            i64::from(presentation.protocol_minor),
            presentation.request_id.as_slice(),
            presentation.trace_id.as_slice(),
            presentation.request_deadline.get(),
            presentation.response_replay_nonce.as_slice(),
            presentation.recorded_at.get(),
        ],
    )?;
    Ok(())
}

fn load(
    connection: &rusqlite::Connection,
    capability_digest: [u8; 32],
) -> Result<Option<FederationStorageCapabilityPresentation>, FederationStorageCapabilityLedgerError>
{
    let row = connection
        .query_row(
            "SELECT operation_id, permit_digest, relationship_id, remote_mesh_id,
                    provider_mesh_id, allocation_id, grant_id, provider_node_id, target_id,
                    target_generation, manifest_digest, stripe_index, shard_index,
                    shard_generation, action, maximum_bytes, relationship_authority_epoch,
                    grant_revision, allocation_revision, capability_nonce, scope_digest,
                    request_digest, issued_at, expires_at, protocol_major, protocol_minor,
                    request_id, trace_id, request_deadline,
                    response_replay_nonce, recorded_at
             FROM local_federation_storage_capabilities WHERE capability_digest = ?1",
            [capability_digest.as_slice()],
            |row| {
                Ok(StoredPresentation {
                    operation_id: row.get(0)?,
                    permit_digest: row.get(1)?,
                    relationship_id: row.get(2)?,
                    remote_mesh_id: row.get(3)?,
                    provider_mesh_id: row.get(4)?,
                    allocation_id: row.get(5)?,
                    grant_id: row.get(6)?,
                    provider_node_id: row.get(7)?,
                    target_id: row.get(8)?,
                    target_generation: row.get(9)?,
                    manifest_digest: row.get(10)?,
                    stripe_index: row.get(11)?,
                    shard_index: row.get(12)?,
                    shard_generation: row.get(13)?,
                    action: row.get(14)?,
                    maximum_bytes: row.get(15)?,
                    relationship_authority_epoch: row.get(16)?,
                    grant_revision: row.get(17)?,
                    allocation_revision: row.get(18)?,
                    capability_nonce: row.get(19)?,
                    scope_digest: row.get(20)?,
                    request_digest: row.get(21)?,
                    issued_at: row.get(22)?,
                    expires_at: row.get(23)?,
                    protocol_major: row.get(24)?,
                    protocol_minor: row.get(25)?,
                    request_id: row.get(26)?,
                    trace_id: row.get(27)?,
                    request_deadline: row.get(28)?,
                    response_replay_nonce: row.get(29)?,
                    recorded_at: row.get(30)?,
                })
            },
        )
        .optional()?;
    row.as_ref()
        .map(|stored| decode(capability_digest, stored))
        .transpose()
}

struct StoredPresentation {
    operation_id: Vec<u8>,
    permit_digest: Vec<u8>,
    relationship_id: Vec<u8>,
    remote_mesh_id: Vec<u8>,
    provider_mesh_id: Vec<u8>,
    allocation_id: Vec<u8>,
    grant_id: Vec<u8>,
    provider_node_id: Vec<u8>,
    target_id: Vec<u8>,
    target_generation: i64,
    manifest_digest: Vec<u8>,
    stripe_index: i64,
    shard_index: i64,
    shard_generation: i64,
    action: i64,
    maximum_bytes: i64,
    relationship_authority_epoch: i64,
    grant_revision: i64,
    allocation_revision: i64,
    capability_nonce: Vec<u8>,
    scope_digest: Vec<u8>,
    request_digest: Vec<u8>,
    issued_at: i64,
    expires_at: i64,
    protocol_major: i64,
    protocol_minor: i64,
    request_id: Vec<u8>,
    trace_id: Vec<u8>,
    request_deadline: i64,
    response_replay_nonce: Vec<u8>,
    recorded_at: i64,
}

fn decode(
    capability_digest: [u8; 32],
    row: &StoredPresentation,
) -> Result<FederationStorageCapabilityPresentation, FederationStorageCapabilityLedgerError> {
    let presentation = FederationStorageCapabilityPresentation {
        capability_digest,
        permit: FederatedShardPermit {
            operation_id: OperationId::from_bytes(exact(&row.operation_id)?)
                .map_err(|_| FederationStorageCapabilityLedgerError::CorruptState)?,
            relationship_id: FederationRelationshipId::from_bytes(exact(&row.relationship_id)?)
                .map_err(|_| FederationStorageCapabilityLedgerError::CorruptState)?,
            remote_mesh_id: MeshId::from_bytes(exact(&row.remote_mesh_id)?)
                .map_err(|_| FederationStorageCapabilityLedgerError::CorruptState)?,
            provider_mesh_id: MeshId::from_bytes(exact(&row.provider_mesh_id)?)
                .map_err(|_| FederationStorageCapabilityLedgerError::CorruptState)?,
            allocation_id: FederationStorageAllocationId::from_bytes(exact(&row.allocation_id)?)
                .map_err(|_| FederationStorageCapabilityLedgerError::CorruptState)?,
            grant_id: FederationGrantId::from_bytes(exact(&row.grant_id)?)
                .map_err(|_| FederationStorageCapabilityLedgerError::CorruptState)?,
            provider_node_id: NodeId::from_bytes(exact(&row.provider_node_id)?)
                .map_err(|_| FederationStorageCapabilityLedgerError::CorruptState)?,
            target_id: TargetId::from_bytes(exact(&row.target_id)?)
                .map_err(|_| FederationStorageCapabilityLedgerError::CorruptState)?,
            target_generation: positive(row.target_generation)?,
            shard: ShardIdentity {
                manifest_digest: exact(&row.manifest_digest)?,
                stripe_index: nonnegative(row.stripe_index)?,
                shard_index: u16::try_from(row.shard_index)
                    .map_err(|_| FederationStorageCapabilityLedgerError::CorruptState)?,
                generation: u32::try_from(row.shard_generation)
                    .map_err(|_| FederationStorageCapabilityLedgerError::CorruptState)?,
            },
            action: FederationStorageAction::from_code(
                u8::try_from(row.action)
                    .map_err(|_| FederationStorageCapabilityLedgerError::CorruptState)?,
            )
            .map_err(|_| FederationStorageCapabilityLedgerError::CorruptState)?,
            maximum_bytes: positive(row.maximum_bytes)?,
            relationship_authority_epoch: positive(row.relationship_authority_epoch)?,
            grant_revision: revision(row.grant_revision)?,
            allocation_revision: revision(row.allocation_revision)?,
            issued_at: UnixMicros::new(row.issued_at),
            expires_at: UnixMicros::new(row.expires_at),
            capability_nonce: exact(&row.capability_nonce)?,
            scope_digest: exact(&row.scope_digest)?,
            request_digest: exact(&row.request_digest)?,
            permit_digest: exact(&row.permit_digest)?,
        },
        protocol_major: u32::try_from(row.protocol_major)
            .map_err(|_| FederationStorageCapabilityLedgerError::CorruptState)?,
        protocol_minor: u32::try_from(row.protocol_minor)
            .map_err(|_| FederationStorageCapabilityLedgerError::CorruptState)?,
        request_id: exact(&row.request_id)?,
        trace_id: exact(&row.trace_id)?,
        request_deadline: UnixMicros::new(row.request_deadline),
        response_replay_nonce: exact(&row.response_replay_nonce)?,
        recorded_at: UnixMicros::new(row.recorded_at),
    };
    validate(&presentation)?;
    Ok(presentation)
}

fn validate(
    presentation: &FederationStorageCapabilityPresentation,
) -> Result<(), FederationStorageCapabilityLedgerError> {
    let permit = presentation.permit;
    let valid = valid_digest(presentation.capability_digest)
        && valid_digest(permit.permit_digest)
        && valid_digest(permit.shard.manifest_digest)
        && valid_digest(permit.capability_nonce)
        && valid_digest(permit.scope_digest)
        && valid_digest(permit.request_digest)
        && permit.shard.generation > 0
        && permit.target_generation > 0
        && permit.maximum_bytes > 0
        && permit.relationship_authority_epoch > 0
        && permit.grant_revision != Revision::ZERO
        && permit.allocation_revision != Revision::ZERO
        && permit.issued_at.get() > 0
        && permit.expires_at > permit.issued_at
        && presentation.protocol_major > 0
        && presentation.request_id != [0; 16]
        && presentation.trace_id != [0; 16]
        && presentation.request_deadline >= permit.expires_at
        && presentation.response_replay_nonce != [0; 32]
        && presentation.response_replay_nonce != permit.capability_nonce
        && presentation.recorded_at >= permit.issued_at
        && presentation.recorded_at < permit.expires_at;
    if valid {
        Ok(())
    } else {
        Err(FederationStorageCapabilityLedgerError::Invalid)
    }
}

fn exact<const LENGTH: usize>(
    bytes: &[u8],
) -> Result<[u8; LENGTH], FederationStorageCapabilityLedgerError> {
    bytes
        .try_into()
        .map_err(|_| FederationStorageCapabilityLedgerError::CorruptState)
}

fn positive(value: i64) -> Result<u64, FederationStorageCapabilityLedgerError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(FederationStorageCapabilityLedgerError::CorruptState)
}

fn nonnegative(value: i64) -> Result<u64, FederationStorageCapabilityLedgerError> {
    u64::try_from(value).map_err(|_| FederationStorageCapabilityLedgerError::CorruptState)
}

fn revision(value: i64) -> Result<Revision, FederationStorageCapabilityLedgerError> {
    let revision = Revision::new(positive(value)?);
    if revision == Revision::ZERO {
        Err(FederationStorageCapabilityLedgerError::CorruptState)
    } else {
        Ok(revision)
    }
}

fn to_i64(value: u64) -> Result<i64, FederationStorageCapabilityLedgerError> {
    i64::try_from(value).map_err(|_| FederationStorageCapabilityLedgerError::Invalid)
}

fn valid_digest(value: [u8; 32]) -> bool {
    value != [0; 32]
}

/// Stable local presentation-ledger failures.
#[derive(Debug, Error)]
pub enum FederationStorageCapabilityLedgerError {
    /// Input was malformed or outside durable bounds.
    #[error("federated storage capability presentation is invalid")]
    Invalid,
    /// A digest, operation or nonce was reused for different evidence.
    #[error("federated storage capability presentation conflicts")]
    Conflict,
    /// Persisted rows contradict their declared shape.
    #[error("federated storage capability presentation is corrupt")]
    CorruptState,
    /// SQLite rejected the atomic transition.
    #[error("federated storage capability presentation database operation failed")]
    Database(#[from] rusqlite::Error),
}

#[cfg(test)]
mod tests {
    use meshspan_contracts::{FederatedShardPermit, ShardIdentity};
    use meshspan_domain::{
        FederationGrantId, FederationRelationshipId, FederationStorageAction,
        FederationStorageAllocationId, MeshId, NodeId, OperationId, Revision, TargetId, UnixMicros,
    };
    use tempfile::tempdir;

    use super::{
        FederationStorageCapabilityDisposition, FederationStorageCapabilityLedgerError,
        FederationStorageCapabilityPresentation,
    };
    use crate::LocalDatabase;

    #[test]
    fn presentations_are_immutable_replayable_and_restart_safe()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let file_path = directory.path().join("local.sqlite3");
        let node_id = NodeId::from_bytes([9; 16])?;
        let mut database = LocalDatabase::open(&file_path, node_id, UnixMicros::new(10))?;
        let presentation = presentation(node_id)?;
        assert_eq!(
            database.record_federated_storage_capability(&presentation)?,
            FederationStorageCapabilityDisposition::Applied
        );
        assert_eq!(
            database.record_federated_storage_capability(&presentation)?,
            FederationStorageCapabilityDisposition::Replayed
        );
        let mut substituted = presentation;
        substituted.permit.maximum_bytes += 1;
        assert!(matches!(
            database.record_federated_storage_capability(&substituted),
            Err(FederationStorageCapabilityLedgerError::Conflict)
        ));
        drop(database);
        let database = LocalDatabase::open(&file_path, node_id, UnixMicros::new(11))?;
        assert_eq!(
            database.federated_storage_capability(presentation.capability_digest)?,
            Some(presentation)
        );
        assert_eq!(
            database
                .federated_storage_capability_for_operation(presentation.permit.operation_id)?,
            Some(presentation)
        );
        Ok(())
    }

    #[test]
    fn persisted_shape_corruption_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let node_id = NodeId::from_bytes([9; 16])?;
        let mut database = LocalDatabase::open(
            &directory.path().join("local.sqlite3"),
            node_id,
            UnixMicros::new(10),
        )?;
        let presentation = presentation(node_id)?;
        database.record_federated_storage_capability(&presentation)?;
        database.connection().execute_batch(
            "DROP TRIGGER local_federation_storage_capabilities_reject_update;
             PRAGMA ignore_check_constraints = ON;
             UPDATE local_federation_storage_capabilities SET protocol_major = 0;",
        )?;
        assert!(matches!(
            database.federated_storage_capability(presentation.capability_digest),
            Err(FederationStorageCapabilityLedgerError::Invalid
                | FederationStorageCapabilityLedgerError::CorruptState)
        ));
        Ok(())
    }

    fn presentation(
        provider_node_id: NodeId,
    ) -> Result<FederationStorageCapabilityPresentation, Box<dyn std::error::Error>> {
        Ok(FederationStorageCapabilityPresentation {
            capability_digest: [1; 32],
            permit: FederatedShardPermit {
                operation_id: OperationId::from_bytes([2; 16])?,
                relationship_id: FederationRelationshipId::from_bytes([3; 16])?,
                remote_mesh_id: MeshId::from_bytes([4; 16])?,
                provider_mesh_id: MeshId::from_bytes([5; 16])?,
                allocation_id: FederationStorageAllocationId::from_bytes([6; 16])?,
                grant_id: FederationGrantId::from_bytes([7; 16])?,
                provider_node_id,
                target_id: TargetId::from_bytes([8; 16])?,
                target_generation: 1,
                shard: ShardIdentity {
                    manifest_digest: [10; 32],
                    stripe_index: 11,
                    shard_index: 12,
                    generation: 13,
                },
                action: FederationStorageAction::Put,
                maximum_bytes: 14,
                relationship_authority_epoch: 1,
                grant_revision: Revision::new(15),
                allocation_revision: Revision::new(16),
                issued_at: UnixMicros::new(17),
                expires_at: UnixMicros::new(30),
                capability_nonce: [18; 32],
                scope_digest: [19; 32],
                request_digest: [20; 32],
                permit_digest: [21; 32],
            },
            protocol_major: 1,
            protocol_minor: 1,
            request_id: [22; 16],
            trace_id: [23; 16],
            request_deadline: UnixMicros::new(31),
            response_replay_nonce: [24; 32],
            recorded_at: UnixMicros::new(17),
        })
    }
}
