// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    BackupDestinationId, BackupId, ComponentInstanceId, MeshId, PartitionId, Revision, TargetId,
    UnixMicros,
};
use rusqlite::{Connection, OptionalExtension, Row, params};

use super::super::RepositoryError;
use super::{
    BackupCopyRecord, BackupCopyState, BackupDestinationCursor, BackupDestinationRecord,
    BackupDestinationState, MetadataBackupRecord, MetadataBackupState,
};
use crate::repository::{Page, PageLimit};
use crate::{BackupDestinationBinding, BackupFailureRelationship};

const DESTINATION_REGISTERED_TARGET: i64 = 1;
const DESTINATION_FEDERATED_MESH: i64 = 2;
const DESTINATION_COMPONENT_PROVIDER: i64 = 3;
const FAILURE_UNKNOWN: i64 = 1;
const FAILURE_OVERLAPPING: i64 = 2;
const FAILURE_INDEPENDENT: i64 = 3;
const DESTINATION_ACTIVE: i64 = 1;
const DESTINATION_PAUSED: i64 = 2;
const BACKUP_RECORDED: i64 = 1;
const BACKUP_VERIFIED: i64 = 2;
const COPY_STORED: i64 = 1;
const COPY_VERIFIED: i64 = 2;

pub(in crate::repository) fn backup(
    connection: &Connection,
    backup_id: BackupId,
) -> Result<Option<MetadataBackupRecord>, RepositoryError> {
    connection
        .query_row(
            "SELECT backup_id, partition_id, mesh_id, last_log_index, last_log_term,
                    state_revision, schema_version, source_byte_length, source_digest,
                    manifest_digest, encrypted_byte_length, encrypted_digest, state, created_at,
                    verified_at, revision
             FROM metadata_backups WHERE backup_id = ?1",
            [backup_id.as_bytes().as_slice()],
            decode_backup,
        )
        .optional()
        .map_err(Into::into)
}

pub(in crate::repository) fn destination(
    connection: &Connection,
    destination_id: BackupDestinationId,
) -> Result<Option<BackupDestinationRecord>, RepositoryError> {
    connection
        .query_row(
            "SELECT destination_id, display_name, canonical_name, destination_kind, target_id,
                    remote_mesh_id, provider_instance_id, provider_generation,
                    failure_relationship, failure_evidence_digest, state, created_at, revision
             FROM backup_destinations WHERE destination_id = ?1",
            [destination_id.as_bytes().as_slice()],
            decode_destination,
        )
        .optional()
        .map_err(Into::into)
}

pub(in crate::repository) fn copy(
    connection: &Connection,
    backup_id: BackupId,
    destination_id: BackupDestinationId,
) -> Result<Option<BackupCopyRecord>, RepositoryError> {
    connection
        .query_row(
            "SELECT backup_id, destination_id, provider_generation, object_reference,
                    byte_length, copy_digest, state, stored_at, verified_at, revision
             FROM backup_copies WHERE backup_id = ?1 AND destination_id = ?2",
            params![
                backup_id.as_bytes().as_slice(),
                destination_id.as_bytes().as_slice()
            ],
            decode_copy,
        )
        .optional()
        .map_err(Into::into)
}

pub(in crate::repository) fn active_destinations(
    connection: &Connection,
    after: Option<BackupDestinationCursor>,
    limit: PageLimit,
) -> Result<Page<BackupDestinationRecord, BackupDestinationCursor>, RepositoryError> {
    destinations(connection, after, limit, true)
}

pub(in crate::repository) fn destinations(
    connection: &Connection,
    after: Option<BackupDestinationCursor>,
    limit: PageLimit,
    active_only: bool,
) -> Result<Page<BackupDestinationRecord, BackupDestinationCursor>, RepositoryError> {
    let lower = after.map_or([0; 16], |cursor| cursor.destination_id.as_bytes());
    let sql_limit = i64::try_from(limit.get().saturating_add(1))
        .map_err(|_| RepositoryError::InvalidPageLimit)?;
    let query = if active_only {
        "SELECT destination_id, display_name, canonical_name, destination_kind, target_id,
                remote_mesh_id, provider_instance_id, provider_generation,
                failure_relationship, failure_evidence_digest, state, created_at, revision
         FROM backup_destinations
         WHERE state = ?1 AND destination_id > ?2
         ORDER BY destination_id LIMIT ?3"
    } else {
        "SELECT destination_id, display_name, canonical_name, destination_kind, target_id,
                remote_mesh_id, provider_instance_id, provider_generation,
                failure_relationship, failure_evidence_digest, state, created_at, revision
         FROM backup_destinations WHERE destination_id > ?2
         ORDER BY destination_id LIMIT ?3"
    };
    let mut statement = connection.prepare(query)?;
    let rows = statement.query_map(
        params![DESTINATION_ACTIVE, lower.as_slice(), sql_limit],
        decode_destination,
    )?;
    let mut items = Vec::with_capacity(limit.get().saturating_add(1));
    for row in rows {
        items.push(row?);
    }
    let next = (items.len() > limit.get()).then(|| BackupDestinationCursor {
        destination_id: items[limit.get() - 1].destination_id,
    });
    items.truncate(limit.get());
    Ok(Page { items, next })
}

fn decode_backup(row: &Row<'_>) -> rusqlite::Result<MetadataBackupRecord> {
    Ok(MetadataBackupRecord {
        backup_id: BackupId::from_bytes(blob16(row, 0)?).map_err(sql_decode_error)?,
        partition_id: PartitionId::from_bytes(blob16(row, 1)?).map_err(sql_decode_error)?,
        mesh_id: MeshId::from_bytes(blob16(row, 2)?).map_err(sql_decode_error)?,
        last_log_index: sql_u64(row, 3)?,
        last_log_term: sql_u64(row, 4)?,
        state_revision: Revision::new(sql_u64(row, 5)?),
        schema_version: u32::try_from(sql_u64(row, 6)?).map_err(sql_decode_error)?,
        source_byte_length: sql_u64(row, 7)?,
        source_digest: digest32(&row.get::<_, Vec<u8>>(8)?).map_err(sql_decode_error)?,
        manifest_digest: digest32(&row.get::<_, Vec<u8>>(9)?).map_err(sql_decode_error)?,
        encrypted_byte_length: sql_u64(row, 10)?,
        encrypted_digest: digest32(&row.get::<_, Vec<u8>>(11)?).map_err(sql_decode_error)?,
        state: decode_backup_state(row.get(12)?).map_err(sql_decode_error)?,
        created_at: UnixMicros::new(row.get(13)?),
        verified_at: row.get::<_, Option<i64>>(14)?.map(UnixMicros::new),
        revision: Revision::new(sql_u64(row, 15)?),
    })
}

fn decode_destination(row: &Row<'_>) -> rusqlite::Result<BackupDestinationRecord> {
    let generation = sql_u64(row, 7)?;
    let binding = match row.get::<_, i64>(3)? {
        DESTINATION_REGISTERED_TARGET => BackupDestinationBinding::RegisteredTarget {
            target_id: TargetId::from_bytes(required_blob16(row, 4)?).map_err(sql_decode_error)?,
            target_generation: generation,
        },
        DESTINATION_FEDERATED_MESH => BackupDestinationBinding::FederatedMesh {
            remote_mesh_id: MeshId::from_bytes(required_blob16(row, 5)?)
                .map_err(sql_decode_error)?,
            provider_generation: generation,
        },
        DESTINATION_COMPONENT_PROVIDER => BackupDestinationBinding::ComponentProvider {
            instance_id: ComponentInstanceId::from_bytes(required_blob16(row, 6)?)
                .map_err(sql_decode_error)?,
            provider_generation: generation,
        },
        _ => {
            return Err(sql_decode_error(CatalogueDecodeError(
                "invalid backup destination kind",
            )));
        }
    };
    Ok(BackupDestinationRecord {
        destination_id: BackupDestinationId::from_bytes(blob16(row, 0)?)
            .map_err(sql_decode_error)?,
        display_name: row.get(1)?,
        canonical_name: row.get(2)?,
        binding,
        failure_relationship: decode_failure_relationship(row.get(8)?).map_err(sql_decode_error)?,
        failure_evidence_digest: digest32(&row.get::<_, Vec<u8>>(9)?).map_err(sql_decode_error)?,
        state: decode_destination_state(row.get(10)?).map_err(sql_decode_error)?,
        created_at: UnixMicros::new(row.get(11)?),
        revision: Revision::new(sql_u64(row, 12)?),
    })
}

fn decode_copy(row: &Row<'_>) -> rusqlite::Result<BackupCopyRecord> {
    Ok(BackupCopyRecord {
        backup_id: BackupId::from_bytes(blob16(row, 0)?).map_err(sql_decode_error)?,
        destination_id: BackupDestinationId::from_bytes(blob16(row, 1)?)
            .map_err(sql_decode_error)?,
        provider_generation: sql_u64(row, 2)?,
        object_reference: row.get(3)?,
        byte_length: sql_u64(row, 4)?,
        copy_digest: digest32(&row.get::<_, Vec<u8>>(5)?).map_err(sql_decode_error)?,
        state: decode_copy_state(row.get(6)?).map_err(sql_decode_error)?,
        stored_at: UnixMicros::new(row.get(7)?),
        verified_at: row.get::<_, Option<i64>>(8)?.map(UnixMicros::new),
        revision: Revision::new(sql_u64(row, 9)?),
    })
}

fn decode_failure_relationship(
    value: i64,
) -> Result<BackupFailureRelationship, CatalogueDecodeError> {
    match value {
        FAILURE_UNKNOWN => Ok(BackupFailureRelationship::Unknown),
        FAILURE_OVERLAPPING => Ok(BackupFailureRelationship::Overlapping),
        FAILURE_INDEPENDENT => Ok(BackupFailureRelationship::Independent),
        _ => Err(CatalogueDecodeError("invalid backup failure relationship")),
    }
}

fn decode_backup_state(value: i64) -> Result<MetadataBackupState, CatalogueDecodeError> {
    match value {
        BACKUP_RECORDED => Ok(MetadataBackupState::Recorded),
        BACKUP_VERIFIED => Ok(MetadataBackupState::Verified),
        3 => Ok(MetadataBackupState::Retired),
        _ => Err(CatalogueDecodeError("invalid metadata backup state")),
    }
}

fn decode_destination_state(value: i64) -> Result<BackupDestinationState, CatalogueDecodeError> {
    match value {
        DESTINATION_ACTIVE => Ok(BackupDestinationState::Active),
        DESTINATION_PAUSED => Ok(BackupDestinationState::Paused),
        3 => Ok(BackupDestinationState::Retired),
        _ => Err(CatalogueDecodeError("invalid backup destination state")),
    }
}

fn decode_copy_state(value: i64) -> Result<BackupCopyState, CatalogueDecodeError> {
    match value {
        COPY_STORED => Ok(BackupCopyState::Stored),
        COPY_VERIFIED => Ok(BackupCopyState::Verified),
        3 => Ok(BackupCopyState::Failed),
        4 => Ok(BackupCopyState::Retired),
        _ => Err(CatalogueDecodeError("invalid backup copy state")),
    }
}

fn required_blob16(row: &Row<'_>, index: usize) -> rusqlite::Result<[u8; 16]> {
    let value = row.get::<_, Option<Vec<u8>>>(index)?.ok_or_else(|| {
        sql_decode_error(CatalogueDecodeError("missing backup destination binding"))
    })?;
    value
        .as_slice()
        .try_into()
        .map_err(|_| sql_decode_error(CatalogueDecodeError("invalid identifier length")))
}

fn blob16(row: &Row<'_>, index: usize) -> rusqlite::Result<[u8; 16]> {
    let value: Vec<u8> = row.get(index)?;
    value
        .as_slice()
        .try_into()
        .map_err(|_| sql_decode_error(CatalogueDecodeError("invalid identifier length")))
}

fn digest32(value: &[u8]) -> Result<[u8; 32], CatalogueDecodeError> {
    value
        .try_into()
        .map_err(|_| CatalogueDecodeError("invalid digest length"))
}

fn sql_u64(row: &Row<'_>, index: usize) -> rusqlite::Result<u64> {
    u64::try_from(row.get::<_, i64>(index)?).map_err(sql_decode_error)
}

#[derive(Debug)]
struct CatalogueDecodeError(&'static str);

impl std::fmt::Display for CatalogueDecodeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for CatalogueDecodeError {}

fn sql_decode_error(error: impl std::error::Error + Send + Sync + 'static) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(error))
}
