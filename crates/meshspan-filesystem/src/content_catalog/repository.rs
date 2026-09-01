// SPDX-License-Identifier: GPL-2.0-only

//! SQLite opening, migration, row decoding and manifest-invariant reconstruction.

use std::fs;
use std::path::Path;

use meshspan_contracts::ShardReceipt;
use meshspan_domain::{ContentManifestId, OperationId, TargetId, UnixMicros, VolumeId};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use super::{CommittedShardPage, ContentCatalogError, PreparedContentChunk};
use crate::content_transfer::ContentManifestAccumulator;
use crate::{
    CompletedStage, ContentLayoutChunk, ContentLayoutTransferPage, ContentPublicationRequest,
    ManifestPublication, PublishedContentReference,
};

const DATABASE_FILE: &str = "filesystem-content.sqlite3";
const MIGRATIONS: &[&str] = &[
    include_str!("../../schema/content/001_initial.sql"),
    include_str!("../../schema/content/002_layout_import.sql"),
    include_str!("../../schema/content/003_publication_volume.sql"),
];
const MAXIMUM_SQLITE_INTEGER: u64 = 9_223_372_036_854_775_807;

pub(super) struct LayoutSummary {
    pub(super) manifest: ManifestPublication,
    pub(super) chunk_count: u64,
}

pub(super) fn open_connection(
    state_directory: &Path,
    opened_at: UnixMicros,
) -> Result<Connection, ContentCatalogError> {
    fs::create_dir_all(state_directory)?;
    let mut connection = Connection::open(state_directory.join(DATABASE_FILE))?;
    configure(&connection)?;
    migrate(&mut connection, opened_at)?;
    verify_database(&connection)?;
    Ok(connection)
}

pub(super) fn validate_request(
    request: ContentPublicationRequest,
) -> Result<(), ContentCatalogError> {
    if request.format_version == 0
        || request.logical_length > MAXIMUM_SQLITE_INTEGER
        || request.authorization_revision.get() == 0
    {
        Err(ContentCatalogError::InvalidInput)
    } else {
        Ok(())
    }
}

pub(super) fn validate_live_request(
    request: ContentPublicationRequest,
) -> Result<(), ContentCatalogError> {
    validate_request(request)?;
    if request.observed_at >= request.deadline {
        Err(ContentCatalogError::InvalidInput)
    } else {
        Ok(())
    }
}

pub(super) fn validate_chunk(
    chunk: PreparedContentChunk,
    expected: u64,
) -> Result<(), ContentCatalogError> {
    if chunk.chunk_index != expected
        || chunk.plaintext_length == 0
        || chunk.ciphertext_length != chunk.plaintext_length.saturating_add(16)
        || chunk.chunk_index > MAXIMUM_SQLITE_INTEGER
    {
        Err(ContentCatalogError::InvalidInput)
    } else {
        Ok(())
    }
}

pub(super) fn validate_exact_request(
    connection: &Connection,
    request: ContentPublicationRequest,
) -> Result<(), ContentCatalogError> {
    validate_request(request)?;
    let stored =
        load_request(connection, request.operation_id)?.ok_or(ContentCatalogError::InvalidInput)?;
    if stored.same_intent(request) {
        Ok(())
    } else {
        Err(ContentCatalogError::Conflict)
    }
}

pub(super) fn load_request(
    connection: &Connection,
    operation_id: OperationId,
) -> Result<Option<ContentPublicationRequest>, ContentCatalogError> {
    connection
        .query_row(
            "SELECT volume_id, request_digest, manifest_id, format_version, logical_length,
                authorization_revision, deadline FROM content_publications WHERE operation_id = ?1",
            [operation_id.as_bytes().as_slice()],
            |row| {
                Ok(ContentPublicationRequest {
                    operation_id,
                    volume_id: decode_volume(&row.get::<_, Vec<u8>>(0)?)?,
                    request_digest: copy_array(&row.get::<_, Vec<u8>>(1)?)?,
                    manifest_id: decode_manifest(&row.get::<_, Vec<u8>>(2)?)?,
                    format_version: u16::try_from(row.get::<_, i64>(3)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    logical_length: from_sql(row.get(4)?)?,
                    authorization_revision: meshspan_domain::Revision::new(from_sql(row.get(5)?)?),
                    deadline: UnixMicros::new(row.get(6)?),
                    observed_at: UnixMicros::new(i64::MIN),
                })
            },
        )
        .optional()
        .map_err(Into::into)
}

pub(super) fn committed_operation_for_manifest(
    connection: &Connection,
    manifest_id: ContentManifestId,
) -> Result<Option<OperationId>, ContentCatalogError> {
    connection
        .query_row(
            "SELECT operation_id FROM content_publications
             WHERE manifest_id = ?1 AND state = 2",
            [manifest_id.as_bytes().as_slice()],
            |row| decode_operation(&row.get::<_, Vec<u8>>(0)?),
        )
        .optional()
        .map_err(Into::into)
}

pub(super) fn layout_is_sealed(
    connection: &Connection,
    operation_id: OperationId,
) -> Result<bool, ContentCatalogError> {
    connection
        .query_row(
            "SELECT root_digest IS NOT NULL FROM content_publications WHERE operation_id = ?1",
            [operation_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(Into::into)
}

pub(super) fn chunk_count(
    connection: &Connection,
    operation_id: OperationId,
) -> Result<u64, ContentCatalogError> {
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM content_chunks WHERE operation_id = ?1",
        [operation_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    from_i64(count)
}

pub(super) fn layout_summary(
    connection: &Connection,
    request: ContentPublicationRequest,
    completed: CompletedStage,
    chunk_bytes: u64,
) -> Result<LayoutSummary, ContentCatalogError> {
    let mut statement = connection.prepare(
        "SELECT chunk_index, plaintext_length, plaintext_digest, ciphertext_length,
                ciphertext_digest, provider_operation_id
         FROM content_chunks WHERE operation_id = ?1 ORDER BY chunk_index",
    )?;
    let mut rows = statement.query([request.operation_id.as_bytes().as_slice()])?;
    let mut accumulator = ContentManifestAccumulator::new(
        request.manifest_id,
        request.format_version,
        completed.logical_length,
        completed.content_digest,
        chunk_bytes,
    )
    .map_err(|_| ContentCatalogError::InvalidInput)?;
    while let Some(row) = rows.next()? {
        let chunk = decode_chunk(row)?;
        accumulator
            .push(ContentLayoutChunk::from(chunk))
            .map_err(|_| ContentCatalogError::Corrupt)?;
    }
    let (manifest, chunk_count) = accumulator
        .finish()
        .map_err(|_| ContentCatalogError::InvalidInput)?;
    Ok(LayoutSummary {
        manifest,
        chunk_count,
    })
}

pub(super) fn load_prepared_manifest(
    connection: &Connection,
    request: ContentPublicationRequest,
) -> Result<Option<ManifestPublication>, ContentCatalogError> {
    validate_request(request)?;
    let Some(stored_request) = load_request(connection, request.operation_id)? else {
        return Ok(None);
    };
    if !stored_request.same_intent(request) {
        return Err(ContentCatalogError::Conflict);
    }
    let stored = connection
        .query_row(
            "SELECT content_digest, root_digest, chunk_bytes
             FROM content_publications
             WHERE operation_id = ?1 AND root_digest IS NOT NULL",
            [request.operation_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    copy_array(&row.get::<_, Vec<u8>>(0)?)?,
                    copy_array(&row.get::<_, Vec<u8>>(1)?)?,
                    from_sql(row.get(2)?)?,
                ))
            },
        )
        .optional()?;
    stored
        .map(|(content_digest, root_digest, chunk_bytes)| {
            let summary = layout_summary(
                connection,
                request,
                CompletedStage {
                    logical_length: request.logical_length,
                    content_digest,
                },
                chunk_bytes,
            )?;
            if summary.manifest.root_digest == root_digest {
                Ok(summary.manifest)
            } else {
                Err(ContentCatalogError::Corrupt)
            }
        })
        .transpose()
}

pub(super) fn load_chunk(
    connection: &Connection,
    operation_id: OperationId,
    index: u64,
) -> Result<PreparedContentChunk, ContentCatalogError> {
    connection
        .query_row(
            "SELECT chunk_index, plaintext_length, plaintext_digest, ciphertext_length,
                    ciphertext_digest, provider_operation_id
             FROM content_chunks WHERE operation_id = ?1 AND chunk_index = ?2",
            params![operation_id.as_bytes().as_slice(), to_i64(index)?],
            decode_chunk,
        )
        .optional()?
        .ok_or(ContentCatalogError::InvalidInput)
}

pub(super) fn decode_chunk(
    row: &rusqlite::Row<'_>,
) -> Result<PreparedContentChunk, rusqlite::Error> {
    Ok(PreparedContentChunk {
        chunk_index: from_sql(row.get(0)?)?,
        plaintext_length: from_sql(row.get(1)?)?,
        plaintext_digest: copy_array(&row.get::<_, Vec<u8>>(2)?)?,
        ciphertext_length: from_sql(row.get(3)?)?,
        ciphertext_digest: copy_array(&row.get::<_, Vec<u8>>(4)?)?,
        provider_operation_id: decode_operation(&row.get::<_, Vec<u8>>(5)?)?,
    })
}

pub(super) fn load_receipt(
    connection: &Connection,
    operation_id: OperationId,
    index: u64,
) -> Result<Option<ShardReceipt>, ContentCatalogError> {
    let chunk = load_chunk(connection, operation_id, index)?;
    let root_digest = connection.query_row(
        "SELECT root_digest FROM content_publications WHERE operation_id = ?1",
        [operation_id.as_bytes().as_slice()],
        |row| copy_array(&row.get::<_, Vec<u8>>(0)?),
    )?;
    connection
        .query_row(
            "SELECT receipt_target_id, receipt_target_generation FROM content_chunks
             WHERE operation_id = ?1 AND chunk_index = ?2 AND receipt_recorded_at IS NOT NULL",
            params![operation_id.as_bytes().as_slice(), to_i64(index)?],
            |row| {
                Ok(ShardReceipt {
                    operation_id: chunk.provider_operation_id,
                    shard: meshspan_contracts::ShardIdentity {
                        manifest_digest: root_digest,
                        stripe_index: index,
                        shard_index: 0,
                        generation: 1,
                    },
                    length: chunk.ciphertext_length,
                    digest: chunk.ciphertext_digest,
                    target_id: decode_target(&row.get::<_, Vec<u8>>(0)?)?,
                    target_generation: from_sql(row.get(1)?)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
}

pub(super) fn load_committed_shard_page(
    connection: &Connection,
    content: PublishedContentReference,
    after_index: Option<u64>,
    limit: usize,
) -> Result<CommittedShardPage, ContentCatalogError> {
    let after = after_index.map_or(-1, |value| i64::try_from(value).unwrap_or(i64::MAX));
    let mut statement = connection.prepare(
        "SELECT chunk_index, provider_operation_id, ciphertext_length,
                ciphertext_digest, receipt_target_id, receipt_target_generation,
                receipt_recorded_at
         FROM content_chunks
         WHERE operation_id = ?1 AND chunk_index > ?2
         ORDER BY chunk_index LIMIT ?3",
    )?;
    let rows = statement.query_map(
        params![
            content.publication_operation_id.as_bytes().as_slice(),
            after,
            i64::try_from(limit.saturating_add(1))
                .map_err(|_| ContentCatalogError::InvalidInput)?,
        ],
        |row| {
            let index = from_sql(row.get(0)?)?;
            let target = row
                .get::<_, Option<Vec<u8>>>(4)?
                .ok_or(rusqlite::Error::InvalidQuery)?;
            let target_generation = row
                .get::<_, Option<i64>>(5)?
                .ok_or(rusqlite::Error::InvalidQuery)?;
            let recorded_at = row.get::<_, Option<i64>>(6)?;
            if recorded_at.is_none() {
                return Err(rusqlite::Error::InvalidQuery);
            }
            Ok(ShardReceipt {
                operation_id: decode_operation(&row.get::<_, Vec<u8>>(1)?)?,
                shard: meshspan_contracts::ShardIdentity {
                    manifest_digest: content.manifest.root_digest,
                    stripe_index: index,
                    shard_index: 0,
                    generation: 1,
                },
                length: from_sql(row.get(2)?)?,
                digest: copy_array(&row.get::<_, Vec<u8>>(3)?)?,
                target_id: decode_target(&target)?,
                target_generation: from_sql(target_generation)?,
            })
        },
    )?;
    let mut shards = rows.collect::<Result<Vec<_>, _>>()?;
    let next_index = if shards.len() > limit {
        shards.pop();
        shards.last().map(|receipt| receipt.shard.stripe_index)
    } else {
        None
    };
    Ok(CommittedShardPage {
        shards: meshspan_contracts::BoundedItems::new(shards, limit)
            .map_err(|_| ContentCatalogError::Corrupt)?,
        next_index,
    })
}

pub(super) fn load_content_layout_page(
    connection: &Connection,
    operation_id: OperationId,
    after_index: Option<u64>,
    limit: usize,
) -> Result<ContentLayoutTransferPage, ContentCatalogError> {
    let after = after_index.map_or(-1, |value| i64::try_from(value).unwrap_or(i64::MAX));
    let mut statement = connection.prepare(
        "SELECT chunk_index, plaintext_length, plaintext_digest, ciphertext_length,
                ciphertext_digest
         FROM content_chunks
         WHERE operation_id = ?1 AND chunk_index > ?2
         ORDER BY chunk_index LIMIT ?3",
    )?;
    let rows = statement.query_map(
        params![
            operation_id.as_bytes().as_slice(),
            after,
            i64::try_from(limit.saturating_add(1))
                .map_err(|_| ContentCatalogError::InvalidInput)?,
        ],
        |row| {
            Ok(ContentLayoutChunk {
                chunk_index: from_sql(row.get(0)?)?,
                plaintext_length: from_sql(row.get(1)?)?,
                plaintext_digest: copy_array(&row.get::<_, Vec<u8>>(2)?)?,
                ciphertext_length: from_sql(row.get(3)?)?,
                ciphertext_digest: copy_array(&row.get::<_, Vec<u8>>(4)?)?,
            })
        },
    )?;
    let mut chunks = rows.collect::<Result<Vec<_>, _>>()?;
    let next_index = if chunks.len() > limit {
        chunks.pop();
        chunks.last().map(|chunk| chunk.chunk_index)
    } else {
        None
    };
    ContentLayoutTransferPage::from_untrusted(chunks, next_index).map_err(|error| match error {
        crate::ContentLayoutTransferError::BoundsExceeded => ContentCatalogError::InvalidInput,
        crate::ContentLayoutTransferError::Invalid => ContentCatalogError::Corrupt,
    })
}

pub(super) fn to_i64(value: u64) -> Result<i64, ContentCatalogError> {
    i64::try_from(value).map_err(|_| ContentCatalogError::InvalidInput)
}

pub(super) fn from_sql(value: i64) -> Result<u64, rusqlite::Error> {
    u64::try_from(value).map_err(|_| rusqlite::Error::InvalidQuery)
}

pub(super) fn copy_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], rusqlite::Error> {
    bytes.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}

fn configure(connection: &Connection) -> Result<(), ContentCatalogError> {
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    connection.execute_batch(
        "PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA journal_mode=WAL;
         PRAGMA synchronous=FULL;",
    )?;
    Ok(())
}

fn migrate(connection: &mut Connection, at: UnixMicros) -> Result<(), ContentCatalogError> {
    let exists = connection
        .query_row(
            "SELECT 1 FROM sqlite_schema
             WHERE type = 'table' AND name = 'schema_migrations'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    let mut applied = if exists {
        connection.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |row| row.get::<_, u32>(0),
        )?
    } else {
        0
    };
    if usize::try_from(applied).map_err(|_| ContentCatalogError::Corrupt)? > MIGRATIONS.len() {
        return Err(ContentCatalogError::Corrupt);
    }
    for (offset, migration) in MIGRATIONS.iter().enumerate() {
        let version = u32::try_from(offset + 1).map_err(|_| ContentCatalogError::Corrupt)?;
        let expected = *blake3::hash(migration.as_bytes()).as_bytes();
        if version <= applied {
            let stored: Vec<u8> = connection.query_row(
                "SELECT migration_digest FROM schema_migrations WHERE version = ?1",
                [version],
                |row| row.get(0),
            )?;
            if stored.as_slice() != expected {
                return Err(ContentCatalogError::Corrupt);
            }
            continue;
        }
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(migration)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version,migration_digest,applied_at)
             VALUES(?1,?2,?3)",
            params![version, expected.as_slice(), at.get()],
        )?;
        transaction.commit()?;
        applied = version;
    }
    Ok(())
}

fn verify_database(connection: &Connection) -> Result<(), ContentCatalogError> {
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    let foreign_keys: i64 =
        connection.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })?;
    if integrity == "ok" && foreign_keys == 0 {
        Ok(())
    } else {
        Err(ContentCatalogError::Corrupt)
    }
}

fn from_i64(value: i64) -> Result<u64, ContentCatalogError> {
    u64::try_from(value).map_err(|_| ContentCatalogError::Corrupt)
}

fn decode_manifest(bytes: &[u8]) -> Result<ContentManifestId, rusqlite::Error> {
    ContentManifestId::from_bytes(copy_array(bytes)?).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn decode_volume(bytes: &[u8]) -> Result<VolumeId, rusqlite::Error> {
    VolumeId::from_bytes(copy_array(bytes)?).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn decode_operation(bytes: &[u8]) -> Result<OperationId, rusqlite::Error> {
    OperationId::from_bytes(copy_array(bytes)?).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn decode_target(bytes: &[u8]) -> Result<TargetId, rusqlite::Error> {
    TargetId::from_bytes(copy_array(bytes)?).map_err(|_| rusqlite::Error::InvalidQuery)
}
