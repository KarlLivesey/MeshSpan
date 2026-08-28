// SPDX-License-Identifier: GPL-2.0-only

//! SQLite-compatible journal for encrypted manifest construction and provider receipts.

use std::fs;
use std::path::Path;

use meshspan_contracts::{BoundedItems, ShardReceipt};
use meshspan_domain::{ContentManifestId, OperationId, TargetId, UnixMicros};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use thiserror::Error;

use crate::{CompletedStage, ContentPublicationRequest, ManifestPublication, WrappedContentKey};

const DATABASE_FILE: &str = "filesystem-content.sqlite3";
const MIGRATION: &str = include_str!("../schema/content/001_initial.sql");
const MAXIMUM_PAGE_ITEMS: usize = 1_000;
const MAXIMUM_SQLITE_INTEGER: u64 = 9_223_372_036_854_775_807;

/// Immutable metadata for one encrypted chunk before provider durability is recorded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedContentChunk {
    /// Zero-based position in the logical file layout.
    pub chunk_index: u64,
    /// Exact plaintext bytes represented by the chunk.
    pub plaintext_length: u64,
    /// BLAKE3 identity of the plaintext chunk.
    pub plaintext_digest: [u8; 32],
    /// Exact encrypted bytes including the authentication tag.
    pub ciphertext_length: u64,
    /// BLAKE3 identity of the complete encrypted bytes.
    pub ciphertext_digest: [u8; 32],
    /// Stable provider mutation identity derived for this chunk.
    pub provider_operation_id: OperationId,
}

/// One bounded page of chunks that still need a provider receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingContentChunkPage {
    /// Prepared chunks in ascending layout order.
    pub chunks: BoundedItems<PreparedContentChunk>,
    /// Next chunk index when more prepared work remains.
    pub next_index: Option<u64>,
}

/// Complete sealed layout state needed to resume provider publication after restart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedContentLayout {
    /// Independently recomputed immutable manifest root.
    pub manifest: ManifestPublication,
    /// Authenticated wrapped per-layout content key.
    pub wrapped_key: WrappedContentKey,
    /// Selected maximum plaintext bytes per chunk.
    pub chunk_bytes: u64,
}

/// Durable encrypted-manifest and provider-receipt catalogue.
pub struct DurableContentCatalog {
    connection: Connection,
}

impl DurableContentCatalog {
    /// Opens, migrates and verifies the content-publication journal.
    ///
    /// # Errors
    ///
    /// Rejects migration drift, newer schemas, corruption and IO/SQLite failure.
    pub fn open(
        state_directory: &Path,
        opened_at: UnixMicros,
    ) -> Result<Self, ContentCatalogError> {
        fs::create_dir_all(state_directory)?;
        let mut connection = Connection::open(state_directory.join(DATABASE_FILE))?;
        configure(&connection)?;
        migrate(&mut connection, opened_at)?;
        verify_database(&connection)?;
        Ok(Self { connection })
    }

    /// Registers one immutable content-publication intent or accepts its exact retry.
    ///
    /// # Errors
    ///
    /// Rejects expired/malformed input and conflicting operation or manifest reuse.
    pub fn begin(&mut self, request: ContentPublicationRequest) -> Result<(), ContentCatalogError> {
        validate_live_request(request)?;
        if let Some(stored) = load_request(&self.connection, request.operation_id)? {
            return if stored.same_intent(request) {
                Ok(())
            } else {
                Err(ContentCatalogError::Conflict)
            };
        }
        self.connection.execute(
            "INSERT INTO content_publications(
                operation_id, request_digest, manifest_id, format_version, logical_length,
                authorization_revision, deadline, state
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1)",
            params![
                request.operation_id.as_bytes().as_slice(),
                request.request_digest.as_slice(),
                request.manifest_id.as_bytes().as_slice(),
                i64::from(request.format_version),
                to_i64(request.logical_length)?,
                to_i64(request.authorization_revision.get())?,
                request.deadline.get()
            ],
        )?;
        Ok(())
    }

    /// Appends one contiguous bounded page of immutable encrypted-chunk identities.
    ///
    /// # Errors
    ///
    /// Rejects gaps, excessive pages, malformed lengths, sealed operations and identity conflict.
    pub fn append_chunks(
        &mut self,
        request: ContentPublicationRequest,
        chunks: &[PreparedContentChunk],
    ) -> Result<(), ContentCatalogError> {
        validate_live_request(request)?;
        validate_exact_request(&self.connection, request)?;
        if chunks.is_empty()
            || chunks.len() > MAXIMUM_PAGE_ITEMS
            || layout_is_sealed(&self.connection, request.operation_id)?
        {
            return Err(ContentCatalogError::InvalidInput);
        }
        let expected = chunk_count(&self.connection, request.operation_id)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for (offset, chunk) in chunks.iter().enumerate() {
            let index = expected
                .checked_add(u64::try_from(offset).map_err(|_| ContentCatalogError::InvalidInput)?)
                .ok_or(ContentCatalogError::InvalidInput)?;
            validate_chunk(*chunk, index)?;
            transaction.execute(
                "INSERT INTO content_chunks(
                    operation_id, chunk_index, plaintext_length, plaintext_digest,
                    ciphertext_length, ciphertext_digest, provider_operation_id
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    request.operation_id.as_bytes().as_slice(),
                    to_i64(chunk.chunk_index)?,
                    to_i64(chunk.plaintext_length)?,
                    chunk.plaintext_digest.as_slice(),
                    to_i64(chunk.ciphertext_length)?,
                    chunk.ciphertext_digest.as_slice(),
                    chunk.provider_operation_id.as_bytes().as_slice()
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Seals the complete chunk catalogue and wrapped key before provider publication begins.
    ///
    /// # Errors
    ///
    /// Rejects length/count mismatch, conflicting reseal and corrupt chunk metadata.
    pub fn seal_layout(
        &mut self,
        request: ContentPublicationRequest,
        completed: CompletedStage,
        chunk_bytes: u64,
        wrapped_key: WrappedContentKey,
    ) -> Result<ManifestPublication, ContentCatalogError> {
        validate_live_request(request)?;
        validate_exact_request(&self.connection, request)?;
        if chunk_bytes == 0 || completed.logical_length != request.logical_length {
            return Err(ContentCatalogError::InvalidInput);
        }
        let summary = layout_summary(
            &self.connection,
            request,
            completed,
            chunk_bytes,
            wrapped_key,
        )?;
        if let Some(manifest) = load_prepared_manifest(&self.connection, request)? {
            return if manifest == summary.manifest {
                Ok(manifest)
            } else {
                Err(ContentCatalogError::Conflict)
            };
        }
        let updated = self.connection.execute(
            "UPDATE content_publications SET
                content_digest = ?1, root_digest = ?2, chunk_bytes = ?3, chunk_count = ?4,
                key_generation = ?5, key_nonce = ?6, key_ciphertext = ?7,
                key_envelope_digest = ?8
             WHERE operation_id = ?9 AND state = 1 AND root_digest IS NULL",
            params![
                completed.content_digest.as_slice(),
                summary.manifest.root_digest.as_slice(),
                to_i64(chunk_bytes)?,
                to_i64(summary.chunk_count)?,
                to_i64(wrapped_key.key_generation)?,
                wrapped_key.nonce.as_slice(),
                wrapped_key.ciphertext.as_slice(),
                wrapped_key.envelope_digest.as_slice(),
                request.operation_id.as_bytes().as_slice()
            ],
        )?;
        if updated == 1 {
            Ok(summary.manifest)
        } else {
            Err(ContentCatalogError::Conflict)
        }
    }

    /// Records one exact provider receipt against its prepared encrypted chunk.
    ///
    /// # Errors
    ///
    /// Rejects unsealed layouts, wrong shard identity/length/digest and conflicting replay.
    pub fn record_receipt(
        &mut self,
        request: ContentPublicationRequest,
        chunk_index: u64,
        receipt: ShardReceipt,
        recorded_at: UnixMicros,
    ) -> Result<(), ContentCatalogError> {
        let manifest = load_prepared_manifest(&self.connection, request)?
            .ok_or(ContentCatalogError::InvalidInput)?;
        let chunk = load_chunk(&self.connection, request.operation_id, chunk_index)?;
        if receipt.operation_id != chunk.provider_operation_id
            || receipt.shard.manifest_digest != manifest.root_digest
            || receipt.shard.stripe_index != chunk_index
            || receipt.shard.shard_index != 0
            || receipt.shard.generation != 1
            || receipt.length != chunk.ciphertext_length
            || receipt.digest != chunk.ciphertext_digest
        {
            return Err(ContentCatalogError::InvalidInput);
        }
        let existing = load_receipt(&self.connection, request.operation_id, chunk_index)?;
        if let Some(existing) = existing {
            return if existing == receipt {
                Ok(())
            } else {
                Err(ContentCatalogError::Conflict)
            };
        }
        let updated = self.connection.execute(
            "UPDATE content_chunks SET receipt_target_id = ?1,
                receipt_target_generation = ?2, receipt_recorded_at = ?3
             WHERE operation_id = ?4 AND chunk_index = ?5 AND receipt_recorded_at IS NULL",
            params![
                receipt.target_id.as_bytes().as_slice(),
                to_i64(receipt.target_generation)?,
                recorded_at.get(),
                request.operation_id.as_bytes().as_slice(),
                to_i64(chunk_index)?
            ],
        )?;
        if updated == 1 {
            Ok(())
        } else {
            Err(ContentCatalogError::Conflict)
        }
    }

    /// Returns a bounded page of chunks without provider receipts.
    ///
    /// # Errors
    ///
    /// Rejects malformed bounds, unknown/conflicting operations and corrupt rows.
    pub fn pending_chunks(
        &self,
        request: ContentPublicationRequest,
        after_index: Option<u64>,
        limit: usize,
    ) -> Result<PendingContentChunkPage, ContentCatalogError> {
        validate_exact_request(&self.connection, request)?;
        if limit == 0 || limit > MAXIMUM_PAGE_ITEMS {
            return Err(ContentCatalogError::InvalidInput);
        }
        let after = after_index.map_or(-1, |value| i64::try_from(value).unwrap_or(i64::MAX));
        let mut statement = self.connection.prepare(
            "SELECT chunk_index, plaintext_length, plaintext_digest, ciphertext_length,
                    ciphertext_digest, provider_operation_id
             FROM content_chunks
             WHERE operation_id = ?1 AND chunk_index > ?2 AND receipt_recorded_at IS NULL
             ORDER BY chunk_index LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![
                request.operation_id.as_bytes().as_slice(),
                after,
                i64::try_from(limit.saturating_add(1))
                    .map_err(|_| ContentCatalogError::InvalidInput)?
            ],
            decode_chunk,
        )?;
        let mut chunks = rows.collect::<Result<Vec<_>, _>>()?;
        let next_index = if chunks.len() > limit {
            chunks.pop();
            chunks.last().map(|chunk| chunk.chunk_index)
        } else {
            None
        };
        Ok(PendingContentChunkPage {
            chunks: BoundedItems::new(chunks, limit).map_err(|_| ContentCatalogError::Corrupt)?,
            next_index,
        })
    }

    /// Loads and revalidates the sealed layout required for exact recovery.
    ///
    /// # Errors
    ///
    /// Rejects conflicting request input and corrupt stored manifest/key records.
    pub fn prepared_layout(
        &self,
        request: ContentPublicationRequest,
    ) -> Result<Option<PreparedContentLayout>, ContentCatalogError> {
        let Some(manifest) = load_prepared_manifest(&self.connection, request)? else {
            return Ok(None);
        };
        let stored = self.connection.query_row(
            "SELECT chunk_bytes, key_generation, key_nonce, key_ciphertext,
                    key_envelope_digest
             FROM content_publications WHERE operation_id = ?1",
            [request.operation_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    from_sql(row.get(0)?)?,
                    WrappedContentKey {
                        key_generation: from_sql(row.get(1)?)?,
                        nonce: copy_array(&row.get::<_, Vec<u8>>(2)?)?,
                        ciphertext: copy_array(&row.get::<_, Vec<u8>>(3)?)?,
                        envelope_digest: copy_array(&row.get::<_, Vec<u8>>(4)?)?,
                    },
                ))
            },
        )?;
        Ok(Some(PreparedContentLayout {
            manifest,
            chunk_bytes: stored.0,
            wrapped_key: stored.1,
        }))
    }

    /// Loads one prepared chunk identity for verified read/recovery work.
    ///
    /// # Errors
    ///
    /// Rejects conflicting request input, unknown indices and corrupt stored rows.
    pub fn content_chunk(
        &self,
        request: ContentPublicationRequest,
        chunk_index: u64,
    ) -> Result<PreparedContentChunk, ContentCatalogError> {
        validate_exact_request(&self.connection, request)?;
        load_chunk(&self.connection, request.operation_id, chunk_index)
    }

    /// Marks the manifest durable only after every prepared chunk has a provider receipt.
    ///
    /// # Errors
    ///
    /// Rejects incomplete/corrupt layouts and conflicting operation input.
    pub fn finish(
        &mut self,
        request: ContentPublicationRequest,
        committed_at: UnixMicros,
    ) -> Result<ManifestPublication, ContentCatalogError> {
        let manifest = load_prepared_manifest(&self.connection, request)?
            .ok_or(ContentCatalogError::InvalidInput)?;
        let pending: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM content_chunks
             WHERE operation_id = ?1 AND receipt_recorded_at IS NULL",
            [request.operation_id.as_bytes().as_slice()],
            |row| row.get(0),
        )?;
        if pending != 0 {
            return Err(ContentCatalogError::Incomplete);
        }
        self.connection.execute(
            "UPDATE content_publications SET state = 2, committed_at = ?1
             WHERE operation_id = ?2 AND state = 1",
            params![
                committed_at.get(),
                request.operation_id.as_bytes().as_slice()
            ],
        )?;
        Ok(manifest)
    }

    /// Resolves one exact fully durable manifest.
    ///
    /// # Errors
    ///
    /// Rejects conflicting input and corrupt durable records.
    pub fn resolve(
        &self,
        request: ContentPublicationRequest,
    ) -> Result<Option<ManifestPublication>, ContentCatalogError> {
        validate_request(request)?;
        let Some(stored) = load_request(&self.connection, request.operation_id)? else {
            return Ok(None);
        };
        if !stored.same_intent(request) {
            return Err(ContentCatalogError::Conflict);
        }
        let state: u8 = self.connection.query_row(
            "SELECT state FROM content_publications WHERE operation_id = ?1",
            [request.operation_id.as_bytes().as_slice()],
            |row| row.get(0),
        )?;
        if state == 2 {
            load_prepared_manifest(&self.connection, request)
        } else {
            Ok(None)
        }
    }
}

/// Stable failures from the encrypted content catalogue.
#[derive(Debug, Error)]
pub enum ContentCatalogError {
    /// Request fields, bounds, sequence or receipt relationships are invalid.
    #[error("content catalogue input is invalid")]
    InvalidInput,
    /// An immutable or idempotency identity belongs to different input.
    #[error("content catalogue identity conflicts with durable state")]
    Conflict,
    /// Not every prepared chunk has a durable provider receipt.
    #[error("content catalogue publication is incomplete")]
    Incomplete,
    /// Stored rows, digests or layout relationships violate an invariant.
    #[error("content catalogue state is corrupt")]
    Corrupt,
    /// State-directory IO failed.
    #[error("content catalogue IO failed")]
    Io(#[from] std::io::Error),
    /// SQLite persistence failed.
    #[error("content catalogue database failed")]
    Sqlite(#[from] rusqlite::Error),
}

struct LayoutSummary {
    manifest: ManifestPublication,
    chunk_count: u64,
}

fn validate_request(request: ContentPublicationRequest) -> Result<(), ContentCatalogError> {
    if request.format_version == 0
        || request.logical_length > MAXIMUM_SQLITE_INTEGER
        || request.authorization_revision.get() == 0
    {
        Err(ContentCatalogError::InvalidInput)
    } else {
        Ok(())
    }
}

fn validate_live_request(request: ContentPublicationRequest) -> Result<(), ContentCatalogError> {
    validate_request(request)?;
    if request.observed_at >= request.deadline {
        Err(ContentCatalogError::InvalidInput)
    } else {
        Ok(())
    }
}

fn validate_chunk(chunk: PreparedContentChunk, expected: u64) -> Result<(), ContentCatalogError> {
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

fn validate_exact_request(
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

fn load_request(
    connection: &Connection,
    operation_id: OperationId,
) -> Result<Option<ContentPublicationRequest>, ContentCatalogError> {
    connection
        .query_row(
            "SELECT request_digest, manifest_id, format_version, logical_length,
                authorization_revision, deadline FROM content_publications WHERE operation_id = ?1",
            [operation_id.as_bytes().as_slice()],
            |row| {
                Ok(ContentPublicationRequest {
                    operation_id,
                    request_digest: copy_array(&row.get::<_, Vec<u8>>(0)?)?,
                    manifest_id: decode_manifest(&row.get::<_, Vec<u8>>(1)?)?,
                    format_version: u16::try_from(row.get::<_, i64>(2)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    logical_length: from_sql(row.get(3)?)?,
                    authorization_revision: meshspan_domain::Revision::new(from_sql(row.get(4)?)?),
                    deadline: UnixMicros::new(row.get(5)?),
                    observed_at: UnixMicros::new(i64::MIN),
                })
            },
        )
        .optional()
        .map_err(Into::into)
}

fn layout_is_sealed(
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

fn chunk_count(
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

fn layout_summary(
    connection: &Connection,
    request: ContentPublicationRequest,
    completed: CompletedStage,
    chunk_bytes: u64,
    wrapped: WrappedContentKey,
) -> Result<LayoutSummary, ContentCatalogError> {
    let mut statement = connection.prepare("SELECT chunk_index, plaintext_length, plaintext_digest, ciphertext_length, ciphertext_digest, provider_operation_id FROM content_chunks WHERE operation_id = ?1 ORDER BY chunk_index")?;
    let mut rows = statement.query([request.operation_id.as_bytes().as_slice()])?;
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.content.unprotected-manifest.v1\0");
    digest.update(&request.manifest_id.as_bytes());
    digest.update(&request.format_version.to_be_bytes());
    digest.update(&completed.logical_length.to_be_bytes());
    digest.update(&completed.content_digest);
    digest.update(&chunk_bytes.to_be_bytes());
    digest.update(&wrapped.envelope_digest);
    let mut count = 0_u64;
    let mut total = 0_u64;
    while let Some(row) = rows.next()? {
        let chunk = decode_chunk(row)?;
        if chunk.chunk_index != count {
            return Err(ContentCatalogError::Corrupt);
        }
        total = total
            .checked_add(chunk.plaintext_length)
            .ok_or(ContentCatalogError::Corrupt)?;
        digest.update(&chunk.chunk_index.to_be_bytes());
        digest.update(&chunk.plaintext_length.to_be_bytes());
        digest.update(&chunk.plaintext_digest);
        digest.update(&chunk.ciphertext_length.to_be_bytes());
        digest.update(&chunk.ciphertext_digest);
        count = count.checked_add(1).ok_or(ContentCatalogError::Corrupt)?;
    }
    if total != completed.logical_length {
        return Err(ContentCatalogError::InvalidInput);
    }
    Ok(LayoutSummary {
        manifest: ManifestPublication {
            manifest_id: request.manifest_id,
            format_version: request.format_version,
            logical_length: completed.logical_length,
            content_digest: completed.content_digest,
            root_digest: digest.finalize().into(),
        },
        chunk_count: count,
    })
}

fn load_prepared_manifest(
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
            "SELECT content_digest, root_digest, chunk_bytes, key_generation,
                    key_nonce, key_ciphertext, key_envelope_digest
             FROM content_publications
             WHERE operation_id = ?1 AND root_digest IS NOT NULL",
            [request.operation_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    copy_array(&row.get::<_, Vec<u8>>(0)?)?,
                    copy_array(&row.get::<_, Vec<u8>>(1)?)?,
                    from_sql(row.get(2)?)?,
                    WrappedContentKey {
                        key_generation: from_sql(row.get(3)?)?,
                        nonce: copy_array(&row.get::<_, Vec<u8>>(4)?)?,
                        ciphertext: copy_array(&row.get::<_, Vec<u8>>(5)?)?,
                        envelope_digest: copy_array(&row.get::<_, Vec<u8>>(6)?)?,
                    },
                ))
            },
        )
        .optional()?;
    stored
        .map(|(content_digest, root_digest, chunk_bytes, wrapped)| {
            let summary = layout_summary(
                connection,
                request,
                CompletedStage {
                    logical_length: request.logical_length,
                    content_digest,
                },
                chunk_bytes,
                wrapped,
            )?;
            if summary.manifest.root_digest == root_digest {
                Ok(summary.manifest)
            } else {
                Err(ContentCatalogError::Corrupt)
            }
        })
        .transpose()
}

fn load_chunk(
    connection: &Connection,
    operation_id: OperationId,
    index: u64,
) -> Result<PreparedContentChunk, ContentCatalogError> {
    connection.query_row("SELECT chunk_index, plaintext_length, plaintext_digest, ciphertext_length, ciphertext_digest, provider_operation_id FROM content_chunks WHERE operation_id = ?1 AND chunk_index = ?2", params![operation_id.as_bytes().as_slice(), to_i64(index)?], decode_chunk).optional()?.ok_or(ContentCatalogError::InvalidInput)
}

fn decode_chunk(row: &rusqlite::Row<'_>) -> Result<PreparedContentChunk, rusqlite::Error> {
    Ok(PreparedContentChunk {
        chunk_index: from_sql(row.get(0)?)?,
        plaintext_length: from_sql(row.get(1)?)?,
        plaintext_digest: copy_array(&row.get::<_, Vec<u8>>(2)?)?,
        ciphertext_length: from_sql(row.get(3)?)?,
        ciphertext_digest: copy_array(&row.get::<_, Vec<u8>>(4)?)?,
        provider_operation_id: decode_operation(&row.get::<_, Vec<u8>>(5)?)?,
    })
}

fn load_receipt(
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
    connection.query_row("SELECT receipt_target_id, receipt_target_generation FROM content_chunks WHERE operation_id = ?1 AND chunk_index = ?2 AND receipt_recorded_at IS NOT NULL", params![operation_id.as_bytes().as_slice(), to_i64(index)?], |row| Ok(ShardReceipt { operation_id: chunk.provider_operation_id, shard: meshspan_contracts::ShardIdentity { manifest_digest: root_digest, stripe_index:index, shard_index:0, generation:1 }, length:chunk.ciphertext_length, digest:chunk.ciphertext_digest, target_id: decode_target(&row.get::<_, Vec<u8>>(0)?)?, target_generation:from_sql(row.get(1)?)? })).optional().map_err(Into::into)
}

fn configure(connection: &Connection) -> Result<(), ContentCatalogError> {
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    connection.execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")?;
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
    let expected = *blake3::hash(MIGRATION.as_bytes()).as_bytes();
    if exists {
        let maximum: i64 = connection.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |row| row.get(0),
        )?;
        if maximum != 1 {
            return Err(ContentCatalogError::Corrupt);
        }
        let stored: Vec<u8> = connection.query_row(
            "SELECT migration_digest FROM schema_migrations WHERE version = 1",
            [],
            |row| row.get(0),
        )?;
        return if stored.as_slice() == expected {
            Ok(())
        } else {
            Err(ContentCatalogError::Corrupt)
        };
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(MIGRATION)?;
    transaction.execute(
        "INSERT INTO schema_migrations(version,migration_digest,applied_at) VALUES(1,?1,?2)",
        params![expected.as_slice(), at.get()],
    )?;
    transaction.commit()?;
    Ok(())
}
fn verify_database(connection: &Connection) -> Result<(), ContentCatalogError> {
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
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
fn to_i64(value: u64) -> Result<i64, ContentCatalogError> {
    i64::try_from(value).map_err(|_| ContentCatalogError::InvalidInput)
}
fn from_i64(value: i64) -> Result<u64, ContentCatalogError> {
    u64::try_from(value).map_err(|_| ContentCatalogError::Corrupt)
}
fn from_sql(value: i64) -> Result<u64, rusqlite::Error> {
    u64::try_from(value).map_err(|_| rusqlite::Error::InvalidQuery)
}
fn copy_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], rusqlite::Error> {
    bytes.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}
fn decode_manifest(bytes: &[u8]) -> Result<ContentManifestId, rusqlite::Error> {
    ContentManifestId::from_bytes(copy_array(bytes)?).map_err(|_| rusqlite::Error::InvalidQuery)
}
fn decode_operation(bytes: &[u8]) -> Result<OperationId, rusqlite::Error> {
    OperationId::from_bytes(copy_array(bytes)?).map_err(|_| rusqlite::Error::InvalidQuery)
}
fn decode_target(bytes: &[u8]) -> Result<TargetId, rusqlite::Error> {
    TargetId::from_bytes(copy_array(bytes)?).map_err(|_| rusqlite::Error::InvalidQuery)
}

#[cfg(test)]
#[path = "content_catalog_tests.rs"]
mod tests;
