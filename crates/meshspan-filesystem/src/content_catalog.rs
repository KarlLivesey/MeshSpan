// SPDX-License-Identifier: GPL-2.0-only

//! SQLite-compatible journal for encrypted manifest construction and provider receipts.

use std::path::Path;

use meshspan_contracts::{BoundedItems, ShardReceipt};
use meshspan_domain::{NodeId, OperationId, TargetId, UnixMicros};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use thiserror::Error;

use crate::{
    CompletedStage, ContentPublicationRequest, ManifestPublication, PublishedContentReference,
    WrappedContentKey,
};

mod repository;
mod transfer;

pub use transfer::CommittedContentLayoutTransfer;

use repository::{
    chunk_count, committed_operation_for_manifest, copy_array, decode_chunk, from_sql,
    layout_is_sealed, layout_summary, load_chunk, load_prepared_manifest, load_receipt,
    load_request, open_connection, to_i64, validate_chunk, validate_exact_request,
    validate_live_request, validate_request,
};

const MAXIMUM_PAGE_ITEMS: usize = 1_000;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ContentShardRoute {
    pub(crate) target_id: TargetId,
    pub(crate) target_generation: u64,
}

/// One bounded page of chunks that still need a provider receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingContentChunkPage {
    /// Prepared chunks in ascending layout order.
    pub chunks: BoundedItems<PreparedContentChunk>,
    /// Next chunk index when more prepared work remains.
    pub next_index: Option<u64>,
}

/// Stable bounded page of exact durable shard placements for one committed manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedShardPage {
    /// Exact provider receipts in ascending logical stripe order.
    pub shards: BoundedItems<ShardReceipt>,
    /// Last returned stripe index when another page exists.
    pub next_index: Option<u64>,
}

/// Borrow-scoped view of one independently verified committed manifest inventory.
///
/// Construction verifies the complete immutable manifest once. The immutable borrow then prevents
/// catalogue mutation while callers consume bounded keyset pages without rescanning the layout.
pub struct CommittedShardInventory<'a> {
    catalog: &'a DurableContentCatalog,
    content: PublishedContentReference,
}

impl CommittedShardInventory<'_> {
    /// Loads one bounded page without repeating complete manifest validation.
    ///
    /// # Errors
    ///
    /// Rejects invalid bounds and any missing, malformed or substituted durable receipt.
    pub fn page(
        &self,
        after_index: Option<u64>,
        limit: usize,
    ) -> Result<CommittedShardPage, ContentCatalogError> {
        if limit == 0 || limit > MAXIMUM_PAGE_ITEMS {
            return Err(ContentCatalogError::InvalidInput);
        }
        repository::load_committed_shard_page(
            &self.catalog.connection,
            self.content,
            after_index,
            limit,
        )
    }
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

pub(crate) struct CommittedContentLayout {
    pub(crate) request: ContentPublicationRequest,
    pub(crate) layout: PreparedContentLayout,
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
        open_connection(state_directory, opened_at).map(|connection| Self { connection })
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
                operation_id, volume_id, request_digest, manifest_id, format_version,
                logical_length, authorization_revision, deadline, state
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1)",
            params![
                request.operation_id.as_bytes().as_slice(),
                request.volume_id.as_bytes().as_slice(),
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
        let imported: bool = self.connection.query_row(
            "SELECT import_header_digest IS NOT NULL FROM content_publications
             WHERE operation_id = ?1",
            [request.operation_id.as_bytes().as_slice()],
            |row| row.get(0),
        )?;
        if imported {
            return Err(ContentCatalogError::Conflict);
        }
        let summary = layout_summary(&self.connection, request, completed, chunk_bytes)?;
        if let Some(existing) = self.prepared_layout(request)? {
            return if existing.manifest == summary.manifest
                && existing.chunk_bytes == chunk_bytes
                && existing.wrapped_key == wrapped_key
            {
                Ok(existing.manifest)
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
        let manifest = match load_prepared_manifest(&self.connection, request)? {
            Some(manifest) => manifest,
            None => {
                transfer::load_import_header(&self.connection, request.operation_id)?
                    .ok_or(ContentCatalogError::InvalidInput)?
                    .manifest
            }
        };
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

    /// Records one authenticated peer's exact durable source receipt for an imported layout.
    ///
    /// The route is distinct from a receiver-local provider receipt: it permits verified remote
    /// reads but is never reported as local durability or local inventory.
    ///
    /// # Errors
    ///
    /// Rejects an unknown/unsealed layout, wrong shard evidence or conflicting route replay.
    pub fn record_remote_shard_route(
        &mut self,
        request: ContentPublicationRequest,
        chunk_index: u64,
        source_node_id: NodeId,
        receipt: ShardReceipt,
        recorded_at: UnixMicros,
    ) -> Result<(), ContentCatalogError> {
        validate_exact_request(&self.connection, request)?;
        let manifest = load_prepared_manifest(&self.connection, request)?
            .ok_or(ContentCatalogError::InvalidInput)?;
        let chunk = load_chunk(&self.connection, request.operation_id, chunk_index)?;
        if receipt.shard.manifest_digest != manifest.root_digest
            || receipt.shard.stripe_index != chunk_index
            || receipt.shard.shard_index != 0
            || receipt.shard.generation != 1
            || receipt.length != chunk.ciphertext_length
            || receipt.digest != chunk.ciphertext_digest
            || receipt.target_generation == 0
        {
            return Err(ContentCatalogError::InvalidInput);
        }
        let existing = self
            .connection
            .query_row(
                "SELECT source_node_id, source_provider_operation_id, target_id,
                        target_generation
                 FROM content_remote_shard_routes
                 WHERE operation_id = ?1 AND chunk_index = ?2",
                params![
                    request.operation_id.as_bytes().as_slice(),
                    to_i64(chunk_index)?
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?;
        let expected = (
            source_node_id.as_bytes().to_vec(),
            receipt.operation_id.as_bytes().to_vec(),
            receipt.target_id.as_bytes().to_vec(),
            to_i64(receipt.target_generation)?,
        );
        if let Some(existing) = existing {
            return if existing == expected {
                Ok(())
            } else {
                Err(ContentCatalogError::Conflict)
            };
        }
        self.connection.execute(
            "INSERT INTO content_remote_shard_routes(
                operation_id, chunk_index, source_node_id, source_provider_operation_id,
                target_id, target_generation, recorded_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                request.operation_id.as_bytes().as_slice(),
                to_i64(chunk_index)?,
                source_node_id.as_bytes().as_slice(),
                receipt.operation_id.as_bytes().as_slice(),
                receipt.target_id.as_bytes().as_slice(),
                to_i64(receipt.target_generation)?,
                recorded_at.get(),
            ],
        )?;
        Ok(())
    }

    pub(crate) fn shard_route(
        &self,
        operation_id: OperationId,
        chunk_index: u64,
    ) -> Result<ContentShardRoute, ContentCatalogError> {
        if let Some(receipt) = load_receipt(&self.connection, operation_id, chunk_index)? {
            return Ok(ContentShardRoute {
                target_id: receipt.target_id,
                target_generation: receipt.target_generation,
            });
        }
        self.connection
            .query_row(
                "SELECT target_id, target_generation FROM content_remote_shard_routes
                 WHERE operation_id = ?1 AND chunk_index = ?2",
                params![operation_id.as_bytes().as_slice(), to_i64(chunk_index)?],
                |row| {
                    Ok(ContentShardRoute {
                        target_id: repository::decode_target(&row.get::<_, Vec<u8>>(0)?)?,
                        target_generation: repository::from_sql(row.get(1)?)?,
                    })
                },
            )
            .optional()?
            .ok_or(ContentCatalogError::Incomplete)
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
        let layout = PreparedContentLayout {
            manifest,
            chunk_bytes: stored.0,
            wrapped_key: stored.1,
        };
        if layout.wrapped_key.valid_for(layout.manifest.manifest_id) {
            Ok(Some(layout))
        } else {
            Err(ContentCatalogError::Corrupt)
        }
    }

    pub(crate) fn committed_layout(
        &self,
        content: PublishedContentReference,
    ) -> Result<CommittedContentLayout, ContentCatalogError> {
        let request = load_request(&self.connection, content.publication_operation_id)?
            .ok_or(ContentCatalogError::Incomplete)?;
        let state: u8 = self.connection.query_row(
            "SELECT state FROM content_publications WHERE operation_id = ?1",
            [content.publication_operation_id.as_bytes().as_slice()],
            |row| row.get(0),
        )?;
        if state != 2 {
            return Err(ContentCatalogError::Incomplete);
        }
        let layout = self
            .prepared_layout(request)?
            .ok_or(ContentCatalogError::Corrupt)?;
        if layout.manifest != content.manifest {
            return Err(ContentCatalogError::Conflict);
        }
        Ok(CommittedContentLayout { request, layout })
    }

    /// Verifies one committed manifest and opens its immutable bounded shard inventory.
    ///
    /// # Errors
    ///
    /// Rejects unknown, incomplete, conflicting or corrupt content state.
    pub fn committed_shard_inventory(
        &self,
        content: PublishedContentReference,
    ) -> Result<CommittedShardInventory<'_>, ContentCatalogError> {
        self.committed_layout(content)?;
        Ok(CommittedShardInventory {
            catalog: self,
            content,
        })
    }

    /// Resolves and independently verifies one committed manifest without source-local operation
    /// knowledge.
    ///
    /// # Errors
    ///
    /// Rejects corrupt or contradictory catalogue state. An unknown or incomplete manifest
    /// returns `None` without exposing partial layout state.
    pub fn committed_content_by_manifest(
        &self,
        manifest_id: meshspan_domain::ContentManifestId,
    ) -> Result<Option<PublishedContentReference>, ContentCatalogError> {
        let Some(operation_id) = committed_operation_for_manifest(&self.connection, manifest_id)?
        else {
            return Ok(None);
        };
        let request =
            load_request(&self.connection, operation_id)?.ok_or(ContentCatalogError::Corrupt)?;
        let layout = self
            .prepared_layout(request)?
            .ok_or(ContentCatalogError::Corrupt)?;
        if request.manifest_id != manifest_id || layout.manifest.manifest_id != manifest_id {
            return Err(ContentCatalogError::Corrupt);
        }
        Ok(Some(PublishedContentReference {
            publication_operation_id: operation_id,
            manifest: layout.manifest,
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

#[cfg(test)]
#[path = "content_catalog_tests.rs"]
mod tests;
