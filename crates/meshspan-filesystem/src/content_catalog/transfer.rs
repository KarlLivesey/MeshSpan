// SPDX-License-Identifier: GPL-2.0-only

//! Durable bounded export and receiver-local import of encrypted-content layouts.

use meshspan_domain::OperationId;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use super::repository::{
    chunk_count, copy_array, from_sql, layout_is_sealed, layout_summary, load_chunk,
    load_prepared_manifest, load_request, to_i64, validate_exact_request, validate_live_request,
};
use super::{ContentCatalogError, DurableContentCatalog, MAXIMUM_PAGE_ITEMS, PreparedContentChunk};
use crate::content_transfer::provider_operation_id;
use crate::{
    CompletedStage, ContentLayoutChunk, ContentLayoutTransferHeader, ContentLayoutTransferPage,
    ContentPublicationRequest, ManifestPublication, PublishedContentReference, WrappedContentKey,
};

/// Borrow-scoped bounded export of one independently verified encrypted-content layout.
pub struct CommittedContentLayoutTransfer<'a> {
    catalog: &'a DurableContentCatalog,
    request: ContentPublicationRequest,
    header: ContentLayoutTransferHeader,
}

impl CommittedContentLayoutTransfer<'_> {
    /// Exact manifest, geometry and receiver-wrapped key for the transfer.
    #[must_use]
    pub const fn header(&self) -> ContentLayoutTransferHeader {
        self.header
    }

    /// Loads one bounded keyset page without copying source-local provider receipts.
    ///
    /// # Errors
    ///
    /// Rejects invalid bounds and missing, malformed or substituted chunk identities.
    pub fn page(
        &self,
        after_index: Option<u64>,
        limit: usize,
    ) -> Result<ContentLayoutTransferPage, ContentCatalogError> {
        if limit == 0 || limit > MAXIMUM_PAGE_ITEMS {
            return Err(ContentCatalogError::InvalidInput);
        }
        super::repository::load_content_layout_page(
            &self.catalog.connection,
            self.request.operation_id,
            after_index,
            limit,
        )
    }
}

impl DurableContentCatalog {
    /// Verifies one committed manifest and opens its provider-neutral bounded layout export.
    ///
    /// Source-local provider operation IDs and durability receipts are deliberately omitted.
    ///
    /// # Errors
    ///
    /// Rejects unknown, incomplete, conflicting or corrupt content state.
    pub fn committed_layout_transfer(
        &self,
        content: PublishedContentReference,
    ) -> Result<CommittedContentLayoutTransfer<'_>, ContentCatalogError> {
        let committed = self.committed_layout(content)?;
        let actual_chunk_count = chunk_count(&self.connection, committed.request.operation_id)?;
        let stored_chunk_count: u64 = self.connection.query_row(
            "SELECT chunk_count FROM content_publications WHERE operation_id = ?1",
            [committed.request.operation_id.as_bytes().as_slice()],
            |row| from_sql(row.get(0)?),
        )?;
        if actual_chunk_count != stored_chunk_count {
            return Err(ContentCatalogError::Corrupt);
        }
        let header = ContentLayoutTransferHeader {
            manifest: committed.layout.manifest,
            chunk_bytes: committed.layout.chunk_bytes,
            chunk_count: actual_chunk_count,
            wrapped_key: committed.layout.wrapped_key,
        };
        header
            .validate()
            .map_err(|_| ContentCatalogError::Corrupt)?;
        Ok(CommittedContentLayoutTransfer {
            catalog: self,
            request: committed.request,
            header,
        })
    }

    /// Begins or resolves the exact receiver-local journal for one transferred layout header.
    ///
    /// # Errors
    ///
    /// Rejects expired requests, malformed headers, request/header mismatch and conflicting replay.
    pub fn begin_layout_import(
        &mut self,
        request: ContentPublicationRequest,
        header: ContentLayoutTransferHeader,
    ) -> Result<(), ContentCatalogError> {
        validate_live_request(request)?;
        validate_import_request(request, header)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(stored) = load_request(&transaction, request.operation_id)? {
            if !stored.same_intent(request) {
                return Err(ContentCatalogError::Conflict);
            }
            let stored_header = load_import_header(&transaction, request.operation_id)?
                .ok_or(ContentCatalogError::Conflict)?;
            if stored_header == header {
                transaction.commit()?;
                return Ok(());
            }
            return Err(ContentCatalogError::Conflict);
        }
        transaction.execute(
            "INSERT INTO content_publications(
                operation_id, volume_id, request_digest, manifest_id, format_version,
                logical_length, authorization_revision, deadline, state, content_digest,
                chunk_bytes, chunk_count, key_generation, key_nonce, key_ciphertext,
                key_envelope_digest, import_header_digest, import_expected_root_digest
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,1,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
            params![
                request.operation_id.as_bytes().as_slice(),
                request.volume_id.as_bytes().as_slice(),
                request.request_digest.as_slice(),
                request.manifest_id.as_bytes().as_slice(),
                i64::from(request.format_version),
                to_i64(request.logical_length)?,
                to_i64(request.authorization_revision.get())?,
                request.deadline.get(),
                header.manifest.content_digest.as_slice(),
                to_i64(header.chunk_bytes)?,
                to_i64(header.chunk_count)?,
                to_i64(header.wrapped_key.key_generation)?,
                header.wrapped_key.nonce.as_slice(),
                header.wrapped_key.ciphertext.as_slice(),
                header.wrapped_key.envelope_digest.as_slice(),
                header.digest().as_slice(),
                header.manifest.root_digest.as_slice(),
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Appends or exactly replays one bounded contiguous imported layout page.
    ///
    /// # Errors
    ///
    /// Rejects gaps, partial overlap, wrong terminal pagination and all header/page substitution.
    pub fn append_layout_import_page(
        &mut self,
        request: ContentPublicationRequest,
        header: ContentLayoutTransferHeader,
        page: &ContentLayoutTransferPage,
    ) -> Result<(), ContentCatalogError> {
        validate_live_request(request)?;
        validate_stored_import(&self.connection, request, header)?;
        validate_import_page(header, page)?;
        let first_index = page
            .chunks()
            .first()
            .ok_or(ContentCatalogError::InvalidInput)?
            .chunk_index;
        let existing_count = chunk_count(&self.connection, request.operation_id)?;
        let prepared = prepare_import_chunks(request.operation_id, page.chunks())?;
        if first_index == existing_count {
            if layout_is_sealed(&self.connection, request.operation_id)? {
                return Err(ContentCatalogError::Conflict);
            }
            return self.append_chunks(request, &prepared);
        }
        replay_import_page(
            &self.connection,
            request.operation_id,
            existing_count,
            prepared,
        )
    }

    /// Seals a complete imported layout only when it reconstructs the advertised manifest exactly.
    ///
    /// # Errors
    ///
    /// Rejects missing pages, substituted metadata, conflicting replay and root mismatch.
    pub fn seal_layout_import(
        &mut self,
        request: ContentPublicationRequest,
        header: ContentLayoutTransferHeader,
    ) -> Result<ManifestPublication, ContentCatalogError> {
        validate_live_request(request)?;
        validate_stored_import(&self.connection, request, header)?;
        let actual_count = chunk_count(&self.connection, request.operation_id)?;
        if actual_count != header.chunk_count {
            return Err(ContentCatalogError::Incomplete);
        }
        let summary = layout_summary(
            &self.connection,
            request,
            CompletedStage {
                logical_length: header.manifest.logical_length,
                content_digest: header.manifest.content_digest,
            },
            header.chunk_bytes,
        )?;
        if summary.chunk_count != header.chunk_count || summary.manifest != header.manifest {
            return Err(ContentCatalogError::Corrupt);
        }
        if let Some(manifest) = load_prepared_manifest(&self.connection, request)? {
            return if manifest == header.manifest {
                Ok(manifest)
            } else {
                Err(ContentCatalogError::Conflict)
            };
        }
        persist_imported_manifest(&self.connection, request, header)?;
        Ok(header.manifest)
    }

    /// Commits a sealed imported layout after every chunk has an authenticated remote route.
    ///
    /// Remote routes deliberately do not masquerade as receiver-local durability receipts. This
    /// separate transition makes the imported manifest readable without reporting its shards as
    /// locally stored.
    ///
    /// # Errors
    ///
    /// Rejects unsealed or non-imported layouts, missing remote routes and conflicting state.
    pub fn finish_remote_layout_import(
        &mut self,
        request: ContentPublicationRequest,
        committed_at: meshspan_domain::UnixMicros,
    ) -> Result<ManifestPublication, ContentCatalogError> {
        validate_live_request(request)?;
        validate_exact_request(&self.connection, request)?;
        load_import_header(&self.connection, request.operation_id)?
            .ok_or(ContentCatalogError::Conflict)?;
        let manifest = load_prepared_manifest(&self.connection, request)?
            .ok_or(ContentCatalogError::Incomplete)?;
        let missing: u64 = self.connection.query_row(
            "SELECT COUNT(*)
             FROM content_chunks AS chunks
             LEFT JOIN content_remote_shard_routes AS routes
               ON routes.operation_id = chunks.operation_id
              AND routes.chunk_index = chunks.chunk_index
             WHERE chunks.operation_id = ?1 AND routes.chunk_index IS NULL",
            [request.operation_id.as_bytes().as_slice()],
            |row| from_sql(row.get(0)?),
        )?;
        if missing != 0 {
            return Err(ContentCatalogError::Incomplete);
        }
        let state: u8 = self.connection.query_row(
            "SELECT state FROM content_publications WHERE operation_id = ?1",
            [request.operation_id.as_bytes().as_slice()],
            |row| row.get(0),
        )?;
        if state == 2 {
            return Ok(manifest);
        }
        let updated = self.connection.execute(
            "UPDATE content_publications SET state = 2, committed_at = ?1
             WHERE operation_id = ?2 AND state = 1",
            params![
                committed_at.get(),
                request.operation_id.as_bytes().as_slice()
            ],
        )?;
        if updated == 1 {
            Ok(manifest)
        } else {
            Err(ContentCatalogError::Conflict)
        }
    }
}

fn validate_import_request(
    request: ContentPublicationRequest,
    header: ContentLayoutTransferHeader,
) -> Result<(), ContentCatalogError> {
    header
        .validate()
        .map_err(|_| ContentCatalogError::InvalidInput)?;
    if request.manifest_id == header.manifest.manifest_id
        && request.format_version == header.manifest.format_version
        && request.logical_length == header.manifest.logical_length
    {
        Ok(())
    } else {
        Err(ContentCatalogError::InvalidInput)
    }
}

fn validate_stored_import(
    connection: &Connection,
    request: ContentPublicationRequest,
    header: ContentLayoutTransferHeader,
) -> Result<(), ContentCatalogError> {
    validate_import_request(request, header)?;
    validate_exact_request(connection, request)?;
    let stored = load_import_header(connection, request.operation_id)?
        .ok_or(ContentCatalogError::Conflict)?;
    if stored == header {
        Ok(())
    } else {
        Err(ContentCatalogError::Conflict)
    }
}

pub(super) fn load_import_header(
    connection: &Connection,
    operation_id: OperationId,
) -> Result<Option<ContentLayoutTransferHeader>, ContentCatalogError> {
    let stored = connection
        .query_row(
            "SELECT manifest_id, format_version, logical_length, content_digest,
                    import_expected_root_digest, chunk_bytes, chunk_count, key_generation,
                    key_nonce, key_ciphertext, key_envelope_digest, import_header_digest
             FROM content_publications
             WHERE operation_id = ?1 AND import_header_digest IS NOT NULL",
            [operation_id.as_bytes().as_slice()],
            decode_import_header,
        )
        .optional()?;
    let Some((header, stored_digest)) = stored else {
        return Ok(None);
    };
    header
        .validate()
        .map_err(|_| ContentCatalogError::Corrupt)?;
    if header.digest() != stored_digest {
        return Err(ContentCatalogError::Corrupt);
    }
    Ok(Some(header))
}

fn decode_import_header(
    row: &rusqlite::Row<'_>,
) -> Result<(ContentLayoutTransferHeader, [u8; 32]), rusqlite::Error> {
    let manifest_id =
        meshspan_domain::ContentManifestId::from_bytes(copy_array(&row.get::<_, Vec<u8>>(0)?)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let header = ContentLayoutTransferHeader {
        manifest: ManifestPublication {
            manifest_id,
            format_version: u16::try_from(row.get::<_, i64>(1)?)
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
            logical_length: from_sql(row.get(2)?)?,
            content_digest: copy_array(&row.get::<_, Vec<u8>>(3)?)?,
            root_digest: copy_array(&row.get::<_, Vec<u8>>(4)?)?,
        },
        chunk_bytes: from_sql(row.get(5)?)?,
        chunk_count: from_sql(row.get(6)?)?,
        wrapped_key: WrappedContentKey {
            key_generation: from_sql(row.get(7)?)?,
            nonce: copy_array(&row.get::<_, Vec<u8>>(8)?)?,
            ciphertext: copy_array(&row.get::<_, Vec<u8>>(9)?)?,
            envelope_digest: copy_array(&row.get::<_, Vec<u8>>(10)?)?,
        },
    };
    Ok((header, copy_array(&row.get::<_, Vec<u8>>(11)?)?))
}

fn validate_import_page(
    header: ContentLayoutTransferHeader,
    page: &ContentLayoutTransferPage,
) -> Result<(), ContentCatalogError> {
    let last = page
        .chunks()
        .last()
        .ok_or(ContentCatalogError::InvalidInput)?
        .chunk_index;
    if last >= header.chunk_count {
        return Err(ContentCatalogError::InvalidInput);
    }
    let has_more = last
        .checked_add(1)
        .ok_or(ContentCatalogError::InvalidInput)?
        < header.chunk_count;
    if page.next_index() == has_more.then_some(last) {
        Ok(())
    } else {
        Err(ContentCatalogError::InvalidInput)
    }
}

fn prepare_import_chunks(
    operation_id: OperationId,
    chunks: &[ContentLayoutChunk],
) -> Result<Vec<PreparedContentChunk>, ContentCatalogError> {
    chunks
        .iter()
        .map(|chunk| {
            let provider_operation = provider_operation_id(operation_id, chunk.chunk_index)
                .map_err(|_| ContentCatalogError::InvalidInput)?;
            Ok(chunk.with_provider_operation(provider_operation))
        })
        .collect()
}

fn replay_import_page(
    connection: &Connection,
    operation_id: OperationId,
    existing_count: u64,
    prepared: Vec<PreparedContentChunk>,
) -> Result<(), ContentCatalogError> {
    let first_index = prepared
        .first()
        .ok_or(ContentCatalogError::InvalidInput)?
        .chunk_index;
    let replay_end = first_index
        .checked_add(u64::try_from(prepared.len()).map_err(|_| ContentCatalogError::InvalidInput)?)
        .ok_or(ContentCatalogError::InvalidInput)?;
    if replay_end > existing_count {
        return Err(ContentCatalogError::Conflict);
    }
    for expected in prepared {
        if load_chunk(connection, operation_id, expected.chunk_index)? != expected {
            return Err(ContentCatalogError::Conflict);
        }
    }
    Ok(())
}

fn persist_imported_manifest(
    connection: &Connection,
    request: ContentPublicationRequest,
    header: ContentLayoutTransferHeader,
) -> Result<(), ContentCatalogError> {
    let updated = connection.execute(
        "UPDATE content_publications SET root_digest = ?1
         WHERE operation_id = ?2 AND state = 1 AND root_digest IS NULL
           AND import_header_digest = ?3 AND import_expected_root_digest = ?1",
        params![
            header.manifest.root_digest.as_slice(),
            request.operation_id.as_bytes().as_slice(),
            header.digest().as_slice(),
        ],
    )?;
    if updated == 1 {
        Ok(())
    } else {
        Err(ContentCatalogError::Conflict)
    }
}
