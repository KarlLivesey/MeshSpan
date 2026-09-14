// SPDX-License-Identifier: GPL-2.0-only

//! Namespace-owned retention of a selected layout until its new file reference commits.

use super::{
    FilePublication, PublicationError, VersionPublicationStore, persist_manifest,
    publication_request_digest, validate_publication,
};
use crate::{CompletedStage, ManifestPublication};
use meshspan_domain::{ContentManifestId, OperationId, VolumeId};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

pub(super) const CANDIDATE_QUERY: &str = "SELECT m.manifest_id, m.format_version, m.logical_length,
    m.content_digest, m.root_digest FROM content_manifests AS m
    WHERE m.content_digest = ?1 AND m.logical_length = ?2 AND m.manifest_id > ?3
      AND EXISTS(SELECT 1 FROM file_versions AS v WHERE v.volume_id = ?4 AND v.manifest_id = m.manifest_id)
    ORDER BY m.manifest_id LIMIT ?5";

impl VersionPublicationStore {
    pub(crate) fn selected_content_reuse(
        &self,
        operation: OperationId,
    ) -> Result<Option<ManifestPublication>, PublicationError> {
        let row = self
            .connection
            .query_row(
                "SELECT r.state, m.manifest_id, m.format_version, m.logical_length,
                m.content_digest, m.root_digest, r.manifest_root_digest
             FROM content_reuse_reservations r JOIN content_manifests m
               ON m.manifest_id = r.manifest_id WHERE r.operation_id = ?1",
                [operation.as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, Vec<u8>>(6)?,
                    ))
                },
            )
            .optional()?;
        row.map(|(state, id, format, length, digest, root, reserved_root)| {
            if state == 3 {
                return Err(PublicationError::OperationConflict);
            }
            if !matches!(state, 1 | 2) || root != reserved_root || format <= 0 {
                return Err(PublicationError::Corrupt);
            }
            Ok(ManifestPublication {
                manifest_id: super::decode_identifier(&id, ContentManifestId::from_bytes)?,
                format_version: u16::try_from(format).map_err(|_| PublicationError::Corrupt)?,
                logical_length: super::from_i64(length)?,
                content_digest: digest.try_into().map_err(|_| PublicationError::Corrupt)?,
                root_digest: root.try_into().map_err(|_| PublicationError::Corrupt)?,
            })
        })
        .transpose()
    }

    /// Finds a bounded identity-ordered batch of possible layouts in this volume's retained metadata.
    ///
    /// Matching plaintext is discovery only, not permission, protection or current-byte proof.
    /// The publisher must verify those before reserving a selection. Pass the last returned
    /// manifest identity to continue a full batch; an empty/short batch exhausts this view.
    /// No names, owners or permissions are merged. Imported mesh history uses the same index.
    ///
    /// # Errors
    /// Rejects zero/excessive batch bounds, unrepresentable lengths and corrupt stored metadata.
    pub fn content_reuse_candidates(
        &self,
        volume: VolumeId,
        completed: CompletedStage,
        after: Option<ContentManifestId>,
        maximum: usize,
    ) -> Result<Vec<ManifestPublication>, PublicationError> {
        if maximum == 0 || maximum > 1_000 {
            return Err(PublicationError::InvalidInput);
        }
        let after = after.map(ContentManifestId::as_bytes);
        let mut statement = self.connection.prepare(CANDIDATE_QUERY)?;
        let rows = statement.query_map(
            params![
                completed.content_digest.as_slice(),
                super::to_i64(completed.logical_length)?,
                after.as_ref().map_or(&[][..], |id| id.as_slice()),
                volume.as_bytes().as_slice(),
                i64::try_from(maximum).map_err(|_| PublicationError::InvalidInput)?
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            },
        )?;
        rows.map(|row| {
            let (id, format, length, digest, root) = row?;
            let format_version = u16::try_from(format).map_err(|_| PublicationError::Corrupt)?;
            if format_version == 0 {
                return Err(PublicationError::Corrupt);
            }
            Ok(ManifestPublication {
                manifest_id: super::decode_identifier(&id, ContentManifestId::from_bytes)?,
                format_version,
                logical_length: super::from_i64(length)?,
                content_digest: digest.try_into().map_err(|_| PublicationError::Corrupt)?,
                root_digest: root.try_into().map_err(|_| PublicationError::Corrupt)?,
            })
        })
        .collect()
    }

    /// Retains verified content for one exact, already-authorised file publication intent.
    ///
    /// This grants no read permission and does not publish the file. The caller must verify
    /// uploaded bytes, layout compatibility and current access independently. The reservation
    /// survives restart and is consumed atomically with the new version, or explicitly cancelled.
    ///
    /// # Errors
    /// Rejects changed intent, prior cancellation, cleanup fences and invalid manifest metadata.
    pub fn reserve_content_reuse(
        &mut self,
        publication: FilePublication,
    ) -> Result<(), PublicationError> {
        validate_publication(publication)?;
        let digest = publication_request_digest(publication);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(state) = load(&transaction, publication)? {
            return if matches!(state, 1 | 2) {
                Ok(())
            } else {
                Err(PublicationError::OperationConflict)
            };
        }
        crate::cleanup_fence::reject_manifest_reference(&transaction, publication.manifest)?;
        let completed: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM file_versions WHERE publication_operation_id = ?1)",
            [publication.operation_id.as_bytes().as_slice()],
            |row| row.get(0),
        )?;
        if completed {
            return Err(PublicationError::OperationConflict);
        }
        persist_manifest(&transaction, publication.manifest)?;
        transaction.execute(
            "INSERT INTO content_reuse_reservations(operation_id, request_digest, volume_id,
                version_id, manifest_id, manifest_root_digest, state) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1)",
            params![publication.operation_id.as_bytes().as_slice(), digest.as_slice(),
                publication.volume_id.as_bytes().as_slice(), publication.version_id.as_bytes().as_slice(),
                publication.manifest.manifest_id.as_bytes().as_slice(), publication.manifest.root_digest.as_slice()],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Cancels an unpublished selection without permitting a late writer to attach it.
    ///
    /// # Errors
    /// Rejects missing/changed intent and cancellation after attachment. Exact cancellation retries succeed.
    pub fn cancel_content_reuse(
        &mut self,
        publication: FilePublication,
    ) -> Result<(), PublicationError> {
        validate_publication(publication)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state = load(&transaction, publication)?.ok_or(PublicationError::OperationConflict)?;
        if !matches!(state, 1 | 3) {
            return Err(PublicationError::OperationConflict);
        }
        transaction.execute(
            "UPDATE content_reuse_reservations SET state = 3 WHERE operation_id = ?1",
            [publication.operation_id.as_bytes().as_slice()],
        )?;
        transaction.commit()?;
        Ok(())
    }
}

pub(super) fn attach(
    transaction: &Transaction<'_>,
    publication: FilePublication,
) -> Result<(), PublicationError> {
    let Some(state) = load(transaction, publication)? else {
        return Ok(());
    };
    if state != 1 {
        return Err(PublicationError::OperationConflict);
    }
    transaction.execute(
        "UPDATE content_reuse_reservations SET state = 2 WHERE operation_id = ?1 AND state = 1",
        [publication.operation_id.as_bytes().as_slice()],
    )?;
    Ok(())
}

type StoredReuse = (Vec<u8>, i64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

fn load(
    connection: &Connection,
    publication: FilePublication,
) -> Result<Option<i64>, PublicationError> {
    let row: Option<StoredReuse> = connection
        .query_row(
            "SELECT request_digest, state, volume_id, version_id, manifest_id, manifest_root_digest
         FROM content_reuse_reservations WHERE operation_id = ?1",
            [publication.operation_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?;
    row.map(|(digest, state, volume, version, manifest, root)| {
        if digest.as_slice() != publication_request_digest(publication) {
            return Err(PublicationError::OperationConflict);
        }
        if !matches!(state, 1..=3)
            || volume.as_slice() != publication.volume_id.as_bytes()
            || version.as_slice() != publication.version_id.as_bytes()
            || manifest.as_slice() != publication.manifest.manifest_id.as_bytes()
            || root.as_slice() != publication.manifest.root_digest
        {
            return Err(PublicationError::Corrupt);
        }
        Ok(state)
    })
    .transpose()
}
