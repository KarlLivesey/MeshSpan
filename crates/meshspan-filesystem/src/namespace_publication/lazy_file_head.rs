// SPDX-License-Identifier: GPL-2.0-only

//! Lazy branch-local file projection for an existing immutable namespace entry.

use meshspan_domain::{FileVersionId, ObjectId, VolumeId};
use rusqlite::{OptionalExtension, Transaction, params};

use super::super::{FilePublication, PublicationError, load_file_head};
use crate::publication::decode_identifier;

pub(super) fn materialize(
    transaction: &Transaction<'_>,
    publication: FilePublication,
) -> Result<(), PublicationError> {
    let Some(expected_version_id) = publication.expected_current_version_id else {
        return Ok(());
    };
    if load_file_head(transaction, publication.branch_id, publication.object_id)?.is_some() {
        return Ok(());
    }
    validate_inherited_version(transaction, publication, expected_version_id)?;
    transaction.execute(
        "INSERT INTO branch_files(
            branch_id, object_id, volume_id, current_version_id, head_sequence
         ) VALUES (?1, ?2, ?3, ?4, 1)",
        params![
            publication.branch_id.as_bytes().as_slice(),
            publication.object_id.as_bytes().as_slice(),
            publication.volume_id.as_bytes().as_slice(),
            expected_version_id.as_bytes().as_slice(),
        ],
    )?;
    Ok(())
}

fn validate_inherited_version(
    transaction: &Transaction<'_>,
    publication: FilePublication,
    version_id: FileVersionId,
) -> Result<(), PublicationError> {
    let stored: Option<(Vec<u8>, Vec<u8>)> = transaction
        .query_row(
            "SELECT volume_id, object_id FROM file_versions WHERE version_id = ?1",
            [version_id.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((volume_id, object_id)) = stored else {
        return Err(PublicationError::Corrupt);
    };
    let valid = decode_identifier(&volume_id, VolumeId::from_bytes)? == publication.volume_id
        && decode_identifier(&object_id, ObjectId::from_bytes)? == publication.object_id;
    if valid {
        Ok(())
    } else {
        Err(PublicationError::Corrupt)
    }
}
