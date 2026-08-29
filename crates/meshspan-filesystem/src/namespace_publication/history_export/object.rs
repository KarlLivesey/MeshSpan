// SPDX-License-Identifier: GPL-2.0-only

//! Exact immutable-body lookup through one live, authority-bound export session.

use meshspan_domain::{FileVersionId, ObjectRevisionId, VolumeId};
use rusqlite::{Connection, OptionalExtension, params};

use super::super::history_records::NamespaceHistoryImmutableRecord;
use super::super::repository::load_object_revision;
use super::super::transfer::export_graph;
use super::NamespaceHistoryObjectRequest;
use super::work::{
    RECORD_IMMUTABLE, WORK_DIRECTORY_NODE, WORK_FILE_VERSION, WORK_MANIFEST, WORK_REVISION,
};
use crate::publication::{copy_array, load_directory_node};
use crate::{DirectoryNodeDigest, PublicationError};

pub(super) fn load(
    connection: &Connection,
    request: NamespaceHistoryObjectRequest,
) -> Result<NamespaceHistoryImmutableRecord, PublicationError> {
    let Some((volume, source_kind, source_identity)) = locate(connection, request)? else {
        return Err(PublicationError::InvalidInput);
    };
    let volume_id = volume_id(&volume)?;
    let record = match source_kind {
        WORK_REVISION => load_revision(connection, volume_id, &source_identity),
        WORK_DIRECTORY_NODE => load_directory(connection, &source_identity),
        WORK_FILE_VERSION => load_version(connection, volume_id, &source_identity),
        WORK_MANIFEST => load_manifest(connection, &source_identity),
        _ => Err(PublicationError::Corrupt),
    }?;
    if record.digest() == request.object_digest {
        Ok(record)
    } else {
        Err(PublicationError::Corrupt)
    }
}

type LocatedObject = (Vec<u8>, i64, Vec<u8>);

fn locate(
    connection: &Connection,
    request: NamespaceHistoryObjectRequest,
) -> Result<Option<LocatedObject>, PublicationError> {
    connection
        .query_row(
            "SELECT export.volume_id, record.source_kind, record.source_identity
             FROM namespace_history_exports AS export
             JOIN namespace_history_export_records AS record
               ON record.request_digest = export.request_digest
             WHERE export.request_digest = ?1
               AND export.scope_binding = ?2
               AND export.expires_at > ?3
               AND record.record_kind = ?4
               AND record.transfer_digest = ?5",
            params![
                request.export_token.as_slice(),
                request.scope_binding.as_slice(),
                request.now.get(),
                RECORD_IMMUTABLE,
                request.object_digest.as_slice()
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(Into::into)
}

fn load_revision(
    connection: &Connection,
    volume_id: VolumeId,
    identity: &[u8],
) -> Result<NamespaceHistoryImmutableRecord, PublicationError> {
    let revision_id = identifier(identity, ObjectRevisionId::from_bytes)?;
    let source = load_object_revision(connection, revision_id)?;
    if source.volume_id != volume_id {
        return Err(PublicationError::Corrupt);
    }
    NamespaceHistoryImmutableRecord::object_revision(source).map_err(|_| PublicationError::Corrupt)
}

fn load_directory(
    connection: &Connection,
    identity: &[u8],
) -> Result<NamespaceHistoryImmutableRecord, PublicationError> {
    let digest = DirectoryNodeDigest::from_bytes(copy_array(identity)?);
    let source = load_directory_node(connection, digest)?.ok_or(PublicationError::Corrupt)?;
    NamespaceHistoryImmutableRecord::directory(&source).map_err(|_| PublicationError::Corrupt)
}

fn load_version(
    connection: &Connection,
    volume_id: VolumeId,
    identity: &[u8],
) -> Result<NamespaceHistoryImmutableRecord, PublicationError> {
    let version_id = identifier(identity, FileVersionId::from_bytes)?;
    let source = export_graph::load_file_version(connection, version_id)?;
    if source.volume_id != volume_id {
        return Err(PublicationError::Corrupt);
    }
    NamespaceHistoryImmutableRecord::file_version(source).map_err(|_| PublicationError::Corrupt)
}

fn load_manifest(
    connection: &Connection,
    identity: &[u8],
) -> Result<NamespaceHistoryImmutableRecord, PublicationError> {
    let manifest_id = identifier(identity, meshspan_domain::ContentManifestId::from_bytes)?;
    let source = export_graph::load_manifest(connection, manifest_id)?;
    NamespaceHistoryImmutableRecord::manifest(source).map_err(|_| PublicationError::Corrupt)
}

fn volume_id(bytes: &[u8]) -> Result<VolumeId, PublicationError> {
    identifier(bytes, VolumeId::from_bytes)
}

fn identifier<T, E>(
    bytes: &[u8],
    constructor: impl FnOnce([u8; 16]) -> Result<T, E>,
) -> Result<T, PublicationError> {
    constructor(bytes.try_into().map_err(|_| PublicationError::Corrupt)?)
        .map_err(|_| PublicationError::Corrupt)
}
