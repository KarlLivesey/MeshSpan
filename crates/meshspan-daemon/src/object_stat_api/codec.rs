// SPDX-License-Identifier: GPL-2.0-only

//! Strict object-query parsing and response conversion.

use meshspan_api_contract::{
    DirectoryEntryKind as ApiDirectoryEntryKind, FileVersionId, GetObjectQuery, GetObjectResponse,
    NamespaceCommitId, NamespacePath as ApiNamespacePath, ObjectId, ObjectMetadataResponse,
    ObjectRevisionId, VolumeId,
};
use meshspan_filesystem::{DirectoryEntryKind, NamespaceObjectStat};

use super::service::ObjectStatError;
use crate::native_query::has_valid_percent_encoding;

pub(super) fn parse_object_query(
    raw_query: Option<&str>,
) -> Result<GetObjectQuery, ObjectStatError> {
    let raw_query = raw_query.ok_or(ObjectStatError::InvalidInput)?;
    if raw_query.is_empty()
        || raw_query.len() > 8_192
        || !has_valid_percent_encoding(raw_query.as_bytes())
    {
        return Err(ObjectStatError::InvalidInput);
    }
    let mut path = None;
    for (name, value) in form_urlencoded::parse(raw_query.as_bytes()) {
        if name != "path" || path.is_some() {
            return Err(ObjectStatError::InvalidInput);
        }
        path = Some(
            ApiNamespacePath::from_decoded(value.into_owned())
                .ok_or(ObjectStatError::InvalidInput)?,
        );
    }
    let query = GetObjectQuery {
        path: path.ok_or(ObjectStatError::InvalidInput)?,
    };
    meshspan_api_contract::validate_get_object_query(&query)
        .map_err(|_| ObjectStatError::InvalidInput)?;
    Ok(query)
}

pub(crate) fn response(
    volume_id: VolumeId,
    query: GetObjectQuery,
    stat: &NamespaceObjectStat,
) -> Result<GetObjectResponse, ObjectStatError> {
    Ok(GetObjectResponse {
        volume_id,
        path: query.path,
        namespace_commit_id: NamespaceCommitId::from_uuid_bytes(
            stat.namespace_commit_id.as_bytes(),
        )
        .ok_or(ObjectStatError::Failed)?,
        object: ObjectMetadataResponse {
            name: stat.name.display().to_owned(),
            object_id: ObjectId::from_uuid_bytes(stat.object_id.as_bytes())
                .ok_or(ObjectStatError::Failed)?,
            object_revision_id: ObjectRevisionId::from_uuid_bytes(
                stat.object_revision_id.as_bytes(),
            )
            .ok_or(ObjectStatError::Failed)?,
            entry_generation: i64::try_from(stat.entry_generation)
                .map_err(|_| ObjectStatError::Failed)?,
            kind: match stat.kind {
                DirectoryEntryKind::Directory => ApiDirectoryEntryKind::Directory,
                DirectoryEntryKind::File => ApiDirectoryEntryKind::File,
            },
            file_version_id: stat
                .file_version_id
                .map(|value| {
                    FileVersionId::from_uuid_bytes(value.as_bytes()).ok_or(ObjectStatError::Failed)
                })
                .transpose()?,
            logical_length: stat
                .logical_length
                .map(i64::try_from)
                .transpose()
                .map_err(|_| ObjectStatError::Failed)?,
        },
    })
}
