// SPDX-License-Identifier: GPL-2.0-only

//! Strict object-query parsing and response conversion.

use meshspan_api_contract::{
    DirectoryEntryKind as ApiDirectoryEntryKind, FileVersionId, GetObjectQuery, GetObjectResponse,
    NamespaceCommitId, NamespacePath as ApiNamespacePath, ObjectId, ObjectMetadataResponse,
    ObjectRevisionId, VolumeId,
};
use meshspan_filesystem::{DirectoryEntryKind, NamespaceObjectStat};

use super::service::ObjectStatError;

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

pub(super) fn response(
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
            entry_generation: stat.entry_generation,
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
            logical_length: stat.logical_length,
        },
    })
}

fn has_valid_percent_encoding(bytes: &[u8]) -> bool {
    let mut index = 0_usize;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || hex_nibble(bytes[index + 1]).is_none()
                || hex_nibble(bytes[index + 2]).is_none()
            {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
}

const fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}
