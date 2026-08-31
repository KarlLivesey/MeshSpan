// SPDX-License-Identifier: GPL-2.0-only

//! Strict query, response and opaque-continuation codecs.

use meshspan_api_contract::{
    DirectoryCursor as ApiDirectoryCursor, DirectoryEntryKind as ApiDirectoryEntryKind,
    FileVersionId as ApiFileVersionId, ListDirectoryQuery, ListDirectoryResponse,
    NamespaceCommitId as ApiNamespaceCommitId, NamespacePath as ApiNamespacePath,
    ObjectId as ApiObjectId, ObjectMetadataResponse, ObjectRevisionId as ApiObjectRevisionId,
    VolumeId as ApiVolumeId, validate_list_directory_query,
};
use meshspan_filesystem::{
    DirectoryEntryKind, DirectoryListCursor, NamespaceComponent, NamespaceLimits, NamespaceListPage,
};

use super::service::DirectoryListingError;

pub(super) fn parse_directory_query(
    raw_query: Option<&str>,
) -> Result<ListDirectoryQuery, DirectoryListingError> {
    let Some(raw_query) = raw_query.filter(|value| !value.is_empty()) else {
        return Ok(ListDirectoryQuery::default());
    };
    if raw_query.len() > 16_384 || !has_valid_percent_encoding(raw_query.as_bytes()) {
        return Err(DirectoryListingError::InvalidInput);
    }
    let mut query = ListDirectoryQuery::default();
    let mut path_seen = false;
    let mut cursor_seen = false;
    let mut limit_seen = false;
    for (name, value) in form_urlencoded::parse(raw_query.as_bytes()) {
        match name.as_ref() {
            "path" if !path_seen => {
                path_seen = true;
                query.path = Some(
                    ApiNamespacePath::from_decoded(value.into_owned())
                        .ok_or(DirectoryListingError::InvalidInput)?,
                );
            }
            "cursor" if !cursor_seen => {
                cursor_seen = true;
                query.cursor = Some(
                    ApiDirectoryCursor::from_encoded(value.into_owned())
                        .ok_or(DirectoryListingError::InvalidInput)?,
                );
            }
            "limit" if !limit_seen => {
                limit_seen = true;
                let parsed = value
                    .parse::<u16>()
                    .ok()
                    .filter(|value| (1..=256).contains(value))
                    .ok_or(DirectoryListingError::InvalidInput)?;
                query.limit = Some(parsed);
            }
            _ => return Err(DirectoryListingError::InvalidInput),
        }
    }
    validate_list_directory_query(&query).map_err(|_| DirectoryListingError::InvalidInput)?;
    Ok(query)
}

pub(super) fn response(
    volume_id: ApiVolumeId,
    query: &ListDirectoryQuery,
    limit: u16,
    page: NamespaceListPage,
) -> Result<ListDirectoryResponse, DirectoryListingError> {
    let entries = page
        .entries
        .into_iter()
        .map(|entry| {
            Ok(ObjectMetadataResponse {
                name: entry.name.display().to_owned(),
                object_id: api_object_id(entry.object_id.as_bytes())?,
                object_revision_id: api_object_revision_id(entry.object_revision_id.as_bytes())?,
                entry_generation: entry.entry_generation,
                kind: match entry.kind {
                    DirectoryEntryKind::Directory => ApiDirectoryEntryKind::Directory,
                    DirectoryEntryKind::File => ApiDirectoryEntryKind::File,
                },
                file_version_id: entry
                    .file_version_id
                    .map(|value| api_file_version_id(value.as_bytes()))
                    .transpose()?,
                logical_length: entry.logical_length,
            })
        })
        .collect::<Result<Vec<_>, DirectoryListingError>>()?;
    let next_page_url = page
        .next_cursor
        .as_ref()
        .map(|cursor| next_page_url(&volume_id, query, limit, cursor))
        .transpose()?;
    Ok(ListDirectoryResponse {
        volume_id,
        path: query.path.clone(),
        namespace_commit_id: api_namespace_commit_id(page.namespace_commit_id.as_bytes())?,
        directory_object_id: api_object_id(page.directory_object_id.as_bytes())?,
        directory_object_revision_id: api_object_revision_id(
            page.directory_object_revision_id.as_bytes(),
        )?,
        entries,
        next_page_url,
    })
}

pub(super) fn decode_cursor(
    cursor: &ApiDirectoryCursor,
) -> Result<DirectoryListCursor, DirectoryListingError> {
    let fields = cursor.as_str().split('.').collect::<Vec<_>>();
    if fields.len() != 6 || fields[0] != "v1" {
        return Err(DirectoryListingError::InvalidInput);
    }
    let name_bytes = decode_hex(fields[5])?;
    let name = std::str::from_utf8(&name_bytes).map_err(|_| DirectoryListingError::InvalidInput)?;
    Ok(DirectoryListCursor {
        namespace_commit_id: meshspan_domain::NamespaceCommitId::from_bytes(decode_array(
            fields[1],
        )?)
        .map_err(|_| DirectoryListingError::InvalidInput)?,
        directory_object_id: meshspan_domain::ObjectId::from_bytes(decode_array(fields[2])?)
            .map_err(|_| DirectoryListingError::InvalidInput)?,
        directory_object_revision_id: meshspan_domain::ObjectRevisionId::from_bytes(decode_array(
            fields[3],
        )?)
        .map_err(|_| DirectoryListingError::InvalidInput)?,
        after_name_hash: decode_array(fields[4])?,
        after_name: NamespaceComponent::new(name, NamespaceLimits::PORTABLE)
            .map_err(|_| DirectoryListingError::InvalidInput)?,
    })
}

fn next_page_url(
    volume_id: &ApiVolumeId,
    query: &ListDirectoryQuery,
    limit: u16,
    cursor: &DirectoryListCursor,
) -> Result<String, DirectoryListingError> {
    let cursor = encode_cursor(cursor)?;
    let mut url = format!(
        "/api/latest/volumes/{}/directory-entries?limit={limit}",
        volume_id.as_str()
    );
    if let Some(path) = &query.path {
        url.push_str("&path=");
        append_percent_encoded(&mut url, path.as_str());
    }
    url.push_str("&cursor=");
    url.push_str(cursor.as_str());
    if url.len() > 16_384 {
        return Err(DirectoryListingError::Failed);
    }
    Ok(url)
}

fn encode_cursor(
    cursor: &DirectoryListCursor,
) -> Result<ApiDirectoryCursor, DirectoryListingError> {
    let mut encoded = String::from("v1");
    for bytes in [
        cursor.namespace_commit_id.as_bytes().as_slice(),
        cursor.directory_object_id.as_bytes().as_slice(),
        cursor.directory_object_revision_id.as_bytes().as_slice(),
        cursor.after_name_hash.as_slice(),
        cursor.after_name.display().as_bytes(),
    ] {
        encoded.push('.');
        append_hex(&mut encoded, bytes);
    }
    ApiDirectoryCursor::from_encoded(encoded).ok_or(DirectoryListingError::Failed)
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

fn decode_array<const N: usize>(value: &str) -> Result<[u8; N], DirectoryListingError> {
    decode_hex(value)?
        .try_into()
        .map_err(|_| DirectoryListingError::InvalidInput)
}

fn decode_hex(value: &str) -> Result<Vec<u8>, DirectoryListingError> {
    if !value.len().is_multiple_of(2) {
        return Err(DirectoryListingError::InvalidInput);
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = hex_nibble(pair[0]).ok_or(DirectoryListingError::InvalidInput)?;
            let low = hex_nibble(pair[1]).ok_or(DirectoryListingError::InvalidInput)?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn append_hex(output: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
}

fn append_percent_encoded(output: &mut String, value: &str) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            output.push(char::from(byte));
        } else {
            output.push('%');
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
}

const fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn api_namespace_commit_id(value: [u8; 16]) -> Result<ApiNamespaceCommitId, DirectoryListingError> {
    ApiNamespaceCommitId::from_uuid_bytes(value).ok_or(DirectoryListingError::Failed)
}

fn api_object_id(value: [u8; 16]) -> Result<ApiObjectId, DirectoryListingError> {
    ApiObjectId::from_uuid_bytes(value).ok_or(DirectoryListingError::Failed)
}

fn api_object_revision_id(value: [u8; 16]) -> Result<ApiObjectRevisionId, DirectoryListingError> {
    ApiObjectRevisionId::from_uuid_bytes(value).ok_or(DirectoryListingError::Failed)
}

fn api_file_version_id(value: [u8; 16]) -> Result<ApiFileVersionId, DirectoryListingError> {
    ApiFileVersionId::from_uuid_bytes(value).ok_or(DirectoryListingError::Failed)
}
