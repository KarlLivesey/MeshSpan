// SPDX-License-Identifier: GPL-2.0-only

//! Source-side bounded export of already durable native gateway state.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use meshspan_cluster::{
    version_native_content_layout_chunk, version_native_content_layout_header,
    version_native_shard_receipt,
};
use meshspan_domain::{
    ContentManifestId, DurationMicros, NamespaceCommitId, NodeId, OperationId, UnixMicros, VolumeId,
};
use meshspan_filesystem::{
    DurableContentCatalog, NamespaceHistoryObjectRequest, NamespaceHistoryPageRequest,
    VersionPublicationStore,
};
use meshspan_protocol::v1::control_envelope::Message;
use meshspan_protocol::v1::{
    FetchNamespaceHistoryObject, FetchNamespaceHistoryPage, FetchNativeContentLayout,
    NamespaceHistoryObjectResult, NamespaceHistoryPageResult, NativeContentLayoutPage,
    VersionedPayload,
};
use sha2::{Digest, Sha256};

use super::{NativeGatewaySyncError, identifier};
const RECORD_FORMAT_VERSION: u32 = 1;
const EXPORT_LIFETIME: DurationMicros = DurationMicros::new(60 * 60 * 1_000_000);
const SCOPE_DOMAIN: &[u8] = b"meshspan.native.gateway-history-scope.v1\0";

pub(super) fn history_page(
    state_directory: &Path,
    requester: NodeId,
    request: FetchNamespaceHistoryPage,
) -> Result<Message, NativeGatewaySyncError> {
    let now = current_time().map_err(|_| NativeGatewaySyncError::Unavailable)?;
    let volume_id = volume(&request.volume_id)?;
    let requested_heads = request
        .requested_heads
        .iter()
        .map(|value| namespace_commit(value))
        .collect::<Result<Vec<_>, _>>()?;
    let known_commits = request
        .known_commits
        .iter()
        .map(|value| namespace_commit(value))
        .collect::<Result<Vec<_>, _>>()?;
    let expires_at = now
        .checked_add(EXPORT_LIFETIME)
        .ok_or(NativeGatewaySyncError::Invalid)?;
    let mut store = VersionPublicationStore::open(&state_directory.join("filesystem"), now)
        .map_err(|_| NativeGatewaySyncError::Unavailable)?;
    let page = store
        .namespace_history_page(NamespaceHistoryPageRequest {
            scope_binding: scope_binding(requester, volume_id),
            volume_id,
            requested_heads,
            known_commits,
            cursor: request.cursor,
            limit: usize::try_from(request.limit).map_err(|_| NativeGatewaySyncError::Invalid)?,
            now,
            expires_at,
        })
        .map_err(|_| NativeGatewaySyncError::Invalid)?;
    Ok(Message::NamespaceHistoryPageResult(
        NamespaceHistoryPageResult {
            export_token: page.export_token.to_vec(),
            commits: page
                .commits
                .into_iter()
                .map(|record| VersionedPayload {
                    format_version: RECORD_FORMAT_VERSION,
                    canonical_bytes: record.canonical_bytes().to_vec(),
                })
                .collect(),
            immutable_object_digests: page
                .immutable_object_digests
                .into_iter()
                .map(|digest| digest.to_vec())
                .collect(),
            next_cursor: page.next_cursor,
        },
    ))
}

pub(super) fn history_object(
    state_directory: &Path,
    requester: NodeId,
    request: FetchNamespaceHistoryObject,
) -> Result<Message, NativeGatewaySyncError> {
    let now = current_time().map_err(|_| NativeGatewaySyncError::Unavailable)?;
    let volume_id = volume(&request.volume_id)?;
    let store = VersionPublicationStore::open(&state_directory.join("filesystem"), now)
        .map_err(|_| NativeGatewaySyncError::Unavailable)?;
    let record = store
        .namespace_history_object(NamespaceHistoryObjectRequest {
            scope_binding: scope_binding(requester, volume_id),
            export_token: identifier(&request.export_token)?,
            object_digest: identifier(&request.object_digest)?,
            now,
        })
        .map_err(|_| NativeGatewaySyncError::Invalid)?;
    Ok(Message::NamespaceHistoryObjectResult(
        NamespaceHistoryObjectResult {
            object: Some(VersionedPayload {
                format_version: RECORD_FORMAT_VERSION,
                canonical_bytes: record.canonical_bytes().to_vec(),
            }),
        },
    ))
}

pub(super) fn content_layout(
    state_directory: &Path,
    request: FetchNativeContentLayout,
) -> Result<Message, NativeGatewaySyncError> {
    let now = current_time().map_err(|_| NativeGatewaySyncError::Unavailable)?;
    let operation_id = OperationId::from_bytes(identifier(&request.publication_operation_id)?)
        .map_err(|_| NativeGatewaySyncError::Invalid)?;
    let manifest_id = ContentManifestId::from_bytes(identifier(&request.manifest_id)?)
        .map_err(|_| NativeGatewaySyncError::Invalid)?;
    let catalog = DurableContentCatalog::open(&state_directory.join("filesystem"), now)
        .map_err(|_| NativeGatewaySyncError::Unavailable)?;
    let content = catalog
        .committed_content_by_manifest(manifest_id)
        .map_err(|_| NativeGatewaySyncError::Unavailable)?
        .filter(|content| content.publication_operation_id == operation_id)
        .ok_or(NativeGatewaySyncError::Invalid)?;
    let transfer = catalog
        .committed_layout_transfer(content)
        .map_err(|_| NativeGatewaySyncError::Unavailable)?;
    let inventory = catalog
        .committed_shard_inventory(content)
        .map_err(|_| NativeGatewaySyncError::Unavailable)?;
    let (chunks, receipts, next_index) = if transfer.header().chunk_count == 0 {
        (Vec::new(), Vec::new(), None)
    } else {
        let limit = usize::try_from(request.limit).map_err(|_| NativeGatewaySyncError::Invalid)?;
        let layout_page = transfer
            .page(request.after_index, limit)
            .map_err(|_| NativeGatewaySyncError::Invalid)?;
        let shard_page = inventory
            .page(request.after_index, limit)
            .map_err(|_| NativeGatewaySyncError::Invalid)?;
        if layout_page.next_index() != shard_page.next_index
            || layout_page.chunks().len() != shard_page.shards.len()
            || layout_page
                .chunks()
                .iter()
                .zip(shard_page.shards.as_slice())
                .any(|(chunk, receipt)| chunk.chunk_index != receipt.shard.stripe_index)
        {
            return Err(NativeGatewaySyncError::Unavailable);
        }
        (
            layout_page
                .chunks()
                .iter()
                .copied()
                .map(version_native_content_layout_chunk)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| NativeGatewaySyncError::Unavailable)?,
            shard_page
                .shards
                .as_slice()
                .iter()
                .copied()
                .map(version_native_shard_receipt)
                .collect(),
            layout_page.next_index(),
        )
    };
    Ok(Message::NativeContentLayoutPage(NativeContentLayoutPage {
        header: Some(version_native_content_layout_header(transfer.header())),
        chunks,
        receipts,
        next_index,
    }))
}

pub(super) fn scope_binding(requester: NodeId, volume_id: VolumeId) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(SCOPE_DOMAIN);
    digest.update(requester.as_bytes());
    digest.update(volume_id.as_bytes());
    digest.finalize().into()
}

fn volume(bytes: &[u8]) -> Result<VolumeId, NativeGatewaySyncError> {
    VolumeId::from_bytes(identifier(bytes)?).map_err(|_| NativeGatewaySyncError::Invalid)
}

fn namespace_commit(bytes: &[u8]) -> Result<NamespaceCommitId, NativeGatewaySyncError> {
    NamespaceCommitId::from_bytes(identifier(bytes)?).map_err(|_| NativeGatewaySyncError::Invalid)
}

fn current_time() -> Result<UnixMicros, NativeGatewaySyncError> {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_micros()).ok())
        .ok_or(NativeGatewaySyncError::Unavailable)?;
    Ok(UnixMicros::new(micros))
}
