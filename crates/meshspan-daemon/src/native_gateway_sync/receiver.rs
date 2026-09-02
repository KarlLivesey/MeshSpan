// SPDX-License-Identifier: GPL-2.0-only

//! Receiver-side native gateway convergence.

use std::collections::BTreeSet;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use meshspan_cluster::{
    ConsensusNetwork, decode_native_content_layout_chunk, decode_native_content_layout_header,
    decode_native_protected_stripe, decode_native_shard_receipt,
};
use meshspan_domain::{
    ContentManifestId, InitialBootstrapMaterial, NamespaceCommitId, NodeId, OperationId, Revision,
    TargetId, UnixMicros, VolumeId,
};
use meshspan_filesystem::{
    ContentLayoutTransferHeader, ContentLayoutTransferPage, ContentPublicationRequest,
    DurableContentCatalog, NamespaceHistoryCommitRecord, NamespaceHistoryImmutableRecord,
    NamespaceHistoryLimits, NamespaceHistoryPage, NamespaceHistoryReceiveRequest,
    NamespaceHistoryReceiveStatus, VersionPublicationStore, provider_operation_id,
};
use meshspan_metadata::{AuthoritativeRepository, PartitionDatabase};
use meshspan_protocol::v1::control_envelope::Message;
use meshspan_protocol::v1::{
    ControlEnvelope, FetchNamespaceHistoryObject, FetchNamespaceHistoryPage,
    FetchNativeContentLayout, NativeContentLayoutPage, NativeContentRoute, OperationOutcome,
    OperationResult, PublishNamespaceHead,
};
use sha2::{Digest, Sha256};

use super::{NativeGatewaySyncError, identifier};

const PAGE_ITEMS: u32 = 128;
const IMMUTABLE_FETCH_CONCURRENCY: usize = 32;
const RECORD_FORMAT_VERSION: u32 = 1;
const REQUEST_TIMEOUT_MICROS: i64 = 60 * 1_000_000;

pub(super) async fn publish_head(
    network: &ConsensusNetwork,
    state_directory: &Path,
    source: NodeId,
    publish_operation_id: OperationId,
    publish_deadline: i64,
    request: &PublishNamespaceHead,
) -> Result<Message, NativeGatewaySyncError> {
    let advertised = AdvertisedHead::parse(request)?;
    let session_id = receive_session_id(
        network.local_node_id(),
        source,
        publish_operation_id,
        &advertised,
    );
    let status = begin_history_receive(
        state_directory,
        network.local_node_id(),
        session_id,
        publish_deadline,
        &advertised,
    )?;
    let status = receive_history_pages(
        network,
        state_directory,
        source,
        session_id,
        &advertised,
        status,
    )
    .await?;
    receive_history_objects(
        network,
        state_directory,
        source,
        session_id,
        advertised.volume_id,
        status,
    )
    .await?;
    complete_received_history(state_directory, session_id, &advertised)?;
    for route in &advertised.content_routes {
        receive_content_layout(
            network,
            state_directory,
            source,
            advertised.volume_id,
            route,
        )
        .await?;
    }
    adopt_received_head(network.local_node_id(), state_directory, &advertised)?;
    Ok(accepted(advertised.result_digest()))
}

#[derive(Clone, Copy)]
struct ParsedContentRoute {
    publication_operation_id: OperationId,
    manifest_id: ContentManifestId,
    target_id: TargetId,
    target_generation: u64,
}

struct AdvertisedHead {
    volume_id: VolumeId,
    namespace_commit_id: NamespaceCommitId,
    root_object_revision_id: meshspan_domain::ObjectRevisionId,
    content_routes: Vec<ParsedContentRoute>,
}

impl AdvertisedHead {
    fn parse(request: &PublishNamespaceHead) -> Result<Self, NativeGatewaySyncError> {
        let volume_id = VolumeId::from_bytes(identifier(&request.volume_id)?)
            .map_err(|_| NativeGatewaySyncError::Invalid)?;
        let namespace_commit_id =
            NamespaceCommitId::from_bytes(identifier(&request.namespace_commit_id)?)
                .map_err(|_| NativeGatewaySyncError::Invalid)?;
        let root_object_revision_id = meshspan_domain::ObjectRevisionId::from_bytes(identifier(
            &request.root_object_revision_id,
        )?)
        .map_err(|_| NativeGatewaySyncError::Invalid)?;
        let content_routes = request
            .content_routes
            .iter()
            .map(ParsedContentRoute::parse)
            .collect::<Result<Vec<_>, _>>()?;
        let unique = content_routes
            .iter()
            .map(|route| (route.publication_operation_id, route.manifest_id))
            .collect::<BTreeSet<_>>();
        if unique.len() != content_routes.len() {
            return Err(NativeGatewaySyncError::Invalid);
        }
        Ok(Self {
            volume_id,
            namespace_commit_id,
            root_object_revision_id,
            content_routes,
        })
    }

    fn result_digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"meshspan.native.gateway-head-accepted.v1\0");
        digest.update(self.volume_id.as_bytes());
        digest.update(self.namespace_commit_id.as_bytes());
        digest.update(self.root_object_revision_id.as_bytes());
        for route in &self.content_routes {
            digest.update(route.publication_operation_id.as_bytes());
            digest.update(route.manifest_id.as_bytes());
            digest.update(route.target_id.as_bytes());
            digest.update(route.target_generation.to_be_bytes());
        }
        digest.finalize().into()
    }
}

impl ParsedContentRoute {
    fn parse(route: &NativeContentRoute) -> Result<Self, NativeGatewaySyncError> {
        let publication_operation_id =
            OperationId::from_bytes(identifier(&route.publication_operation_id)?)
                .map_err(|_| NativeGatewaySyncError::Invalid)?;
        let manifest_id = ContentManifestId::from_bytes(identifier(&route.manifest_id)?)
            .map_err(|_| NativeGatewaySyncError::Invalid)?;
        let target_id = TargetId::from_bytes(identifier(&route.target_id)?)
            .map_err(|_| NativeGatewaySyncError::Invalid)?;
        if route.target_generation == 0 {
            return Err(NativeGatewaySyncError::Invalid);
        }
        Ok(Self {
            publication_operation_id,
            manifest_id,
            target_id,
            target_generation: route.target_generation,
        })
    }
}

fn begin_history_receive(
    state_directory: &Path,
    local_node_id: NodeId,
    session_id: [u8; 32],
    publish_deadline: i64,
    advertised: &AdvertisedHead,
) -> Result<NamespaceHistoryReceiveStatus, NativeGatewaySyncError> {
    let now = current_time()?;
    let expires_at = UnixMicros::new(publish_deadline);
    open_version_store(state_directory, now)?
        .begin_namespace_history_receive(&NamespaceHistoryReceiveRequest {
            session_id,
            scope_binding: super::source::scope_binding(local_node_id, advertised.volume_id),
            volume_id: advertised.volume_id,
            requested_heads: vec![advertised.namespace_commit_id],
            limits: NamespaceHistoryLimits::DEFAULT,
            now,
            expires_at,
        })
        .map_err(|_| NativeGatewaySyncError::Invalid)
}

async fn receive_history_pages(
    network: &ConsensusNetwork,
    state_directory: &Path,
    source: NodeId,
    session_id: [u8; 32],
    advertised: &AdvertisedHead,
    mut status: NamespaceHistoryReceiveStatus,
) -> Result<NamespaceHistoryReceiveStatus, NativeGatewaySyncError> {
    let known_commits = local_known_commits(
        network.local_node_id(),
        state_directory,
        advertised.volume_id,
    )?;
    while !status.terminal {
        let input_cursor = status.next_cursor.clone();
        let response = request(
            network,
            source,
            &session_id,
            1,
            &input_cursor,
            Message::FetchNamespaceHistoryPage(FetchNamespaceHistoryPage {
                volume_id: advertised.volume_id.as_bytes().to_vec(),
                requested_heads: vec![advertised.namespace_commit_id.as_bytes().to_vec()],
                known_commits: known_commits
                    .iter()
                    .map(|commit| commit.as_bytes().to_vec())
                    .collect(),
                cursor: input_cursor.clone(),
                limit: PAGE_ITEMS,
            }),
        )
        .await?;
        let Some(Message::NamespaceHistoryPageResult(result)) =
            response.as_inner().message.as_ref()
        else {
            return Err(NativeGatewaySyncError::Invalid);
        };
        let page = decode_history_page(result)?;
        let now = current_time()?;
        status = open_version_store(state_directory, now)?
            .receive_namespace_history_page(session_id, &input_cursor, &page, now)
            .map_err(|_| NativeGatewaySyncError::Invalid)?;
    }
    Ok(status)
}

fn local_known_commits(
    local_node_id: NodeId,
    state_directory: &Path,
    volume_id: VolumeId,
) -> Result<Vec<NamespaceCommitId>, NativeGatewaySyncError> {
    let branch_id = InitialBootstrapMaterial::local_branch_id(local_node_id)
        .map_err(|_| NativeGatewaySyncError::Invalid)?;
    let now = current_time()?;
    Ok(open_version_store(state_directory, now)?
        .namespace_head(branch_id, volume_id)
        .map_err(|_| NativeGatewaySyncError::Invalid)?
        .map(|head| vec![head.namespace_commit_id])
        .unwrap_or_default())
}

fn decode_history_page(
    result: &meshspan_protocol::v1::NamespaceHistoryPageResult,
) -> Result<NamespaceHistoryPage, NativeGatewaySyncError> {
    let commits = result
        .commits
        .iter()
        .map(|record| {
            if record.format_version != RECORD_FORMAT_VERSION {
                return Err(NativeGatewaySyncError::Invalid);
            }
            NamespaceHistoryCommitRecord::from_canonical_bytes(record.canonical_bytes.clone())
                .map_err(|_| NativeGatewaySyncError::Invalid)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let immutable = result
        .immutable_object_digests
        .iter()
        .map(|digest| identifier(digest))
        .collect::<Result<Vec<[u8; 32]>, _>>()?;
    NamespaceHistoryPage::from_untrusted(
        identifier(&result.export_token)?,
        commits,
        immutable,
        result.next_cursor.clone(),
    )
    .map_err(|_| NativeGatewaySyncError::Invalid)
}

async fn receive_history_objects(
    network: &ConsensusNetwork,
    state_directory: &Path,
    source: NodeId,
    session_id: [u8; 32],
    volume_id: VolumeId,
    mut status: NamespaceHistoryReceiveStatus,
) -> Result<(), NativeGatewaySyncError> {
    while status.missing_immutable_records != 0 {
        let export_token = status.export_token.ok_or(NativeGatewaySyncError::Invalid)?;
        let digests = open_version_store(state_directory, current_time()?)?
            .namespace_history_missing_immutable_digests(session_id, IMMUTABLE_FETCH_CONCURRENCY)
            .map_err(|_| NativeGatewaySyncError::Invalid)?;
        if digests.is_empty() {
            return Err(NativeGatewaySyncError::Invalid);
        }
        let mut requests = tokio::task::JoinSet::new();
        for digest in digests {
            let network = network.clone();
            requests.spawn(async move {
                fetch_history_object(
                    &network,
                    source,
                    session_id,
                    export_token,
                    volume_id,
                    digest,
                )
                .await
            });
        }
        while let Some(result) = requests.join_next().await {
            let record = result.map_err(|_| NativeGatewaySyncError::Unavailable)??;
            let now = current_time()?;
            status = open_version_store(state_directory, now)?
                .receive_namespace_history_object(session_id, &record, now)
                .map_err(|_| NativeGatewaySyncError::Invalid)?;
        }
    }
    if status.terminal && status.missing_immutable_records == 0 {
        Ok(())
    } else {
        Err(NativeGatewaySyncError::Invalid)
    }
}

async fn fetch_history_object(
    network: &ConsensusNetwork,
    source: NodeId,
    session_id: [u8; 32],
    export_token: [u8; 32],
    volume_id: VolumeId,
    expected_digest: [u8; 32],
) -> Result<NamespaceHistoryImmutableRecord, NativeGatewaySyncError> {
    let response = request(
        network,
        source,
        &session_id,
        2,
        &expected_digest,
        Message::FetchNamespaceHistoryObject(FetchNamespaceHistoryObject {
            export_token: export_token.to_vec(),
            object_digest: expected_digest.to_vec(),
            volume_id: volume_id.as_bytes().to_vec(),
        }),
    )
    .await?;
    let Some(Message::NamespaceHistoryObjectResult(result)) = response.as_inner().message.as_ref()
    else {
        return Err(NativeGatewaySyncError::Invalid);
    };
    let object = result
        .object
        .as_ref()
        .ok_or(NativeGatewaySyncError::Invalid)?;
    if object.format_version != RECORD_FORMAT_VERSION {
        return Err(NativeGatewaySyncError::Invalid);
    }
    NamespaceHistoryImmutableRecord::from_expected_digest(
        expected_digest,
        object.canonical_bytes.clone(),
    )
    .map_err(|_| NativeGatewaySyncError::Invalid)
}

fn complete_received_history(
    state_directory: &Path,
    session_id: [u8; 32],
    advertised: &AdvertisedHead,
) -> Result<(), NativeGatewaySyncError> {
    let now = current_time()?;
    let mut store = open_version_store(state_directory, now)?;
    store
        .complete_namespace_history_receive(session_id, now)
        .map_err(|_| NativeGatewaySyncError::Invalid)?;
    let actual_root = store
        .namespace_commit_root(advertised.volume_id, advertised.namespace_commit_id)
        .map_err(|_| NativeGatewaySyncError::Invalid)?;
    if actual_root != advertised.root_object_revision_id {
        return Err(NativeGatewaySyncError::Invalid);
    }
    Ok(())
}

fn adopt_received_head(
    local_node_id: NodeId,
    state_directory: &Path,
    advertised: &AdvertisedHead,
) -> Result<(), NativeGatewaySyncError> {
    let now = current_time()?;
    let mut store = open_version_store(state_directory, now)?;
    let branch_id = InitialBootstrapMaterial::local_branch_id(local_node_id)
        .map_err(|_| NativeGatewaySyncError::Unavailable)?;
    store
        .adopt_imported_namespace_head(
            branch_id,
            advertised.volume_id,
            advertised.namespace_commit_id,
            advertised.root_object_revision_id,
        )
        .map_err(|_| NativeGatewaySyncError::Invalid)?;
    Ok(())
}

async fn receive_content_layout(
    network: &ConsensusNetwork,
    state_directory: &Path,
    source: NodeId,
    volume_id: VolumeId,
    route: &ParsedContentRoute,
) -> Result<(), NativeGatewaySyncError> {
    validate_source_target(state_directory, source, route)?;
    let (contract, header) =
        import_layout_pages(network, state_directory, source, volume_id, route).await?;
    let now = current_time()?;
    open_catalog(state_directory, now)?
        .seal_layout_import(contract, header)
        .map_err(|_| NativeGatewaySyncError::Invalid)?;
    let now = current_time()?;
    if header.manifest.format_version == 2 {
        if header.chunk_count != 0 {
            import_protected_receipts(network, state_directory, source, contract, header, route)
                .await?;
        }
        open_catalog(state_directory, now)?
            .finish(contract, now)
            .map_err(|_| NativeGatewaySyncError::Invalid)?;
    } else {
        import_remote_routes(network, state_directory, source, contract, route).await?;
        let now = current_time()?;
        open_catalog(state_directory, now)?
            .finish_remote_layout_import(contract, now)
            .map_err(|_| NativeGatewaySyncError::Invalid)?;
    }
    Ok(())
}

async fn import_layout_pages(
    network: &ConsensusNetwork,
    state_directory: &Path,
    source: NodeId,
    volume_id: VolumeId,
    route: &ParsedContentRoute,
) -> Result<(ContentPublicationRequest, ContentLayoutTransferHeader), NativeGatewaySyncError> {
    let mut after_index = None;
    let mut expected_header = None;
    loop {
        let page = fetch_layout_page(network, source, route, after_index, 3).await?;
        let header = decode_layout_header(&page)?;
        if expected_header.is_some_and(|expected| expected != header) {
            return Err(NativeGatewaySyncError::Invalid);
        }
        expected_header = Some(header);
        let contract = import_contract(source, volume_id, route, header)?;
        let layout_page = if page.chunks.is_empty() {
            decode_receipts(&page, route)?;
            if header.chunk_count != 0
                || page.next_index.is_some()
                || !page.protected_stripes.is_empty()
            {
                return Err(NativeGatewaySyncError::Invalid);
            }
            None
        } else {
            Some(decode_layout_page(&page, route)?)
        };
        let now = current_time()?;
        let mut catalog = open_catalog(state_directory, now)?;
        catalog
            .begin_layout_import(contract, header)
            .map_err(|_| NativeGatewaySyncError::Invalid)?;
        if let Some(layout_page) = layout_page {
            catalog
                .append_layout_import_page(contract, header, &layout_page)
                .map_err(|_| NativeGatewaySyncError::Invalid)?;
            if header.manifest.format_version == 2 {
                let protected = decode_protected_stripes(&page, contract, header, &layout_page)?;
                catalog
                    .append_protected_layout_import_page(
                        contract,
                        &protected
                            .iter()
                            .map(|value| value.stripe.clone())
                            .collect::<Vec<_>>(),
                    )
                    .map_err(|_| NativeGatewaySyncError::Invalid)?;
            }
        }
        after_index = page.next_index;
        if after_index.is_none() {
            return Ok((contract, header));
        }
    }
}

async fn import_protected_receipts(
    network: &ConsensusNetwork,
    state_directory: &Path,
    source: NodeId,
    contract: ContentPublicationRequest,
    header: ContentLayoutTransferHeader,
    route: &ParsedContentRoute,
) -> Result<(), NativeGatewaySyncError> {
    let mut after_index = None;
    loop {
        let page = fetch_layout_page(network, source, route, after_index, 5).await?;
        if decode_layout_header(&page)? != header {
            return Err(NativeGatewaySyncError::Invalid);
        }
        let layout_page = decode_layout_page(&page, route)?;
        let protected = decode_protected_stripes(&page, contract, header, &layout_page)?;
        let now = current_time()?;
        let mut catalog = open_catalog(state_directory, now)?;
        for value in protected {
            for receipt in value.receipts.as_slice() {
                catalog
                    .record_protected_receipt(contract, *receipt, now)
                    .map_err(|_| NativeGatewaySyncError::Invalid)?;
            }
        }
        after_index = page.next_index;
        if after_index.is_none() {
            return Ok(());
        }
    }
}

async fn import_remote_routes(
    network: &ConsensusNetwork,
    state_directory: &Path,
    source: NodeId,
    contract: ContentPublicationRequest,
    route: &ParsedContentRoute,
) -> Result<(), NativeGatewaySyncError> {
    let mut after_index = None;
    loop {
        let page = fetch_layout_page(network, source, route, after_index, 4).await?;
        let receipts = decode_receipts(&page, route)?;
        let now = current_time()?;
        let mut catalog = open_catalog(state_directory, now)?;
        for (chunk_index, receipt) in receipts {
            catalog
                .record_remote_shard_route(contract, chunk_index, source, receipt, now)
                .map_err(|_| NativeGatewaySyncError::Invalid)?;
        }
        after_index = page.next_index;
        if after_index.is_none() {
            return Ok(());
        }
    }
}

async fn fetch_layout_page(
    network: &ConsensusNetwork,
    source: NodeId,
    route: &ParsedContentRoute,
    after_index: Option<u64>,
    purpose: u8,
) -> Result<NativeContentLayoutPage, NativeGatewaySyncError> {
    let response = request(
        network,
        source,
        &route.publication_operation_id.as_bytes(),
        purpose,
        &after_index.unwrap_or(u64::MAX).to_be_bytes(),
        Message::FetchNativeContentLayout(FetchNativeContentLayout {
            publication_operation_id: route.publication_operation_id.as_bytes().to_vec(),
            manifest_id: route.manifest_id.as_bytes().to_vec(),
            after_index,
            limit: PAGE_ITEMS,
        }),
    )
    .await?;
    let Some(Message::NativeContentLayoutPage(page)) = response.as_inner().message.as_ref() else {
        return Err(NativeGatewaySyncError::Invalid);
    };
    Ok(page.clone())
}

fn decode_layout_header(
    page: &NativeContentLayoutPage,
) -> Result<ContentLayoutTransferHeader, NativeGatewaySyncError> {
    decode_native_content_layout_header(
        page.header
            .as_ref()
            .ok_or(NativeGatewaySyncError::Invalid)?,
    )
    .map_err(|_| NativeGatewaySyncError::Invalid)
}

fn decode_layout_page(
    page: &NativeContentLayoutPage,
    route: &ParsedContentRoute,
) -> Result<ContentLayoutTransferPage, NativeGatewaySyncError> {
    if page.protected_stripes.is_empty() {
        decode_receipts(page, route)?;
    } else if !page.receipts.is_empty() || page.protected_stripes.len() != page.chunks.len() {
        return Err(NativeGatewaySyncError::Invalid);
    }
    let chunks = page
        .chunks
        .iter()
        .map(decode_native_content_layout_chunk)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| NativeGatewaySyncError::Invalid)?;
    ContentLayoutTransferPage::from_untrusted(chunks, page.next_index)
        .map_err(|_| NativeGatewaySyncError::Invalid)
}

fn decode_protected_stripes(
    page: &NativeContentLayoutPage,
    contract: ContentPublicationRequest,
    header: ContentLayoutTransferHeader,
    layout: &ContentLayoutTransferPage,
) -> Result<Vec<meshspan_filesystem::CommittedProtectedStripe>, NativeGatewaySyncError> {
    if page.protected_stripes.len() != layout.chunks().len() || !page.receipts.is_empty() {
        return Err(NativeGatewaySyncError::Invalid);
    }
    layout
        .chunks()
        .iter()
        .zip(&page.protected_stripes)
        .map(|(chunk, payload)| {
            let operation_id = provider_operation_id(contract.operation_id, chunk.chunk_index)
                .map_err(|_| NativeGatewaySyncError::Invalid)?;
            decode_native_protected_stripe(
                payload,
                contract,
                chunk.with_provider_operation(operation_id),
                header.manifest,
            )
            .map_err(|_| NativeGatewaySyncError::Invalid)
        })
        .collect()
}

fn decode_receipts(
    page: &NativeContentLayoutPage,
    route: &ParsedContentRoute,
) -> Result<Vec<(u64, meshspan_contracts::ShardReceipt)>, NativeGatewaySyncError> {
    if page.chunks.len() != page.receipts.len() {
        return Err(NativeGatewaySyncError::Invalid);
    }
    page.receipts
        .iter()
        .map(|payload| {
            let receipt = decode_native_shard_receipt(payload)
                .map_err(|_| NativeGatewaySyncError::Invalid)?;
            if receipt.target_id != route.target_id
                || receipt.target_generation != route.target_generation
            {
                return Err(NativeGatewaySyncError::Invalid);
            }
            Ok((receipt.shard.stripe_index, receipt))
        })
        .collect()
}

fn import_contract(
    source: NodeId,
    volume_id: VolumeId,
    route: &ParsedContentRoute,
    header: ContentLayoutTransferHeader,
) -> Result<ContentPublicationRequest, NativeGatewaySyncError> {
    if header.manifest.manifest_id != route.manifest_id {
        return Err(NativeGatewaySyncError::Invalid);
    }
    let mut digest = Sha256::new();
    digest.update(b"meshspan.native.layout-import.v1\0");
    digest.update(source.as_bytes());
    digest.update(volume_id.as_bytes());
    digest.update(route.publication_operation_id.as_bytes());
    digest.update(header.digest());
    Ok(ContentPublicationRequest {
        operation_id: route.publication_operation_id,
        volume_id,
        request_digest: digest.finalize().into(),
        manifest_id: route.manifest_id,
        format_version: header.manifest.format_version,
        logical_length: header.manifest.logical_length,
        authorization_revision: Revision::new(1),
        deadline: UnixMicros::new(i64::MAX),
        observed_at: current_time()?,
    })
}

fn validate_source_target(
    state_directory: &Path,
    source: NodeId,
    route: &ParsedContentRoute,
) -> Result<(), NativeGatewaySyncError> {
    let now = current_time()?;
    let database =
        PartitionDatabase::open_existing(&state_directory.join("root-authority.sqlite3"), now)
            .map_err(|_| NativeGatewaySyncError::Unavailable)?;
    let repository = AuthoritativeRepository::new(database);
    let context = repository
        .storage_target_provider_context_by_target(route.target_id)
        .map_err(|_| NativeGatewaySyncError::Unavailable)?
        .ok_or(NativeGatewaySyncError::Invalid)?;
    if context.node_id == source && context.generation == route.target_generation {
        Ok(())
    } else {
        Err(NativeGatewaySyncError::Invalid)
    }
}

async fn request(
    network: &ConsensusNetwork,
    source: NodeId,
    operation_scope: &[u8],
    purpose: u8,
    page_scope: &[u8],
    message: Message,
) -> Result<meshspan_protocol::ValidatedControlEnvelope, NativeGatewaySyncError> {
    let deadline = current_time()?
        .get()
        .checked_add(REQUEST_TIMEOUT_MICROS)
        .ok_or(NativeGatewaySyncError::Invalid)?;
    let operation_id = request_operation_id(operation_scope, purpose, page_scope)?;
    network
        .request_control(
            source,
            &ControlEnvelope {
                header: Some(network.control_header(operation_id, deadline)?),
                message: Some(message),
            },
        )
        .await
        .map_err(Into::into)
}

fn request_operation_id(
    operation_scope: &[u8],
    purpose: u8,
    page_scope: &[u8],
) -> Result<OperationId, NativeGatewaySyncError> {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.native.gateway-request.v1\0");
    digest.update(operation_scope);
    digest.update([purpose]);
    digest.update(page_scope);
    let bytes: [u8; 32] = digest.finalize().into();
    let mut identity = [0_u8; 16];
    identity.copy_from_slice(&bytes[..16]);
    OperationId::from_bytes(meshspan_domain::uuid_v8(identity))
        .map_err(|_| NativeGatewaySyncError::Unavailable)
}

fn receive_session_id(
    local: NodeId,
    source: NodeId,
    publish_operation_id: OperationId,
    head: &AdvertisedHead,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.native.gateway-receive.v1\0");
    digest.update(local.as_bytes());
    digest.update(source.as_bytes());
    digest.update(publish_operation_id.as_bytes());
    digest.update(head.volume_id.as_bytes());
    digest.update(head.namespace_commit_id.as_bytes());
    digest.finalize().into()
}

fn open_version_store(
    state_directory: &Path,
    now: UnixMicros,
) -> Result<VersionPublicationStore, NativeGatewaySyncError> {
    VersionPublicationStore::open(&state_directory.join("filesystem"), now)
        .map_err(|_| NativeGatewaySyncError::Unavailable)
}

fn open_catalog(
    state_directory: &Path,
    now: UnixMicros,
) -> Result<DurableContentCatalog, NativeGatewaySyncError> {
    DurableContentCatalog::open(&state_directory.join("filesystem"), now)
        .map_err(|_| NativeGatewaySyncError::Unavailable)
}

fn current_time() -> Result<UnixMicros, NativeGatewaySyncError> {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_micros()).ok())
        .ok_or(NativeGatewaySyncError::Unavailable)?;
    Ok(UnixMicros::new(micros))
}

pub(super) fn accepted(result_digest: [u8; 32]) -> Message {
    Message::NamespaceHeadAccepted(meshspan_protocol::v1::NamespaceHeadAccepted {
        result: Some(OperationResult {
            outcome: OperationOutcome::Durable.into(),
            committed_revision: None,
            error: None,
            result: None,
            result_digest: result_digest.to_vec(),
        }),
    })
}
