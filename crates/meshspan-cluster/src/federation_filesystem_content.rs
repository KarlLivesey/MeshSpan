// SPDX-License-Identifier: GPL-2.0-only

//! Filesystem-backed federated content-layout paging on a designated blocking worker.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use meshspan_contracts::{
    BoundedItems, ContractError, ContractVersion, RequestContext, ShardReadPermit,
    StoragePermitMacKey, StorageProvider, read_permit_mac,
};
use meshspan_domain::{MeshId, NodeId, TargetId};
use meshspan_filesystem::{
    ContentCatalogError, DurableContentCatalog, NamespaceHistoryImmutableKind,
    NamespaceHistoryObjectRequest, PublicationError, VersionPublicationStore,
};

use crate::federation_branch_page_source::grant_allows_history_read;
use crate::federation_filesystem_history::authority_binding;
use crate::{
    FederationContentLayoutFuture, FederationContentLayoutQuery, FederationContentLayoutRecords,
    FederationContentLayoutSource, FederationContentLayoutSourceError, FederationContentShard,
    FederationContentShardFuture, FederationContentShardQuery, FederationContentShardSource,
    FederationContentShardSourceError,
};

/// Exact local provider route and byte bound exposed by one shard source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationContentShardProviderBinding {
    /// Owning swarm whose local storage capability signs the provider read.
    pub mesh_id: MeshId,
    /// Exact local node serving the provider target.
    pub provider_node_id: NodeId,
    /// Exact local storage target.
    pub target_id: TargetId,
    /// Positive target-incarnation fence.
    pub target_generation: u64,
    /// Hard upper bound for one encrypted shard allocation.
    pub maximum_shard_bytes: usize,
}

/// Filesystem catalogue plus one provider-local target capable of serving its committed shards.
pub struct FilesystemFederationContentShardSource<P> {
    state_directory: PathBuf,
    provider: Arc<Mutex<P>>,
    binding: FederationContentShardProviderBinding,
    permit_key: Arc<StoragePermitMacKey>,
}

impl<P> FilesystemFederationContentShardSource<P> {
    /// Composes durable manifest evidence with one exact provider target and private permit key.
    ///
    /// # Errors
    ///
    /// Rejects an invalid target generation or zero byte bound before the source is exposed.
    pub fn new(
        state_directory: impl Into<PathBuf>,
        provider: P,
        binding: FederationContentShardProviderBinding,
        permit_key: StoragePermitMacKey,
    ) -> Result<Self, FederationContentShardSourceError> {
        if binding.target_generation == 0 || binding.maximum_shard_bytes == 0 {
            return Err(FederationContentShardSourceError::InvalidQuery);
        }
        Ok(Self {
            state_directory: state_directory.into(),
            provider: Arc::new(Mutex::new(provider)),
            binding,
            permit_key: Arc::new(permit_key),
        })
    }
}

impl<P: StorageProvider + Send + 'static> FederationContentShardSource
    for FilesystemFederationContentShardSource<P>
{
    fn content_shard(
        &self,
        query: FederationContentShardQuery,
    ) -> FederationContentShardFuture<'_> {
        let state_directory = self.state_directory.clone();
        let provider = Arc::clone(&self.provider);
        let binding = self.binding;
        let permit_key = Arc::clone(&self.permit_key);
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                load_shard(
                    &state_directory,
                    provider.as_ref(),
                    binding,
                    permit_key.as_ref(),
                    &query,
                )
            })
            .await
            .map_err(|_| FederationContentShardSourceError::Unavailable)?
        })
    }
}

/// Opens daemon-owned namespace and content catalogues per request after external admission.
#[derive(Clone, Debug)]
pub struct FilesystemFederationContentSource {
    state_directory: PathBuf,
}

impl FilesystemFederationContentSource {
    /// Selects the daemon-owned filesystem state directory.
    #[must_use]
    pub fn new(state_directory: impl Into<PathBuf>) -> Self {
        Self {
            state_directory: state_directory.into(),
        }
    }

    /// Returns the selected daemon-owned state directory.
    #[must_use]
    pub fn state_directory(&self) -> &Path {
        &self.state_directory
    }
}

impl FederationContentLayoutSource for FilesystemFederationContentSource {
    fn content_layout(
        &self,
        query: FederationContentLayoutQuery,
    ) -> FederationContentLayoutFuture<'_> {
        let state_directory = self.state_directory.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || load_layout(&state_directory, &query))
                .await
                .map_err(|_| FederationContentLayoutSourceError::Unavailable)?
        })
    }
}

fn load_layout(
    state_directory: &Path,
    query: &FederationContentLayoutQuery,
) -> Result<FederationContentLayoutRecords, FederationContentLayoutSourceError> {
    validate_query(query)?;
    let namespace = VersionPublicationStore::open(state_directory, query.now)
        .map_err(|error| map_publication_error(&error))?;
    let advertised = namespace
        .namespace_history_object(NamespaceHistoryObjectRequest {
            scope_binding: authority_binding(&query.authority, query.resource),
            export_token: query.export_token,
            object_digest: query.manifest_object_digest,
            now: query.now,
        })
        .map_err(|error| map_publication_error(&error))?;
    if advertised.kind() != NamespaceHistoryImmutableKind::Manifest {
        return Err(FederationContentLayoutSourceError::InvalidQuery);
    }
    let advertised_manifest = advertised
        .as_manifest()
        .map_err(|_| FederationContentLayoutSourceError::Corrupt)?
        .ok_or(FederationContentLayoutSourceError::Corrupt)?;
    if advertised_manifest.manifest_id != query.manifest_id {
        return Err(FederationContentLayoutSourceError::InvalidQuery);
    }

    let catalog = DurableContentCatalog::open(state_directory, query.now)
        .map_err(|error| map_catalog_error(&error))?;
    let content = catalog
        .committed_content_by_manifest(query.manifest_id)
        .map_err(|error| map_catalog_error(&error))?
        .ok_or(FederationContentLayoutSourceError::Unavailable)?;
    if content.manifest != advertised_manifest {
        return Err(FederationContentLayoutSourceError::Corrupt);
    }
    let transfer = catalog
        .committed_layout_transfer(content)
        .map_err(|error| map_catalog_error(&error))?;
    let header = transfer.header();
    let (page, placements) = if header.chunk_count == 0 {
        if query.after_index.is_some() {
            return Err(FederationContentLayoutSourceError::InvalidQuery);
        }
        (
            None,
            BoundedItems::new(Vec::new(), query.limit)
                .map_err(|_| FederationContentLayoutSourceError::Corrupt)?,
        )
    } else {
        let page = transfer
            .page(query.after_index, query.limit)
            .map_err(|error| map_catalog_error(&error))?;
        let placements = catalog
            .committed_shard_inventory(content)
            .map_err(|error| map_catalog_error(&error))?
            .page(query.after_index, query.limit)
            .map_err(|error| map_catalog_error(&error))?
            .shards;
        validate_layout_placements(header.manifest.root_digest, &page, &placements)?;
        (Some(page), placements)
    };
    Ok(FederationContentLayoutRecords {
        header,
        page,
        placements,
    })
}

fn validate_layout_placements(
    manifest_digest: [u8; 32],
    page: &meshspan_filesystem::ContentLayoutTransferPage,
    placements: &BoundedItems<meshspan_contracts::ShardReceipt>,
) -> Result<(), FederationContentLayoutSourceError> {
    if page.chunks().len() != placements.len() {
        return Err(FederationContentLayoutSourceError::Corrupt);
    }
    let exact = page
        .chunks()
        .iter()
        .zip(placements.as_slice())
        .all(|(chunk, receipt)| {
            receipt.shard.manifest_digest == manifest_digest
                && receipt.shard.stripe_index == chunk.chunk_index
                && receipt.shard.shard_index == 0
                && receipt.shard.generation == 1
                && receipt.length == chunk.ciphertext_length
                && receipt.digest == chunk.ciphertext_digest
        });
    if exact {
        Ok(())
    } else {
        Err(FederationContentLayoutSourceError::Corrupt)
    }
}

fn load_shard<P: StorageProvider>(
    state_directory: &Path,
    provider: &Mutex<P>,
    binding: FederationContentShardProviderBinding,
    permit_key: &StoragePermitMacKey,
    query: &FederationContentShardQuery,
) -> Result<FederationContentShard, FederationContentShardSourceError> {
    validate_shard_query(binding, query)?;
    let namespace = VersionPublicationStore::open(state_directory, query.now)
        .map_err(|error| map_shard_publication_error(&error))?;
    let advertised = namespace
        .namespace_history_object(NamespaceHistoryObjectRequest {
            scope_binding: authority_binding(&query.authority, query.resource),
            export_token: query.export_token,
            object_digest: query.manifest_object_digest,
            now: query.now,
        })
        .map_err(|error| map_shard_publication_error(&error))?;
    let manifest = advertised
        .as_manifest()
        .map_err(|_| FederationContentShardSourceError::Corrupt)?
        .filter(|manifest| manifest.manifest_id == query.manifest_id)
        .ok_or(FederationContentShardSourceError::InvalidQuery)?;
    let catalog = DurableContentCatalog::open(state_directory, query.now)
        .map_err(|error| map_shard_catalog_error(&error))?;
    let content = catalog
        .committed_content_by_manifest(query.manifest_id)
        .map_err(|error| map_shard_catalog_error(&error))?
        .ok_or(FederationContentShardSourceError::Unavailable)?;
    if content.manifest != manifest {
        return Err(FederationContentShardSourceError::Corrupt);
    }
    validate_committed_shard(&catalog, content, query)?;
    let request_context = RequestContext {
        contract_version: ContractVersion::V1_0,
        operation_id: query.operation_id,
        deadline: query.deadline,
        expected_revision: Some(query.authority.local_grant_revision),
    };
    let mut permit = ShardReadPermit {
        operation_id: query.operation_id,
        mesh_id: binding.mesh_id,
        target_id: binding.target_id,
        target_generation: binding.target_generation,
        shard: query.shard,
        authorization_revision: query.authority.local_grant_revision,
        expires_at: query.deadline,
        permit_digest: [0; 32],
    };
    permit.permit_digest = read_permit_mac(permit_key, permit);
    let provider = provider
        .lock()
        .map_err(|_| FederationContentShardSourceError::Unavailable)?;
    let bytes = provider
        .get_exact(request_context, permit, query.now)
        .map_err(map_provider_error)?;
    let exact = u64::try_from(bytes.len()).ok() == Some(query.expected_length)
        && blake3::hash(bytes.as_slice()).as_bytes() == &query.expected_digest;
    if exact {
        Ok(FederationContentShard { bytes })
    } else {
        Err(FederationContentShardSourceError::Corrupt)
    }
}

fn validate_shard_query(
    binding: FederationContentShardProviderBinding,
    query: &FederationContentShardQuery,
) -> Result<(), FederationContentShardSourceError> {
    let grant = &query.authority.grant;
    let length = usize::try_from(query.expected_length).ok();
    let valid = grant.resource() == query.resource
        && grant_allows_history_read(&query.authority)
        && query.now >= grant.valid_from()
        && grant
            .valid_until()
            .is_none_or(|expiry| query.now < expiry && query.deadline <= expiry)
        && query.deadline > query.now
        && query.provider_node_id == binding.provider_node_id
        && query.target_id == binding.target_id
        && query.target_generation == binding.target_generation
        && query.expected_digest != [0; 32]
        && length.is_some_and(|length| length > 0 && length <= binding.maximum_shard_bytes);
    if valid {
        Ok(())
    } else {
        Err(FederationContentShardSourceError::InvalidQuery)
    }
}

fn validate_committed_shard(
    catalog: &DurableContentCatalog,
    content: meshspan_filesystem::PublishedContentReference,
    query: &FederationContentShardQuery,
) -> Result<(), FederationContentShardSourceError> {
    let chunk_index = query.shard.stripe_index;
    let valid_identity = query.shard.manifest_digest == content.manifest.root_digest
        && query.shard.shard_index == 0
        && query.shard.generation == 1;
    if !valid_identity {
        return Err(FederationContentShardSourceError::InvalidQuery);
    }
    let after_index = chunk_index.checked_sub(1);
    let layout = catalog
        .committed_layout_transfer(content)
        .map_err(|error| map_shard_catalog_error(&error))?;
    let layout_page = layout
        .page(after_index, 1)
        .map_err(|error| map_shard_catalog_error(&error))?;
    let chunk = layout_page
        .chunks()
        .first()
        .filter(|chunk| chunk.chunk_index == chunk_index)
        .ok_or(FederationContentShardSourceError::InvalidQuery)?;
    let inventory = catalog
        .committed_shard_inventory(content)
        .map_err(|error| map_shard_catalog_error(&error))?;
    let receipt_page = inventory
        .page(after_index, 1)
        .map_err(|error| map_shard_catalog_error(&error))?;
    let receipt = receipt_page
        .shards
        .as_slice()
        .first()
        .filter(|receipt| receipt.shard == query.shard)
        .ok_or(FederationContentShardSourceError::Corrupt)?;
    let exact = chunk.ciphertext_length == query.expected_length
        && chunk.ciphertext_digest == query.expected_digest
        && receipt.target_id == query.target_id
        && receipt.target_generation == query.target_generation
        && receipt.length == query.expected_length
        && receipt.digest == query.expected_digest;
    if exact {
        Ok(())
    } else {
        Err(FederationContentShardSourceError::Corrupt)
    }
}

fn validate_query(
    query: &FederationContentLayoutQuery,
) -> Result<(), FederationContentLayoutSourceError> {
    let grant = &query.authority.grant;
    if grant.resource() != query.resource
        || !grant_allows_history_read(&query.authority)
        || query.now < grant.valid_from()
        || grant
            .valid_until()
            .is_some_and(|expiry| query.now >= expiry)
        || query.limit == 0
    {
        Err(FederationContentLayoutSourceError::InvalidQuery)
    } else {
        Ok(())
    }
}

const fn map_publication_error(error: &PublicationError) -> FederationContentLayoutSourceError {
    match error {
        PublicationError::InvalidInput => FederationContentLayoutSourceError::InvalidQuery,
        PublicationError::Io(_) | PublicationError::Sqlite(_) | PublicationError::InjectedFault => {
            FederationContentLayoutSourceError::Unavailable
        }
        PublicationError::StaleHead
        | PublicationError::OperationConflict
        | PublicationError::CleanupFenced
        | PublicationError::Corrupt
        | PublicationError::Directory(_) => FederationContentLayoutSourceError::Corrupt,
    }
}

const fn map_catalog_error(error: &ContentCatalogError) -> FederationContentLayoutSourceError {
    match error {
        ContentCatalogError::InvalidInput | ContentCatalogError::Conflict => {
            FederationContentLayoutSourceError::InvalidQuery
        }
        ContentCatalogError::Incomplete
        | ContentCatalogError::Io(_)
        | ContentCatalogError::Sqlite(_) => FederationContentLayoutSourceError::Unavailable,
        ContentCatalogError::Corrupt => FederationContentLayoutSourceError::Corrupt,
    }
}

const fn map_shard_publication_error(
    error: &PublicationError,
) -> FederationContentShardSourceError {
    match map_publication_error(error) {
        FederationContentLayoutSourceError::InvalidQuery => {
            FederationContentShardSourceError::InvalidQuery
        }
        FederationContentLayoutSourceError::Unavailable => {
            FederationContentShardSourceError::Unavailable
        }
        FederationContentLayoutSourceError::Corrupt => FederationContentShardSourceError::Corrupt,
    }
}

const fn map_shard_catalog_error(error: &ContentCatalogError) -> FederationContentShardSourceError {
    match map_catalog_error(error) {
        FederationContentLayoutSourceError::InvalidQuery => {
            FederationContentShardSourceError::InvalidQuery
        }
        FederationContentLayoutSourceError::Unavailable => {
            FederationContentShardSourceError::Unavailable
        }
        FederationContentLayoutSourceError::Corrupt => FederationContentShardSourceError::Corrupt,
    }
}

const fn map_provider_error(error: ContractError) -> FederationContentShardSourceError {
    match error {
        ContractError::InvalidInput
        | ContractError::Unauthorized
        | ContractError::Stale
        | ContractError::Conflict
        | ContractError::UnsupportedVersion
        | ContractError::NotFound
        | ContractError::ResourceExhausted
        | ContractError::DeadlineExceeded => FederationContentShardSourceError::InvalidQuery,
        ContractError::Corrupt | ContractError::InternalContract => {
            FederationContentShardSourceError::Corrupt
        }
        ContractError::Unavailable => FederationContentShardSourceError::Unavailable,
    }
}
