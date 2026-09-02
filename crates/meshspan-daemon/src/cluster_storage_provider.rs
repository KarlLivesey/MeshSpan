// SPDX-License-Identifier: GPL-2.0-only

//! Local-write and authenticated remote-read composition for native gateway content.

use std::sync::Arc;

use meshspan_contracts::{
    BoundedBytes, ContractError, ImplementationDescriptor, InventoryEntry, InventoryPage,
    PutShardRequest, ReclamationReceipt, RemovalAuthorityFence, RemovalPermit, RequestContext,
    ReserveStorageRequest, ScrubObservation, ScrubPage, ShardIdentity, ShardReadPermit,
    ShardReceipt, StorageProvider, StorageReservation, TombstoneReceipt,
};
use meshspan_domain::{TargetId, UnixMicros};
use meshspan_metadata::AuthoritativeRepository;
use meshspan_protocol::v1::ErrorCode;

use crate::LocalFolderStorageProvider;
use crate::native_filesystem_runtime::MAXIMUM_NATIVE_SHARD_BYTES;
use crate::private_consensus_runtime::PrivateConsensusRuntime;

/// Provider boundary which keeps writes target-local and resolves remote immutable reads by
/// replicated target ownership over the mesh's existing authenticated QUIC network.
pub(crate) struct ClusterStorageProvider {
    local: LocalFolderStorageProvider,
    local_target_id: TargetId,
    local_target_generation: u64,
    authority: AuthoritativeRepository,
    network: Arc<PrivateConsensusRuntime>,
    runtime: tokio::runtime::Handle,
}

impl ClusterStorageProvider {
    /// Binds one local placement target to current replicated routing authority.
    #[must_use]
    pub(crate) const fn new(
        local: LocalFolderStorageProvider,
        local_target_id: TargetId,
        local_target_generation: u64,
        authority: AuthoritativeRepository,
        network: Arc<PrivateConsensusRuntime>,
        runtime: tokio::runtime::Handle,
    ) -> Self {
        Self {
            local,
            local_target_id,
            local_target_generation,
            authority,
            network,
            runtime,
        }
    }

    fn is_local(&self, target_id: TargetId, target_generation: u64) -> bool {
        target_id == self.local_target_id && target_generation == self.local_target_generation
    }

    fn remote_get(
        &self,
        context: RequestContext,
        permit: ShardReadPermit,
    ) -> Result<BoundedBytes, ContractError> {
        let route = self
            .authority
            .storage_target_provider_context_by_target(permit.target_id)
            .map_err(|_| ContractError::Unavailable)?
            .ok_or(ContractError::Unavailable)?;
        if route.mesh_id != permit.mesh_id || route.generation != permit.target_generation {
            return Err(ContractError::Stale);
        }
        let network = self
            .network
            .network()
            .map_err(|()| ContractError::Unavailable)?;
        let header = network
            .control_header(context.operation_id, context.deadline.get())
            .map_err(|_| ContractError::InvalidInput)?;
        let connection = self
            .runtime
            .block_on(network.connect_data_peer(route.node_id))
            .map_err(|_| ContractError::Unavailable)?;
        self.runtime
            .block_on(meshspan_data_plane::get_shard(
                &connection,
                header,
                permit,
                MAXIMUM_NATIVE_SHARD_BYTES,
                network.wire_limits(),
            ))
            .map_err(|error| map_data_plane_error(&error))
    }
}

impl StorageProvider for ClusterStorageProvider {
    fn describe(&self) -> ImplementationDescriptor {
        self.local.describe()
    }

    fn reserve(
        &mut self,
        request: ReserveStorageRequest,
    ) -> Result<StorageReservation, ContractError> {
        self.local.reserve(request)
    }

    fn put_exact(
        &mut self,
        request: PutShardRequest,
        observed_at: UnixMicros,
    ) -> Result<ShardReceipt, ContractError> {
        self.local.put_exact(request, observed_at)
    }

    fn get_exact(
        &self,
        context: RequestContext,
        permit: ShardReadPermit,
        observed_at: UnixMicros,
    ) -> Result<BoundedBytes, ContractError> {
        if self.is_local(permit.target_id, permit.target_generation) {
            self.local.get_exact(context, permit, observed_at)
        } else {
            self.remote_get(context, permit)
        }
    }

    fn removal_authority_fence(&self) -> RemovalAuthorityFence {
        self.local.removal_authority_fence()
    }

    fn tombstone(
        &mut self,
        permit: RemovalPermit,
        observed_at: UnixMicros,
    ) -> Result<TombstoneReceipt, ContractError> {
        self.local.tombstone(permit, observed_at)
    }

    fn unlink_tombstoned(
        &mut self,
        receipt: TombstoneReceipt,
        observed_at: UnixMicros,
    ) -> Result<ReclamationReceipt, ContractError> {
        self.local.unlink_tombstoned(receipt, observed_at)
    }

    fn inventory(
        &self,
        cursor: Option<&BoundedBytes>,
        limit: usize,
    ) -> Result<InventoryPage, ContractError> {
        self.local.inventory(cursor, limit)
    }

    fn inventory_exact(
        &self,
        shard: ShardIdentity,
    ) -> Result<Option<InventoryEntry>, ContractError> {
        self.local.inventory_exact(shard)
    }

    fn scrub_exact(
        &mut self,
        expected: InventoryEntry,
        observed_at: UnixMicros,
    ) -> Result<ScrubObservation, ContractError> {
        self.local.scrub_exact(expected, observed_at)
    }

    fn scrub(
        &mut self,
        cursor: Option<&BoundedBytes>,
        limit: usize,
        observed_at: UnixMicros,
    ) -> Result<ScrubPage, ContractError> {
        self.local.scrub(cursor, limit, observed_at)
    }
}

fn map_data_plane_error(error: &meshspan_data_plane::DataPlaneError) -> ContractError {
    match error {
        meshspan_data_plane::DataPlaneError::Contract(error) => *error,
        meshspan_data_plane::DataPlaneError::Remote(code) => match code {
            ErrorCode::Invalid => ContractError::InvalidInput,
            ErrorCode::Unauthorised => ContractError::Unauthorized,
            ErrorCode::Stale => ContractError::Stale,
            ErrorCode::Conflict => ContractError::Conflict,
            ErrorCode::Unsupported => ContractError::UnsupportedVersion,
            ErrorCode::Exhausted => ContractError::ResourceExhausted,
            ErrorCode::Corrupt => ContractError::Corrupt,
            ErrorCode::Deadline => ContractError::DeadlineExceeded,
            ErrorCode::NotFound => ContractError::NotFound,
            ErrorCode::Unavailable => ContractError::Unavailable,
            ErrorCode::InternalContract | ErrorCode::Unspecified => ContractError::InternalContract,
        },
        meshspan_data_plane::DataPlaneError::InvalidConfiguration
        | meshspan_data_plane::DataPlaneError::Transport(_) => ContractError::Unavailable,
        meshspan_data_plane::DataPlaneError::Capability(_)
        | meshspan_data_plane::DataPlaneError::InvalidMessage => ContractError::InternalContract,
    }
}
