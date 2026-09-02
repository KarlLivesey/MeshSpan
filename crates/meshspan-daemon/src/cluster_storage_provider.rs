// SPDX-License-Identifier: GPL-2.0-only

//! Local-write and authenticated remote-read composition for native gateway content.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use meshspan_contracts::{
    BoundedBytes, ContractError, PutShardRequest, RequestContext, ReserveStorageRequest,
    ShardReadPermit, ShardReceipt, ShardWritePermit, StoragePermitMacKey, StorageProvider,
    StorageReservation, write_permit_mac,
};
use meshspan_domain::{MeshId, TargetId, UnixMicros};
use meshspan_filesystem::ContentShardRouter;
use meshspan_metadata::{AuthoritativeRepository, StorageTargetProviderContext};
use meshspan_protocol::v1::ErrorCode;

use crate::LocalFolderStorageProvider;
use crate::native_filesystem_runtime::MAXIMUM_NATIVE_SHARD_BYTES;
use crate::private_consensus_runtime::PrivateConsensusRuntime;

/// Target-aware protected-content route over every local folder and authenticated remote peers.
pub(crate) struct ClusterShardRouter {
    mesh_id: MeshId,
    locals: BTreeMap<TargetId, (u64, LocalFolderStorageProvider)>,
    writable_targets: BTreeSet<TargetId>,
    permit_key: StoragePermitMacKey,
    authority: AuthoritativeRepository,
    network: Arc<PrivateConsensusRuntime>,
    runtime: tokio::runtime::Handle,
}

impl ClusterShardRouter {
    /// Binds the current local providers and replicated routing authority.
    #[must_use]
    pub(crate) fn new(
        mesh_id: MeshId,
        locals: impl IntoIterator<Item = (StorageTargetProviderContext, LocalFolderStorageProvider)>,
        writable_targets: impl IntoIterator<Item = TargetId>,
        permit_key: StoragePermitMacKey,
        authority: AuthoritativeRepository,
        network: Arc<PrivateConsensusRuntime>,
        runtime: tokio::runtime::Handle,
    ) -> Self {
        Self {
            mesh_id,
            locals: locals
                .into_iter()
                .map(|(context, provider)| (context.target_id, (context.generation, provider)))
                .collect(),
            writable_targets: writable_targets.into_iter().collect(),
            permit_key,
            authority,
            network,
            runtime,
        }
    }

    fn local(&self, target_id: TargetId, generation: u64) -> Option<&LocalFolderStorageProvider> {
        self.locals
            .get(&target_id)
            .filter(|(current, _)| *current == generation)
            .map(|(_, provider)| provider)
    }

    fn writable_local_mut(
        &mut self,
        target_id: TargetId,
        generation: u64,
    ) -> Option<&mut LocalFolderStorageProvider> {
        if !self.writable_targets.contains(&target_id) {
            return None;
        }
        self.locals
            .get_mut(&target_id)
            .filter(|(current, _)| *current == generation)
            .map(|(_, provider)| provider)
    }

    fn writable_route(
        &self,
        target_id: TargetId,
        generation: u64,
    ) -> Result<StorageTargetProviderContext, ContractError> {
        let route = self
            .authority
            .storage_target_provider_context_by_target(target_id)
            .map_err(|_| ContractError::Unavailable)?
            .ok_or(ContractError::Unavailable)?;
        if route.mesh_id != self.mesh_id || route.generation != generation {
            Err(ContractError::Stale)
        } else {
            Ok(route)
        }
    }

    fn readable_route(
        &self,
        target_id: TargetId,
        generation: u64,
    ) -> Result<StorageTargetProviderContext, ContractError> {
        let route = self
            .authority
            .readable_storage_target_provider_context_by_target(target_id)
            .map_err(|_| ContractError::Unavailable)?
            .ok_or(ContractError::Unavailable)?;
        if route.mesh_id != self.mesh_id || route.generation != generation {
            Err(ContractError::Stale)
        } else {
            Ok(route)
        }
    }

    fn remote_reservation(
        &self,
        request: ReserveStorageRequest,
    ) -> Result<StorageReservation, ContractError> {
        self.writable_route(request.target_id, request.target_generation)?;
        if request.bytes == 0
            || request.context.deadline <= request.observed_at
            || request.context.expected_revision.is_none()
        {
            return Err(ContractError::InvalidInput);
        }
        let mut reservation = StorageReservation {
            operation_id: request.context.operation_id,
            target_id: request.target_id,
            target_generation: request.target_generation,
            class: request.class,
            maximum_bytes: request.bytes,
            expires_at: request.context.deadline,
            reservation_digest: [0; 32],
        };
        reservation.reservation_digest = routed_reservation_digest(reservation);
        Ok(reservation)
    }

    fn remote_put(&self, request: &PutShardRequest) -> Result<ShardReceipt, ContractError> {
        let authorization_revision = request
            .context
            .expected_revision
            .ok_or(ContractError::InvalidInput)?;
        if request.reservation.reservation_digest != routed_reservation_digest(request.reservation)
            || request.context.operation_id != request.reservation.operation_id
            || request.context.deadline > request.reservation.expires_at
            || request.expected_length == 0
            || request.expected_length > request.reservation.maximum_bytes
            || usize::try_from(request.expected_length).ok() != Some(request.bytes.len())
            || blake3::hash(request.bytes.as_slice()).as_bytes() != &request.expected_digest
        {
            return Err(ContractError::InvalidInput);
        }
        let route = self.writable_route(
            request.reservation.target_id,
            request.reservation.target_generation,
        )?;
        let mut permit = ShardWritePermit {
            operation_id: request.context.operation_id,
            mesh_id: self.mesh_id,
            target_id: request.reservation.target_id,
            target_generation: request.reservation.target_generation,
            shard: request.shard,
            reservation_class: request.reservation.class,
            maximum_bytes: request.reservation.maximum_bytes,
            authorization_revision,
            expires_at: request.reservation.expires_at,
            permit_digest: [0; 32],
        };
        permit.permit_digest = write_permit_mac(&self.permit_key, permit);
        let network = self
            .network
            .network()
            .map_err(|()| ContractError::Unavailable)?;
        let header = network
            .control_header(request.context.operation_id, request.context.deadline.get())
            .map_err(|_| ContractError::InvalidInput)?;
        let connection = self
            .runtime
            .block_on(network.connect_data_peer(route.node_id))
            .map_err(|_| ContractError::Unavailable)?;
        self.runtime
            .block_on(meshspan_data_plane::put_shard(
                &connection,
                header,
                permit,
                &request.bytes,
                network.wire_limits(),
            ))
            .map_err(|error| map_data_plane_error(&error))
    }

    fn remote_get(
        &self,
        context: RequestContext,
        permit: ShardReadPermit,
    ) -> Result<BoundedBytes, ContractError> {
        let route = self.readable_route(permit.target_id, permit.target_generation)?;
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

impl ContentShardRouter for ClusterShardRouter {
    fn read_priority(&self, target_id: TargetId, generation: u64) -> u8 {
        u8::from(self.local(target_id, generation).is_none())
    }

    fn reserve(
        &mut self,
        request: ReserveStorageRequest,
    ) -> Result<StorageReservation, ContractError> {
        match self.writable_local_mut(request.target_id, request.target_generation) {
            Some(provider) => StorageProvider::reserve(provider, request),
            None => self.remote_reservation(request),
        }
    }

    fn put_exact(
        &mut self,
        request: PutShardRequest,
        observed_at: UnixMicros,
    ) -> Result<ShardReceipt, ContractError> {
        match self.writable_local_mut(
            request.reservation.target_id,
            request.reservation.target_generation,
        ) {
            Some(provider) => StorageProvider::put_exact(provider, request, observed_at),
            None => self.remote_put(&request),
        }
    }

    fn get_exact(
        &self,
        context: RequestContext,
        permit: ShardReadPermit,
        observed_at: UnixMicros,
    ) -> Result<BoundedBytes, ContractError> {
        match self.local(permit.target_id, permit.target_generation) {
            Some(provider) => StorageProvider::get_exact(provider, context, permit, observed_at),
            None => self.remote_get(context, permit),
        }
    }
}

fn routed_reservation_digest(reservation: StorageReservation) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.daemon.routed-storage-reservation.v1\0");
    digest.update(&reservation.operation_id.as_bytes());
    digest.update(&reservation.target_id.as_bytes());
    digest.update(&reservation.target_generation.to_be_bytes());
    digest.update(&[match reservation.class {
        meshspan_contracts::ReservationClass::ForegroundWrite => 1,
        meshspan_contracts::ReservationClass::Repair => 2,
        meshspan_contracts::ReservationClass::Relocation => 3,
    }]);
    digest.update(&reservation.maximum_bytes.to_be_bytes());
    digest.update(&reservation.expires_at.get().to_be_bytes());
    digest.finalize().into()
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
