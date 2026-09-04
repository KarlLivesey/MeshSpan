// SPDX-License-Identifier: GPL-2.0-only

//! Local-or-remote resolution of registered-target metadata-backup destinations.

use std::io::{Read, Write};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use meshspan_contracts::{
    BackupDeleteReceipt, BackupDeleteRequest, BackupObjectReceipt, BackupProvider,
    BackupReadReceipt, BackupReadRequest, BackupStoreRequest, BackupVerifyRequest, ContractError,
    ContractKind, ContractLimits, ContractVersion, ImplementationDescriptor,
};
use meshspan_domain::{MeshId, NodeId, UnixMicros};
use meshspan_metadata::{
    AuthoritativeRepository, BackupDestinationBinding, BackupDestinationRecord,
    StorageTargetProviderContext,
};
use meshspan_protocol::v1::ErrorCode;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::metadata_backup_provider_resolution::{
    MetadataBackupProviderResolutionError, MetadataBackupProviderResolver,
    RegisteredTargetBackupProviderResolver,
};
use crate::private_consensus_runtime::PrivateConsensusRuntime;

const REMOTE_PROVIDER_VERSIONS: &[ContractVersion] = &[ContractVersion::V1_0];

/// Resolves registered targets on this node directly and other nodes over private QUIC/mTLS.
pub(crate) struct ClusterBackupProviderResolver<'a> {
    mesh_id: MeshId,
    local_node_id: NodeId,
    authority: &'a AuthoritativeRepository,
    local: RegisteredTargetBackupProviderResolver,
    network: Arc<PrivateConsensusRuntime>,
    runtime: tokio::runtime::Handle,
}

impl<'a> ClusterBackupProviderResolver<'a> {
    /// Binds exact local providers to the current replicated routing projection.
    pub(crate) const fn new(
        mesh_id: MeshId,
        local_node_id: NodeId,
        authority: &'a AuthoritativeRepository,
        local: RegisteredTargetBackupProviderResolver,
        network: Arc<PrivateConsensusRuntime>,
        runtime: tokio::runtime::Handle,
    ) -> Self {
        Self {
            mesh_id,
            local_node_id,
            authority,
            local,
            network,
            runtime,
        }
    }
}

impl MetadataBackupProviderResolver for ClusterBackupProviderResolver<'_> {
    fn resolve(
        &mut self,
        destination: &BackupDestinationRecord,
    ) -> Result<Box<dyn BackupProvider>, MetadataBackupProviderResolutionError> {
        let BackupDestinationBinding::RegisteredTarget {
            target_id,
            target_generation,
        } = destination.binding
        else {
            return Err(MetadataBackupProviderResolutionError::Unsupported);
        };
        let route = self
            .authority
            .storage_target_provider_context_by_target(target_id)
            .map_err(|_| MetadataBackupProviderResolutionError::Unavailable)?
            .ok_or(MetadataBackupProviderResolutionError::Unavailable)?;
        match classify_route(route, self.mesh_id, self.local_node_id, target_generation)? {
            BackupRoute::Local => self.local.resolve(destination),
            BackupRoute::Remote(node_id) => Ok(Box::new(RemoteBackupProvider::new(
                node_id,
                Arc::clone(&self.network),
                self.runtime.clone(),
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BackupRoute {
    Local,
    Remote(NodeId),
}

fn classify_route(
    route: StorageTargetProviderContext,
    mesh_id: MeshId,
    local_node_id: NodeId,
    target_generation: u64,
) -> Result<BackupRoute, MetadataBackupProviderResolutionError> {
    if route.mesh_id != mesh_id || route.generation != target_generation {
        Err(MetadataBackupProviderResolutionError::Stale)
    } else if route.node_id == local_node_id {
        Ok(BackupRoute::Local)
    } else {
        Ok(BackupRoute::Remote(route.node_id))
    }
}

/// Synchronous provider facade used only by the daemon's blocking backup worker.
struct RemoteBackupProvider {
    node_id: NodeId,
    network: Arc<PrivateConsensusRuntime>,
    runtime: tokio::runtime::Handle,
}

impl RemoteBackupProvider {
    const fn new(
        node_id: NodeId,
        network: Arc<PrivateConsensusRuntime>,
        runtime: tokio::runtime::Handle,
    ) -> Self {
        Self {
            node_id,
            network,
            runtime,
        }
    }

    fn connection(
        &self,
        context: meshspan_contracts::RequestContext,
    ) -> Result<
        (
            meshspan_cluster::ConsensusNetwork,
            meshspan_protocol::v1::RequestHeader,
        ),
        ContractError,
    > {
        let network = self
            .network
            .network()
            .map_err(|()| ContractError::Unavailable)?;
        let header = network
            .control_header(context.operation_id, context.deadline.get())
            .map_err(|_| ContractError::InvalidInput)?;
        Ok((network, header))
    }
}

impl BackupProvider for RemoteBackupProvider {
    fn describe(&self) -> ImplementationDescriptor {
        ImplementationDescriptor {
            implementation_id: "meshspan-private-quic-backup",
            contract: ContractKind::BackupProvider,
            versions: REMOTE_PROVIDER_VERSIONS,
            limits: ContractLimits {
                maximum_control_bytes: 64 * 1_024,
                maximum_items: 1_000,
                maximum_concurrency: 1,
            },
        }
    }

    fn store_exact(
        &mut self,
        request: BackupStoreRequest,
        source: &mut dyn Read,
        observed_at: UnixMicros,
    ) -> Result<BackupObjectReceipt, ContractError> {
        let (network, header) = self.connection(request.context)?;
        let connection = self
            .runtime
            .block_on(network.connect_data_peer(self.node_id))
            .map_err(|_| ContractError::Unavailable)?;
        self.runtime
            .block_on(meshspan_data_plane::store_backup(
                &connection,
                header,
                request,
                &mut BlockingAsyncReader(source),
                network.wire_limits(),
                observed_at,
            ))
            .map_err(|error| map_backup_plane_error(&error))
    }

    fn read_exact(
        &self,
        request: &BackupReadRequest,
        destination: &mut dyn Write,
        observed_at: UnixMicros,
    ) -> Result<BackupReadReceipt, ContractError> {
        let (network, header) = self.connection(request.context)?;
        let connection = self
            .runtime
            .block_on(network.connect_data_peer(self.node_id))
            .map_err(|_| ContractError::Unavailable)?;
        self.runtime
            .block_on(meshspan_data_plane::read_backup(
                &connection,
                header,
                request,
                &mut BlockingAsyncWriter(destination),
                network.wire_limits(),
                observed_at,
            ))
            .map_err(|error| map_backup_plane_error(&error))
    }

    fn verify_exact(
        &self,
        request: &BackupVerifyRequest,
        observed_at: UnixMicros,
    ) -> Result<BackupObjectReceipt, ContractError> {
        let (network, header) = self.connection(request.context)?;
        let connection = self
            .runtime
            .block_on(network.connect_data_peer(self.node_id))
            .map_err(|_| ContractError::Unavailable)?;
        self.runtime
            .block_on(meshspan_data_plane::verify_backup(
                &connection,
                header,
                request,
                network.wire_limits(),
                observed_at,
            ))
            .map_err(|error| map_backup_plane_error(&error))
    }

    fn delete_exact(
        &mut self,
        request: &BackupDeleteRequest,
        observed_at: UnixMicros,
    ) -> Result<BackupDeleteReceipt, ContractError> {
        let (network, header) = self.connection(request.context)?;
        let connection = self
            .runtime
            .block_on(network.connect_data_peer(self.node_id))
            .map_err(|_| ContractError::Unavailable)?;
        self.runtime
            .block_on(meshspan_data_plane::delete_backup(
                &connection,
                header,
                request,
                network.wire_limits(),
                observed_at,
            ))
            .map_err(|error| map_backup_plane_error(&error))
    }
}

struct BlockingAsyncReader<'a>(&'a mut dyn Read);

impl AsyncRead for BlockingAsyncReader<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let read = self.0.read(buffer.initialize_unfilled())?;
        buffer.advance(read);
        Poll::Ready(Ok(()))
    }
}

struct BlockingAsyncWriter<'a>(&'a mut dyn Write);

impl AsyncWrite for BlockingAsyncWriter<'_> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(self.0.write(bytes))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(self.0.flush())
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn map_backup_plane_error(error: &meshspan_data_plane::BackupPlaneError) -> ContractError {
    match error {
        meshspan_data_plane::BackupPlaneError::Remote(code) => match code {
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
        meshspan_data_plane::BackupPlaneError::InvalidConfiguration
        | meshspan_data_plane::BackupPlaneError::Transport(_) => ContractError::Unavailable,
        meshspan_data_plane::BackupPlaneError::Io(_)
        | meshspan_data_plane::BackupPlaneError::Worker
        | meshspan_data_plane::BackupPlaneError::InvalidMessage => ContractError::InternalContract,
    }
}

#[cfg(test)]
mod tests {
    use meshspan_domain::{MeshId, NodeId, Revision, TargetId};
    use meshspan_metadata::{StorageTargetProviderContext, StorageUsageLimit};

    use super::{BackupRoute, classify_route};

    #[test]
    fn route_classification_is_exact_about_mesh_generation_and_owner()
    -> Result<(), Box<dyn std::error::Error>> {
        let mesh_id = MeshId::from_bytes([1; 16])?;
        let local_node_id = NodeId::from_bytes([2; 16])?;
        let remote_node_id = NodeId::from_bytes([3; 16])?;
        let route = StorageTargetProviderContext {
            mesh_id,
            node_id: remote_node_id,
            target_id: TargetId::from_bytes([4; 16])?,
            generation: 7,
            usage_limit: StorageUsageLimit::Percent(95),
            policy_revision: Revision::new(8),
            catalogue_revision: Revision::new(9),
        };

        assert_eq!(
            classify_route(route, mesh_id, local_node_id, 7)?,
            BackupRoute::Remote(remote_node_id)
        );
        assert_eq!(
            classify_route(route, mesh_id, remote_node_id, 7)?,
            BackupRoute::Local
        );
        assert!(classify_route(route, MeshId::from_bytes([5; 16])?, local_node_id, 7).is_err());
        assert!(classify_route(route, mesh_id, local_node_id, 8).is_err());
        Ok(())
    }
}
