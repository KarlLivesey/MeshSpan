// SPDX-License-Identifier: GPL-2.0-only

//! Authenticated asynchronous QUIC composition for one exact cleanup-worker transition.

use std::future::Future;

use meshspan_data_plane::{DataPlaneError, reclaim_shard, tombstone_shard};
use meshspan_domain::{DurationMicros, MeshId, NodeId, OperationId, PartitionId, UnixMicros};
use meshspan_protocol::WireLimits;
use meshspan_protocol::v1::{ProtocolVersion, RequestHeader};
use meshspan_transport::AuthenticatedPeer;

use crate::cleanup_worker::{
    CleanupWorkAction, CleanupWorkEntry, CleanupWorkerError, CleanupWorkerOutcome,
    validate_attempt, validate_completion, validate_item_authority, validate_reclamation,
    validate_reporter,
};
use crate::{version_cleanup_reclamation, version_cleanup_tombstone_completion};

/// Compiled ceiling for one remote cleanup request, independent of provider permit expiry.
pub const MAXIMUM_CLEANUP_REQUEST_TIMEOUT: DurationMicros = DurationMicros::new(5 * 60 * 1_000_000);

/// Immutable private-wire identity and resource bounds for cleanup dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CleanupNetworkContext {
    mesh_id: MeshId,
    partition_id: PartitionId,
    routing_epoch: u64,
    sender_node_id: NodeId,
    sender_incarnation: u64,
    request_timeout: DurationMicros,
    wire_limits: WireLimits,
}

impl CleanupNetworkContext {
    /// Constructs one bounded private cleanup dispatch context.
    ///
    /// # Errors
    ///
    /// Rejects zero identity fences and zero or excessive request timeouts.
    pub const fn new(
        mesh_id: MeshId,
        partition_id: PartitionId,
        routing_epoch: u64,
        sender_node_id: NodeId,
        sender_incarnation: u64,
        request_timeout: DurationMicros,
        wire_limits: WireLimits,
    ) -> Result<Self, CleanupNetworkError> {
        if routing_epoch == 0
            || sender_incarnation == 0
            || request_timeout.get() == 0
            || request_timeout.get() > MAXIMUM_CLEANUP_REQUEST_TIMEOUT.get()
        {
            return Err(CleanupNetworkError::InvalidContext);
        }
        Ok(Self {
            mesh_id,
            partition_id,
            routing_epoch,
            sender_node_id,
            sender_incarnation,
            request_timeout,
            wire_limits,
        })
    }

    fn request_header(
        self,
        operation_id: OperationId,
        observed_at: UnixMicros,
        authority_expiry: Option<UnixMicros>,
    ) -> Result<RequestHeader, CleanupNetworkError> {
        let configured_deadline = observed_at
            .checked_add(self.request_timeout)
            .ok_or(CleanupNetworkError::InvalidContext)?;
        let deadline = authority_expiry.map_or(configured_deadline, |expiry| {
            expiry.min(configured_deadline)
        });
        if observed_at.get() <= 0 || deadline <= observed_at {
            return Err(CleanupNetworkError::InvalidContext);
        }
        Ok(RequestHeader {
            version: Some(ProtocolVersion { major: 1, minor: 0 }),
            mesh_id: self.mesh_id.as_bytes().to_vec(),
            partition_id: self.partition_id.as_bytes().to_vec(),
            routing_epoch: self.routing_epoch,
            sender_node_id: self.sender_node_id.as_bytes().to_vec(),
            sender_incarnation: self.sender_incarnation,
            request_id: operation_id.as_bytes().to_vec(),
            operation_id: operation_id.as_bytes().to_vec(),
            deadline_unix_micros: deadline.get(),
            trace_id: operation_id.as_bytes().to_vec(),
        })
    }
}

/// Closed failures for one asynchronous cleanup dispatch attempt.
#[derive(Debug, thiserror::Error)]
pub enum CleanupNetworkError {
    /// Dispatch identity, epoch, timeout or observed time is invalid.
    #[error("cleanup network context is invalid")]
    InvalidContext,
    /// Replicated work and authenticated provider authority disagree.
    #[error("cleanup work authority is inconsistent")]
    Worker(#[from] CleanupWorkerError),
    /// The authenticated shard stream failed or returned invalid evidence.
    #[error("cleanup data-plane dispatch failed")]
    DataPlane(#[from] DataPlaneError),
}

/// Replaceable source of one connection and its certificate-authenticated peer identity.
pub trait CleanupConnectionSource {
    /// Resolves the current connection for one inventory-bound storage node.
    ///
    /// The dispatcher independently checks the returned peer, so stale or substituted routing
    /// fails before a provider stream is opened.
    fn connection_for(
        &self,
        storage_node_id: NodeId,
    ) -> impl Future<Output = Result<(quinn::Connection, AuthenticatedPeer), DataPlaneError>> + Send;
}

/// Resolves the inventory-bound peer and executes at most one cleanup transition over QUIC.
///
/// Permit acquisition and already-complete entries do not resolve a network connection. Provider
/// work resolves only the exact storage node recorded in the sealed inventory; the lower adapter
/// then repeats the certificate-peer check before opening a stream.
///
/// # Errors
///
/// Rejects invalid work, unavailable/stale connection routing, peer substitution, data-plane
/// failure and receipt-to-command conversion failure.
pub async fn dispatch_cleanup_work_over_quic<Source: CleanupConnectionSource>(
    source: &Source,
    context: CleanupNetworkContext,
    entry: CleanupWorkEntry,
    observed_at: UnixMicros,
) -> Result<CleanupWorkerOutcome, CleanupNetworkError> {
    match entry.action {
        CleanupWorkAction::AcquirePermit(authority) => {
            validate_item_authority(entry.cleanup_operation_id, entry.item, authority)?;
            Ok(CleanupWorkerOutcome::PermitRequired(authority))
        }
        CleanupWorkAction::Complete(reclamation) => {
            validate_reclamation(entry.cleanup_operation_id, entry.item, &reclamation)?;
            Ok(CleanupWorkerOutcome::Complete(reclamation))
        }
        CleanupWorkAction::Tombstone { .. } | CleanupWorkAction::Reclaim(_) => {
            let (connection, peer) = source.connection_for(entry.item.storage_node_id).await?;
            execute_cleanup_work_over_quic(&connection, peer, context, entry, observed_at).await
        }
    }
}

/// Executes at most one exact cleanup transition against one certificate-authenticated peer.
///
/// The peer identity is derived by `PeerRegistry::authenticate_connection`; it cannot be supplied
/// as an unauthenticated message field. The function rejects a peer other than the sealed target
/// owner before opening a data stream and uses that same identity in the authoritative result.
///
/// # Errors
///
/// Rejects invalid bounds, inconsistent work/peer authority, data-plane failure and receipt-to-
/// command conversion failure. No failure manufactures a metadata completion.
pub async fn execute_cleanup_work_over_quic(
    connection: &quinn::Connection,
    peer: AuthenticatedPeer,
    context: CleanupNetworkContext,
    entry: CleanupWorkEntry,
    observed_at: UnixMicros,
) -> Result<CleanupWorkerOutcome, CleanupNetworkError> {
    match entry.action {
        CleanupWorkAction::AcquirePermit(authority) => {
            validate_item_authority(entry.cleanup_operation_id, entry.item, authority)?;
            Ok(CleanupWorkerOutcome::PermitRequired(authority))
        }
        CleanupWorkAction::Tombstone {
            inventory_sealed_revision,
            attempt,
        } => {
            validate_attempt(entry.cleanup_operation_id, entry.item, attempt)?;
            validate_reporter(entry.item, peer.node_id())?;
            let header = context.request_header(
                attempt.permit.operation_id,
                observed_at,
                Some(attempt.permit.expires_at),
            )?;
            let receipt =
                tombstone_shard(connection, header, attempt.permit, context.wire_limits).await?;
            Ok(CleanupWorkerOutcome::CommandReady(
                version_cleanup_tombstone_completion(
                    inventory_sealed_revision,
                    attempt,
                    receipt,
                    peer.node_id(),
                    peer.incarnation(),
                )
                .map_err(CleanupWorkerError::from)?,
            ))
        }
        CleanupWorkAction::Reclaim(completion) => {
            validate_completion(entry.cleanup_operation_id, entry.item, completion)?;
            validate_reporter(entry.item, peer.node_id())?;
            let header =
                context.request_header(completion.receipt.operation_id, observed_at, None)?;
            let receipt =
                reclaim_shard(connection, header, completion.receipt, context.wire_limits).await?;
            Ok(CleanupWorkerOutcome::CommandReady(
                version_cleanup_reclamation(
                    completion,
                    receipt,
                    peer.node_id(),
                    peer.incarnation(),
                )
                .map_err(CleanupWorkerError::from)?,
            ))
        }
        CleanupWorkAction::Complete(reclamation) => {
            validate_reclamation(entry.cleanup_operation_id, entry.item, &reclamation)?;
            Ok(CleanupWorkerOutcome::Complete(reclamation))
        }
    }
}
