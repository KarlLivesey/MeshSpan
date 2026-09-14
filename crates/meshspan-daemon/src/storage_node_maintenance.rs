// SPDX-License-Identifier: GPL-2.0-only

//! Fresh committed cleanup admission for non-voting storage. Never authorises by MAC alone.

use std::{
    path::Path,
    time::{Duration, Instant},
};

use meshspan_cluster::{ConsensusNetwork, MetadataReadFence, MetadataReplicaRuntimeHandle};
use meshspan_contracts::{ContractError, RemovalPermit, ShardIdentity, TombstoneReceipt};
use meshspan_domain::{Clock as _, NodeId, OperationId, RandomSource as _, UnixMicros};
use meshspan_metadata::{AuthoritativeRepository, JoinRoles, VersionCleanupStorageAuthority};
use meshspan_protocol::v1::{RequestHeader, data_control_envelope::Message};
use meshspan_transport::PeerBinding;
use tokio::sync::watch;

use super::open_root_repository_at;

#[cfg(test)]
#[path = "storage_node_maintenance_tests.rs"]
mod tests;

#[derive(Clone, Copy)]
enum Evidence {
    Delete(RemovalPermit),
    Reclaim(TombstoneReceipt),
}

/// Parsed request retains exactly the operation and evidence that will reach the provider.
pub(super) struct MaintenanceRequest {
    header: RequestHeader,
    evidence: Evidence,
    peer: PeerBinding,
}

impl MaintenanceRequest {
    /// Cheap structural/identity checks precede all database and quorum work.
    pub(super) fn parse(
        message: &Message,
        peer: PeerBinding,
        routing_epoch: u64,
        now: UnixMicros,
    ) -> Result<Self, ContractError> {
        let (header, payload, target, generation, shard, is_delete) = match message {
            Message::DeleteShardRequest(request)
                if request.federation_capability.is_empty()
                    && request.federation_capability_digest.is_empty() =>
            {
                (
                    &request.header,
                    &request.removal_permit,
                    &request.target_id,
                    request.target_generation,
                    &request.shard,
                    true,
                )
            }
            Message::ReclaimShardRequest(request)
                if request.federation_capability.is_empty()
                    && request.federation_capability_digest.is_empty() =>
            {
                (
                    &request.header,
                    &request.tombstone_receipt,
                    &request.target_id,
                    request.target_generation,
                    &request.shard,
                    false,
                )
            }
            _ => return Err(ContractError::Unauthorized),
        };
        let header = header.as_ref().ok_or(ContractError::InvalidInput)?;
        let payload = payload.as_ref().ok_or(ContractError::InvalidInput)?;
        if payload.format_version != 1 || header.routing_epoch != routing_epoch {
            return Err(ContractError::InvalidInput);
        }
        let evidence = if is_delete {
            Evidence::Delete(
                meshspan_data_plane::decode_removal_permit(&payload.canonical_bytes)
                    .map_err(|_| ContractError::InvalidInput)?,
            )
        } else {
            Evidence::Reclaim(
                meshspan_data_plane::decode_tombstone_receipt(&payload.canonical_bytes)
                    .map_err(|_| ContractError::InvalidInput)?,
            )
        };
        let request = Self {
            header: header.clone(),
            evidence,
            peer,
        };
        let (operation, expected_target, expected_generation, expected_shard) = request.identity();
        if header.operation_id.as_slice() != operation.as_bytes()
            || target.as_slice() != expected_target.as_bytes()
            || generation != expected_generation
            || !shard
                .as_ref()
                .is_some_and(|shard| matches_shard(shard, expected_shard))
        {
            return Err(ContractError::Unauthorized);
        }
        request.admit_header(now)?;
        Ok(request)
    }

    /// This worker owns SQLite; network/catch-up waits hold neither a read view nor provider lock.
    pub(super) fn authorise(
        &self,
        directory: &Path,
        network: &ConsensusNetwork,
        replica: &MetadataReplicaRuntimeHandle,
        mut stop: watch::Receiver<bool>,
    ) -> Result<(), ContractError> {
        let now = crate::OperatingSystemClock.now();
        let deadline = Instant::now() + Duration::from_secs(30);
        self.admit_header(now)?;
        let repository =
            open_root_repository_at(directory, now).map_err(|_| ContractError::Unavailable)?;
        let candidates = repository
            .with_read_view(|repository| {
                self.admit_current(repository, network, now)?;
                Ok::<_, ContractError>(
                    repository
                        .load_active_consensus_quorum_plan()
                        .map_err(|_| ContractError::Unavailable)?
                        .ok_or(ContractError::Unavailable)?
                        .voters()
                        .into_iter()
                        .collect(),
                )
            })
            .map_err(|_| ContractError::Unavailable)??;
        let operation = self.identity().0;
        let source = network.clone();
        let runtime = tokio::runtime::Handle::current();
        if *stop.borrow() {
            return Err(ContractError::Unavailable);
        }
        let fence = runtime
            .block_on(crate::metadata_forwarding::discovery::discover(
                candidates,
                None,
                move |candidate| {
                    let network = source.clone();
                    async move {
                        let mut nonce = [0; 32];
                        crate::OperatingSystemRandom
                            .fill_bytes(&mut nonce)
                            .map_err(|_| meshspan_cluster::MetadataAuthorityRequestError::Failed)?;
                        network
                            .fetch_metadata_read_fence(
                                candidate,
                                operation,
                                nonce,
                                crate::OperatingSystemClock.now(),
                            )
                            .await
                    }
                },
            ))
            .map_err(|_| ContractError::Unavailable)?;
        let mut progress = replica.subscribe();
        replica.request_sync();
        loop {
            if *stop.borrow() {
                return Err(ContractError::Unavailable);
            }
            let budget = deadline
                .checked_duration_since(Instant::now())
                .ok_or(ContractError::DeadlineExceeded)?;
            let now = crate::OperatingSystemClock.now();
            self.admit_header(now)?;
            let admitted = repository
                .with_read_view(|repository| {
                    if !caught_up(repository, fence)? {
                        return Ok(false);
                    }
                    self.admit_current(repository, network, now)?;
                    let authority = repository
                        .version_cleanup_storage_authority(operation)
                        .map_err(|_| ContractError::Unavailable)?
                        .ok_or(ContractError::Unauthorized)?;
                    self.admit_record(&authority, network.local_node_id(), fence, now)?;
                    Ok(true)
                })
                .map_err(|_| ContractError::Unavailable)??;
            if admitted {
                return Ok(());
            }
            let remaining = self
                .header
                .deadline_unix_micros
                .checked_sub(now.get())
                .and_then(|value| u64::try_from(value).ok())
                .ok_or(ContractError::DeadlineExceeded)?;
            runtime.block_on(async {
                tokio::select! {
                    _changed = stop.changed() => Err(ContractError::Unavailable),
                    result = tokio::time::timeout(Duration::from_micros(remaining).min(budget), progress.changed()) => {
                        result.map_err(|_| ContractError::DeadlineExceeded)?
                            .map_err(|_| ContractError::Unavailable)
                    }
                }
            })?;
        }
    }

    fn admit_header(&self, now: UnixMicros) -> Result<(), ContractError> {
        let remaining = self
            .header
            .deadline_unix_micros
            .checked_sub(now.get())
            .ok_or(ContractError::DeadlineExceeded)?;
        if !u64::try_from(remaining).is_ok_and(|remaining| {
            (1..=meshspan_cluster::MAXIMUM_CLEANUP_REQUEST_TIMEOUT.get()).contains(&remaining)
        }) {
            return Err(ContractError::DeadlineExceeded);
        }
        if self.header.sender_node_id.as_slice() != self.peer.node_id.as_bytes()
            || self.header.sender_incarnation != self.peer.incarnation
        {
            return Err(ContractError::Unauthorized);
        }
        if matches!(self.evidence, Evidence::Delete(permit) if permit.expires_at <= now) {
            return Err(ContractError::Unauthorized);
        }
        Ok(())
    }

    fn admit_current(
        &self,
        repository: &AuthoritativeRepository,
        network: &ConsensusNetwork,
        now: UnixMicros,
    ) -> Result<(), ContractError> {
        let local = network.local_node_id();
        let mesh = repository
            .local_mesh_id()
            .map_err(|_| ContractError::Unavailable)?
            .ok_or(ContractError::Unauthorized)?;
        if self.header.mesh_id.as_slice() != mesh.as_bytes()
            || self.header.partition_id.as_slice() != repository.partition_id().as_bytes()
        {
            return Err(ContractError::Unauthorized);
        }
        let sender = repository
            .active_node_certificate(self.peer.node_id)
            .map_err(|_| ContractError::Unavailable)?
            .ok_or(ContractError::Unauthorized)?;
        let plan = repository
            .load_active_consensus_quorum_plan()
            .map_err(|_| ContractError::Unavailable)?
            .ok_or(ContractError::Unavailable)?;
        let recipient = repository
            .active_node_certificate(local)
            .map_err(|_| ContractError::Unavailable)?
            .ok_or(ContractError::Unauthorized)?;
        if sender.incarnation != self.peer.incarnation
            || sender.certificate_fingerprint != self.peer.certificate_fingerprint
            || sender.valid_until <= now
            || (!plan.voters().contains(&sender.node_id)
                && sender.roles.bits() & JoinRoles::GATEWAY == 0)
            || recipient.valid_until <= now
            || recipient.roles.bits() & JoinRoles::STORAGE == 0
            || recipient.incarnation != network.local_incarnation()
            || recipient.certificate_fingerprint
                != network
                    .local_certificate()
                    .map_err(|_| ContractError::Unavailable)?
                    .certificate_fingerprint
        {
            return Err(ContractError::Unauthorized);
        }
        let (_, target, generation, _) = self.identity();
        let target = repository
            .readable_storage_target_provider_context(local, target)
            .map_err(|_| ContractError::Unavailable)?
            .ok_or(ContractError::Unauthorized)?;
        if target.generation != generation || target.mesh_id != mesh {
            return Err(ContractError::Unauthorized);
        }
        Ok(())
    }

    fn admit_record(
        &self,
        authority: &VersionCleanupStorageAuthority,
        local: NodeId,
        fence: MetadataReadFence,
        now: UnixMicros,
    ) -> Result<(), ContractError> {
        if authority.item.storage_node_id != local {
            return Err(ContractError::Unauthorized);
        }
        match self.evidence {
            Evidence::Delete(permit) => {
                if permit != authority.attempt.permit
                    || permit.authority_epoch != fence.membership_epoch
                    || permit.expires_at <= now
                    || permit.catalogue_revision > fence.revision
                    || self.header.mesh_id.as_slice() != permit.mesh_id.as_bytes()
                {
                    return Err(ContractError::Unauthorized);
                }
            }
            Evidence::Reclaim(receipt) => {
                // Completion commits the exact tombstone. Reclamation accounting follows unlink.
                if !authority
                    .completion
                    .is_some_and(|completion| completion.receipt == receipt)
                {
                    return Err(ContractError::Unauthorized);
                }
            }
        }
        Ok(())
    }

    fn identity(&self) -> (OperationId, meshspan_domain::TargetId, u64, ShardIdentity) {
        match self.evidence {
            Evidence::Delete(permit) => (
                permit.operation_id,
                permit.target_id,
                permit.target_generation,
                permit.shard,
            ),
            Evidence::Reclaim(receipt) => (
                receipt.operation_id,
                receipt.target_id,
                receipt.target_generation,
                receipt.shard,
            ),
        }
    }
}

/// Must run inside the same read view as operation-specific admission, not against watch progress.
fn caught_up(
    repository: &AuthoritativeRepository,
    fence: MetadataReadFence,
) -> Result<bool, ContractError> {
    if repository.partition_id() != fence.partition_id {
        return Err(ContractError::Unauthorized);
    }
    let plan = repository
        .load_active_consensus_quorum_plan()
        .map_err(|_| ContractError::Unavailable)?
        .ok_or(ContractError::Unavailable)?;
    if plan.membership_epoch() < fence.membership_epoch {
        return Ok(false);
    }
    if plan.membership_epoch() != fence.membership_epoch
        || plan.proof_digest() != fence.plan_digest
        || !plan.voters().contains(&fence.leader_node_id)
    {
        return Err(ContractError::Stale);
    }
    let Some(entry) = repository
        .applied_consensus_entry(fence.applied)
        .map_err(|_| ContractError::Unavailable)?
    else {
        return Ok(false);
    };
    if entry.entry_digest() != fence.applied_digest {
        return Err(ContractError::Stale);
    }
    Ok(repository
        .current_revision()
        .map_err(|_| ContractError::Unavailable)?
        >= fence.revision)
}

fn matches_shard(wire: &meshspan_protocol::v1::ShardIdentity, expected: ShardIdentity) -> bool {
    wire.manifest_digest.as_slice() == expected.manifest_digest
        && wire.stripe_index == expected.stripe_index
        && wire.shard_index == u32::from(expected.shard_index)
        && wire.generation == expected.generation
}
