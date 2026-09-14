// SPDX-License-Identifier: GPL-2.0-only

//! Cycle-owned delivery of durable source-branch publications, including after peer outages.

use std::{path::Path, sync::Arc, time::Duration};

use meshspan_cluster::ConsensusNetwork;
use meshspan_domain::{BranchId, Clock as _, InitialBootstrapMaterial, NodeId, OperationId};
use meshspan_filesystem::NamespaceDelivery;
use meshspan_protocol::v1::{
    ControlEnvelope, NativeContentRoute, OperationOutcome, PublishNamespaceHead,
    control_envelope::Message,
};
use sha2::{Digest, Sha256};
use tokio::sync::watch;

use super::{NativeGatewayHistory, NativeGatewaySyncError, receiver::AdvertisedHead};
use crate::{
    OperatingSystemClock, native_filesystem_runtime::NativeFilesystemRuntime,
    private_consensus_runtime::PrivateConsensusRuntime,
};

const POLL_INTERVAL: Duration = Duration::from_millis(250);
const REQUEST_DEADLINE: Duration = Duration::from_secs(60);
const PEER_WORKERS: usize = 4;

#[derive(Clone)]
pub(crate) struct NamespaceDeliveryWorker {
    history: NativeGatewayHistory,
    branch: BranchId,
    network: Arc<PrivateConsensusRuntime>,
    filesystem: NativeFilesystemRuntime,
}

impl NamespaceDeliveryWorker {
    pub(crate) fn new(
        directory: &Path,
        node: NodeId,
        network: Arc<PrivateConsensusRuntime>,
        filesystem: NativeFilesystemRuntime,
    ) -> Result<Self, NativeGatewaySyncError> {
        Ok(Self {
            history: NativeGatewayHistory::new(directory),
            branch: InitialBootstrapMaterial::local_branch_id(node)
                .map_err(|_| NativeGatewaySyncError::Invalid)?,
            network,
            filesystem,
        })
    }

    pub(crate) async fn run_until(self, mut stop: watch::Receiver<bool>) {
        let mut convergence_after = None;
        loop {
            if *stop.borrow() {
                return;
            }
            let convergence_failed = match self.network.network() {
                Ok(network) => super::convergence::run_one(
                    &self.history,
                    &self.filesystem,
                    network.local_node_id(),
                    &mut convergence_after,
                )
                .await
                .is_err(),
                Err(()) => true,
            };
            let failed = self.deliver_round(stop.clone()).await || convergence_failed;
            let pause = if failed {
                Duration::from_secs(1)
            } else {
                POLL_INTERVAL
            };
            tokio::select! {
                _changed = stop.changed() => return,
                () = tokio::time::sleep(pause) => {},
            }
        }
    }

    async fn deliver_round(&self, stop: watch::Receiver<bool>) -> bool {
        let Ok(network) = self.network.network() else {
            return true;
        };
        let Ok(peers) = network.peer_routes() else {
            return true;
        };
        let mut peers = peers.into_iter();
        let mut jobs = tokio::task::JoinSet::new();
        let mut failed = false;
        loop {
            while jobs.len() < PEER_WORKERS && !*stop.borrow() {
                let Some(peer) = peers.next() else {
                    break;
                };
                let worker = self.clone();
                let network = network.clone();
                let stop = stop.clone();
                jobs.spawn(async move { worker.deliver_next(network, peer.node_id, stop).await });
            }
            let Some(result) = jobs.join_next().await else {
                return failed;
            };
            if !matches!(result, Ok(Ok(()))) {
                // Failed work remains at the durable cursor. Drain this round's owned jobs
                // before retrying; transport failure never deletes or skips the publication.
                failed = true;
            }
        }
    }

    async fn deliver_next(
        &self,
        network: ConsensusNetwork,
        peer: NodeId,
        mut stop: watch::Receiver<bool>,
    ) -> Result<(), NativeGatewaySyncError> {
        let branch = self.branch;
        let filesystem = self.filesystem.clone();
        let prepared = self
            .history
            .execute(move |store| {
                let Some(delivery) = store
                    .next_namespace_delivery(branch, peer)
                    .map_err(|_| NativeGatewaySyncError::Unavailable)?
                else {
                    return Ok(None);
                };
                let routes = if let Some(version) = delivery.file_version_id {
                    let content = store
                        .published_content_for_version(version)
                        .map_err(|_| NativeGatewaySyncError::Unavailable)?
                        .ok_or(NativeGatewaySyncError::Invalid)?;
                    let targets = filesystem
                        .update_provider_targets()
                        .map_err(|_| NativeGatewaySyncError::Unavailable)?;
                    let target = targets
                        .first()
                        .ok_or(NativeGatewaySyncError::Unavailable)?
                        .context();
                    vec![NativeContentRoute {
                        publication_operation_id: content
                            .publication_operation_id
                            .as_bytes()
                            .to_vec(),
                        manifest_id: content.manifest.manifest_id.as_bytes().to_vec(),
                        target_id: target.target_id.as_bytes().to_vec(),
                        target_generation: target.generation,
                    }]
                } else {
                    Vec::new()
                };
                Ok(Some((
                    delivery,
                    PublishNamespaceHead {
                        volume_id: delivery.volume_id.as_bytes().to_vec(),
                        namespace_commit_id: delivery.namespace_commit_id.as_bytes().to_vec(),
                        root_object_revision_id: delivery
                            .root_object_revision_id
                            .as_bytes()
                            .to_vec(),
                        content_routes: routes,
                    },
                )))
            })
            .await?;
        let Some((delivery, message)) = prepared else {
            return Ok(());
        };
        if *stop.borrow() {
            return Ok(());
        }
        let now = OperatingSystemClock.now();
        let operation = operation_id(delivery, peer, now.get())?;
        let expected = AdvertisedHead::parse(&message)?.result_digest();
        let deadline = now
            .get()
            .checked_add(60_000_000)
            .ok_or(NativeGatewaySyncError::Invalid)?;
        let envelope = ControlEnvelope {
            header: Some(network.control_header(operation, deadline)?),
            message: Some(Message::PublishNamespaceHead(message)),
        };
        let response = tokio::select! {
            _changed = stop.changed() => return Ok(()),
            response = tokio::time::timeout(REQUEST_DEADLINE, network.request_control(peer, &envelope)) => response.map_err(|_| NativeGatewaySyncError::Unavailable)??,
        };
        if !accepted(&response, operation, expected) {
            return Err(NativeGatewaySyncError::Invalid);
        }
        self.history
            .execute(move |store| {
                store
                    .acknowledge_namespace_delivery(branch, peer, delivery)
                    .map_err(|_| NativeGatewaySyncError::Unavailable)
            })
            .await
    }
}

fn accepted(
    response: &meshspan_protocol::ValidatedControlEnvelope,
    operation: OperationId,
    expected: [u8; 32],
) -> bool {
    let envelope = response.as_inner();
    if envelope
        .header
        .as_ref()
        .is_none_or(|header| header.operation_id != operation.as_bytes())
    {
        return false;
    }
    let Some(Message::NamespaceHeadAccepted(accepted)) = envelope.message.as_ref() else {
        return false;
    };
    accepted.result.as_ref().is_some_and(|result| {
        result.outcome == i32::from(OperationOutcome::Durable) && result.result_digest == expected
    })
}

fn operation_id(
    delivery: NamespaceDelivery,
    peer: NodeId,
    now: i64,
) -> Result<OperationId, NativeGatewaySyncError> {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.native.publish-head.v1\0");
    digest.update(delivery.namespace_commit_id.as_bytes());
    digest.update(peer.as_bytes());
    digest.update(now.to_be_bytes());
    let bytes: [u8; 16] = digest.finalize()[..16]
        .try_into()
        .map_err(|_| NativeGatewaySyncError::Invalid)?;
    OperationId::from_bytes(meshspan_domain::uuid_v8(bytes))
        .map_err(|_| NativeGatewaySyncError::Invalid)
}
