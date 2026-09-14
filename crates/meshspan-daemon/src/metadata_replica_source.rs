// SPDX-License-Identifier: GPL-2.0-only

//! Historical metadata source: independent admission and owned work, never a permission barrier.

use std::{path::PathBuf, sync::Arc};

use meshspan_cluster::{
    MAXIMUM_METADATA_REPLICA_TRANSFER_TIME, MetadataAuthorityHandle, PeerDataStream,
    PreparedMetadataReplicaPage, admit_metadata_replica_request, reject_metadata_replica_page,
    send_metadata_replica_page,
};
use meshspan_protocol::v1::{ErrorCode, FetchMetadataReplicaPage};
use tokio::sync::{Semaphore, watch};

use super::{current_time, open_root_repository_at};

#[derive(Clone)]
pub(super) struct MetadataReplicaSource {
    directory: PathBuf,
    authority: MetadataAuthorityHandle,
    admission: Arc<Semaphore>,
}

impl MetadataReplicaSource {
    pub(super) fn new(directory: PathBuf, authority: MetadataAuthorityHandle) -> Self {
        Self {
            directory,
            authority,
            admission: Arc::new(Semaphore::new(2)),
        }
    }

    pub(super) async fn serve(
        &self,
        mut incoming: PeerDataStream,
        request: FetchMetadataReplicaPage,
        mut stop: watch::Receiver<bool>,
    ) -> Result<(), ()> {
        let deadline = tokio::time::Instant::now() + MAXIMUM_METADATA_REPLICA_TRANSFER_TIME;
        let _permit = Arc::clone(&self.admission)
            .try_acquire_owned()
            .map_err(|_| ())?;
        let request_id = request.header.as_ref().ok_or(())?.request_id.clone();
        // No trailing request payload is accepted, and a peer cannot hold a worker by omitting EOF.
        tokio::select! {
            _changed = stop.changed() => return Ok(()),
            result = tokio::time::timeout_at(deadline, incoming.stream.receive.read_to_end(0)) => { result.map_err(|_| ())?.map_err(|_| ())?; }
        }
        let prepared = self.prepare(&incoming, request).await;
        // Never detach database/encoder workers when the cycle stops. Preparation is bounded and
        // owned; cancellation applies only to the following network IO.
        if *stop.borrow() || tokio::time::Instant::now() >= deadline {
            return Ok(());
        }
        let send = async move {
            match prepared {
                Ok(page) => {
                    send_metadata_replica_page(incoming.stream, page, incoming.limits).await
                }
                Err(code) => {
                    reject_metadata_replica_page(incoming.stream, request_id, code, incoming.limits)
                        .await
                }
            }
        };
        tokio::select! {
            _changed = stop.changed() => Ok(()),
            result = tokio::time::timeout_at(deadline, send) => result.map_err(|_| ())?.map_err(|_| ()),
        }
    }

    async fn prepare(
        &self,
        incoming: &PeerDataStream,
        request: FetchMetadataReplicaPage,
    ) -> Result<PreparedMetadataReplicaPage, ErrorCode> {
        let directory = self.directory.clone();
        let peer = incoming.peer;
        let routing_epoch = incoming.routing_epoch;
        let (after, request) = tokio::task::spawn_blocking(move || {
            let now = current_time().map_err(|_| ErrorCode::Unavailable)?;
            let repository =
                open_root_repository_at(&directory, now).map_err(|_| ErrorCode::Unavailable)?;
            let after =
                admit_metadata_replica_request(&repository, peer, routing_epoch, &request, now)
                    .map_err(|_| ErrorCode::Unauthorised)?;
            Ok::<_, ErrorCode>((after, request))
        })
        .await
        .map_err(|_| ErrorCode::Unavailable)??;
        let page = self
            .authority
            .replica_page(after)
            .await
            .map_err(|error| match error {
                meshspan_cluster::MetadataReplicaError::StaleCursor => ErrorCode::Stale,
                meshspan_cluster::MetadataReplicaError::Unavailable
                | meshspan_cluster::MetadataReplicaError::LocalMember
                | meshspan_cluster::MetadataReplicaError::Source
                | meshspan_cluster::MetadataReplicaError::InvalidPage
                | meshspan_cluster::MetadataReplicaError::ReloadRequired
                | meshspan_cluster::MetadataReplicaError::Persistence(_)
                | meshspan_cluster::MetadataReplicaError::Repository(_) => ErrorCode::Unavailable,
            })?;
        let directory = self.directory.clone();
        let limits = incoming.limits;
        tokio::task::spawn_blocking(move || {
            let now = current_time().map_err(|_| ErrorCode::Unavailable)?;
            let repository =
                open_root_repository_at(&directory, now).map_err(|_| ErrorCode::Unavailable)?;
            // The history lookup may have advanced the node's retirement/certificate state.
            admit_metadata_replica_request(&repository, peer, routing_epoch, &request, now)
                .map_err(|_| ErrorCode::Unauthorised)?;
            PreparedMetadataReplicaPage::new(request, &page, limits)
                .map_err(|_| ErrorCode::Unavailable)
        })
        .await
        .map_err(|_| ErrorCode::Unavailable)?
    }
}
