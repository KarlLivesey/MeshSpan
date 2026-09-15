// SPDX-License-Identifier: GPL-2.0-only

//! Owned per-cycle data routing, including executable sources on nodes without storage targets.

use super::{StorageTargetRuntime, current_time, open_root_repository_at};
use meshspan_cluster::PeerDataStream;
use meshspan_protocol::v1::data_control_envelope::Message;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{Semaphore, mpsc, watch};

#[path = "metadata_replica_source.rs"]
mod metadata_replica_source;
use metadata_replica_source::MetadataReplicaSource;

pub(super) struct RuntimeDataPlane {
    targets: Arc<Mutex<StorageTargetRuntime>>,
    streams: mpsc::Receiver<PeerDataStream>,
    blocking_admission: Arc<Semaphore>,
    replica_source: MetadataReplicaSource,
}

impl RuntimeDataPlane {
    /// Transfer exclusive receiver ownership into this cycle's bounded data dispatcher.
    pub(super) fn take_receiver(
        targets: Arc<Mutex<StorageTargetRuntime>>,
        streams: &mut Option<mpsc::Receiver<PeerDataStream>>,
        authority: meshspan_cluster::MetadataAuthorityHandle,
    ) -> Result<Self, super::DaemonProcessError> {
        let directory = targets
            .lock()
            .map_err(|_| super::DaemonProcessError::PrivateNetworkState)?
            .state_directory
            .clone();
        Ok(Self {
            targets,
            streams: streams
                .take()
                .ok_or(super::DaemonProcessError::PrivateNetworkState)?,
            blocking_admission: Arc::new(Semaphore::new(2)),
            replica_source: MetadataReplicaSource::new(directory, authority),
        })
    }

    pub(super) async fn run_until(mut self, mut stop: watch::Receiver<bool>) {
        let mut jobs = tokio::task::JoinSet::new();
        loop {
            if *stop.borrow() {
                break;
            }
            tokio::select! {
                _changed = stop.changed() => break,
                Some(result) = jobs.join_next(), if !jobs.is_empty() => self.observe(&result),
                incoming = self.streams.recv() => {
                    let Some(stream) = incoming else { break; };
                    jobs.spawn(serve(Arc::clone(&self.targets), Arc::clone(&self.blocking_admission), self.replica_source.clone(), stream, stop.clone()));
                }
            }
        }
        // Each transfer observes the cycle stop. Blocking source verification is still owned
        // and drained before its file/permit can escape into another daemon cycle.
        while let Some(result) = jobs.join_next().await {
            self.observe(&result);
        }
    }

    fn observe(&self, result: &Result<Result<(), ()>, tokio::task::JoinError>) {
        // Rejected/disconnected streams affect their own caller, not appliance availability.
        if result.is_err() {
            match self.targets.lock() {
                Ok(targets) => targets.readiness.store_degraded(true),
                Err(poisoned) => poisoned.into_inner().readiness.store_degraded(true),
            }
        }
    }
}

async fn serve(
    targets: Arc<Mutex<StorageTargetRuntime>>,
    admission: Arc<Semaphore>,
    replica_source: MetadataReplicaSource,
    mut stream: PeerDataStream,
    mut stop: watch::Receiver<bool>,
) -> Result<(), ()> {
    if *stop.borrow() {
        return Ok(());
    }
    let envelope = tokio::select! {
        _changed = stop.changed() => return Ok(()),
        result = tokio::time::timeout(Duration::from_secs(5), meshspan_transport::receive_data_control(&mut stream.stream.receive, stream.limits)) => result.map_err(|_| ())?.map_err(|_| ())?,
    };
    if matches!(
        envelope.as_inner().message,
        Some(Message::ForwardFederatedBackupRequest(_))
    ) {
        let owner = targets
            .lock()
            .map_err(|_| ())?
            .federation_backup_owner
            .clone();
        // Do not cancel a blocking provider write by dropping its handle. The owned worker
        // has a bounded deadline and the cycle drains it before replacing folder ownership.
        return owner.serve(stream, envelope).await.map_err(|_| ());
    }
    let message = envelope.into_inner().message.ok_or(())?;
    if let Message::FetchMetadataReplicaPage(request) = message {
        return replica_source.serve(stream, request, stop).await;
    }
    let now = current_time().map_err(|_| ())?;
    if let Message::GetUpdateArtifactRequest(request) = message {
        let remaining = request
            .header
            .as_ref()
            .ok_or(())?
            .deadline_unix_micros
            .checked_sub(now.get())
            .ok_or(())?;
        let deadline = tokio::time::Instant::now()
            + Duration::from_micros(u64::try_from(remaining).map_err(|_| ())?)
                .min(crate::update_peer::DEADLINE);
        let permit = admission.try_acquire_owned().map_err(|_| ())?;
        let prepared = tokio::task::spawn_blocking(move || {
            let directory = targets.lock().map_err(|_| ())?.state_directory.clone();
            let repository = open_root_repository_at(&directory, now).map_err(|_| ())?;
            let prepared = crate::update_peer::prepare_source(
                &repository,
                &directory,
                stream.peer,
                &request,
                now,
            )
            .map_err(|_| ())?;
            Ok::<_, ()>((permit, prepared))
        })
        .await
        .map_err(|_| ())??;
        let (_permit, (expected, file)) = prepared;
        if *stop.borrow() || tokio::time::Instant::now() >= deadline {
            return Ok(());
        }
        tokio::select! {
            _changed = stop.changed() => Ok(()),
            result = crate::update_peer::send(stream.stream, expected, file, stream.limits, deadline) => result.map_err(|_| ()),
        }
    } else {
        let permit = admission.try_acquire_owned().map_err(|_| ())?;
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            // Keep the capacity permit and provider operation owned until synchronous IO ends.
            // Dropping a network future cannot undo a pack write or journal commitment.
            let _permit = permit;
            let mut router = match targets.lock() {
                Ok(mut targets) => targets.data_router(now),
                Err(poisoned) => {
                    poisoned.into_inner().readiness.store_degraded(true);
                    Err(())
                }
            }?;
            if *stop.borrow() {
                return Ok(());
            }
            runtime.block_on(async {
                tokio::select! {
                    _changed = stop.changed() => Ok(()),
                    result = tokio::time::timeout(Duration::from_secs(30), router.serve_message(stream.stream, stream.peer, stream.limits, now, message)) => result.map_err(|_| ())?.map_err(|_| ()),
                }
            })
        }).await.map_err(|_| ())?
    }
}
