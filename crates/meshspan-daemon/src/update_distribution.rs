// SPDX-License-Identifier: GPL-2.0-only

//! One owned, restart-recoverable candidate fetcher per daemon, separate from restart admission.

use super::{UpdateError, UpdateService};
use crate::{
    ConsensusAuthenticationAuthority, GatewaySessionIdentity, IdentityAdministrator,
    private_consensus_runtime::PrivateConsensusRuntime,
    update_artifact_store::{ArtifactReader, UpdateArtifactStore},
    update_peer,
};
use meshspan_domain::{Clock as _, NodeId, OperationId, WorkId, uuid_v8};
use meshspan_metadata::{PageLimit, UpdateRolloutRecord};
use meshspan_protocol::v1::{GetUpdateArtifactRequest, UpdateArtifactIdentity};
use meshspan_transport::{AcceptedStream, StreamKind, open_stream};
use sha2::{Digest as _, Sha256};
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

pub(crate) struct UpdateDistribution {
    service: UpdateService,
    network: Arc<PrivateConsensusRuntime>,
    directory: PathBuf,
    verified: Option<(WorkId, String)>,
    source_cursor: Option<NodeId>,
}

impl UpdateDistribution {
    pub(crate) fn new(
        authority: ConsensusAuthenticationAuthority,
        gateway: GatewaySessionIdentity,
        network: Arc<PrivateConsensusRuntime>,
        directory: PathBuf,
    ) -> Self {
        Self {
            service: UpdateService::new(authority, gateway),
            network,
            directory,
            verified: None,
            source_cursor: None,
        }
    }

    pub(crate) async fn run_until(mut self, mut stop: tokio::sync::watch::Receiver<bool>) {
        loop {
            if *stop.borrow() {
                return;
            }
            tokio::select! {
                _changed = stop.changed() => return,
                () = tokio::time::sleep(Duration::from_secs(2)) => {}
            }
            let handle = tokio::runtime::Handle::current();
            let stopping = stop.clone();
            // Exactly one owned fetch job per daemon. Shutdown interrupts transport, then
            // observes cache cleanup; no failed update takes down file or consensus service.
            let result = tokio::task::spawn_blocking(move || {
                let outcome = handle.block_on(self.run_once(stopping));
                (self, outcome)
            })
            .await;
            if let Ok((returned, _retryable_outcome)) = result {
                self = returned;
            } else {
                // A stopped updater does not terminate healthy filesystem services.
                let _shutdown = stop.wait_for(|stopping| *stopping).await;
                return;
            }
        }
    }

    async fn run_once(
        &mut self,
        stop: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), update_peer::UpdatePeerError> {
        let Some(active) = self.service.authority.reader().active_update_rollout()? else {
            return Ok(());
        };
        let record = update_peer::candidate(self.service.authority.reader(), active.rollout_id)?;
        let target = local_target()?;
        if self
            .verified
            .as_ref()
            .is_some_and(|(id, platform)| *id == record.rollout_id && platform == target)
        {
            return Ok(());
        }
        let expected = update_peer::identity(record.rollout_id, &record.manifest, target)?;
        let store = UpdateArtifactStore::open(&self.directory)?;
        match store.open_verified(&record.manifest, target) {
            Ok(_verified_file) => {}
            Err(crate::update_artifact_store::ArtifactStoreError::Io(error))
                if error.kind() == std::io::ErrorKind::NotFound =>
            {
                self.fetch(&record, &expected, stop).await?;
            }
            Err(error) => return Err(error.into()),
        }
        self.advertise(&record, target)
            .map_err(|_| update_peer::UpdatePeerError::Unavailable)?;
        self.verified = Some((record.rollout_id, target.to_owned()));
        self.source_cursor = None;
        Ok(())
    }

    async fn fetch(
        &mut self,
        record: &UpdateRolloutRecord,
        expected: &UpdateArtifactIdentity,
        mut stop: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), update_peer::UpdatePeerError> {
        let sources = self.service.authority.reader().update_artifact_sources(
            record.rollout_id,
            &expected.target,
            self.source_cursor,
            PageLimit::new(1).map_err(|_| update_peer::UpdatePeerError::Rejected)?,
        )?;
        let Some(source) = sources.first() else {
            self.source_cursor = None;
            return Err(update_peer::UpdatePeerError::Unavailable);
        };
        self.source_cursor = Some(source.node_id);
        if source.node_id == self.service.gateway.node_id {
            return Err(update_peer::UpdatePeerError::Unavailable);
        }
        let network = self
            .network
            .network()
            .map_err(|()| update_peer::UpdatePeerError::Unavailable)?;
        let directory = self.directory.clone();
        let manifest = record.manifest.clone();
        let target = expected.target.clone();
        let (chunks, mut reader) = ArtifactReader::channel(Instant::now() + update_peer::DEADLINE);
        let cache = tokio::task::spawn_blocking(move || {
            UpdateArtifactStore::open(&directory)?.stage(&manifest, &target, &mut reader)
        });
        let transfer = async {
            let connection = network
                .connect_data_peer(source.node_id)
                .await
                .map_err(|_| update_peer::UpdatePeerError::Unavailable)?;
            let (send, receive) = open_stream(&connection, StreamKind::Data).await?;
            let now = crate::OperatingSystemClock.now();
            let deadline = now
                .get()
                .checked_add(1_800_000_000)
                .ok_or(update_peer::UpdatePeerError::Rejected)?;
            let operation = operation(record.rollout_id, self.service.gateway, &expected.target)?;
            let header = network
                .control_header(operation, deadline)
                .map_err(|_| update_peer::UpdatePeerError::Unavailable)?;
            update_peer::receive(
                AcceptedStream {
                    kind: StreamKind::Data,
                    send,
                    receive,
                },
                GetUpdateArtifactRequest {
                    header: Some(header),
                    artifact: Some(expected.clone()),
                },
                chunks,
                network.wire_limits(),
            )
            .await
        };
        let transferred = tokio::select! {
            _changed = stop.changed() => Err(update_peer::UpdatePeerError::Unavailable),
            result = tokio::time::timeout(update_peer::DEADLINE, transfer) => result.map_err(|_| update_peer::UpdatePeerError::Unavailable).and_then(|value| value),
        };
        let stored = cache
            .await
            .map_err(|_| update_peer::UpdatePeerError::Unavailable)?;
        transferred?;
        stored?;
        Ok(())
    }

    fn advertise(&self, record: &UpdateRolloutRecord, target: &str) -> Result<(), UpdateError> {
        let operation = operation(record.rollout_id, self.service.gateway, target)
            .map_err(|_| UpdateError::Failed)?;
        let id = meshspan_api_contract::OperationId::parse(&crate::create_mesh_setup::format_uuid(
            operation.as_bytes(),
        ))
        .ok_or(UpdateError::Failed)?;
        self.service.publish_artifact(
            IdentityAdministrator {
                principal_id: record.created_by,
                now: crate::OperatingSystemClock.now(),
            },
            id,
            record.rollout_id,
            target.to_owned(),
        )?;
        Ok(())
    }
}

fn operation(
    rollout: WorkId,
    gateway: GatewaySessionIdentity,
    target: &str,
) -> Result<OperationId, update_peer::UpdatePeerError> {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.update.source.v1\0");
    digest.update(rollout.as_bytes());
    digest.update(gateway.node_id.as_bytes());
    digest.update(gateway.incarnation.to_be_bytes());
    digest.update(target.as_bytes());
    let bytes: [u8; 32] = digest.finalize().into();
    OperationId::from_bytes(uuid_v8(
        bytes[..16]
            .try_into()
            .map_err(|_| update_peer::UpdatePeerError::Rejected)?,
    ))
    .map_err(|_| update_peer::UpdatePeerError::Rejected)
}

fn local_target() -> Result<&'static str, update_peer::UpdatePeerError> {
    match (std::env::consts::ARCH, std::env::consts::OS) {
        ("aarch64", "macos") => Ok("aarch64-apple-darwin"),
        ("x86_64", "macos") => Ok("x86_64-apple-darwin"),
        ("aarch64", "linux") => Ok("aarch64-unknown-linux-musl"),
        ("x86_64", "linux") => Ok("x86_64-unknown-linux-musl"),
        _ => Err(update_peer::UpdatePeerError::Rejected),
    }
}
