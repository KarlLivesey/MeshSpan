// SPDX-License-Identifier: GPL-2.0-only

//! Fresh authenticated process observations. This endpoint does not authorise a restart.

use meshspan_cluster::{ConsensusNetwork, MetadataAuthorityHandle, PeerControlRequest};
use meshspan_domain::{Clock as _, NodeId, OperationId, WorkId};
use meshspan_metadata::{AuthoritativeRepository, PartitionDatabase};
use meshspan_protocol::v1::{
    ControlEnvelope, RequestHeader, UpdateReadinessResult, control_envelope::Message,
};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::Semaphore;

#[derive(Clone)]
pub(crate) struct UpdateReadiness {
    authority: MetadataAuthorityHandle,
    database: PathBuf,
    reader: Arc<Mutex<Option<AuthoritativeRepository>>>,
    listeners: Arc<AtomicBool>,
    admission: Arc<Semaphore>,
    runtime_report: Arc<Vec<u8>>,
}

impl UpdateReadiness {
    pub(crate) fn new(directory: &Path, authority: MetadataAuthorityHandle) -> Result<Self, ()> {
        let report = crate::update_runtime_info::report().map_err(|_| ())?;
        Ok(Self {
            authority,
            database: directory.join("root-authority.sqlite3"),
            reader: Arc::default(),
            listeners: Arc::default(),
            admission: Arc::new(Semaphore::new(2)),
            runtime_report: Arc::new(serde_json::to_vec(&report).map_err(|_| ())?),
        })
    }

    /// Called only after all public listeners bind. Drop withdraws the claim on every exit path.
    pub(crate) fn serving(&self) -> ServingGuard {
        self.listeners.store(true, Ordering::Release);
        ServingGuard(Arc::clone(&self.listeners))
    }

    pub(crate) async fn handle(
        &self,
        network: &ConsensusNetwork,
        request: &PeerControlRequest,
    ) -> Result<ControlEnvelope, ()> {
        let envelope = request.envelope.as_inner();
        let header = envelope.header.as_ref().ok_or(())?;
        let Some(Message::ProbeUpdateReadiness(query)) = &envelope.message else {
            return Err(());
        };
        let operation =
            OperationId::from_bytes(header.operation_id.as_slice().try_into().map_err(|_| ())?)
                .map_err(|_| ())?;
        let rollout = WorkId::from_bytes(query.rollout_id.as_slice().try_into().map_err(|_| ())?)
            .map_err(|_| ())?;
        let permit = Arc::clone(&self.admission)
            .try_acquire_owned()
            .map_err(|_| ())?;
        let source = self.clone();
        let from = request.from;
        let incarnation = request.sender_incarnation;
        let header = header.clone();
        let read_header = header.clone();
        let _permit = tokio::task::spawn_blocking(move || {
            source.admit(&read_header, from, incarnation, rollout)?;
            Ok(permit)
        })
        .await
        .map_err(|_| ())??;
        let observed = self.authority.observe().await.map_err(|_| ())?;
        if observed.node_id != network.local_node_id()
            || observed.partition_id.as_bytes() != header.partition_id.as_slice()
            || observed.plan_digest.as_slice() != query.quorum_plan_digest
            || observed.applied_index < query.minimum_applied_index
            || header.deadline_unix_micros <= crate::OperatingSystemClock.now().get()
        {
            return Err(());
        }
        Ok(ControlEnvelope {
            header: Some(
                network
                    .control_header(operation, header.deadline_unix_micros)
                    .map_err(|_| ())?,
            ),
            message: Some(Message::UpdateReadinessResult(UpdateReadinessResult {
                rollout_id: query.rollout_id.clone(),
                node_id: observed.node_id.as_bytes().to_vec(),
                incarnation: network.local_incarnation(),
                quorum_plan_digest: observed.plan_digest.to_vec(),
                applied_index: observed.applied_index,
                committed_index: observed.commit_index,
                persistence_blocked: observed.persistence_blocked,
                listeners_bound: self.listeners.load(Ordering::Acquire),
                runtime_report: self.runtime_report.as_ref().clone(),
                observed_at_unix_micros: crate::OperatingSystemClock.now().get(),
            })),
        })
    }

    /// One indexed authority read, separate from the live reactor observation.
    fn admit(
        &self,
        header: &RequestHeader,
        from: NodeId,
        incarnation: u64,
        rollout: WorkId,
    ) -> Result<(), ()> {
        let now = crate::OperatingSystemClock.now();
        let remaining = header
            .deadline_unix_micros
            .checked_sub(now.get())
            .ok_or(())?;
        if !(1..=5_000_000).contains(&remaining) {
            return Err(());
        }
        let mut reader = self.reader.lock().map_err(|_| ())?;
        if reader.is_none() {
            *reader = Some(AuthoritativeRepository::new(
                PartitionDatabase::open_existing(&self.database, now).map_err(|_| ())?,
            ));
        }
        let repository = reader.as_ref().ok_or(())?;
        let mesh = repository.local_mesh_id().map_err(|_| ())?.ok_or(())?;
        let certificate = repository
            .active_node_certificate(from)
            .map_err(|_| ())?
            .ok_or(())?;
        if header.mesh_id != mesh.as_bytes()
            || header.partition_id != repository.partition_id().as_bytes()
            || header.sender_node_id != from.as_bytes()
            || header.sender_incarnation != incarnation
            || certificate.incarnation != incarnation
            || certificate.valid_until <= now
        {
            return Err(());
        }
        crate::update_peer::candidate(repository, rollout).map_err(|_| ())?;
        Ok(())
    }
}

pub(crate) struct ServingGuard(Arc<AtomicBool>);
impl Drop for ServingGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
