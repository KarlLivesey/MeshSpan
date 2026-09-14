// SPDX-License-Identifier: GPL-2.0-only

//! Bounded admitted private requests and their activation followups.

use super::{
    DaemonProcessError, PRIVATE_CONTROL_CONCURRENCY, PrivateNetworkStarter, ShutdownOutcome,
    handle_private_control, private_control_is_fetch, wait_for_shutdown,
};
use meshspan_cluster::{ConsensusNetwork, MetadataAuthorityHandle, PeerControlRequest};
use meshspan_protocol::v1::{ControlEnvelope, control_envelope::Message};
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex;
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::task::JoinSet;

#[derive(Clone)]
pub(super) struct PrivateControlService {
    network: ConsensusNetwork,
    authority: MetadataAuthorityHandle,
    directory: PathBuf,
    runtime: tokio::runtime::Handle,
    http01: crate::http01_gateway::Http01PeerReader,
    readiness: crate::update_readiness::UpdateReadiness,
    history: crate::native_gateway_sync::NativeGatewayHistory,
    mutations: Arc<Semaphore>,
    failed: watch::Sender<bool>,
    #[cfg(test)]
    admission_gate: Arc<Mutex<Option<crate::metadata_forwarding::AdmissionGate>>>,
}

pub(super) struct PrivateControlWork {
    #[cfg(test)]
    pub(super) admission_gate: Option<crate::metadata_forwarding::AdmissionGate>,
    pub(super) runtime: tokio::runtime::Handle,
    pub(super) followups: JoinSet<Result<PrivateFollowupOutcome, DaemonProcessError>>,
}

pub(super) enum PrivateFollowupOutcome {
    Completed,
    Unavailable,
}

impl PrivateControlService {
    pub(super) fn new(starter: &PrivateNetworkStarter, network: ConsensusNetwork) -> Self {
        Self {
            network,
            authority: starter.authority.clone(),
            directory: starter.state_directory.clone(),
            runtime: starter.runtime.clone(),
            http01: crate::http01_gateway::Http01PeerReader::new(&starter.state_directory),
            readiness: starter.update_readiness.clone(),
            history: crate::native_gateway_sync::NativeGatewayHistory::new(
                &starter.state_directory,
            ),
            mutations: Arc::new(Semaphore::new(1)),
            failed: starter.generation.failure_signal(),
            #[cfg(test)]
            admission_gate: Arc::clone(&starter.admission_gate),
        }
    }

    pub(super) async fn run(
        self,
        mut requests: mpsc::Receiver<PeerControlRequest>,
        stop: watch::Receiver<bool>,
    ) -> Result<(), DaemonProcessError> {
        let shutdown = wait_for_shutdown(stop);
        tokio::pin!(shutdown);
        let mut jobs = JoinSet::new();
        let mut outcome = ShutdownOutcome::default();
        loop {
            tokio::select! {
                biased;
                () = &mut shutdown => break,
                result = jobs.join_next(), if !jobs.is_empty() => {
                    if let Some(result) = result
                        && let Err(error) = resolve_control_job(result) {
                            outcome.record(Err(error));
                            // Withdraw readiness before waiting for other admitted request owners.
                            self.failed.send_replace(true);
                            break;
                    }
                }
                request = requests.recv(), if jobs.len() < PRIVATE_CONTROL_CONCURRENCY => {
                    let Some(request) = request else { break; };
                    let service = self.clone();
                    jobs.spawn(async move { service.handle(request).await });
                }
            }
        }
        // Only jobs admitted above can have effects. Closing/dropping queued requests leaves
        // their callers with unknown outcomes; it cannot undo an already admitted operation.
        requests.close();
        drop(requests);
        while let Some(result) = jobs.join_next().await {
            outcome.record(resolve_control_job(result));
        }
        outcome.finish()
    }

    async fn handle(&self, request: PeerControlRequest) -> Result<(), DaemonProcessError> {
        let permit = if private_control_is_fetch(&request) {
            None
        } else {
            Some(
                self.mutations
                    .acquire()
                    .await
                    .map_err(|_| DaemonProcessError::PrivateNetworkState)?,
            )
        };
        let mut work = PrivateControlWork {
            #[cfg(test)]
            admission_gate: self
                .admission_gate
                .lock()
                .map_err(|_| DaemonProcessError::PrivateNetworkState)?
                .take(),
            runtime: self.runtime.clone(),
            followups: JoinSet::new(),
        };
        let response = self.response(&request, &mut work).await;
        // Followups do not delay the response or retain the single mutation admission permit.
        drop(permit);
        match response {
            Ok(response) => match request.respond.send(response) {
                Ok(()) => {}
                Err(_response) => {} // Caller disconnected; committed work is still drained below.
            },
            // The response channel closes without a success receipt. A denied/malformed request
            // or unavailable authority is an operation outcome, not a failed generation.
            Err(_error) => {}
        }
        let mut infrastructure = ShutdownOutcome::default();
        while let Some(result) = work.followups.join_next().await {
            match result {
                // Remote unavailability is retryable operation failure. Temporary-file cleanup
                // and task infrastructure failures below remain in the generation shutdown report.
                Ok(Ok(PrivateFollowupOutcome::Completed | PrivateFollowupOutcome::Unavailable)) => {
                }
                Ok(Err(error)) => infrastructure.record(Err(error)),
                Err(_error) => infrastructure.record(Err(DaemonProcessError::PrivateNetworkState)),
            }
        }
        infrastructure.finish()
    }

    async fn response(
        &self,
        request: &PeerControlRequest,
        work: &mut PrivateControlWork,
    ) -> Result<ControlEnvelope, DaemonProcessError> {
        match request.envelope.as_inner().message {
            Some(Message::FetchHttp01Challenge(_)) => self
                .http01
                .handle(&self.network, request)
                .await
                .map_err(|()| DaemonProcessError::PrivateNetworkState),
            Some(Message::ProbeUpdateReadiness(_)) => self
                .readiness
                .handle(&self.network, request)
                .await
                .map_err(|()| DaemonProcessError::PrivateNetworkState),
            _ => {
                handle_private_control(
                    &self.network,
                    &self.authority,
                    &self.directory,
                    &self.history,
                    work,
                    request,
                )
                .await
            }
        }
    }
}

fn resolve_control_job(
    result: Result<Result<(), DaemonProcessError>, tokio::task::JoinError>,
) -> Result<(), DaemonProcessError> {
    result.map_err(|_| DaemonProcessError::PrivateNetworkState)?
}
