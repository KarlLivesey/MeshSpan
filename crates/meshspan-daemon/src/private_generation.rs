// SPDX-License-Identifier: GPL-2.0-only

//! Fixed private-service ownership for one appliance generation.

use super::{
    DaemonProcessError, PrivateAuthorityRuntime, PrivateNetworkStarter, ShutdownOutcome,
    load_active_peer_routes, open_root_repository_at, private_control_runtime,
    private_network_bootstrap, reconcile_active_peer_routes, wait_for_shutdown,
};
use meshspan_cluster::{ConsensusNetwork, PeerConsensusMessage, PeerControlRequest};
use meshspan_domain::UnixMicros;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::JoinHandle;

type PrivateTask = JoinHandle<Result<(), DaemonProcessError>>;

pub(super) struct PrivateGeneration {
    // Serializes synchronous startup/registration against closing admission. Never held across await.
    tasks: Mutex<PrivateTasks>,
    stop: watch::Sender<bool>,
    failed: watch::Sender<bool>,
    #[cfg(test)]
    pub(super) control_requests: Mutex<Option<tokio::sync::mpsc::Sender<PeerControlRequest>>>,
}

#[derive(Default)]
struct PrivateTasks {
    closed: bool,
    topology: Option<PrivateTask>,
    peers: Option<PrivateTask>,
    controls: Option<PrivateTask>,
    starting_network: Option<ConsensusNetwork>,
}

impl PrivateGeneration {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            tasks: Mutex::new(PrivateTasks::default()),
            stop: watch::channel(false).0,
            failed: watch::channel(false).0,
            #[cfg(test)]
            control_requests: Mutex::new(None),
        })
    }

    pub(super) fn stop_admission(&self) -> Result<(), DaemonProcessError> {
        let (mut tasks, poisoned) = match self.tasks.lock() {
            Ok(tasks) => (tasks, false),
            Err(error) => (error.into_inner(), true),
        };
        tasks.closed = true;
        self.stop.send_replace(true);
        if poisoned {
            Err(DaemonProcessError::PrivateNetworkState)
        } else {
            Ok(())
        }
    }

    #[cfg(test)]
    pub(super) async fn stopped(&self) {
        wait_for_shutdown(self.stop.subscribe()).await;
    }

    pub(super) fn failure_signal(&self) -> watch::Sender<bool> {
        self.failed.clone()
    }

    pub(super) async fn failed(&self) {
        wait_for_shutdown(self.failed.subscribe()).await;
    }

    fn spawn<F>(&self, runtime: &tokio::runtime::Handle, work: F) -> PrivateTask
    where
        F: Future<Output = Result<(), DaemonProcessError>> + Send + 'static,
    {
        let exit = PrivateWorkerExit {
            stop: self.stop.subscribe(),
            failed: self.failed.clone(),
        };
        runtime.spawn(async move {
            // Includes panic unwinding: unexpected worker disappearance withdraws public readiness.
            let _exit = exit;
            work.await
        })
    }

    async fn drain_producers(&self, outcome: &mut ShutdownOutcome) {
        let (topology, controls) = {
            let mut tasks = match self.tasks.lock() {
                Ok(tasks) => tasks,
                Err(error) => {
                    outcome.record(Err(DaemonProcessError::PrivateNetworkState));
                    error.into_inner()
                }
            };
            (tasks.topology.take(), tasks.controls.take())
        };
        observe_private_task(topology, outcome).await;
        observe_private_task(controls, outcome).await;
    }

    async fn drain_peers(&self, outcome: &mut ShutdownOutcome) {
        let task = {
            let mut tasks = match self.tasks.lock() {
                Ok(tasks) => tasks,
                Err(error) => {
                    outcome.record(Err(DaemonProcessError::PrivateNetworkState));
                    error.into_inner()
                }
            };
            tasks.peers.take()
        };
        observe_private_task(task, outcome).await;
    }
}

struct PrivateWorkerExit {
    stop: watch::Receiver<bool>,
    failed: watch::Sender<bool>,
}

impl Drop for PrivateWorkerExit {
    fn drop(&mut self) {
        if !*self.stop.borrow() {
            self.failed.send_replace(true);
        }
    }
}

async fn observe_private_task(task: Option<PrivateTask>, outcome: &mut ShutdownOutcome) {
    if let Some(task) = task {
        outcome.record(
            task.await
                .map_err(|_| DaemonProcessError::PrivateNetworkState)
                .and_then(|result| result),
        );
    }
}

impl PrivateAuthorityRuntime {
    pub(super) async fn drain(self, outcome: &mut ShutdownOutcome) {
        let generation = &self.network_starter.generation;
        outcome.record(generation.stop_admission());
        generation.drain_producers(outcome).await;
        let pending = {
            let mut tasks = match generation.tasks.lock() {
                Ok(tasks) => tasks,
                Err(error) => {
                    outcome.record(Err(DaemonProcessError::PrivateNetworkState));
                    error.into_inner()
                }
            };
            tasks.starting_network.take()
        };
        if let Some(network) = pending {
            outcome.record(
                network
                    .shutdown()
                    .await
                    .map_err(|_| DaemonProcessError::PrivateNetworkState),
            );
        }
        outcome.record(
            self.network_starter
                .network
                .shutdown()
                .await
                .map_err(|()| DaemonProcessError::PrivateNetworkState),
        );
        generation.drain_peers(outcome).await;
        outcome.record(self.authority.shutdown().await.map_err(Into::into));
        outcome.record(
            self.authority_task
                .await
                .map_err(|_| DaemonProcessError::AuthorityTaskStopped)
                .and_then(|result| result.map_err(Into::into)),
        );
    }
}

impl PrivateNetworkStarter {
    pub(super) fn start(&self, now: UnixMicros) -> Result<(), DaemonProcessError> {
        let mut tasks = self
            .generation
            .tasks
            .lock()
            .map_err(|_| DaemonProcessError::PrivateNetworkState)?;
        if tasks.closed {
            return Err(DaemonProcessError::PrivateNetworkState);
        }
        if self.network.network().is_ok() {
            return self.start_topology(&mut tasks, now);
        }
        let (messages, received_messages) = tokio::sync::mpsc::channel(256);
        let (controls, received_controls) = tokio::sync::mpsc::channel(64);
        #[cfg(test)]
        {
            *self
                .generation
                .control_requests
                .lock()
                .map_err(|_| DaemonProcessError::PrivateNetworkState)? = Some(controls.clone());
        }
        let config = private_network_bootstrap::configuration(
            &self.state_directory,
            self.local_node_id,
            &self.local_private_key_pkcs8,
            self.listen_address,
            now,
        )?;
        let network = {
            let _entered = self.runtime.enter();
            ConsensusNetwork::start_with_control_and_data(
                config,
                messages,
                controls,
                self.data_streams.clone(),
            )?
        };
        // The gate guarantees this generation is the only installer. Keep a failed installation's
        // live network reachable by the cycle cleanup path as well.
        tasks.starting_network = Some(network.clone());
        self.network
            .install(network.clone())
            .map_err(|()| DaemonProcessError::PrivateNetworkState)?;
        tasks.starting_network = None;
        tasks.peers = Some(self.peer_dispatch(received_messages));
        tasks.controls = Some(self.control_dispatch(network, received_controls));
        self.start_topology(&mut tasks, now)
    }

    pub(super) fn start_joined_receivers(
        &self,
        peers: Option<tokio::sync::mpsc::Receiver<PeerConsensusMessage>>,
        controls: Option<tokio::sync::mpsc::Receiver<PeerControlRequest>>,
    ) -> Result<(), DaemonProcessError> {
        let mut tasks = self
            .generation
            .tasks
            .lock()
            .map_err(|_| DaemonProcessError::PrivateNetworkState)?;
        if tasks.closed {
            return Err(DaemonProcessError::PrivateNetworkState);
        }
        if (peers.is_some() && tasks.peers.is_some())
            || (controls.is_some() && tasks.controls.is_some())
        {
            return Err(DaemonProcessError::PrivateNetworkState);
        }
        if let Some(peers) = peers {
            tasks.peers = Some(self.peer_dispatch(peers));
        }
        if let Some(controls) = controls {
            let network = self
                .network
                .network()
                .map_err(|()| DaemonProcessError::PrivateNetworkState)?;
            tasks.controls = Some(self.control_dispatch(network, controls));
        }
        Ok(())
    }

    fn start_topology(
        &self,
        tasks: &mut PrivateTasks,
        now: UnixMicros,
    ) -> Result<(), DaemonProcessError> {
        if tasks.topology.is_some() {
            return Ok(());
        }
        let repository = open_root_repository_at(&self.state_directory, now)?;
        let network = Arc::clone(&self.network);
        let local = self.local_node_id;
        let stop = self.generation.stop.subscribe();
        tasks.topology = Some(self.generation.spawn(&self.runtime, async move {
            let shutdown = wait_for_shutdown(stop);
            tokio::pin!(shutdown);
            let mut interval = tokio::time::interval(Duration::from_millis(250));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! { biased; () = &mut shutdown => return Ok(()), _ = interval.tick() => {} }
                let Ok(active) = network.network() else { continue; };
                let Ok(routes) = load_active_peer_routes(&repository, local) else { continue; };
                reconcile_active_peer_routes(&active, routes).await;
            }
        }));
        Ok(())
    }

    fn peer_dispatch(
        &self,
        mut messages: tokio::sync::mpsc::Receiver<PeerConsensusMessage>,
    ) -> PrivateTask {
        let authority = self.authority.clone();
        self.generation.spawn(&self.runtime, async move {
            while let Some(message) = messages.recv().await {
                authority.receive_peer(message).await?;
            }
            Ok(())
        })
    }

    fn control_dispatch(
        &self,
        network: ConsensusNetwork,
        requests: tokio::sync::mpsc::Receiver<PeerControlRequest>,
    ) -> PrivateTask {
        let service = private_control_runtime::PrivateControlService::new(self, network);
        let stop = self.generation.stop.subscribe();
        self.generation
            .spawn(&self.runtime, service.run(requests, stop))
    }
}
