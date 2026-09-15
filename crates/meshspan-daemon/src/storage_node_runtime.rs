// SPDX-License-Identifier: GPL-2.0-only

//! Non-member storage composition. No synthetic authority handle or gateway key access.

use super::storage_node_certificates::StorageNodeCertificates;
use super::storage_node_providers::StorageNodeProviders;
use super::{
    DaemonCycleExit, DaemonNodeRuntime, DaemonProcessError, ROOT_AUTHORITY_DATABASE,
    RuntimeReadiness, current_time, load_active_peer_routes, open_root_repository,
    open_root_repository_at, private_network_bootstrap, reconcile_active_peer_routes,
    wait_for_shutdown,
};
use crate::{
    HeadlessDaemonConfig, HttpsServer, HttpsServerError, SetupStatusSource,
    public_contract_api_router,
};
use meshspan_api_contract::SetupState;
use meshspan_cluster::{
    ConsensusNetwork, ConsensusNetworkConfig, MetadataReplicaRuntimeConfig,
    MetadataReplicaRuntimeExit, MetadataReplicaRuntimeHandle, PeerConsensusMessage,
    PeerControlRequest, PeerDataStream, spawn_metadata_replica,
};
use meshspan_domain::UnixMicros;
use meshspan_metadata::JoinRoles;
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

/// Select the service path from committed role and membership, never from a command-line hint.
pub(super) fn required(
    node: &DaemonNodeRuntime,
    now: UnixMicros,
) -> Result<bool, DaemonProcessError> {
    if node.setup_state.setup_state() != SetupState::Configured {
        return Ok(false);
    }
    let repo = open_root_repository(&node.local_state, now)?;
    let id = node.local_state.node_id();
    let plan = repo
        .load_active_consensus_quorum_plan()?
        .ok_or(DaemonProcessError::PrivateNetworkState)?;
    let certificate = repo
        .active_node_certificate(id)?
        .ok_or(DaemonProcessError::PrivateNetworkState)?;
    Ok(!plan.members().contains(&id)
        && certificate.roles.bits() & JoinRoles::STORAGE != 0
        && certificate.roles.bits() & JoinRoles::GATEWAY == 0)
}

pub(super) async fn run<F: Future<Output = ()> + Send>(
    node: DaemonNodeRuntime,
    config: &HeadlessDaemonConfig,
    shutdown: Pin<&mut F>,
) -> Result<DaemonCycleExit, DaemonProcessError> {
    let network = Arc::clone(&node.private_network);
    let result = run_inner(node, config, shutdown).await;
    let mut outcome = super::ShutdownOutcome::default();
    let exit = match result {
        Ok(exit) => Some(exit),
        Err(error) => {
            outcome.record(Err(error));
            None
        }
    };
    outcome.record(
        network
            .shutdown()
            .await
            .map_err(|()| DaemonProcessError::PrivateNetworkState),
    );
    outcome.finish()?;
    exit.ok_or(DaemonProcessError::PrivateNetworkState)
}

async fn run_inner<F: Future<Output = ()> + Send>(
    node: DaemonNodeRuntime,
    config: &HeadlessDaemonConfig,
    shutdown: Pin<&mut F>,
) -> Result<DaemonCycleExit, DaemonProcessError> {
    let paths = config.storage().storage_paths().to_vec();
    let listen = config.private_listen();
    let runtime = tokio::runtime::Handle::current();
    let (mut node, network_config, providers, certificates, tls) =
        tokio::task::spawn_blocking(move || {
            let now = current_time()?;
            let network_config = private_network_bootstrap::configuration(
                node.local_state.state_directory(),
                node.local_state.node_id(),
                node.local_state.node_identity_private_key_pkcs8(),
                listen,
                now,
            )?;
            let providers = StorageNodeProviders::new(&node, paths, &runtime, now)?;
            let certificates = StorageNodeCertificates::new(&node)?;
            let tls = node.local_state.bootstrap_server_config()?;
            Ok::<_, DaemonProcessError>((node, network_config, providers, certificates, tls))
        })
        .await
        .map_err(|_| DaemonProcessError::LocalStateWorker)??;
    let streams = node
        .received_data_streams
        .take()
        .ok_or(DaemonProcessError::PrivateNetworkState)?;
    let providers = Arc::new(Mutex::new(providers));
    let readiness = Arc::new(RuntimeReadiness::default());
    // This narrow service is configured, but does not yet prove privileged-operation readiness.
    readiness.store_degraded(true);
    let router = crate::setup_api_router(Arc::clone(&node.setup_state))?
        .merge(public_contract_api_router(readiness)?);
    let https = HttpsServer::bind(config.https_listen(), tls, router).await?;
    let (network, peers, controls) = start_network(&mut node, network_config).await?;
    let (stop, stopped) = watch::channel(false);
    let replica = spawn_metadata_replica(
        MetadataReplicaRuntimeConfig {
            database_path: node
                .local_state
                .state_directory()
                .join(ROOT_AUTHORITY_DATABASE),
            partition_id: network.partition_id(),
            local_node_id: network.local_node_id(),
        },
        network.clone(),
        crate::OperatingSystemClock,
        stopped.clone(),
    );
    let Ok((replica_handle, replica_task)) = replica else {
        network
            .shutdown()
            .await
            .map_err(|_| DaemonProcessError::PrivateNetworkState)?;
        return Err(DaemonProcessError::PrivateNetworkState);
    };
    let https_stop = stopped.clone();
    let https_task =
        tokio::spawn(async move { https.run_until(wait_for_shutdown(https_stop)).await });
    let reporter = crate::node_capability_reporting::NodeCapabilityReporter::new(
        node.local_state.state_directory().to_path_buf(),
        Arc::clone(&node.private_network),
        None,
    );
    let capability_task = tokio::spawn(reporter.run_until(stopped.clone()));
    let mut cycle = StorageCycle {
        node,
        network,
        providers,
        certificates: Arc::new(Mutex::new(certificates)),
        stop,
        peers,
        controls,
        streams,
        replica: Some(replica_task),
        replica_handle,
        https: Some(https_task),
        capabilities: Some(capability_task),
        maintenance: None,
        jobs: tokio::task::JoinSet::new(),
    };
    let outcome = cycle.serve_until(shutdown).await;
    let mut errors = super::ShutdownOutcome::default();
    let exit = match outcome {
        Ok(exit) => Some(exit),
        Err(error) => {
            errors.record(Err(error));
            None
        }
    };
    errors.record(cycle.drain().await);
    errors.finish()?;
    exit.ok_or(DaemonProcessError::PrivateNetworkState)
}

/// Owns every cycle task until observed, including after a listener or worker fails.
struct StorageCycle {
    node: DaemonNodeRuntime,
    network: ConsensusNetwork,
    providers: Arc<Mutex<StorageNodeProviders>>,
    certificates: Arc<Mutex<StorageNodeCertificates>>,
    stop: watch::Sender<bool>,
    peers: mpsc::Receiver<PeerConsensusMessage>,
    controls: mpsc::Receiver<PeerControlRequest>,
    streams: mpsc::Receiver<PeerDataStream>,
    replica: Option<JoinHandle<MetadataReplicaRuntimeExit>>,
    replica_handle: MetadataReplicaRuntimeHandle,
    https: Option<JoinHandle<Result<(), HttpsServerError>>>,
    maintenance: Option<JoinHandle<Result<(), ()>>>,
    capabilities: Option<JoinHandle<Result<(), meshspan_cluster::MetadataAuthorityRequestError>>>,
    jobs: tokio::task::JoinSet<Result<(), ()>>,
}

impl StorageCycle {
    async fn serve_until<F: Future<Output = ()> + Send>(
        &mut self,
        mut shutdown: Pin<&mut F>,
    ) -> Result<DaemonCycleExit, DaemonProcessError> {
        let mut tick = tokio::time::interval(Duration::from_millis(250));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                () = &mut shutdown => return Ok(DaemonCycleExit::Shutdown),
                result = wait_task(&mut self.replica) => {
                    self.replica = None;
                    return match result {
                        Ok(MetadataReplicaRuntimeExit::MembershipAdmitted) => Ok(DaemonCycleExit::RestartRequested),
                        Ok(MetadataReplicaRuntimeExit::Stopped) | Err(_) => Err(DaemonProcessError::AuthorityTaskStopped),
                    };
                }
                result = wait_task(&mut self.capabilities) => {
                    self.capabilities = None;
                    return result.map_err(|_| DaemonProcessError::AuthorityTaskStopped)?
                        .map(|()| DaemonCycleExit::Shutdown).map_err(|_| DaemonProcessError::PrivateNetworkState);
                }
                result = wait_task(&mut self.https) => {
                    self.https = None;
                    return result.map_err(|_| DaemonProcessError::ListenerTaskStopped)?
                        .map(|()| DaemonCycleExit::Shutdown).map_err(Into::into);
                }
                _ = tick.tick(), if self.maintenance.is_none() => {
                    self.maintenance = Some(spawn_reconcile(&self.node, &self.network, Arc::clone(&self.providers), Arc::clone(&self.certificates)));
                }
                result = wait_task(&mut self.maintenance) => {
                    self.maintenance = None;
                    if result.is_err() { return Err(DaemonProcessError::LocalStateWorker); }
                    // Target/authority failures remain retryable; this path advertises degraded health.
                }
                Some(_message) = self.peers.recv() => {}, // Non-members never vote or acknowledge append.
                Some(request) = self.controls.recv() => { drop(request); }, // No local control authority.
                Some(result) = self.jobs.join_next(), if !self.jobs.is_empty() => {
                    if result.is_err() { return Err(DaemonProcessError::ListenerTaskStopped); }
                    // A denied or disconnected request affects its caller, not the listener.
                }
                Some(stream) = self.streams.recv(), if self.jobs.len() < 4 => {
                    let providers = Arc::clone(&self.providers);
                    let stop = self.stop.subscribe();
                    let admission = MaintenanceAdmission {
                        directory: self.node.local_state.state_directory().to_path_buf(),
                        network: self.network.clone(),
                        replica: self.replica_handle.clone(),
                    };
                    self.jobs.spawn(async move { serve(providers, stream, stop, admission).await });
                }
            }
        }
    }

    async fn drain(mut self) -> Result<(), DaemonProcessError> {
        self.stop.send_replace(true);
        let mut failed = false;
        while let Some(result) = self.jobs.join_next().await {
            failed |= result.is_err(); // Protocol errors are already returned to their caller.
        }
        if let Some(task) = self.capabilities {
            failed |= !matches!(task.await, Ok(Ok(())));
        }
        if let Some(task) = self.maintenance {
            failed |= task.await.is_err();
        }
        if let Some(task) = self.replica {
            failed |= task.await.is_err();
        }
        if let Some(task) = self.https {
            failed |= !matches!(task.await, Ok(Ok(())));
        }
        failed |= self.network.shutdown().await.is_err();
        if failed {
            Err(DaemonProcessError::ListenerTaskStopped)
        } else {
            Ok(())
        }
    }
}

async fn wait_task<T>(task: &mut Option<JoinHandle<T>>) -> Result<T, tokio::task::JoinError> {
    match task {
        Some(task) => task.await,
        None => std::future::pending().await,
    }
}

pub(super) async fn start_network(
    node: &mut DaemonNodeRuntime,
    config: ConsensusNetworkConfig,
) -> Result<
    (
        ConsensusNetwork,
        mpsc::Receiver<PeerConsensusMessage>,
        mpsc::Receiver<PeerControlRequest>,
    ),
    DaemonProcessError,
> {
    if let Ok(network) = node.private_network.network() {
        initialise_peer_routes(node, &network).await?;
        return Ok((
            network,
            node.joining_peer_messages
                .take()
                .ok_or(DaemonProcessError::PrivateNetworkState)?,
            node.joining_control_requests
                .take()
                .ok_or(DaemonProcessError::PrivateNetworkState)?,
        ));
    }
    let (peers, received_peers) = mpsc::channel(32);
    let (controls, received_controls) = mpsc::channel(32);
    let network = ConsensusNetwork::start_with_control_and_data(
        config,
        peers,
        controls,
        node.data_streams.clone(),
    )?;
    if node.private_network.install(network.clone()).is_err() {
        let mut outcome = super::ShutdownOutcome::default();
        outcome.record(Err(DaemonProcessError::PrivateNetworkState));
        outcome.record(
            network
                .shutdown()
                .await
                .map_err(|_| DaemonProcessError::PrivateNetworkState),
        );
        return outcome
            .finish()
            .and(Err(DaemonProcessError::PrivateNetworkState));
    }
    initialise_peer_routes(node, &network).await?;
    Ok((network, received_peers, received_controls))
}

/// Bootstrap transport starts without peers. Try committed routes before HTTPS exposes setup
/// status; periodic maintenance still retries unavailable routes and refreshes certificate overlap.
async fn initialise_peer_routes(
    node: &DaemonNodeRuntime,
    network: &ConsensusNetwork,
) -> Result<(), DaemonProcessError> {
    let directory = node.local_state.state_directory().to_path_buf();
    let local = node.local_state.node_id();
    let routes = tokio::task::spawn_blocking(move || {
        let repository = open_root_repository_at(&directory, current_time()?)?;
        load_active_peer_routes(&repository, local)
    })
    .await
    .map_err(|_| DaemonProcessError::LocalStateWorker)??;
    reconcile_active_peer_routes(network, routes).await;
    Ok(())
}

fn spawn_reconcile(
    node: &DaemonNodeRuntime,
    network: &ConsensusNetwork,
    providers: Arc<Mutex<StorageNodeProviders>>,
    certificates: Arc<Mutex<StorageNodeCertificates>>,
) -> JoinHandle<Result<(), ()>> {
    let directory = node.local_state.state_directory().to_path_buf();
    let network = network.clone();
    let runtime = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        let now = current_time().map_err(|_| ())?;
        let repo = open_root_repository_at(&directory, now).map_err(|_| ())?;
        let routes = load_active_peer_routes(&repo, network.local_node_id()).map_err(|_| ())?;
        runtime.block_on(reconcile_active_peer_routes(&network, routes));
        certificates
            .lock()
            .map_err(|_| ())?
            .reconcile(&repo, &runtime, &network, now)?;
        providers.lock().map_err(|_| ())?.reconcile(now)
    })
}

async fn serve(
    providers: Arc<Mutex<StorageNodeProviders>>,
    mut incoming: PeerDataStream,
    mut stop: watch::Receiver<bool>,
    admission: MaintenanceAdmission,
) -> Result<(), ()> {
    if *stop.borrow() {
        return Ok(());
    }
    let message = tokio::select! {
        _changed = stop.changed() => return Ok(()),
        result = tokio::time::timeout(Duration::from_secs(5), meshspan_transport::receive_data_control(&mut incoming.stream.receive, incoming.limits)) => result.map_err(|_| ())?.map_err(|_| ())?.into_inner().message.ok_or(())?,
    };
    if matches!(
        message,
        meshspan_protocol::v1::data_control_envelope::Message::DeleteShardRequest(_)
            | meshspan_protocol::v1::data_control_envelope::Message::ReclaimShardRequest(_)
    ) {
        let parsed = super::storage_node_maintenance::MaintenanceRequest::parse(
            &message,
            meshspan_transport::PeerBinding {
                node_id: incoming.peer.node_id(),
                incarnation: incoming.peer.incarnation(),
                certificate_fingerprint: incoming.peer.certificate_fingerprint(),
            },
            incoming.routing_epoch,
            current_time().map_err(|_| ())?,
        );
        let result = match parsed {
            Ok(request) => {
                let stopped = stop.clone();
                tokio::task::spawn_blocking(move || {
                    request.authorise(
                        &admission.directory,
                        &admission.network,
                        &admission.replica,
                        stopped,
                    )
                })
                .await
                .map_err(|_| ())?
            }
            Err(error) => Err(error),
        };
        if let Err(error) = result {
            return tokio::time::timeout(
                Duration::from_secs(5),
                meshspan_data_plane::reject_shard_maintenance(
                    &mut incoming.stream,
                    incoming.limits,
                    &message,
                    error,
                ),
            )
            .await
            .map_err(|_| ())?
            .map_err(|_| ());
        }
    }
    if !matches!(
        message,
        meshspan_protocol::v1::data_control_envelope::Message::GetShardRequest(_)
            | meshspan_protocol::v1::data_control_envelope::Message::PutShardBegin(_)
            | meshspan_protocol::v1::data_control_envelope::Message::ResolveShardPutRequest(_)
            | meshspan_protocol::v1::data_control_envelope::Message::DeleteShardRequest(_)
            | meshspan_protocol::v1::data_control_envelope::Message::ReclaimShardRequest(_)
    ) {
        return Err(());
    }
    let runtime = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        let mut router = providers.lock().map_err(|_| ())?.router()?;
        let now = current_time().map_err(|_| ())?;
        if *stop.borrow() { return Ok(()); }
        // The task owns provider IO through completion; cancellation only interrupts network awaits.
        runtime.block_on(async {
            tokio::select! {
                _changed = stop.changed() => Ok(()),
                result = tokio::time::timeout(Duration::from_secs(30), router.serve_message(incoming.stream, incoming.peer, incoming.limits, now, message)) => result.map_err(|_| ())?.map_err(|_| ()),
            }
        })
    }).await.map_err(|_| ())?
}

/// Cloneable composition inputs only; no cached authorisation result crosses requests.
struct MaintenanceAdmission {
    directory: std::path::PathBuf,
    network: ConsensusNetwork,
    replica: MetadataReplicaRuntimeHandle,
}
