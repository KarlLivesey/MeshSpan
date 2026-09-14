// SPDX-License-Identifier: GPL-2.0-only

//! Bounded ownership of this network's accept, outbound and authenticated connection workers.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock, Weak};

use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};
use tokio::task::{JoinHandle, JoinSet};

use super::{
    ConsensusNetwork, ConsensusNetworkError, NodeId, PeerConsensusMessage, PeerControlRequest,
    PeerDataStream, ReceivedConsensusSnapshot, bulk,
};

// Operational worker capacities, not membership limits. A stable plan supports 9 voters and
// 256 learners, but network routes also include storage/gateway peers. Replaced workers retain
// their slots until drained. Admission rejects explicitly rather than accepting unowned work.
pub(super) const MAXIMUM_OUTBOUND_WORKERS: usize = 4096;
const MAXIMUM_CONNECTION_WORKERS: usize = 4096;
const MAXIMUM_CONNECTIONS_PER_PEER: usize = 128;
const REGISTRATION_CAPACITY: usize = MAXIMUM_OUTBOUND_WORKERS + MAXIMUM_CONNECTION_WORKERS + 1;

/// Terminal failure of the shared network shutdown barrier.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ConsensusNetworkShutdownError {
    /// An owned network worker panicked or was canceled before its result was observed.
    #[error("network shutdown observed {count} failed workers")]
    WorkerFailed {
        /// Number of owned task failures observed before the shared drain completed.
        count: u64,
    },
    /// The supervisor itself failed; descendant completion cannot be claimed.
    #[error("network shutdown supervisor failed")]
    SupervisorFailed,
    /// Closing the shared admission or connection registries failed.
    #[error("network shutdown admission state failed")]
    AdmissionFailed,
}

type ShutdownResult = Result<(), ConsensusNetworkShutdownError>;

enum SupervisorState {
    Running(JoinHandle<ShutdownResult>),
    Completed(ShutdownResult),
}

pub(super) struct NetworkOwner {
    admission: Mutex<Option<mpsc::Sender<NetworkJob>>>,
    closing: watch::Sender<bool>,
    supervisor: OnceLock<tokio::sync::Mutex<SupervisorState>>,
    outbound: Arc<Semaphore>,
    connections: Arc<Semaphore>,
    accept: Arc<Semaphore>,
    peer_connections: Mutex<BTreeMap<NodeId, Weak<Semaphore>>>,
}

#[derive(Clone)]
pub(super) struct IncomingChannels {
    pub(super) messages: mpsc::Sender<PeerConsensusMessage>,
    pub(super) controls: Option<mpsc::Sender<PeerControlRequest>>,
    pub(super) snapshots: Option<mpsc::Sender<ReceivedConsensusSnapshot>>,
    pub(super) data: Option<mpsc::Sender<PeerDataStream>>,
}

pub(super) enum NetworkTask {
    Accept {
        network: ConsensusNetwork,
        server: quinn::Endpoint,
        channels: IncomingChannels,
    },
    Outbound {
        network: ConsensusNetwork,
        peer: NodeId,
        messages: mpsc::Receiver<bulk::OutboundConsensusMessage>,
    },
    Connection {
        network: ConsensusNetwork,
        incoming: Box<quinn::Incoming>,
        channels: IncomingChannels,
    },
}

pub(super) struct NetworkJob {
    task: NetworkTask,
    permit: OwnedSemaphorePermit,
}

impl NetworkOwner {
    pub(super) fn prepare() -> (Arc<Self>, mpsc::Receiver<NetworkJob>) {
        let (send, receive) = mpsc::channel(REGISTRATION_CAPACITY);
        let (closing, _) = watch::channel(false);
        (
            Arc::new(Self {
                admission: Mutex::new(Some(send)),
                closing,
                supervisor: OnceLock::new(),
                outbound: Arc::new(Semaphore::new(MAXIMUM_OUTBOUND_WORKERS)),
                connections: Arc::new(Semaphore::new(MAXIMUM_CONNECTION_WORKERS)),
                accept: Arc::new(Semaphore::new(1)),
                peer_connections: Mutex::new(BTreeMap::new()),
            }),
            receive,
        )
    }

    pub(super) fn start(
        &self,
        runtime: &tokio::runtime::Handle,
        incoming: mpsc::Receiver<NetworkJob>,
    ) {
        // Called only after all initial route/worker preparation succeeds. Before this point,
        // disposing the receiver closes every queued job synchronously without detached cleanup.
        self.supervisor.get_or_init(|| {
            tokio::sync::Mutex::new(SupervisorState::Running(runtime.spawn(supervise(incoming))))
        });
    }

    #[cfg(test)]
    pub(super) fn outbound_slots(&self) -> Arc<Semaphore> {
        Arc::clone(&self.outbound)
    }

    #[cfg(test)]
    pub(super) fn connection_jobs(&self) -> usize {
        MAXIMUM_CONNECTION_WORKERS - self.connections.available_permits()
    }

    pub(super) fn register(&self, task: NetworkTask) -> Result<(), ConsensusNetworkError> {
        let budget = match &task {
            NetworkTask::Accept { .. } => &self.accept,
            NetworkTask::Outbound { .. } => &self.outbound,
            NetworkTask::Connection { .. } => &self.connections,
        };
        let Ok(permit) = Arc::clone(budget).try_acquire_owned() else {
            task.reject();
            return Err(ConsensusNetworkError::NetworkBusy);
        };
        let Ok(admission) = self.admission.lock() else {
            task.reject();
            return Err(ConsensusNetworkError::InvalidConfiguration);
        };
        let Some(sender) = admission.as_ref() else {
            drop(admission);
            task.reject();
            return Err(ConsensusNetworkError::AuthorityStopped);
        };
        let queued = sender.try_send(NetworkJob { task, permit });
        drop(admission);
        queued.map_err(|error| {
            let job = error.into_inner();
            job.task.reject();
            ConsensusNetworkError::NetworkBusy
        })
    }

    pub(super) fn close(&self) -> Result<(), ConsensusNetworkError> {
        // Release this gate before the caller closes transport or locks peer registries.
        // Every accepted registration owns its permit and queued job before this transition.
        let result = match self.admission.lock() {
            Ok(mut admission) => {
                drop(admission.take());
                Ok(())
            }
            Err(poisoned) => {
                drop(poisoned.into_inner().take());
                Err(ConsensusNetworkError::InvalidConfiguration)
            }
        };
        self.closing.send_replace(true);
        result
    }

    pub(super) fn is_closing(&self) -> bool {
        *self.closing.borrow()
    }

    pub(super) fn closing(&self) -> watch::Receiver<bool> {
        self.closing.subscribe()
    }

    pub(super) async fn join(&self) -> ShutdownResult {
        // This lock owns the join handle through the await. Never take or move the handle
        // into a caller future: cancellation must leave it available to the next waiter.
        // No worker takes this lock; registration and closure use the separate sync gate.
        let Some(supervisor) = self.supervisor.get() else {
            return Err(ConsensusNetworkShutdownError::SupervisorFailed);
        };
        let mut state = supervisor.lock().await;
        let result = match &mut *state {
            SupervisorState::Running(handle) => match handle.await {
                Ok(result) => result,
                Err(_) => Err(ConsensusNetworkShutdownError::SupervisorFailed),
            },
            SupervisorState::Completed(result) => return *result,
        };
        *state = SupervisorState::Completed(result);
        result
    }

    pub(super) fn admit_peer(
        &self,
        peer: NodeId,
    ) -> Result<OwnedSemaphorePermit, ConsensusNetworkError> {
        let mut peers = self
            .peer_connections
            .lock()
            .map_err(|_| ConsensusNetworkError::InvalidConfiguration)?;
        peers.retain(|_, budget| budget.strong_count() > 0);
        let budget = peers.get(&peer).and_then(Weak::upgrade).unwrap_or_else(|| {
            let budget = Arc::new(Semaphore::new(MAXIMUM_CONNECTIONS_PER_PEER));
            peers.insert(peer, Arc::downgrade(&budget));
            budget
        });
        budget
            .try_acquire_owned()
            .map_err(|_| ConsensusNetworkError::NetworkBusy)
    }
}

impl NetworkTask {
    fn reject(self) {
        match self {
            Self::Connection { incoming, .. } => (*incoming).refuse(),
            Self::Accept { server, .. } => server.close(0_u32.into(), b"network admission stopped"),
            Self::Outbound { .. } => {}
        }
    }

    async fn run(self) {
        match self {
            Self::Accept {
                network,
                server,
                channels,
            } => network.run_accept_loop(server, channels).await,
            Self::Outbound {
                network,
                peer,
                messages,
            } => network.run_outbound_worker(peer, messages).await,
            Self::Connection {
                network,
                incoming,
                channels,
            } => network.run_incoming_connection(*incoming, channels).await,
        }
    }
}

async fn supervise(mut incoming: mpsc::Receiver<NetworkJob>) -> ShutdownResult {
    let mut workers = JoinSet::new();
    let mut permits = BTreeMap::new();
    let mut registrations_open = true;
    let mut failures = 0_u64;
    while registrations_open || !workers.is_empty() {
        tokio::select! {
            job = incoming.recv(), if registrations_open => {
                match job {
                    Some(job) => {
                        let task = workers.spawn(job.task.run());
                        // Task IDs are unique while owned. Keep permits outside the future so
                        // even a panicked completed handle occupies its slot until reaped.
                        drop(permits.insert(task.id(), job.permit));
                    }
                    None => registrations_open = false,
                }
            }
            outcome = workers.join_next_with_id(), if !workers.is_empty() => {
                let id = match outcome {
                    Some(Ok((id, ()))) => Some(id),
                    Some(Err(error)) => {
                        failures = failures.saturating_add(1);
                        Some(error.id())
                    }
                    None => None,
                };
                if let Some(id) = id && permits.remove(&id).is_none() {
                    failures = failures.saturating_add(1);
                }
            }
        }
    }
    if failures == 0 {
        Ok(())
    } else {
        Err(ConsensusNetworkShutdownError::WorkerFailed { count: failures })
    }
}
