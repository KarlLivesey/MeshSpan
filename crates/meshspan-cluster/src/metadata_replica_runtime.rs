// SPDX-License-Identifier: GPL-2.0-only

//! Owned, non-voting historical catch-up. Progress is never fresh authorisation.

use crate::{
    ConsensusNetwork, MetadataReplica, MetadataReplicaCursor, MetadataReplicaError,
    MetadataReplicaFetch, MetadataReplicaTransferError,
};
use meshspan_domain::{Clock, NodeId, OperationId, PartitionId};
use meshspan_metadata::{AuthoritativeRepository, PartitionDatabase};
use sha2::{Digest, Sha256};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::{Notify, watch};

const POLL_INTERVAL: Duration = Duration::from_millis(250);
const MAXIMUM_RETRY_INTERVAL: Duration = Duration::from_secs(8);

/// Existing authenticated installation selected by daemon startup, never a bootstrap path.
pub struct MetadataReplicaRuntimeConfig {
    /// Existing partition database; missing files are never created by this worker.
    pub database_path: PathBuf,
    /// Partition bound by the installed state and private transport.
    pub partition_id: PartitionId,
    /// This process's admitted node identity.
    pub local_node_id: NodeId,
}

/// Historical progress only. Even `Applied` is neither readiness nor current permission evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataReplicaProgress {
    /// Opening or validating the existing installation.
    Opening,
    /// A verified page was applied, possibly an empty historical page.
    Applied(MetadataReplicaCursor),
    /// Catch-up is retrying; the optional cursor is only its last successful local application.
    Unavailable(Option<MetadataReplicaCursor>),
    /// Membership now requires ordinary consensus composition instead of passive replication.
    MembershipAdmitted(Option<MetadataReplicaCursor>),
    /// The owner stopped after draining its work.
    Stopped(Option<MetadataReplicaCursor>),
}

/// Why the owned passive worker ended; neither outcome claims service readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataReplicaRuntimeExit {
    /// Cooperative stop or the owner closed its stop channel.
    Stopped,
    /// The daemon must reopen through its normal voter/learner startup path.
    MembershipAdmitted,
}

/// Coalesced catch-up wake-ups and non-authoritative observations for the composing daemon.
#[derive(Clone)]
pub struct MetadataReplicaRuntimeHandle {
    wake: Arc<Notify>,
    progress: watch::Receiver<MetadataReplicaProgress>,
}

impl MetadataReplicaRuntimeHandle {
    /// Requests another catch-up attempt without adding an unbounded queue of jobs.
    pub fn request_sync(&self) {
        self.wake.notify_one();
    }

    /// Subscribes to historical progress. A closed channel means the owner is no longer running.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<MetadataReplicaProgress> {
        self.progress.clone()
    }
}

/// Starts one owned blocking database worker with independent asynchronous QUIC IO.
///
/// The caller must retain and await the returned task during shutdown. IO observes `stop`;
/// any already-started parsing/application finishes before the database owner exits. Failed
/// application drops and reopens the SQLite connection, retaining only durable applied state.
/// Missing media, source outages and malformed pages retry with bounded backoff. No membership
/// mutation, gateway secret or current-permission claim is created by this worker.
///
/// # Errors
/// Rejects a network/config identity mismatch before starting work.
pub fn spawn_metadata_replica<C: Clock + Send + 'static>(
    config: MetadataReplicaRuntimeConfig,
    network: ConsensusNetwork,
    clock: C,
    stop: watch::Receiver<bool>,
) -> Result<
    (
        MetadataReplicaRuntimeHandle,
        tokio::task::JoinHandle<MetadataReplicaRuntimeExit>,
    ),
    MetadataReplicaError,
> {
    if config.local_node_id != network.local_node_id()
        || network.partition_id() != config.partition_id
    {
        return Err(MetadataReplicaError::Source);
    }
    let (progress, observed) = watch::channel(MetadataReplicaProgress::Opening);
    let wake = Arc::new(Notify::new());
    let handle = MetadataReplicaRuntimeHandle {
        wake: Arc::clone(&wake),
        progress: observed,
    };
    let runtime = tokio::runtime::Handle::current();
    let task = tokio::task::spawn_blocking(move || {
        ReplicaWorker {
            config,
            network,
            clock,
            runtime,
            stop,
            wake,
            progress,
            last_applied: None,
            previous_source: None,
            retry_interval: POLL_INTERVAL,
        }
        .run()
    });
    Ok((handle, task))
}

struct ReplicaWorker<C> {
    config: MetadataReplicaRuntimeConfig,
    network: ConsensusNetwork,
    clock: C,
    runtime: tokio::runtime::Handle,
    stop: watch::Receiver<bool>,
    wake: Arc<Notify>,
    progress: watch::Sender<MetadataReplicaProgress>,
    last_applied: Option<MetadataReplicaCursor>,
    previous_source: Option<NodeId>,
    retry_interval: Duration,
}

impl<C: Clock> ReplicaWorker<C> {
    fn run(mut self) -> MetadataReplicaRuntimeExit {
        let mut replica = None;
        loop {
            if self.stopping() {
                return self.finish(MetadataReplicaRuntimeExit::Stopped);
            }
            if replica.is_none() {
                match self.open() {
                    Ok(opened) => replica = Some(opened),
                    Err(MetadataReplicaError::LocalMember) => {
                        return self.finish(MetadataReplicaRuntimeExit::MembershipAdmitted);
                    }
                    Err(
                        MetadataReplicaError::Unavailable
                        | MetadataReplicaError::Source
                        | MetadataReplicaError::StaleCursor
                        | MetadataReplicaError::InvalidPage
                        | MetadataReplicaError::ReloadRequired
                        | MetadataReplicaError::Persistence(_)
                        | MetadataReplicaError::Repository(_),
                    ) => {
                        self.retry();
                        continue;
                    }
                }
            }
            let Some(current) = replica.as_mut() else {
                continue;
            };
            match self.synchronise(current) {
                Ok(changed) => {
                    self.retry_interval = POLL_INTERVAL;
                    if !changed {
                        self.wait(POLL_INTERVAL);
                    }
                }
                Err(MetadataReplicaError::LocalMember) => {
                    return self.finish(MetadataReplicaRuntimeExit::MembershipAdmitted);
                }
                Err(MetadataReplicaError::Unavailable) => self.retry(),
                Err(
                    MetadataReplicaError::Source
                    | MetadataReplicaError::StaleCursor
                    | MetadataReplicaError::InvalidPage
                    | MetadataReplicaError::ReloadRequired
                    | MetadataReplicaError::Persistence(_)
                    | MetadataReplicaError::Repository(_),
                ) => {
                    replica = None;
                    self.retry();
                }
            }
        }
    }

    fn open(&self) -> Result<MetadataReplica, MetadataReplicaError> {
        let database =
            PartitionDatabase::open_existing(&self.config.database_path, self.clock.now())
                .map_err(|_| MetadataReplicaError::Unavailable)?;
        if database.partition_id() != self.config.partition_id {
            return Err(MetadataReplicaError::Source);
        }
        MetadataReplica::new(
            AuthoritativeRepository::new(database),
            self.config.local_node_id,
        )
    }

    fn synchronise(&mut self, replica: &mut MetadataReplica) -> Result<bool, MetadataReplicaError> {
        let after = replica.cursor()?;
        self.last_applied = Some(after);
        let voters = replica.source_voters()?;
        let candidates = self
            .network
            .peer_routes()
            .map_err(|_| MetadataReplicaError::Unavailable)?
            .into_iter()
            .filter(|route| voters.get(&route.node_id) == Some(&route.incarnation))
            .map(|route| route.node_id)
            .collect::<Vec<_>>();
        let source = candidates
            .iter()
            .copied()
            .find(|node| self.previous_source.is_none_or(|previous| *node > previous))
            .or_else(|| candidates.first().copied())
            .ok_or(MetadataReplicaError::Unavailable)?;
        self.previous_source = Some(source);
        let transfer = self
            .runtime
            .block_on(self.network.fetch_metadata_replica_page_until(
                MetadataReplicaFetch {
                    source,
                    after,
                    operation: read_operation(self.config.local_node_id, after)?,
                    now: self.clock.now(),
                },
                &mut self.stop,
            ))
            .map_err(|error| match error {
                MetadataReplicaTransferError::Cancelled
                | MetadataReplicaTransferError::Deadline
                | MetadataReplicaTransferError::Network(_)
                | MetadataReplicaTransferError::Remote(_)
                | MetadataReplicaTransferError::Transport(_) => MetadataReplicaError::Unavailable,
                MetadataReplicaTransferError::Rejected
                | MetadataReplicaTransferError::Worker
                | MetadataReplicaTransferError::Wire(_)
                | MetadataReplicaTransferError::Repository(_) => MetadataReplicaError::InvalidPage,
            })?;
        if self.stopping() {
            return Err(MetadataReplicaError::Unavailable);
        }
        let cursor = replica.apply(
            transfer.source.node_id(),
            transfer.source.incarnation(),
            &transfer.page,
            self.clock.now(),
        )?;
        self.last_applied = Some(cursor);
        self.progress
            .send_replace(MetadataReplicaProgress::Applied(cursor));
        Ok(cursor != after)
    }

    fn stopping(&self) -> bool {
        *self.stop.borrow() || self.stop.has_changed().is_err()
    }

    fn wait(&mut self, delay: Duration) {
        if self.stopping() {
            return;
        }
        self.runtime.block_on(async {
            tokio::select! {
                _changed = self.stop.changed() => {},
                () = self.wake.notified() => {},
                () = tokio::time::sleep(delay) => {},
            }
        });
    }

    fn retry(&mut self) {
        self.progress
            .send_replace(MetadataReplicaProgress::Unavailable(self.last_applied));
        self.wait(self.retry_interval);
        self.retry_interval = self
            .retry_interval
            .saturating_mul(2)
            .min(MAXIMUM_RETRY_INTERVAL);
    }

    fn finish(self, exit: MetadataReplicaRuntimeExit) -> MetadataReplicaRuntimeExit {
        self.progress.send_replace(match exit {
            MetadataReplicaRuntimeExit::Stopped => {
                MetadataReplicaProgress::Stopped(self.last_applied)
            }
            MetadataReplicaRuntimeExit::MembershipAdmitted => {
                MetadataReplicaProgress::MembershipAdmitted(self.last_applied)
            }
        });
        exit
    }
}

fn read_operation(
    node: NodeId,
    cursor: MetadataReplicaCursor,
) -> Result<OperationId, MetadataReplicaError> {
    // Read-only identity names this frontier. Every retry still gets a fresh transport request ID.
    let mut digest = Sha256::new();
    digest.update(b"meshspan.metadata-replica-read.v1");
    digest.update(node.as_bytes());
    digest.update(cursor.partition_id.as_bytes());
    digest.update(cursor.membership_epoch.to_le_bytes());
    digest.update(cursor.plan_digest);
    digest.update(cursor.applied_digest);
    let bytes: [u8; 16] = digest
        .finalize()
        .get(..16)
        .ok_or(MetadataReplicaError::InvalidPage)?
        .try_into()
        .map_err(|_| MetadataReplicaError::InvalidPage)?;
    OperationId::from_bytes(bytes).map_err(|_| MetadataReplicaError::InvalidPage)
}
