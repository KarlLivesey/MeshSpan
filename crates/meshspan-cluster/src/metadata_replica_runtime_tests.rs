// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::{
    MetadataReplicaProgress, MetadataReplicaRuntimeConfig, MetadataReplicaRuntimeExit,
    spawn_metadata_replica,
};
use std::sync::{Arc, Mutex};
use tokio::sync::{Notify, watch};

struct FixedClock;
impl meshspan_domain::Clock for FixedClock {
    fn now(&self) -> UnixMicros {
        UnixMicros::new(100)
    }
}

#[derive(Clone, Copy)]
enum FirstResponse {
    Send,
    Drop,
    Stall,
}

#[derive(Default)]
struct RequestObservations {
    cursors: Mutex<Vec<u64>>,
    ready: Notify,
}

struct SourceHarness {
    directory: tempfile::TempDir,
    driver: Arc<Mutex<PartitionConsensusDriver<AuthoritativeRepository>>>,
    client: ConsensusNetwork,
    _source: ConsensusNetwork,
    received: Arc<RequestObservations>,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<Result<(), String>>,
    storage: NodeId,
    partition: PartitionId,
}

impl SourceHarness {
    async fn new(fault: FirstResponse, eligible: bool) -> Result<Self, Box<dyn std::error::Error>> {
        let roles = JoinRoles::new(
            JoinRoles::STORAGE
                | if eligible {
                    JoinRoles::METADATA_ELIGIBLE
                } else {
                    0
                },
        )?;
        let TransferFixture {
            state,
            source,
            client,
            incoming,
        } = TransferFixture::with_roles(roles).await?;
        let Fixture {
            directory,
            source: driver,
            replica,
            storage,
            partition,
            ..
        } = state;
        drop(replica);
        let driver = Arc::new(Mutex::new(driver));
        let received = Arc::new(RequestObservations::default());
        let (stop, stopped) = watch::channel(false);
        let task = tokio::spawn(serve_pages(
            incoming,
            Arc::clone(&driver),
            Arc::clone(&received),
            stopped,
            fault,
        ));
        Ok(Self {
            directory,
            driver,
            client,
            _source: source,
            received,
            stop,
            task,
            storage,
            partition,
        })
    }

    fn config(&self) -> MetadataReplicaRuntimeConfig {
        MetadataReplicaRuntimeConfig {
            database_path: self.directory.path().join("replica.sqlite3"),
            partition_id: self.partition,
            local_node_id: self.storage,
        }
    }

    async fn append_groups(&self, start: u8, end: u8) -> TestResult {
        let source = Arc::clone(&self.driver);
        tokio::task::spawn_blocking(move || {
            let mut source = source.lock().map_err(|_| "source lock")?;
            for index in start..=end {
                let command = AuthoritativeCommand::CreateGroup(CreateGroup {
                    group_id: GroupId::from_bytes([index + 80; 16]).map_err(|e| e.to_string())?,
                    name: RecordName::new(&format!("Runtime group {index}"))
                        .map_err(|e| e.to_string())?,
                    activation_policy_id: None,
                });
                let entry = propose(&mut source, index, &command).map_err(|e| e.to_string())?;
                source
                    .apply_authoritative_committed(&entry, UnixMicros::new(100))
                    .map_err(|e| e.to_string())?;
            }
            Ok::<_, String>(())
        })
        .await??;
        Ok(())
    }

    async fn finish(self) -> TestResult {
        self.stop.send(true)?;
        self.task.await??;
        Ok(())
    }
}

async fn serve_pages(
    mut incoming: mpsc::Receiver<PeerDataStream>,
    driver: Arc<Mutex<PartitionConsensusDriver<AuthoritativeRepository>>>,
    received: Arc<RequestObservations>,
    mut stop: watch::Receiver<bool>,
    fault: FirstResponse,
) -> Result<(), String> {
    let mut first = true;
    loop {
        let incoming = tokio::select! {
            _changed = stop.changed() => return Ok(()),
            stream = incoming.recv() => stream.ok_or("source queue closed")?,
        };
        let (mut stream, limits, peer, epoch) = (
            incoming.stream,
            incoming.limits,
            incoming.peer,
            incoming.routing_epoch,
        );
        let envelope = receive_data_control(&mut stream.receive, limits)
            .await
            .map_err(|e| e.to_string())?;
        let Some(Message::FetchMetadataReplicaPage(request)) = envelope.into_inner().message else {
            return Err("wrong request".into());
        };
        stream
            .receive
            .read_to_end(0)
            .await
            .map_err(|e| e.to_string())?;
        let index = request
            .after
            .as_ref()
            .and_then(|value| value.applied.as_ref())
            .ok_or("cursor")?
            .index;
        {
            let mut seen = received.cursors.lock().map_err(|_| "observations lock")?;
            if seen.len() < 32 {
                seen.push(index);
            }
        }
        received.ready.notify_one();
        if first {
            first = false;
            match fault {
                FirstResponse::Drop => continue,
                FirstResponse::Stall => {
                    stop.changed().await.map_err(|e| e.to_string())?;
                    return Ok(());
                }
                FirstResponse::Send => {}
            }
        }
        let driver = Arc::clone(&driver);
        let prepared = tokio::task::spawn_blocking(move || {
            let driver = driver.lock().map_err(|_| "source lock")?;
            let after = admit_metadata_replica_request(
                driver.persistence(),
                peer,
                epoch,
                &request,
                UnixMicros::new(100),
            )
            .map_err(|e| e.to_string())?;
            let page = driver
                .metadata_replica_page(after)
                .map_err(|e| e.to_string())?;
            PreparedMetadataReplicaPage::new(request, &page, limits).map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| e.to_string())??;
        // Stopping the receiver may cancel this response; the next request resumes durably.
        if let Err(error) = send_metadata_replica_page(stream, prepared, limits).await
            && !matches!(error, crate::MetadataReplicaTransferError::Transport(_))
        {
            return Err(error.to_string());
        }
    }
}

async fn wait_applied(
    progress: &mut watch::Receiver<MetadataReplicaProgress>,
    index: u64,
) -> TestResult {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if matches!(*progress.borrow(), MetadataReplicaProgress::Applied(cursor) if cursor.applied.index == index) { return Ok::<_, Box<dyn std::error::Error>>(()); }
            progress.changed().await?;
        }
    }).await??;
    Ok(())
}

#[tokio::test]
async fn metadata_replica_worker_retries_loss_pages_automatically_and_restarts_at_durable_cursor()
-> TestResult {
    let harness = SourceHarness::new(FirstResponse::Drop, false).await?;
    harness.append_groups(6, 71).await?;
    let (stop, stopped) = watch::channel(false);
    let (handle, task) = spawn_metadata_replica(
        harness.config(),
        harness.client.clone(),
        FixedClock,
        stopped,
    )?;
    wait_applied(&mut handle.subscribe(), 71).await?;
    stop.send(true)?;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), task).await??,
        MetadataReplicaRuntimeExit::Stopped
    );
    assert!(
        matches!(*handle.subscribe().borrow(), MetadataReplicaProgress::Stopped(Some(cursor)) if cursor.applied.index == 71)
    );
    let seen = harness
        .received
        .cursors
        .lock()
        .map_err(|_| "observations lock")?
        .clone();
    assert_eq!(seen.get(..3), Some([0, 0, 64].as_slice()));
    harness.append_groups(72, 72).await?;
    let (stop, stopped) = watch::channel(false);
    let (handle, task) = spawn_metadata_replica(
        harness.config(),
        harness.client.clone(),
        FixedClock,
        stopped,
    )?;
    wait_applied(&mut handle.subscribe(), 72).await?;
    stop.send(true)?;
    assert_eq!(task.await?, MetadataReplicaRuntimeExit::Stopped);
    let config = harness.config();
    tokio::task::spawn_blocking(move || {
        let repo = AuthoritativeRepository::new(
            PartitionDatabase::open_existing(&config.database_path, UnixMicros::new(100))
                .map_err(|e| e.to_string())?,
        );
        let replica =
            MetadataReplica::new(repo, config.local_node_id).map_err(|e| e.to_string())?;
        assert_eq!(
            replica.cursor().map_err(|e| e.to_string())?.applied.index,
            72
        );
        assert_eq!(
            replica
                .repository()
                .current_revision()
                .map_err(|e| e.to_string())?,
            Revision::new(72)
        );
        assert!(
            !replica
                .source_voters()
                .map_err(|e| e.to_string())?
                .contains_key(&config.local_node_id)
        );
        Ok::<_, String>(())
    })
    .await??;
    harness.finish().await
}

#[tokio::test]
async fn metadata_replica_worker_cancels_a_stalled_body_without_waiting_for_the_transfer_deadline()
-> TestResult {
    let harness = SourceHarness::new(FirstResponse::Stall, false).await?;
    let (stop, stopped) = watch::channel(false);
    let (_handle, task) = spawn_metadata_replica(
        harness.config(),
        harness.client.clone(),
        FixedClock,
        stopped,
    )?;
    tokio::time::timeout(Duration::from_secs(5), harness.received.ready.notified()).await?;
    stop.send(true)?;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), task).await??,
        MetadataReplicaRuntimeExit::Stopped
    );
    harness.finish().await
}

#[tokio::test]
async fn metadata_replica_worker_hands_off_only_after_committed_learner_admission() -> TestResult {
    let harness = SourceHarness::new(FirstResponse::Send, true).await?;
    let (stop, stopped) = watch::channel(false);
    let (handle, task) = spawn_metadata_replica(
        harness.config(),
        harness.client.clone(),
        FixedClock,
        stopped,
    )?;
    wait_applied(&mut handle.subscribe(), 5).await?;
    assert!(
        !task.is_finished(),
        "eligibility alone must not end passive catch-up"
    );
    let source = Arc::clone(&harness.driver);
    tokio::task::spawn_blocking(move || {
        let mut source = source.lock().map_err(|_| "source lock")?;
        let membership = source
            .persistence()
            .partition_membership()
            .map_err(|e| e.to_string())?
            .ok_or("membership missing")?;
        let command = crate::membership::plan_next_transition(
            source.active_plan(),
            source.member_incarnations(),
            membership.active_voters(),
            membership.admitted_learners(),
            membership.retiring_members(),
            source.committed_entry(),
            |_| None,
        )
        .map_err(|e| e.to_string())?
        .ok_or("admission missing")?;
        super::super::membership::apply_transition(&mut source, command, 6)
            .map_err(|e| e.to_string())
    })
    .await??;
    handle.request_sync();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), task).await??,
        MetadataReplicaRuntimeExit::MembershipAdmitted,
    );
    assert!(matches!(
        *handle.subscribe().borrow(),
        MetadataReplicaProgress::MembershipAdmitted(Some(cursor)) if cursor.applied.index == 6
    ));
    let config = harness.config();
    tokio::task::spawn_blocking(move || {
        let repo = AuthoritativeRepository::new(
            PartitionDatabase::open_existing(&config.database_path, UnixMicros::new(100))
                .map_err(|e| e.to_string())?,
        );
        assert_eq!(
            repo.current_revision().map_err(|e| e.to_string())?,
            Revision::new(5)
        );
        assert!(matches!(
            MetadataReplica::new(repo, config.local_node_id),
            Err(MetadataReplicaError::LocalMember)
        ));
        Ok::<_, String>(())
    })
    .await??;
    drop(stop);
    harness.finish().await
}

#[tokio::test]
async fn metadata_replica_worker_never_creates_missing_state_and_recovers_when_it_returns()
-> TestResult {
    let harness = SourceHarness::new(FirstResponse::Send, false).await?;
    let config = harness.config();
    let original = config.database_path.clone();
    let held = original.with_extension("held");
    std::fs::rename(&original, &held)?;
    let (stop, stopped) = watch::channel(false);
    let (handle, task) =
        spawn_metadata_replica(config, harness.client.clone(), FixedClock, stopped)?;
    let mut progress = handle.subscribe();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !matches!(
            *progress.borrow(),
            MetadataReplicaProgress::Unavailable(None)
        ) {
            progress.changed().await?;
        }
        Ok::<_, watch::error::RecvError>(())
    })
    .await??;
    assert!(!original.exists());
    std::fs::rename(held, original)?;
    handle.request_sync();
    wait_applied(&mut progress, 5).await?;
    stop.send(true)?;
    assert_eq!(task.await?, MetadataReplicaRuntimeExit::Stopped);
    harness.finish().await
}

#[tokio::test]
async fn metadata_replica_worker_rejects_mismatched_identity_and_honours_an_absent_owner()
-> TestResult {
    let harness = SourceHarness::new(FirstResponse::Send, false).await?;
    let (stop, stopped) = watch::channel(false);
    let mut wrong_node = harness.config();
    wrong_node.local_node_id = NodeId::from_bytes([88; 16])?;
    assert!(matches!(
        spawn_metadata_replica(
            wrong_node,
            harness.client.clone(),
            FixedClock,
            stopped.clone()
        ),
        Err(MetadataReplicaError::Source)
    ));
    let mut wrong_partition = harness.config();
    wrong_partition.partition_id = PartitionId::from_bytes([89; 16])?;
    assert!(matches!(
        spawn_metadata_replica(
            wrong_partition,
            harness.client.clone(),
            FixedClock,
            stopped.clone()
        ),
        Err(MetadataReplicaError::Source)
    ));
    drop(stop);
    let (handle, task) = spawn_metadata_replica(
        harness.config(),
        harness.client.clone(),
        FixedClock,
        stopped,
    )?;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), task).await??,
        MetadataReplicaRuntimeExit::Stopped
    );
    assert_eq!(
        *handle.subscribe().borrow(),
        MetadataReplicaProgress::Stopped(None)
    );
    assert!(
        harness
            .received
            .cursors
            .lock()
            .map_err(|_| "observations lock")?
            .is_empty()
    );
    harness.finish().await
}
