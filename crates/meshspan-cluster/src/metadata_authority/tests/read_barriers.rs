// SPDX-License-Identifier: GPL-2.0-only

use super::super::linearizable_read::ReadRequest;
use super::*;
use meshspan_consensus::{AppendResponse, ReadBarrierId, VoteRequest};

#[tokio::test]
async fn first_read_confirms_the_term_and_later_reads_do_not_append()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("read.sqlite3");
    let local = NodeId::from_bytes([31; 16])?;
    let driver = driver(&file, local)?;
    let partition = driver.persistence().partition_id();
    let (authority, runtime) = spawn_metadata_authority(
        driver,
        Arc::new(|_, _| {}),
        MetadataAuthorityConfig::default(),
    )?;
    assert!(matches!(
        authority.read_fence().await,
        Err(MetadataAuthorityRequestError::NotLeader { .. })
    ));
    authority.begin_election().await?;
    let first = authority.read_fence().await?;
    assert_eq!(
        first.applied,
        meshspan_consensus::LogPosition { term: 1, index: 1 }
    );
    assert_eq!(first.revision, Revision::new(0));
    assert_eq!(first.partition_id, partition);
    assert_eq!(first.leader_node_id, local);
    let (context, command) = command(local, [32; 16])?;
    let receipt = authority.commit_or_resolve(context, command).await?;
    assert_eq!(receipt.committed_position.index, 2);
    let second = authority.read_fence().await?;
    assert_eq!(second.revision, Revision::new(1));
    assert_eq!(second.applied.index, 2);
    assert_eq!(authority.read_fence().await?, second);
    authority.shutdown().await?;
    runtime.await??;
    let repository = AuthoritativeRepository::new(PartitionDatabase::open_existing(&file, now())?);
    let durable = repository.load_consensus_state(1)?;
    assert_eq!(durable.applied_index, 2);
    assert!(
        durable
            .log
            .first()
            .is_some_and(meshspan_consensus::LogEntry::is_term_confirmation)
    );
    assert_eq!(durable.log.len(), 2);
    let mut expected_replay = receipt;
    expected_replay.disposition = meshspan_metadata::ApplyDisposition::Replayed;
    assert_eq!(
        repository.resolve_operation(context.operation_id)?,
        Some(expected_replay)
    );
    Ok(())
}

#[test]
fn read_waits_for_both_quorums_and_preserves_a_queued_application_write()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let (mut runtime, peer) =
        leadership_waiters::elected_runtime(&directory.path().join("quorums.sqlite3"))?;
    let (requests, mut sent) = mpsc::channel(32);
    runtime.transport = Arc::new(move |to, message| {
        assert!(requests.try_send((to, message)).is_ok());
    });
    let mut read = begin(&mut runtime)?;
    assert!(matches!(
        read.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    // Read contact and term-confirmation replication are independent proof lanes.
    // Keep both original requests: a negative contact does not retry or consume data.
    let initial: Vec<_> = std::iter::from_fn(|| sent.try_recv().ok()).collect();
    acknowledge(&mut runtime, peer, false, Some(ReadBarrierId(1)), &initial)?;
    assert!(matches!(
        read.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    let (context, command) = command(runtime.driver.local_node_id(), [89; 16])?;
    let (respond, mut response) = oneshot::channel();
    runtime.submit(AuthoritySubmission {
        context: AuthoritativeCommandContext::Principal(context),
        command,
        respond,
    })?;
    assert_eq!(runtime.queued.len(), 1);
    assert!(matches!(
        response.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    acknowledge(&mut runtime, peer, true, None, &initial)?;
    let fence = read.try_recv()??;
    assert_eq!(fence.applied.index, 1);
    assert_eq!(fence.revision, Revision::new(0));
    assert!(runtime.queued.is_empty());
    let application: Vec<_> = std::iter::from_fn(|| sent.try_recv().ok()).collect();
    acknowledge(&mut runtime, peer, true, None, &application)?;
    let receipt = response.try_recv()??;
    assert_eq!(receipt.operation_id, context.operation_id);
    assert_eq!(receipt.committed_position.index, 2);
    assert_eq!(receipt.committed_revision, Revision::new(1));
    Ok(())
}

#[test]
fn cancelled_expired_and_deposed_reads_never_become_successful()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let (mut runtime, peer) =
        leadership_waiters::elected_runtime(&directory.path().join("cancel.sqlite3"))?;
    drop(begin(&mut runtime)?);
    runtime.expire_reads(Instant::now())?;
    assert!(runtime.reads.is_empty());
    let mut expired = begin(&mut runtime)?;
    runtime.expire_reads(Instant::now() + Duration::from_secs(6))?;
    assert_eq!(
        expired.try_recv()?,
        Err(MetadataAuthorityRequestError::Unavailable)
    );
    assert!(runtime.reads.is_empty());
    let mut deposed = begin(&mut runtime)?;
    let last = runtime
        .driver
        .last_log_entry()
        .ok_or("term confirmation missing")?
        .position;
    runtime.receive_peer(PeerConsensusMessage::new(
        peer,
        1,
        CoreMessage::VoteRequest(VoteRequest {
            term: 2,
            candidate: peer,
            candidate_incarnation: 1,
            last_log: last,
            membership_epoch: 1,
            plan_digest: runtime.driver.active_plan().proof_digest(),
        }),
    ))?;
    assert!(matches!(
        deposed.try_recv()?,
        Err(MetadataAuthorityRequestError::NotLeader { .. })
    ));
    assert!(runtime.reads.is_empty());
    assert_eq!(runtime.driver.applied_index(), 0);
    Ok(())
}

type ReadResponse = oneshot::Receiver<Result<MetadataReadFence, MetadataAuthorityRequestError>>;

pub(super) async fn read_on_survivor(
    authorities: &[AuthorityTask],
) -> Result<MetadataReadFence, Box<dyn std::error::Error>> {
    Ok(tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            for (authority, _) in authorities {
                match authority.read_fence().await {
                    Err(
                        MetadataAuthorityRequestError::NotLeader { .. }
                        | MetadataAuthorityRequestError::Unavailable,
                    ) => {}
                    result => return result,
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await??)
}

#[test]
fn pending_reads_are_bounded_and_cancellation_releases_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let (mut runtime, _) =
        leadership_waiters::elected_runtime(&directory.path().join("bounds.sqlite3"))?;
    let mut pending = Vec::new();
    for _ in 0..64 {
        pending.push(begin(&mut runtime)?);
    }
    assert_eq!(runtime.reads.len(), 64);
    assert_eq!(
        begin(&mut runtime)?.try_recv()?,
        Err(MetadataAuthorityRequestError::Unavailable)
    );
    drop(pending);
    runtime.expire_reads(Instant::now())?;
    assert!(runtime.reads.is_empty());
    let mut admitted = begin(&mut runtime)?;
    assert!(matches!(
        admitted.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert_eq!(runtime.reads.len(), 1);
    assert_eq!(
        runtime
            .driver
            .last_log_entry()
            .ok_or("confirmation missing")?
            .position
            .index,
        1
    );
    Ok(())
}

fn begin(
    runtime: &mut MetadataAuthorityRuntime,
) -> Result<ReadResponse, MetadataAuthorityRuntimeError> {
    let (respond, response) = oneshot::channel();
    runtime.begin_read(ReadRequest {
        respond,
        deadline: Instant::now() + Duration::from_secs(5),
    })?;
    Ok(response)
}

fn acknowledge(
    runtime: &mut MetadataAuthorityRuntime,
    peer: NodeId,
    accepted: bool,
    barrier: Option<ReadBarrierId>,
    sent: &[(NodeId, CoreMessage)],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut probe = None;
    for (to, message) in sent {
        if let CoreMessage::AppendRequest(request) = message
            && *to == peer
            && request.read_barrier_id == barrier
        {
            probe = Some(request);
        }
    }
    let probe = probe.ok_or("missing emitted append probe for acknowledgement")?;
    let (position, digest) = probe
        .entries
        .last()
        .map_or((probe.previous, probe.previous_digest), |entry| {
            (entry.position, entry.entry_digest())
        });
    runtime.receive_peer(PeerConsensusMessage::new(
        peer,
        1,
        CoreMessage::AppendResponse(AppendResponse {
            probe_id: Some(probe.probe_id),
            matched_digest: if accepted { digest } else { [0; 32] },
            term: probe.term,
            accepted,
            matched_index: if accepted { position.index } else { 0 },
            next_index_hint: position.index + 1,
            read_barrier_id: probe.read_barrier_id,
            membership_epoch: probe.membership_epoch,
            plan_digest: probe.plan_digest,
        }),
    ))?;
    Ok(())
}
