// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use meshspan_consensus::{AppendRequest, LogPosition, VoteRequest, VoteResponse};

#[test]
fn leadership_loss_redirects_pending_and_queued_waiters_without_erasing_durable_work()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let (mut runtime, peer) = elected_runtime(&directory.path().join("waiters.sqlite3"))?;
    let plan_digest = runtime.driver.active_plan().proof_digest();
    let (context, command) = command(runtime.driver.local_node_id(), [78; 16])?;
    let mut receivers = Vec::new();
    for index in 0..3 {
        let (respond, response) = oneshot::channel();
        let mut queued_context = context;
        if index == 2 {
            queued_context.operation_id = OperationId::from_bytes([79; 16])?;
        }
        runtime.submit(AuthoritySubmission {
            context: queued_context,
            command: command.clone(),
            respond,
        })?;
        receivers.push(response);
    }
    assert_eq!(runtime.pending.len(), 1);
    assert_eq!(runtime.queued.len(), 1);
    let entry = runtime
        .driver
        .last_log_entry()
        .ok_or("missing durable proposal")?
        .clone();
    runtime.receive_peer(PeerConsensusMessage {
        from: peer,
        sender_incarnation: 1,
        message: CoreMessage::VoteRequest(VoteRequest {
            term: 2,
            candidate: peer,
            candidate_incarnation: 1,
            last_log: entry.position,
            membership_epoch: 1,
            plan_digest,
        }),
    })?;
    assert_eq!(runtime.driver.role(), Role::Follower);
    for mut receiver in receivers {
        assert!(
            matches!(
                receiver.try_recv(),
                Ok(Err(MetadataAuthorityRequestError::NotLeader { .. }))
            ),
            "leadership loss left an operation waiter unresolved"
        );
    }
    assert!(runtime.pending.is_empty());
    assert!(runtime.queued.is_empty());
    assert_eq!(runtime.driver.last_log_entry(), Some(&entry));
    assert_eq!(runtime.driver.commit_index(), 0);
    assert!(
        runtime
            .driver
            .persistence()
            .resolve_operation(context.operation_id)?
            .is_none()
    );
    // Redirection is not rollback or a claim of failure: the next leader can commit these bytes.
    runtime.receive_peer(PeerConsensusMessage {
        from: peer,
        sender_incarnation: 1,
        message: CoreMessage::AppendRequest(AppendRequest {
            term: 2,
            leader: peer,
            leader_incarnation: 1,
            previous: LogPosition::GENESIS,
            previous_digest: [0; 32],
            entries: vec![entry],
            leader_commit_index: 1,
            read_barrier_id: None,
            membership_epoch: 1,
            plan_digest,
        }),
    })?;
    let (respond, mut response) = oneshot::channel();
    runtime.submit(AuthoritySubmission {
        context,
        command,
        respond,
    })?;
    let receipt = response.try_recv()??;
    assert_eq!(receipt.operation_id, context.operation_id);
    assert_eq!(receipt.committed_revision, Revision::new(1));
    assert_eq!(runtime.driver.applied_index(), 1);
    Ok(())
}

pub(super) fn elected_runtime(
    file_path: &std::path::Path,
) -> Result<(MetadataAuthorityRuntime, NodeId), Box<dyn std::error::Error>> {
    let local = NodeId::from_bytes([76; 16])?;
    let peer = NodeId::from_bytes([77; 16])?;
    let plan = plan(&[local, peer, NodeId::from_bytes([80; 16])?])?;
    let driver = driver_with_plan(file_path, local, &plan)?;
    let (_sender, events) = mpsc::channel(8);
    let mut runtime = MetadataAuthorityRuntime::new(
        driver,
        Arc::new(|_, _| {}),
        MetadataAuthorityConfig::default(),
        events,
        false,
    );
    runtime.process_input(CoreInput::ElectionTimeout)?;
    runtime.receive_peer(PeerConsensusMessage {
        from: peer,
        sender_incarnation: 1,
        message: CoreMessage::VoteResponse(VoteResponse {
            term: 1,
            granted: true,
            membership_epoch: 1,
            plan_digest: plan.proof_digest(),
        }),
    })?;
    assert_eq!(runtime.driver.role(), Role::Leader);
    Ok((runtime, peer))
}
