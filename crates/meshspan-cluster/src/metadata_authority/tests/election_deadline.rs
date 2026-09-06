// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use meshspan_consensus::{LogPosition, ProposalId, VoteRequest, VoteResponse};

#[tokio::test]
async fn only_accepted_leader_contact_resets_the_election_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let local = NodeId::from_bytes([74; 16])?;
    let peer = NodeId::from_bytes([75; 16])?;
    let plan = plan(&[local, peer])?;
    let driver = driver_with_plan(&directory.path().join("contact.sqlite3"), local, &plan)?;
    let (_sender, events) = mpsc::channel(8);
    let mut runtime = MetadataAuthorityRuntime::new(
        driver,
        Arc::new(|_, _| {}),
        MetadataAuthorityConfig::default(),
        events,
        false,
    );
    let deadline = Instant::now();
    runtime.election_deadline = deadline;
    let mut append = meshspan_consensus::AppendRequest {
        term: 1,
        leader: peer,
        leader_incarnation: 1,
        previous: LogPosition::GENESIS,
        previous_digest: [0; 32],
        entries: Vec::new(),
        leader_commit_index: 0,
        read_barrier_id: None,
        membership_epoch: 1,
        plan_digest: [0; 32],
    };
    runtime.receive_peer(PeerConsensusMessage {
        from: peer,
        sender_incarnation: 1,
        message: CoreMessage::AppendRequest(append.clone()),
    })?;
    assert_eq!(runtime.driver.current_term(), 0);
    assert_eq!(runtime.election_deadline, deadline);
    append.plan_digest = plan.proof_digest();
    runtime.receive_peer(PeerConsensusMessage {
        from: peer,
        sender_incarnation: 1,
        message: CoreMessage::AppendRequest(append.clone()),
    })?;
    assert_eq!(runtime.driver.current_term(), 1);
    assert_eq!(runtime.driver.leader_id(), Some(peer));
    assert!(runtime.election_deadline > deadline);
    // Remembering this sender as leader does not authenticate a later mismatched plan.
    runtime.election_deadline = deadline;
    append.plan_digest = [0; 32];
    runtime.receive_peer(PeerConsensusMessage {
        from: peer,
        sender_incarnation: 1,
        message: CoreMessage::AppendRequest(append),
    })?;
    assert_eq!(runtime.election_deadline, deadline);
    Ok(())
}

#[tokio::test]
async fn higher_term_stale_candidate_cannot_postpone_an_up_to_date_voters_election()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let stale = NodeId::from_bytes([71; 16])?;
    let local = NodeId::from_bytes([72; 16])?;
    let plan = plan(&[stale, local])?;
    let driver = driver_with_plan(&directory.path().join("voter.sqlite3"), local, &plan)?;
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
        from: stale,
        sender_incarnation: 1,
        message: CoreMessage::VoteResponse(VoteResponse {
            term: 1,
            granted: true,
            membership_epoch: 1,
            plan_digest: plan.proof_digest(),
        }),
    })?;
    let (context, command) = command(local, [73; 16])?;
    runtime.process_input(CoreInput::Propose {
        proposal_id: ProposalId(1),
        operation_id: context.operation_id,
        command_version: METADATA_COMMAND_VERSION,
        command: encode_authoritative_command(context, &command)?,
    })?;
    assert!(runtime.driver.last_log_entry().is_some());
    let election_deadline = runtime.election_deadline;
    for term in 2..=4 {
        runtime.receive_peer(PeerConsensusMessage {
            from: stale,
            sender_incarnation: 1,
            message: CoreMessage::VoteRequest(VoteRequest {
                term,
                candidate: stale,
                candidate_incarnation: 1,
                last_log: LogPosition::GENESIS,
                membership_epoch: 1,
                plan_digest: plan.proof_digest(),
            }),
        })?;
        assert_eq!(runtime.driver.current_term(), term);
        assert_eq!(runtime.driver.role(), Role::Follower);
        assert_eq!(
            runtime.election_deadline, election_deadline,
            "rejecting an outdated candidate postponed the local election"
        );
    }
    runtime.election_deadline = Instant::now();
    runtime.check_election_timeout()?;
    assert_eq!(runtime.driver.role(), Role::Candidate);
    assert_eq!(runtime.driver.current_term(), 5);
    Ok(())
}
