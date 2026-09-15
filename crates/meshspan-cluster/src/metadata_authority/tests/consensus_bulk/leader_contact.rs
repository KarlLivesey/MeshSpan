// SPDX-License-Identifier: GPL-2.0-only

use super::interruption::{
    BulkGate, assert_no_progress, prepare_interruption_baseline, verify_committed_receipts,
};
use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[tokio::test]
async fn delayed_bulk_keeps_leader_contact_and_commits_original_proof_after_seventy_heartbeats()
-> TestResult {
    let gate = Arc::new(BulkGate::default());
    assert!(gate.election_timeout().is_none());
    let cluster = RealAuthorityCluster::start_with_bulk_gate(Some(Arc::clone(&gate))).await?;
    let result =
        tokio::time::timeout(Duration::from_secs(15), prove_contact(&cluster, &gate)).await;
    let directory = stop_preserving_storage(cluster).await?;
    let (context, encoded, receipt) = match result {
        Ok(Ok(proof)) => proof,
        failed => {
            return Err(format!(
                "delayed body contact failed: {failed:?}; retained {:?}",
                directory.keep()
            )
            .into());
        }
    };
    for index in 0..3 {
        let repository = AuthoritativeRepository::new(PartitionDatabase::open_existing(
            &directory.path().join(format!("quinn-node-{index}.sqlite3")),
            now(),
        )?);
        let state = repository.load_consensus_state(1)?;
        assert_eq!(state.applied_index, receipt.committed_position.index);
        let entries: Vec<_> = state
            .log
            .iter()
            .filter(|entry| entry.operation_id == context.operation_id)
            .collect();
        assert_eq!(
            entries.len(),
            1,
            "recovery appended another copy of the operation"
        );
        assert_eq!(entries[0].position.index, receipt.committed_position.index);
        assert_eq!(entries[0].position.term, receipt.committed_position.term);
        assert!(
            entries[0].command.as_ref() == encoded,
            "reopened command bytes changed"
        );
        let reopened = repository
            .resolve_operation(context.operation_id)?
            .ok_or("missing reopened receipt")?;
        assert_eq!(reopened.committed_position, receipt.committed_position);
        assert_eq!(reopened.result_digest, receipt.result_digest);
    }
    Ok(())
}

async fn prove_contact(
    cluster: &RealAuthorityCluster,
    gate: &BulkGate,
) -> TestResult<(CommandContext, Vec<u8>, CommandReceipt)> {
    let baseline = prepare_interruption_baseline(cluster, gate).await?;
    let leader = &cluster.authorities[0].0;
    let term = leader.observe().await?.term;
    let (mut context, command) = large_target_command(cluster.nodes[0], 70 * 1024)?;
    context.expected_revision = Some(Revision::new(8));
    let encoded = encode_authoritative_command(context, &command)?;
    gate.block(Some(context.operation_id))?;
    let submit = leader.commit_or_resolve(context, command.clone());
    tokio::pin!(submit);
    let request = tokio::select! {
        outcome = &mut submit => return Err(format!("operation returned before body delivery: {outcome:?}").into()),
        request = gate.captured(cluster.nodes[0], cluster.nodes[1]) => request?,
    };
    let held = Instant::now();
    tokio::select! {
        outcome = &mut submit => return Err(format!("leader contact failed while original body was held: {outcome:?}").into()),
        result = gate.contacts(cluster.nodes[0], &cluster.nodes[1..], 70) => result?,
    }
    // Ordinary follower base timeouts are 600/850ms; rank jitter raises the longest to 1487.5ms.
    assert!(held.elapsed() >= Duration::from_millis(1500));
    assert_stalled_authorities(cluster, gate, term, baseline, context.operation_id).await?;
    assert_eq!(request.entries.len(), 1);
    let entry = request.entries.first().ok_or("missing original entry")?;
    assert!(
        entry.command.as_ref() == encoded,
        "held command bytes changed"
    );
    for peer in &cluster.nodes[1..] {
        let original = gate.captured(cluster.nodes[0], *peer).await?;
        cluster.networks[0].send(*peer, CoreMessage::AppendRequest(original.clone()));
        let reply = gate
            .matched(*peer, cluster.nodes[0], entry.position.index)
            .await?;
        assert_eq!(reply.probe_id, Some(original.probe_id));
        assert_eq!(reply.matched_digest, entry.entry_digest());
    }
    gate.block(None)?;
    let receipt = submit.await?;
    assert_eq!(receipt.committed_position.index, entry.position.index);
    assert_eq!(receipt.committed_position.term, entry.position.term);
    verify_committed_receipts(cluster, context, &command, &receipt).await?;
    Ok((context, encoded, receipt))
}

async fn assert_stalled_authorities(
    cluster: &RealAuthorityCluster,
    gate: &BulkGate,
    term: u64,
    baseline: u64,
    operation: OperationId,
) -> TestResult {
    for (authority, _) in &cluster.authorities {
        let observed = authority.observe().await?;
        assert_eq!(
            observed.term, term,
            "delayed data suppressed valid leader contact"
        );
        assert_eq!(observed.known_leader, Some(cluster.nodes[0]));
        assert_eq!(observed.applied_index, baseline);
    }
    assert_no_progress(cluster, gate, baseline, operation).await
}
