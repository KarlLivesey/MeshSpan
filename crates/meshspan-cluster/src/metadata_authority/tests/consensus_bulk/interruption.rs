// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use meshspan_consensus::{AppendRequest, AppendResponse};
use tokio::sync::Notify;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Default)]
pub(in crate::metadata_authority::tests) struct BulkGate {
    state: Mutex<GateState>,
    changed: Notify,
    reconnect_timeout: bool,
}

#[derive(Default)]
struct GateState {
    blocked: Option<OperationId>,
    contacts: BTreeMap<(NodeId, NodeId), u64>,
    captured: BTreeMap<(NodeId, NodeId), AppendRequest>,
    replies: BTreeMap<(NodeId, NodeId, u64), AppendResponse>,
}

pub(in crate::metadata_authority::tests) struct GatedTransport {
    network: ConsensusNetwork,
    gate: Arc<BulkGate>,
}

impl GatedTransport {
    pub(in crate::metadata_authority::tests) const fn new(
        network: ConsensusNetwork,
        gate: Arc<BulkGate>,
    ) -> Self {
        Self { network, gate }
    }
}

impl ConsensusMessageTransport for GatedTransport {
    #[expect(
        clippy::expect_used,
        reason = "The synchronous test transport cannot return mutex failures; poison invalidates this fixture."
    )]
    fn send(&self, to: NodeId, message: CoreMessage) {
        let from = self.network.local_node_id();
        let mut state = self.gate.state.lock().expect("test gate mutex");
        if let CoreMessage::AppendResponse(response) = &message
            && response.accepted
        {
            state
                .replies
                .entry((from, to, response.matched_index))
                .or_insert(*response);
            self.gate.changed.notify_waiters();
        }
        if let CoreMessage::AppendRequest(request) = &message
            && request.entries.is_empty()
            && state.blocked.is_some()
        {
            *state.contacts.entry((from, to)).or_default() += 1;
            self.gate.changed.notify_waiters();
        }
        if let CoreMessage::AppendRequest(request) = &message
            && request
                .entries
                .iter()
                .any(|entry| Some(entry.operation_id) == state.blocked)
        {
            state
                .captured
                .entry((from, to))
                .or_insert_with(|| request.clone());
            self.gate.changed.notify_waiters();
            return;
        }
        drop(state);
        self.network.send(to, message);
    }

    fn consensus_transfer_support_for(
        &self,
        expected: meshspan_transport::PeerBinding,
        digest: [u8; 32],
    ) -> Result<Option<crate::ObservedConsensusTransferSupport>, ConsensusNetworkError> {
        self.network
            .consensus_transfer_support_for(expected, digest)
    }
}

impl BulkGate {
    fn for_reconnect() -> Self {
        Self {
            reconnect_timeout: true,
            ..Self::default()
        }
    }

    pub(in crate::metadata_authority::tests) fn election_timeout(&self) -> Option<Duration> {
        self.reconnect_timeout.then_some(Duration::from_secs(5))
    }

    pub(super) fn block(&self, operation: Option<OperationId>) -> TestResult {
        let mut state = self.state.lock().map_err(|_| "test gate mutex poisoned")?;
        state.blocked = operation;
        state.contacts.clear();
        Ok(())
    }

    pub(super) async fn contacts(
        &self,
        from: NodeId,
        peers: &[NodeId],
        minimum: u64,
    ) -> TestResult {
        loop {
            let changed = self.changed.notified();
            let complete = {
                let state = self.state.lock().map_err(|_| "test gate mutex poisoned")?;
                peers
                    .iter()
                    .all(|peer| state.contacts.get(&(from, *peer)).copied().unwrap_or(0) >= minimum)
            };
            if complete {
                return Ok(());
            }
            changed.await;
        }
    }

    pub(super) async fn captured(&self, from: NodeId, to: NodeId) -> TestResult<AppendRequest> {
        loop {
            let changed = self.changed.notified();
            if let Some(request) = self
                .state
                .lock()
                .map_err(|_| "test gate mutex poisoned")?
                .captured
                .get(&(from, to))
                .cloned()
            {
                return Ok(request);
            }
            changed.await;
        }
    }

    pub(super) async fn matched(
        &self,
        from: NodeId,
        to: NodeId,
        index: u64,
    ) -> TestResult<AppendResponse> {
        loop {
            let changed = self.changed.notified();
            if let Some(response) = self
                .state
                .lock()
                .map_err(|_| "test gate mutex poisoned")?
                .replies
                .get(&(from, to, index))
            {
                return Ok(*response);
            }
            changed.await;
        }
    }
}

#[tokio::test]
async fn interrupted_bulk_reconnect_retries_original_entry_and_reopens_exact_receipts() -> TestResult
{
    let gate = Arc::new(BulkGate::for_reconnect());
    let cluster = RealAuthorityCluster::start_with_bulk_gate(Some(Arc::clone(&gate))).await?;
    let result =
        tokio::time::timeout(Duration::from_secs(20), prove_interruption(&cluster, &gate)).await;
    let directory = stop_preserving_storage(cluster).await?;
    let (context, encoded, receipt) = result??;
    for index in 0..3 {
        let repository = AuthoritativeRepository::new(PartitionDatabase::open_existing(
            &directory.path().join(format!("quinn-node-{index}.sqlite3")),
            now(),
        )?);
        let state = repository.load_consensus_state(1)?;
        assert_eq!(state.applied_index, receipt.committed_position.index);
        let entry = state
            .log
            .iter()
            .find(|entry| entry.operation_id == context.operation_id)
            .ok_or("lost original entry")?;
        assert!(
            entry.command.as_ref() == encoded,
            "original canonical command bytes changed"
        );
        let reopened = repository
            .resolve_operation(context.operation_id)?
            .ok_or("missing reopened receipt")?;
        assert_eq!(reopened.committed_position, receipt.committed_position);
        assert_eq!(reopened.result_digest, receipt.result_digest);
    }
    Ok(())
}

async fn prove_interruption(
    cluster: &RealAuthorityCluster,
    gate: &BulkGate,
) -> TestResult<(CommandContext, Vec<u8>, CommandReceipt)> {
    let baseline = prepare_interruption_baseline(cluster, gate).await?;
    let leader = &cluster.authorities[0].0;
    let (mut context, command) = large_target_command(cluster.nodes[0], 70 * 1024)?;
    context.expected_revision = Some(Revision::new(8));
    let encoded = encode_authoritative_command(context, &command)?;
    gate.state
        .lock()
        .map_err(|_| "test gate mutex poisoned")?
        .blocked = Some(context.operation_id);
    let submit = leader.commit_or_resolve(context, command.clone());
    tokio::pin!(submit);
    let request = tokio::select! {
        outcome = &mut submit => return Err(format!("operation completed before transfer: {outcome:?}").into()),
        request = gate.captured(cluster.nodes[0], cluster.nodes[1]) => request?,
    };
    assert_eq!(request.previous.index, baseline);
    assert_eq!(request.entries.len(), 1);
    let entry = request.entries.first().ok_or("captured append missing")?;
    assert!(
        entry.command.as_ref() == encoded,
        "original canonical command bytes changed"
    );
    assert_eq!(entry.operation_id, context.operation_id);
    let message = CoreMessage::AppendRequest(request.clone());
    cluster.networks[0]
        .interrupt_bulk_body_for_test(&cluster.networks[1], &message)
        .await?;
    assert_no_progress(cluster, gate, baseline, context.operation_id).await?;
    cluster.networks[0].send(cluster.nodes[1], message);
    let matched = gate
        .matched(cluster.nodes[1], cluster.nodes[0], entry.position.index)
        .await?;
    assert_eq!(matched.probe_id, Some(request.probe_id));
    assert_eq!(matched.matched_digest, entry.entry_digest());
    gate.state
        .lock()
        .map_err(|_| "test gate mutex poisoned")?
        .blocked = None;
    let receipt = submit.await?;
    assert_eq!(receipt.committed_position.index, entry.position.index);
    assert_eq!(receipt.committed_position.term, entry.position.term);
    assert_eq!(receipt.committed_revision, Revision::new(9));
    verify_committed_receipts(cluster, context, &command, &receipt).await?;
    for peer in &cluster.nodes[1..] {
        let reply = gate
            .matched(*peer, cluster.nodes[0], entry.position.index)
            .await?;
        assert_eq!(reply.matched_digest, entry.entry_digest());
    }
    Ok((context, encoded, receipt))
}

pub(super) async fn verify_committed_receipts(
    cluster: &RealAuthorityCluster,
    context: CommandContext,
    command: &AuthoritativeCommand,
    receipt: &CommandReceipt,
) -> TestResult {
    for (authority, _) in &cluster.authorities {
        let replay = resolve_after_replication(authority, context, command).await?;
        assert_eq!(replay.committed_position, receipt.committed_position);
        assert_eq!(replay.result_digest, receipt.result_digest);
        assert_eq!(
            authority.observe().await?.applied_index,
            receipt.committed_position.index
        );
    }
    Ok(())
}

pub(super) async fn prepare_interruption_baseline(
    cluster: &RealAuthorityCluster,
    gate: &BulkGate,
) -> TestResult<u64> {
    cluster.authorities[0].0.begin_election().await?;
    prepare_admitted_bulk_members(cluster).await?;
    let leader = &cluster.authorities[0].0;
    let baseline = leader.observe().await?;
    assert_eq!(baseline.role, Role::Leader);
    for (authority, _) in &cluster.authorities {
        loop {
            if authority.observe().await?.applied_index == baseline.applied_index {
                break;
            }
            tokio::task::yield_now().await;
        }
    }
    for peer in &cluster.nodes[1..] {
        gate.matched(*peer, cluster.nodes[0], baseline.applied_index)
            .await?;
    }
    Ok(baseline.applied_index)
}

pub(super) async fn assert_no_progress(
    cluster: &RealAuthorityCluster,
    gate: &BulkGate,
    baseline: u64,
    operation: OperationId,
) -> TestResult {
    let reply = gate
        .state
        .lock()
        .map_err(|_| "test gate mutex poisoned")?
        .replies
        .get(&(cluster.nodes[1], cluster.nodes[0], baseline))
        .copied()
        .ok_or("baseline match absent")?;
    assert_eq!(reply.matched_index, baseline);
    assert!(
        gate.state
            .lock()
            .map_err(|_| "test gate mutex poisoned")?
            .replies
            .keys()
            .all(|(_, _, index)| *index <= baseline)
    );
    for (index, (authority, _)) in cluster.authorities.iter().enumerate() {
        let observed = authority.observe().await?;
        assert_eq!(observed.commit_index, baseline);
        assert_eq!(observed.applied_index, baseline);
        let repository = AuthoritativeRepository::new(PartitionDatabase::open_existing(
            &cluster
                .directory
                .path()
                .join(format!("quinn-node-{index}.sqlite3")),
            now(),
        )?);
        let state = repository.load_consensus_state(1)?;
        assert_eq!(state.applied_index, baseline);
        assert!(repository.resolve_operation(operation)?.is_none());
        if index != 0 {
            assert_eq!(
                state
                    .log
                    .last()
                    .ok_or("baseline log absent")?
                    .position
                    .index,
                baseline
            );
        }
    }
    Ok(())
}
