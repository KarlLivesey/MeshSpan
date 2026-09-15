// SPDX-License-Identifier: GPL-2.0-only

use meshspan_consensus::{AppendProbeId, AppendRequest, LogEntry};
use meshspan_protocol::MAXIMUM_CONSENSUS_BULK_BODY_BYTES;
use meshspan_protocol::v1::consensus_bulk_start::Metadata;
use meshspan_protocol::v1::data_control_envelope::Message as DataMessage;
use meshspan_protocol::v1::{ConsensusBulkStart, DataControlEnvelope};
use meshspan_transport::send_data_control;

use super::*;

#[tokio::test]
async fn bulk_consensus_delivers_exact_maximum_generic_command_and_keeps_queued_lease()
-> Result<(), Box<dyn std::error::Error>> {
    let (first, second, mut incoming) = pair()?;
    let peer = second.local_node_id();
    let expected = append(first.local_node_id(), 16 * 1024 * 1024)?;
    let started = std::time::Instant::now();
    first.send(peer, expected.clone());
    let received = tokio::time::timeout(Duration::from_secs(15), incoming.recv())
        .await
        .map_err(|_| bulk_delivery_timeout(&first, &second, &incoming, started))?
        .ok_or("bulk append absent")?;
    assert_eq!(received.message, expected);
    // The receive task may already have returned its ingress receipt. Ownership in the
    // application queue still excludes a second maximum transfer from this peer.
    assert!(
        second
            .bulk_budgets
            .reserve(first.local_node_id(), MAXIMUM_CONSENSUS_BULK_BODY_BYTES)
            .is_err()
    );
    drop(received);
    assert!(
        second
            .bulk_budgets
            .reserve(first.local_node_id(), MAXIMUM_CONSENSUS_BULK_BODY_BYTES)
            .is_ok()
    );
    first.close()?;
    second.close()?;
    Ok(())
}

// These facts are sampled only after the original receive deadline has expired. They do not
// extend that deadline, retry the send, or print command/credential bytes.
fn bulk_delivery_timeout(
    first: &ConsensusNetwork,
    second: &ConsensusNetwork,
    incoming: &mpsc::Receiver<PeerConsensusMessage>,
    started: std::time::Instant,
) -> std::io::Error {
    let first_state = bulk_delivery_state(first, second.local_node_id());
    let second_state = bulk_delivery_state(second, first.local_node_id());
    let (incoming_len, incoming_closed) = (incoming.len(), incoming.is_closed());
    let first_closed = first.close().map_err(|_| "network close failed");
    let second_closed = second.close().map_err(|_| "network close failed");
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!(
            "maximum bulk receive exceeded 15s after {}ms; sender={first_state}; \
             receiver={second_state}; incoming_len={incoming_len}; incoming_closed={incoming_closed}; \
             sender_close={first_closed:?}; receiver_close={second_closed:?}",
            started.elapsed().as_millis(),
        ),
    )
}

fn bulk_delivery_state(network: &ConsensusNetwork, peer: NodeId) -> String {
    let (outbound, authenticated) = match network.peers.read() {
        Ok(peers) => (
            peers.outbound.get(&peer).map(|sender| {
                (
                    sender.max_capacity() - sender.capacity(),
                    sender.is_closed(),
                )
            }),
            Some(peers.transfer_support.contains_key(&peer)),
        ),
        Err(_) => (None, None),
    };
    let maximum_reservation_available = network
        .bulk_budgets
        .reserve(peer, MAXIMUM_CONSENSUS_BULK_BODY_BYTES)
        .is_ok();
    let latest_receive = match network.latest_bulk_receive.lock() {
        Ok(progress) => progress.as_ref().map_or_else(
            || "none".to_owned(),
            |progress| {
                format!(
                    "{:?}, total_ms={}, stage_ms={}",
                    progress.stage,
                    progress.started.elapsed().as_millis(),
                    progress.stage_started.elapsed().as_millis()
                )
            },
        ),
        Err(_) => "unavailable: diagnostic lock poisoned".to_owned(),
    };
    format!(
        "request_sequence={}, outbound_used_slots_and_closed={outbound:?}, \
         authenticated_support_cached={authenticated:?}, codec_permits={}, \
         maximum_reservation_available={maximum_reservation_available}, latest_receive={latest_receive}",
        network.next_request.load(Ordering::Relaxed),
        network.bulk_codecs.available_permits(),
    )
}

#[tokio::test]
async fn stalled_bulk_stream_preserves_same_connection_votes_and_releases_on_reset()
-> Result<(), Box<dyn std::error::Error>> {
    let (first, second, mut incoming) = pair()?;
    let connection = first.connect_peer(second.local_node_id()).await?;
    let (mut stalled, _response) = open_stream(&connection, StreamKind::ConsensusBulk).await?;
    send_data_control(&mut stalled, &descriptor(&first)?, first.wire_limits).await?;
    wait_for_budget(&second, first.local_node_id(), false).await?;
    let vote = CoreMessage::VoteRequest(VoteRequest {
        term: 41,
        candidate: first.local_node_id(),
        candidate_incarnation: 1,
        last_log: LogPosition::GENESIS,
        membership_epoch: 1,
        plan_digest: [9; 32],
    });
    let (mut send, mut receipt) = open_stream(&connection, StreamKind::Consensus).await?;
    send_control(
        &mut send,
        &ControlEnvelope {
            header: Some(first.request_header(OperationId::from_bytes([29; 16])?, i64::MAX)),
            message: Some(encode_consensus_message(&vote)),
        },
        first.wire_limits,
    )
    .await?;
    send.finish()?;
    let received = tokio::time::timeout(Duration::from_secs(2), incoming.recv())
        .await?
        .ok_or("control blocked behind bulk")?;
    assert_eq!(received.message, vote);
    receive_receipt(&mut receipt, first.wire_limits).await?;
    stalled.reset(0_u32.into())?;
    wait_for_budget(&second, first.local_node_id(), true).await?;
    assert!(connection.close_reason().is_none());
    assert!(
        incoming.try_recv().is_err(),
        "partial body reached consensus"
    );
    first.close()?;
    second.close()?;
    Ok(())
}

#[tokio::test]
async fn bulk_consensus_rejects_body_substitution_without_dispatch()
-> Result<(), Box<dyn std::error::Error>> {
    let (first, second, mut incoming) = pair()?;
    let connection = first.connect_peer(second.local_node_id()).await?;
    let (mut send, _receive) = open_stream(&connection, StreamKind::ConsensusBulk).await?;
    let mut start = descriptor(&first)?;
    let Some(DataMessage::ConsensusBulkStart(start)) = &mut start.message else {
        return Err("descriptor absent".into());
    };
    start.byte_length = 1;
    let envelope = DataControlEnvelope {
        message: Some(DataMessage::ConsensusBulkStart(start.clone())),
    };
    send_data_control(&mut send, &envelope, first.wire_limits).await?;
    meshspan_transport::send_data_frame(
        &mut send,
        &meshspan_protocol::v1::DataFrame {
            offset: 0,
            bytes: vec![1],
        },
        first.wire_limits,
    )
    .await?;
    send.finish()?;
    tokio::time::timeout(Duration::from_secs(5), connection.closed()).await?;
    assert!(
        incoming.try_recv().is_err(),
        "substituted body reached consensus"
    );
    first.close()?;
    second.close()?;
    Ok(())
}

#[tokio::test]
async fn consensus_transfer_cache_distinguishes_unknown_and_exact_authenticated_support()
-> Result<(), Box<dyn std::error::Error>> {
    let (first, second, _incoming) = pair()?;
    let route = second
        .peer_routes()?
        .into_iter()
        .next()
        .ok_or("peer route absent")?;
    let expected = PeerBinding {
        node_id: first.local_node_id(),
        incarnation: 1,
        certificate_fingerprint: certificate_fingerprint(&CertificateDer::from(
            route.certificate_der,
        )),
    };
    assert!(second.peer_consensus_transfer_support(expected)?.is_none());
    let connection = first.connect_peer(second.local_node_id()).await?;
    let observed = second
        .peer_consensus_transfer_support(expected)?
        .ok_or("authenticated support absent")?;
    assert_eq!(observed.capability_digest, first.local_capability_digest()?);
    assert_eq!(
        observed.support,
        Some(meshspan_protocol::consensus_transfer_support())
    );
    assert!(
        second
            .peer_consensus_transfer_support(PeerBinding {
                incarnation: 2,
                ..expected
            })?
            .is_none()
    );
    assert!(
        second
            .peer_consensus_transfer_support(PeerBinding {
                certificate_fingerprint: [99; 32],
                ..expected
            })?
            .is_none()
    );
    // A later hello that explicitly omits the feature is known unsupported, not Unknown.
    let route = first
        .peer_routes()?
        .into_iter()
        .next()
        .ok_or("peer route absent")?;
    let legacy = first
        .transport
        .connect(route.address, &route.certificate_name)
        .await?;
    let (mut send, mut receive) = open_stream(&legacy, StreamKind::Metadata).await?;
    let mut hello = first.hello()?;
    hello.consensus_transfer = None;
    send_control(
        &mut send,
        &ControlEnvelope {
            header: None,
            message: Some(Message::NodeHello(hello.clone())),
        },
        first.wire_limits,
    )
    .await?;
    receive_control(&mut receive, first.wire_limits).await?;
    let observed = second
        .peer_consensus_transfer_support(expected)?
        .ok_or("known legacy support absent")?;
    assert_eq!(
        observed.capability_digest,
        meshspan_protocol::node_capability_digest(&hello)
    );
    assert!(observed.support.is_none());
    drop(connection);
    first.close()?;
    second.close()?;
    Ok(())
}

async fn wait_for_budget(
    network: &ConsensusNetwork,
    peer: NodeId,
    available: bool,
) -> Result<(), tokio::time::error::Elapsed> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if network
                .bulk_budgets
                .reserve(peer, MAXIMUM_CONSENSUS_BULK_BODY_BYTES)
                .is_ok()
                == available
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
}

fn descriptor(
    network: &ConsensusNetwork,
) -> Result<DataControlEnvelope, Box<dyn std::error::Error>> {
    let message = append(network.local_node_id(), 0)?;
    let Message::AppendRequest(mut append) = encode_consensus_message(&message) else {
        return Err("append absent".into());
    };
    append.entries.clear();
    Ok(DataControlEnvelope {
        message: Some(DataMessage::ConsensusBulkStart(ConsensusBulkStart {
            header: Some(network.request_header(OperationId::from_bytes([25; 16])?, i64::MAX)),
            format_version: 1,
            byte_length: MAXIMUM_CONSENSUS_BULK_BODY_BYTES as u64,
            body_digest: vec![9; 32],
            entry_count: 1,
            metadata: Some(Metadata::Append(append)),
        })),
    })
}

pub(super) fn append(
    leader: NodeId,
    command_bytes: usize,
) -> Result<CoreMessage, Box<dyn std::error::Error>> {
    Ok(CoreMessage::AppendRequest(AppendRequest {
        probe_id: AppendProbeId(17),
        term: 1,
        leader,
        leader_incarnation: 1,
        previous: LogPosition::GENESIS,
        previous_digest: [0; 32],
        entries: vec![LogEntry::new(
            LogPosition { term: 1, index: 1 },
            OperationId::from_bytes([21; 16])?,
            1,
            vec![7; command_bytes],
        )?],
        leader_commit_index: 1,
        membership_epoch: 1,
        plan_digest: [9; 32],
        read_barrier_id: None,
    }))
}

pub(super) fn pair() -> Result<
    (
        ConsensusNetwork,
        ConsensusNetwork,
        mpsc::Receiver<PeerConsensusMessage>,
    ),
    Box<dyn std::error::Error>,
> {
    let authority = CertificateAuthority::new()?;
    let first_identity = authority.issue_node("meshspan.internal")?;
    let second_identity = authority.issue_node("meshspan.internal")?;
    let first_node = NodeId::from_bytes([1; 16])?;
    let second_node = NodeId::from_bytes([2; 16])?;
    let first_address = unused_udp_address()?;
    let second_address = unused_udp_address()?;
    let mesh_id = MeshId::from_bytes([3; 16])?;
    let partition_id = PartitionId::from_bytes([4; 16])?;
    let roots = authority.certificate_der().to_vec();
    let (first_messages, _received) = mpsc::channel(8);
    let (second_messages, incoming) = mpsc::channel(8);
    let first = ConsensusNetwork::start(
        config(
            first_node,
            first_address,
            &first_identity,
            roots.clone(),
            peer(
                second_node,
                second_address,
                second_identity.certificate_der(),
            ),
            mesh_id,
            partition_id,
        ),
        first_messages,
    )?;
    let second = ConsensusNetwork::start(
        config(
            second_node,
            second_address,
            &second_identity,
            roots,
            peer(first_node, first_address, first_identity.certificate_der()),
            mesh_id,
            partition_id,
        ),
        second_messages,
    )?;
    Ok((first, second, incoming))
}

#[tokio::test]
async fn changed_local_roles_invalidate_cached_hello_and_preserve_in_flight_connection()
-> Result<(), Box<dyn std::error::Error>> {
    let (first, second, _incoming) = pair()?;
    let before = first.local_capability_presentation()?;
    let old_connection = first.control_connection(second.local_node_id()).await?;
    assert_eq!(
        second
            .peer_consensus_transfer_support(before.binding)?
            .ok_or("original hello")?
            .capability_digest,
        before.observed.capability_digest
    );
    assert!(!first.replace_local_roles(&[NodeRole::MetadataVoter])?);
    for invalid in [
        vec![],
        vec![NodeRole::Unspecified],
        vec![NodeRole::MetadataVoter, NodeRole::MetadataLearner],
        vec![NodeRole::Gateway, NodeRole::Gateway],
    ] {
        assert!(first.replace_local_roles(&invalid).is_err());
        assert_eq!(first.local_capability_presentation()?, before);
    }
    assert!(first.replace_local_roles(&[NodeRole::Gateway, NodeRole::MetadataLearner])?);
    let changed = first.local_capability_presentation()?;
    assert_eq!(changed.binding, before.binding);
    assert_ne!(
        changed.observed.capability_digest,
        before.observed.capability_digest
    );
    assert!(
        old_connection.close_reason().is_none(),
        "role replacement canceled an in-flight request"
    );
    let new_connection = first.control_connection(second.local_node_id()).await?;
    assert_ne!(old_connection.stable_id(), new_connection.stable_id());
    assert_eq!(
        second
            .peer_consensus_transfer_support(changed.binding)?
            .ok_or("new hello")?
            .capability_digest,
        changed.observed.capability_digest
    );
    first.close()?;
    second.close()?;
    Ok(())
}

#[tokio::test]
async fn codec_semaphore_stall_expires_before_bulk_dispatch_and_releases_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    let (first, second, mut incoming) = pair()?;
    let codecs = Arc::clone(&first.bulk_codecs).acquire_many_owned(2).await?;
    let peer = second.local_node_id();
    let message = append(first.local_node_id(), 70 * 1024)?;
    let allocation = first
        .bulk_budgets
        .reserve(peer, MAXIMUM_CONSENSUS_BULK_BODY_BYTES)?;
    let deadline = tokio::time::Instant::now() + Duration::from_millis(100);
    let outcome = tokio::time::timeout(
        Duration::from_secs(1),
        first.send_bulk_until(peer, message, allocation, deadline),
    )
    .await;
    let released = first
        .bulk_budgets
        .reserve(peer, MAXIMUM_CONSENSUS_BULK_BODY_BYTES)
        .is_ok();
    drop(codecs);
    first.close()?;
    second.close()?;
    assert!(
        matches!(
            outcome,
            Ok(Err(ConsensusNetworkError::BulkTransferUnconfirmed))
        ),
        "codec admission exceeded the original transfer deadline: {outcome:?}"
    );
    assert!(released, "expired codec admission retained transfer bytes");
    assert!(
        incoming.try_recv().is_err(),
        "expired bulk operation reached consensus"
    );
    Ok(())
}

#[tokio::test]
async fn exact_control_payload_boundary_uses_inline_then_bulk_without_losing_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    let (first, second, mut incoming) = pair()?;
    let header = first.request_header(OperationId::from_bytes([21; 16])?, i64::MAX);
    let extended = WireLimits::new(
        128 * 1024,
        MAXIMUM_DATA_BYTES,
        MAXIMUM_ITEMS,
        MAXIMUM_TEXT_BYTES,
    )?;
    let sample = append(first.local_node_id(), 70 * 1024)?;
    let encoded = meshspan_protocol::encode_control_frame(
        &ControlEnvelope {
            header: Some(header.clone()),
            message: Some(encode_consensus_message(&sample)),
        },
        extended,
    )?;
    let overhead = encoded.len() - 4 - 70 * 1024;
    let boundary = MAXIMUM_CONTROL_BYTES - overhead;
    let mut connection = None;
    for length in [boundary - 1, boundary, boundary + 1] {
        let message = append(first.local_node_id(), length)?;
        let envelope = ControlEnvelope {
            header: Some(header.clone()),
            message: Some(encode_consensus_message(&message)),
        };
        assert_eq!(
            meshspan_protocol::encode_control_frame(&envelope, extended)?.len() - 4,
            length + overhead
        );
        assert_eq!(
            meshspan_protocol::encode_control_frame(&envelope, first.wire_limits).is_ok(),
            length <= boundary
        );
        if length <= boundary {
            first
                .send_with_connection(second.local_node_id(), &mut connection, message.clone())
                .await?;
        } else {
            first.send(second.local_node_id(), message.clone());
        }
        let received = tokio::time::timeout(Duration::from_secs(5), incoming.recv())
            .await?
            .ok_or("boundary append absent")?;
        assert_eq!(received.message, message);
    }
    first.close()?;
    second.close()?;
    Ok(())
}

impl ConsensusNetwork {
    pub(crate) async fn interrupt_bulk_body_for_test(
        &self,
        receiver: &Self,
        message: &CoreMessage,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let Message::AppendRequest(mut request) = encode_consensus_message(message) else {
            return Err("expected genuine append request".into());
        };
        let header = self.request_header(OperationId::from_bytes([166; 16])?, i64::MAX);
        let entries = std::mem::take(&mut request.entries);
        let count = u32::try_from(entries.len())?;
        let body = meshspan_protocol::encode_consensus_bulk_entries(
            &meshspan_protocol::v1::ConsensusBulkEntries {
                format_version: 1,
                request_id: header.request_id.clone(),
                entries,
            },
        )?;
        // Fill capacity with owned test leases, leaving exactly one body-sized slot. Observing
        // that final slot disappear proves the receiver admitted this body before interruption.
        let mut held = Vec::new();
        while let Ok(lease) = receiver
            .bulk_budgets
            .reserve(self.local_node_id(), body.len())
        {
            held.push(lease);
        }
        drop(held.pop().ok_or("no capacity for interrupted body")?);
        let connection = self.connect_peer(receiver.local_node_id()).await?;
        let (mut send, _receive) = open_stream(&connection, StreamKind::ConsensusBulk).await?;
        send_data_control(
            &mut send,
            &DataControlEnvelope {
                message: Some(DataMessage::ConsensusBulkStart(ConsensusBulkStart {
                    header: Some(header),
                    format_version: 1,
                    byte_length: u64::try_from(body.len())?,
                    body_digest: Sha256::digest(&body).to_vec(),
                    entry_count: count,
                    metadata: Some(Metadata::Append(request)),
                })),
            },
            self.wire_limits,
        )
        .await?;
        meshspan_transport::send_data_frame(
            &mut send,
            &meshspan_protocol::v1::DataFrame {
                offset: 0,
                bytes: body.get(..1024).ok_or("body is not bulk sized")?.to_vec(),
            },
            self.wire_limits,
        )
        .await?;
        wait_for_body_slot(receiver, self.local_node_id(), body.len(), false).await?;
        send.reset(0_u32.into())?;
        connection.close(0_u32.into(), b"controlled interrupted bulk reconnect");
        connection.closed().await;
        wait_for_body_slot(receiver, self.local_node_id(), body.len(), true).await?;
        Ok(())
    }
}

async fn wait_for_body_slot(
    network: &ConsensusNetwork,
    peer: NodeId,
    length: usize,
    available: bool,
) -> Result<(), tokio::time::error::Elapsed> {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if network.bulk_budgets.reserve(peer, length).is_ok() == available {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
}
