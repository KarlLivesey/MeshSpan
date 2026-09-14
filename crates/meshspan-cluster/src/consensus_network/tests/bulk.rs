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
    first.send(peer, expected.clone());
    let received = tokio::time::timeout(Duration::from_secs(15), incoming.recv())
        .await?
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

fn append(leader: NodeId, command_bytes: usize) -> Result<CoreMessage, Box<dyn std::error::Error>> {
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

fn pair() -> Result<
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
