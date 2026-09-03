// SPDX-License-Identifier: GPL-2.0-only

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use meshspan_consensus::{
    ActiveQuorumPlan, CoreMessage, LogPosition, VoteRequest, compile_plan, flat_plan,
};
use meshspan_domain::{BackupId, OperationId, QuorumPlanId, Revision, SnapshotId, UnixMicros};
use meshspan_metadata::{
    LogPosition as MetadataLogPosition, PartitionBackupManifest, PartitionSnapshotManifest,
};
use meshspan_protocol::v1::control_envelope::Message;
use meshspan_protocol::v1::{ControlEnvelope, Ping, Pong};
use meshspan_test_certificates::CertificateAuthority;
use sha2::{Digest, Sha256};

use super::*;

#[tokio::test]
async fn real_quinn_mtls_delivers_one_exact_authenticated_consensus_message()
-> Result<(), Box<dyn std::error::Error>> {
    let authority = CertificateAuthority::new()?;
    let first_identity = authority.issue_node("meshspan.internal")?;
    let second_identity = authority.issue_node("meshspan.internal")?;
    let first_node = NodeId::from_bytes([1; 16])?;
    let second_node = NodeId::from_bytes([2; 16])?;
    let first_address = unused_udp_address()?;
    let second_address = unused_udp_address()?;
    let mesh_id = MeshId::from_bytes([3; 16])?;
    let partition_id = PartitionId::from_bytes([4; 16])?;
    let authority_certificate = authority.certificate_der().to_vec();
    let (first_messages, _first_received) = mpsc::channel(8);
    let (second_messages, mut second_received) = mpsc::channel(8);
    let first = ConsensusNetwork::start(
        config(
            first_node,
            first_address,
            &first_identity,
            authority_certificate.clone(),
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
    let _second = ConsensusNetwork::start(
        config(
            second_node,
            second_address,
            &second_identity,
            authority_certificate,
            peer(first_node, first_address, first_identity.certificate_der()),
            mesh_id,
            partition_id,
        ),
        second_messages,
    )?;
    let message = CoreMessage::VoteRequest(VoteRequest {
        term: 7,
        candidate: first_node,
        candidate_incarnation: 1,
        last_log: LogPosition::GENESIS,
        membership_epoch: 1,
        plan_digest: [9; 32],
    });
    first.send(second_node, message.clone());
    let received = tokio::time::timeout(Duration::from_secs(5), second_received.recv())
        .await?
        .ok_or("consensus receive queue closed")?;
    assert_eq!(
        received,
        PeerConsensusMessage {
            from: first_node,
            sender_incarnation: 1,
            message,
        }
    );
    Ok(())
}

#[tokio::test]
async fn real_quinn_mtls_transfers_and_confirms_one_verified_snapshot()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let source = directory.path().join("source.snapshot");
    let bytes = b"exact snapshot bytes".to_vec();
    std::fs::write(&source, &bytes)?;
    let authority = CertificateAuthority::new()?;
    let first_identity = authority.issue_node("meshspan.internal")?;
    let second_identity = authority.issue_node("meshspan.internal")?;
    let first_node = NodeId::from_bytes([11; 16])?;
    let second_node = NodeId::from_bytes([12; 16])?;
    let first_address = unused_udp_address()?;
    let second_address = unused_udp_address()?;
    let mesh_id = MeshId::from_bytes([13; 16])?;
    let partition_id = PartitionId::from_bytes([14; 16])?;
    let trust_anchor = authority.certificate_der().to_vec();
    let (first_messages, _first_received) = mpsc::channel(8);
    let (second_messages, _second_received) = mpsc::channel(8);
    let (snapshots, mut received_snapshots) = mpsc::channel(1);
    let first = ConsensusNetwork::start(
        config(
            first_node,
            first_address,
            &first_identity,
            trust_anchor.clone(),
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
    let mut second_config = config(
        second_node,
        second_address,
        &second_identity,
        trust_anchor,
        peer(first_node, first_address, first_identity.certificate_der()),
        mesh_id,
        partition_id,
    );
    second_config.snapshot_staging_path = Some(directory.path().join("receiver.sqlite3"));
    let _second =
        ConsensusNetwork::start_with_snapshots(second_config, second_messages, snapshots)?;
    let plan = compile_plan(flat_plan(
        QuorumPlanId::from_bytes([15; 16])?,
        1,
        std::collections::BTreeSet::from([first_node]),
        std::collections::BTreeSet::from([second_node]),
    )?)?;
    let snapshot_id = SnapshotId::from_bytes([16; 16])?;
    let manifest = PartitionSnapshotManifest {
        snapshot_id,
        backup: PartitionBackupManifest {
            backup_id: BackupId::from_bytes(snapshot_id.as_bytes())?,
            partition_id,
            mesh_id,
            applied_position: MetadataLogPosition { term: 1, index: 1 },
            state_revision: Revision::new(1),
            schema_version: 1,
            byte_length: u64::try_from(bytes.len())?,
            digest: Sha256::digest(&bytes).into(),
            created_at: UnixMicros::new(1),
        },
        membership_epoch: 1,
        quorum_plan_digest: plan.proof_digest(),
    };
    let snapshot = OutboundConsensusSnapshot {
        path: source,
        manifest,
        quorum_plan: ActiveQuorumPlan::Stable(Box::new(plan)).encode()?,
    };
    let installed = tokio::spawn(async move {
        let received = received_snapshots
            .recv()
            .await
            .ok_or_else(|| std::io::Error::other("snapshot receive queue closed"))?;
        let staged = tokio::fs::read(&received.snapshot.staging_path).await?;
        received
            .installed
            .send(())
            .map_err(|()| std::io::Error::other("snapshot sender closed"))?;
        Ok::<_, std::io::Error>(staged)
    });
    first.send_snapshot(second_node, &snapshot).await?;
    assert_eq!(installed.await??, bytes);
    Ok(())
}

#[tokio::test]
async fn one_blocked_control_stream_does_not_block_another_on_the_same_connection()
-> Result<(), Box<dyn std::error::Error>> {
    let authority = CertificateAuthority::new()?;
    let first_identity = authority.issue_node("meshspan.internal")?;
    let second_identity = authority.issue_node("meshspan.internal")?;
    let first_node = NodeId::from_bytes([21; 16])?;
    let second_node = NodeId::from_bytes([22; 16])?;
    let first_address = unused_udp_address()?;
    let second_address = unused_udp_address()?;
    let mesh_id = MeshId::from_bytes([23; 16])?;
    let partition_id = PartitionId::from_bytes([24; 16])?;
    let trust_anchor = authority.certificate_der().to_vec();
    let (first_messages, _first_received) = mpsc::channel(8);
    let (second_messages, _second_received) = mpsc::channel(8);
    let (controls, mut received_controls) = mpsc::channel(2);
    let first = ConsensusNetwork::start(
        config(
            first_node,
            first_address,
            &first_identity,
            trust_anchor.clone(),
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
    let second = ConsensusNetwork::start_with_control(
        config(
            second_node,
            second_address,
            &second_identity,
            trust_anchor,
            peer(first_node, first_address, first_identity.certificate_der()),
            mesh_id,
            partition_id,
        ),
        second_messages,
        controls,
    )?;
    let first_operation = OperationId::from_bytes([25; 16])?;
    let second_operation = OperationId::from_bytes([26; 16])?;
    let first_request = control_request(&first, first_operation, 1)?;
    let second_request = control_request(&first, second_operation, 2)?;
    let first_client = first.clone();
    let first_call = tokio::spawn(async move {
        first_client
            .request_control(second_node, &first_request)
            .await
    });
    let first_received = tokio::time::timeout(Duration::from_secs(5), received_controls.recv())
        .await?
        .ok_or("first control receive queue closed")?;
    let second_client = first.clone();
    let second_call = tokio::spawn(async move {
        second_client
            .request_control(second_node, &second_request)
            .await
    });
    let second_received = tokio::time::timeout(Duration::from_secs(5), received_controls.recv())
        .await?
        .ok_or("second control stream was blocked behind the first")?;

    second_received
        .respond
        .send(control_response(&second, second_operation, 2)?)
        .map_err(|_| "second response receiver closed")?;
    first_received
        .respond
        .send(control_response(&second, first_operation, 1)?)
        .map_err(|_| "first response receiver closed")?;
    assert!(first_call.await?.is_ok());
    assert!(second_call.await?.is_ok());
    Ok(())
}

fn control_request(
    network: &ConsensusNetwork,
    operation_id: OperationId,
    nonce: u64,
) -> Result<ControlEnvelope, ConsensusNetworkError> {
    Ok(ControlEnvelope {
        header: Some(network.control_header(operation_id, i64::MAX)?),
        message: Some(Message::Ping(Ping {
            nonce,
            sent_monotonic_micros: nonce,
        })),
    })
}

fn control_response(
    network: &ConsensusNetwork,
    operation_id: OperationId,
    nonce: u64,
) -> Result<ControlEnvelope, ConsensusNetworkError> {
    Ok(ControlEnvelope {
        header: Some(network.control_header(operation_id, i64::MAX)?),
        message: Some(Message::Pong(Pong {
            nonce,
            received_monotonic_micros: nonce,
            sent_monotonic_micros: nonce,
        })),
    })
}

fn config(
    local_node_id: NodeId,
    listen_address: SocketAddr,
    identity: &meshspan_test_certificates::IssuedCertificate,
    trust_anchor: Vec<u8>,
    peer: ConsensusPeerConfig,
    mesh_id: MeshId,
    partition_id: PartitionId,
) -> ConsensusNetworkConfig {
    ConsensusNetworkConfig {
        local_node_id,
        local_incarnation: 1,
        mesh_id,
        partition_id,
        routing_epoch: 1,
        roles: vec![meshspan_protocol::v1::NodeRole::MetadataVoter],
        listen_address,
        client_address: SocketAddr::from(([127, 0, 0, 1], 0)),
        certificate_chain_der: vec![identity.certificate_der().to_vec()],
        private_key_pkcs8: Zeroizing::new(identity.private_key().to_vec()),
        trust_anchors: vec![trust_anchor],
        peers: vec![peer],
        snapshot_staging_path: None,
    }
}

fn peer(node_id: NodeId, address: SocketAddr, certificate_der: &[u8]) -> ConsensusPeerConfig {
    ConsensusPeerConfig {
        node_id,
        incarnation: 1,
        address,
        certificate_der: certificate_der.to_vec(),
        certificate_name: "meshspan.internal".to_owned(),
    }
}

fn unused_udp_address() -> Result<SocketAddr, std::io::Error> {
    UdpSocket::bind("127.0.0.1:0")?.local_addr()
}
