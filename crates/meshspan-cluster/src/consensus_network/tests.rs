// SPDX-License-Identifier: GPL-2.0-only

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use meshspan_consensus::{CoreMessage, LogPosition, VoteRequest};
use meshspan_test_certificates::CertificateAuthority;

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
        listen_address,
        client_address: SocketAddr::from(([127, 0, 0, 1], 0)),
        certificate_name: "meshspan.internal".to_owned(),
        certificate_der: identity.certificate_der().to_vec(),
        private_key_pkcs8: Zeroizing::new(identity.private_key().to_vec()),
        trust_anchors: vec![trust_anchor],
        peers: vec![peer],
    }
}

fn peer(node_id: NodeId, address: SocketAddr, certificate_der: &[u8]) -> ConsensusPeerConfig {
    ConsensusPeerConfig {
        node_id,
        incarnation: 1,
        address,
        certificate_der: certificate_der.to_vec(),
    }
}

fn unused_udp_address() -> Result<SocketAddr, std::io::Error> {
    UdpSocket::bind("127.0.0.1:0")?.local_addr()
}
