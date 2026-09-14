// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::consensus_network::ConsensusPeerConfig;
use meshspan_domain::PartitionId;
use meshspan_protocol::v1::NodeRole;
use tokio::sync::mpsc;

#[test]
fn local_capability_preimage_reopens_and_rejects_digest_and_incarnation_tampering()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("local.sqlite3");
    let local = NodeId::from_bytes([1; 16])?;
    let remote = NodeId::from_bytes([2; 16])?;
    let hello = hello(remote);
    let mut database = LocalDatabase::open(&path, local, UnixMicros::new(1))?;
    let presentation = CachedNodeCapabilityPresentation {
        node_id: remote,
        incarnation: 1,
        certificate_fingerprint: [3; 32],
        capability_digest: node_capability_digest(&hello),
        canonical_hello: encode_control_frame(
            &ControlEnvelope {
                header: None,
                message: Some(Message::NodeHello(hello)),
            },
            WireLimits::new(
                MAXIMUM_CONTROL_BYTES,
                MAXIMUM_DATA_BYTES,
                MAXIMUM_ITEMS,
                MAXIMUM_TEXT_BYTES,
            )?,
        )?,
    };
    database.cache_node_capability_presentation(&presentation)?;
    drop(database);
    let restored = ConsensusCapabilityCacheConfig::open(path.clone(), local, UnixMicros::new(2))?;
    assert_eq!(restored.restored.len(), 1);
    let cached = restored.restored.first().ok_or("presentation absent")?;
    assert_eq!(cached.binding.node_id, remote);
    assert_eq!(
        cached.observed.capability_digest,
        presentation.capability_digest
    );
    assert_eq!(
        cached.observed.support,
        Some(meshspan_protocol::consensus_transfer_support())
    );
    let mut database = LocalDatabase::open_existing(&path, UnixMicros::new(3))?;
    let mut tampered = presentation.clone();
    tampered.capability_digest = [99; 32];
    database.cache_node_capability_presentation(&tampered)?;
    assert!(ConsensusCapabilityCacheConfig::open(path.clone(), local, UnixMicros::new(4)).is_err());
    let mut tampered = presentation;
    tampered.incarnation = 2;
    database.cache_node_capability_presentation(&tampered)?;
    assert!(ConsensusCapabilityCacheConfig::open(path, local, UnixMicros::new(5)).is_err());
    Ok(())
}

fn hello(node: NodeId) -> NodeHello {
    NodeHello {
        versions: vec![meshspan_protocol::v1::ProtocolVersion { major: 1, minor: 0 }],
        mesh_id: vec![7; 16],
        node_id: node.as_bytes().to_vec(),
        incarnation: 1,
        roles: vec![i32::from(NodeRole::MetadataVoter)],
        components: vec![meshspan_protocol::v1::ComponentSupport {
            contract_kind: 1,
            implementation_id: "meshspan-consensus".to_owned(),
            versions: vec![meshspan_protocol::v1::ProtocolVersion { major: 1, minor: 0 }],
            maximum_control_bytes: 64 * 1024,
            maximum_items: 64,
            maximum_concurrency: 1,
        }],
        feature_bits: vec![],
        maximum_control_bytes: 64 * 1024,
        maximum_data_frame_bytes: 64 * 1024,
        maximum_streams: 128,
        consensus_transfer: Some(meshspan_protocol::consensus_transfer_support()),
    }
}

#[tokio::test]
async fn exact_authenticated_capability_preimage_remains_available_offline_after_network_restart()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::consensus_network::tests::{config, peer, unused_udp_address};
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("local.sqlite3");
    let authority = meshspan_test_certificates::CertificateAuthority::new()?;
    let first_identity = authority.issue_node("meshspan.internal")?;
    let second_identity = authority.issue_node("meshspan.internal")?;
    let first_node = NodeId::from_bytes([1; 16])?;
    let second_node = NodeId::from_bytes([2; 16])?;
    let first_address = unused_udp_address()?;
    let second_address = unused_udp_address()?;
    let mesh = MeshId::from_bytes([3; 16])?;
    let partition = PartitionId::from_bytes([4; 16])?;
    let first_peer = peer(first_node, first_address, first_identity.certificate_der());
    let (first_sender, _first_received) = mpsc::channel(8);
    let (second_sender, _second_received) = mpsc::channel(8);
    let first = ConsensusNetwork::start(
        config(
            first_node,
            first_address,
            &first_identity,
            authority.certificate_der().to_vec(),
            peer(
                second_node,
                second_address,
                second_identity.certificate_der(),
            ),
            mesh,
            partition,
        ),
        first_sender,
    )?;
    let mut second_config = config(
        second_node,
        second_address,
        &second_identity,
        authority.certificate_der().to_vec(),
        first_peer.clone(),
        mesh,
        partition,
    );
    second_config.capability_cache = Some(ConsensusCapabilityCacheConfig::open(
        path.clone(),
        second_node,
        UnixMicros::new(1),
    )?);
    let second = ConsensusNetwork::start(second_config, second_sender)?;
    let local = first.local_capability_presentation()?;
    assert!(
        second
            .consensus_transfer_support_for(local.binding, local.observed.capability_digest)?
            .is_none()
    );
    let connection = first.connect_peer(second_node).await?;
    assert_eq!(
        second.consensus_transfer_support_for(local.binding, local.observed.capability_digest)?,
        Some(local.observed.clone())
    );
    connection.close(0_u32.into(), b"offline restart proof");
    first.close()?;
    second.close()?;
    drop(first);
    drop(second);
    let (sender, _received) = mpsc::channel(8);
    let mut restored_config = config(
        second_node,
        unused_udp_address()?,
        &second_identity,
        authority.certificate_der().to_vec(),
        first_peer.clone(),
        mesh,
        partition,
    );
    restored_config.capability_cache = Some(ConsensusCapabilityCacheConfig::open(
        path,
        second_node,
        UnixMicros::new(2),
    )?);
    let restored = ConsensusNetwork::start(restored_config, sender)?;
    assert_offline_binding_revalidation(&restored, &local, first_peer)?;
    restored.close()?;
    Ok(())
}

fn assert_offline_binding_revalidation(
    restored: &ConsensusNetwork,
    local: &LocalNodeCapabilityPresentation,
    first_peer: ConsensusPeerConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    // The source endpoint is closed. These queries must use exact validated persisted bytes.
    assert_eq!(
        restored.consensus_transfer_support_for(local.binding, local.observed.capability_digest)?,
        Some(local.observed.clone())
    );
    assert!(
        restored
            .consensus_transfer_support_for(local.binding, [99; 32])?
            .is_none()
    );
    assert!(
        restored
            .consensus_transfer_support_for(
                PeerBinding {
                    certificate_fingerprint: [98; 32],
                    ..local.binding
                },
                local.observed.capability_digest
            )?
            .is_none()
    );
    restored.upsert_peer(&ConsensusPeerConfig {
        incarnation: 2,
        ..first_peer
    })?;
    assert!(
        restored
            .consensus_transfer_support_for(local.binding, local.observed.capability_digest)?
            .is_none()
    );
    Ok(())
}

#[test]
fn cache_retains_committed_preimage_and_new_incarnation_candidate_until_refresh()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("local.sqlite3");
    let local = NodeId::from_bytes([1; 16])?;
    let node = NodeId::from_bytes([2; 16])?;
    let mut database = LocalDatabase::open(&path, local, UnixMicros::new(1))?;
    let mut digests = Vec::new();
    for incarnation in [1, 2] {
        let mut hello = hello(node);
        hello.incarnation = incarnation;
        let digest = node_capability_digest(&hello);
        let bytes = encode_control_frame(
            &ControlEnvelope {
                header: None,
                message: Some(Message::NodeHello(hello)),
            },
            WireLimits::new(
                MAXIMUM_CONTROL_BYTES,
                MAXIMUM_DATA_BYTES,
                MAXIMUM_ITEMS,
                MAXIMUM_TEXT_BYTES,
            )?,
        )?;
        database.cache_node_capability_presentation(&CachedNodeCapabilityPresentation {
            node_id: node,
            incarnation,
            certificate_fingerprint: [3; 32],
            capability_digest: digest,
            canonical_hello: bytes,
        })?;
        digests.push(digest);
    }
    database.retain_node_capability_presentations(node, 1, digests[0], (2, digests[1]))?;
    assert_eq!(database.node_capability_presentations()?.len(), 2);
    assert_eq!(
        ConsensusCapabilityCacheConfig::open(path.clone(), local, UnixMicros::new(2))?
            .restored
            .len(),
        2
    );
    database.retain_node_capability_presentations(node, 2, digests[1], (2, digests[1]))?;
    let retained = database.node_capability_presentations()?;
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].incarnation, 2);
    assert_eq!(retained[0].capability_digest, digests[1]);
    Ok(())
}
