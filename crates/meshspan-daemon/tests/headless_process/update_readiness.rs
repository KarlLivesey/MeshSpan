// SPDX-License-Identifier: GPL-2.0-only

//! Actual daemon reactor/listener observations through an enrolled peer's private mTLS identity.

use super::super as fixture;
use super::{Error, ProcessFixture, UpdateApi, candidate, pin};
use meshspan_certificates::NodeIdentityKey;
use meshspan_cluster::{ConsensusNetwork, ConsensusNetworkConfig, ConsensusPeerConfig};
use meshspan_domain::{Clock as _, NodeId, OperationId, UnixMicros};
use meshspan_metadata::{AuthoritativeRepository, PartitionDatabase};
use meshspan_protocol::v1::{
    ControlEnvelope, NodeRole, ProbeUpdateReadiness, UpdateReadinessResult,
    control_envelope::Message,
};

#[tokio::test]
async fn update_readiness_observes_the_real_peer_and_rejects_stale_barriers_after_restart()
-> Result<(), Box<dyn Error>> {
    let root = ProcessFixture::new()?;
    let peer = ProcessFixture::new()?;
    let mut processes = vec![root.start()?];
    let proof = async {
        let claim = fixture::wait_for_claim(&root.claim_path).await?;
        let client = fixture::wait_for_client(&root.identity_path).await?;
        fixture::wait_for_status(root.address, &client, "claim_required").await?;
        let created = fixture::create_process_mesh(&root, &client, &claim).await?;
        let key = created["api_key"].as_str().ok_or("bootstrap key absent")?;
        fixture::save_and_verify_recovery_bundle(&root, &client, key, &created).await?;
        processes.push(peer.start_join(&fixture::issue_join_code(&root, &client, key).await?)?);
        let peer_client = fixture::wait_for_client(&peer.identity_path).await?;
        fixture::wait_for_status(peer.address, &peer_client, "configured").await?;
        let api = UpdateApi {
            root: &root,
            client: &client,
            key,
        };
        let signer = NodeIdentityKey::generate()?;
        api.manage(&pin(&signer), "200 OK").await?;
        api.manage(&candidate(&root, &signer)?, "200 OK").await?;
        let repository = repository(&root)?;
        let plan = repository
            .load_active_consensus_quorum_plan()?
            .ok_or("missing plan")?;
        let network = network(&peer, &root)?;
        let target = fixture::fixture_node_id(&root)?;
        let first = probe(&network, target, plan.proof_digest(), 0).await?;
        assert_eq!(first.node_id, target.as_bytes());
        assert!(first.listeners_bound);
        assert!(!first.persistence_blocked);
        assert!(first.applied_index > 0 && first.committed_index >= first.applied_index);
        let report: serde_json::Value = serde_json::from_slice(&first.runtime_report)?;
        assert_eq!(report["licence"], "GPL-2.0-only");
        assert_eq!(report["target"], env!("MESHSPAN_BUILD_TARGET"));
        assert!(probe(&network, target, [9; 32], 0).await.is_err());
        assert!(
            probe(&network, target, plan.proof_digest(), u64::MAX)
                .await
                .is_err()
        );
        processes[0].kill()?;
        processes[0].wait()?;
        processes[0] = root.start()?;
        fixture::wait_for_status(root.address, &client, "configured").await?;
        let next = probe(&network, target, plan.proof_digest(), first.applied_index).await?;
        assert!(next.listeners_bound && !next.persistence_blocked);
        assert!(next.applied_index >= first.applied_index);
        assert_eq!(next.runtime_report, first.runtime_report);
        assert_eq!(
            api.status(false).await?["rollout"]["progress"]["restarting"],
            "0"
        );
        Ok::<_, Box<dyn Error>>(())
    }
    .await;
    fixture::stop_processes(&mut processes);
    fixture::retain_failure_state(proof, [root.temporary, peer.temporary])
}

async fn probe(
    network: &ConsensusNetwork,
    peer: NodeId,
    plan: [u8; 32],
    minimum: u64,
) -> Result<UpdateReadinessResult, Box<dyn Error>> {
    let operation = OperationId::from_bytes([7; 16])?;
    let deadline = meshspan_daemon::OperatingSystemClock.now().get() + 2_000_000;
    let request = ControlEnvelope {
        header: Some(network.control_header(operation, deadline)?),
        message: Some(Message::ProbeUpdateReadiness(ProbeUpdateReadiness {
            rollout_id: 0x0000_0000_0000_4000_8000_0000_0000_0402_u128
                .to_be_bytes()
                .to_vec(),
            quorum_plan_digest: plan.to_vec(),
            minimum_applied_index: minimum,
        })),
    };
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        network.request_control(peer, &request),
    )
    .await??
    .into_inner();
    let header = response.header.ok_or("response header absent")?;
    assert_eq!(header.operation_id, operation.as_bytes());
    let Some(Message::UpdateReadinessResult(result)) = response.message else {
        return Err("wrong readiness result".into());
    };
    assert_eq!(result.node_id, header.sender_node_id);
    assert_eq!(result.incarnation, header.sender_incarnation);
    assert_eq!(result.quorum_plan_digest, plan);
    Ok(result)
}

fn repository(fixture: &ProcessFixture) -> Result<AuthoritativeRepository, Box<dyn Error>> {
    Ok(AuthoritativeRepository::new(
        PartitionDatabase::open_existing(
            &fixture.state_path.join("root-authority.sqlite3"),
            UnixMicros::new(1),
        )?,
    ))
}

fn network(
    source: &ProcessFixture,
    target: &ProcessFixture,
) -> Result<ConsensusNetwork, Box<dyn Error>> {
    let repository = repository(source)?;
    let local = fixture::fixture_node_id(source)?;
    let remote = fixture::fixture_node_id(target)?;
    let mesh = repository.local_mesh_id()?.ok_or("missing mesh")?;
    let certificate = repository
        .active_node_certificate(local)?
        .ok_or("missing local certificate")?;
    let remote_certificate = repository
        .active_node_certificate(remote)?
        .ok_or("missing remote certificate")?;
    let issuer = repository
        .online_certificate_authority(mesh)?
        .ok_or("missing issuer")?;
    let root = repository
        .mesh_recovery_authority(mesh)?
        .ok_or("missing root")?;
    let (messages, _received) = tokio::sync::mpsc::channel(8);
    Ok(ConsensusNetwork::start(
        ConsensusNetworkConfig {
            local_node_id: local,
            local_incarnation: certificate.incarnation,
            mesh_id: mesh,
            partition_id: repository.partition_id(),
            routing_epoch: 1,
            roles: vec![
                NodeRole::Storage,
                NodeRole::Gateway,
                NodeRole::MetadataLearner,
            ],
            listen_address: "127.0.0.1:0".parse()?,
            client_address: "127.0.0.1:0".parse()?,
            certificate_chain_der: vec![certificate.certificate_der, issuer.certificate_der],
            certificate_generation: certificate.generation,
            certificate_name: name(local),
            private_key_pkcs8: zeroize::Zeroizing::new(std::fs::read(&source.identity_path)?),
            trust_anchors: vec![root.root_certificate_der],
            snapshot_staging_path: None,
            peers: vec![ConsensusPeerConfig {
                node_id: remote,
                incarnation: remote_certificate.incarnation,
                address: target.private_address,
                certificate_der: remote_certificate.certificate_der,
                certificate_name: name(remote),
            }],
        },
        messages,
    )?)
}

fn name(node: NodeId) -> String {
    format!(
        "node-{}.meshspan.internal",
        node.to_string().replace('-', "")
    )
}
