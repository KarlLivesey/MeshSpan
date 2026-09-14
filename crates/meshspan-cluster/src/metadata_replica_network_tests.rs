// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::JoinGrantId;
use meshspan_metadata::{ActivateNode, ConsumeJoinGrant, IssueJoinGrant, JoinRoles};
use meshspan_protocol::v1::{NodeRole, data_control_envelope::Message};
use meshspan_test_certificates::CertificateAuthority;
use meshspan_transport::receive_data_control;
use sha2::{Digest, Sha256};
use std::{
    net::{SocketAddr, UdpSocket},
    time::Duration,
};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use super::*;
use crate::{
    ConsensusNetwork, ConsensusNetworkConfig, ConsensusPeerConfig, PeerDataStream,
    PreparedMetadataReplicaPage, admit_metadata_replica_request, send_metadata_replica_page,
};

#[path = "metadata_replica_network_fault_tests.rs"]
mod faults;

#[path = "metadata_replica_runtime_tests.rs"]
mod runtime;

struct TransferFixture {
    state: Fixture,
    source: ConsensusNetwork,
    client: ConsensusNetwork,
    incoming: mpsc::Receiver<PeerDataStream>,
}

impl TransferFixture {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_roles(JoinRoles::new(JoinRoles::STORAGE)?).await
    }

    async fn with_roles(roles: JoinRoles) -> Result<Self, Box<dyn std::error::Error>> {
        let state =
            tokio::task::spawn_blocking(|| Fixture::new().map_err(|e| e.to_string())).await??;
        let ca = CertificateAuthority::new()?;
        let source_leaf = ca.issue_node("meshspan.internal")?;
        let client_leaf = ca.issue_node("meshspan.internal")?;
        let source_address = UdpSocket::bind("127.0.0.1:0")?.local_addr()?;
        let client_address = UdpSocket::bind("127.0.0.1:0")?.local_addr()?;
        let (data, incoming) = mpsc::channel(2);
        let mut networks = Vec::new();
        for (local, remote, identity, remote_identity, address, remote_address, roles) in [
            (
                state.voter,
                state.storage,
                &source_leaf,
                &client_leaf,
                source_address,
                client_address,
                vec![NodeRole::MetadataVoter],
            ),
            (
                state.storage,
                state.voter,
                &client_leaf,
                &source_leaf,
                client_address,
                source_address,
                vec![NodeRole::Storage],
            ),
        ] {
            let config = ConsensusNetworkConfig {
                local_node_id: local,
                local_incarnation: 1,
                mesh_id: MeshId::from_bytes([5; 16])?,
                partition_id: state.partition,
                routing_epoch: 1,
                roles,
                listen_address: address,
                client_address: SocketAddr::from(([127, 0, 0, 1], 0)),
                certificate_chain_der: vec![identity.certificate_der().to_vec()],
                certificate_generation: 1,
                certificate_name: "meshspan.internal".to_owned(),
                private_key_pkcs8: Zeroizing::new(identity.private_key().to_vec()),
                trust_anchors: vec![ca.certificate_der().to_vec()],
                peers: vec![ConsensusPeerConfig {
                    node_id: remote,
                    incarnation: 1,
                    address: remote_address,
                    certificate_der: remote_identity.certificate_der().to_vec(),
                    certificate_name: "meshspan.internal".to_owned(),
                }],
                snapshot_staging_path: None,
            };
            let (messages, _received) = mpsc::channel(2);
            let (controls, _received) = mpsc::channel(2);
            networks.push(ConsensusNetwork::start_with_control_and_data(
                config,
                messages,
                controls,
                data.clone(),
            )?);
        }
        let certificate = client_leaf.certificate_der().to_vec();
        let state = tokio::task::spawn_blocking(move || {
            let mut state = state;
            state.apply_bootstrap().map_err(|e| e.to_string())?;
            enrol_storage(&mut state, certificate, roles).map_err(|e| e.to_string())?;
            Ok::<_, String>(state)
        })
        .await??;
        let client = networks.pop().ok_or("client missing")?;
        let source = networks.pop().ok_or("source missing")?;
        Ok(Self {
            state,
            source,
            client,
            incoming,
        })
    }
}

fn enrol_storage(fixture: &mut Fixture, certificate: Vec<u8>, roles: JoinRoles) -> TestResult {
    let grant = JoinGrantId::from_bytes([18; 16])?;
    let commands = [
        crate::protected_volume_test_support::confirm_recovery(MeshId::from_bytes([5; 16])?),
        AuthoritativeCommand::IssueJoinGrant(IssueJoinGrant {
            join_grant_id: grant,
            secret_digest: [18; 32],
            allowed_roles: roles,
            maximum_uses: 1,
            expires_at: UnixMicros::new(500),
        }),
        AuthoritativeCommand::ConsumeJoinGrant(ConsumeJoinGrant {
            join_grant_id: grant,
            secret_digest: [18; 32],
            host_id: HostId::from_bytes([19; 16])?,
            new_host_name: Some(RecordName::new("Storage host")?),
            node_id: fixture.storage,
            node_name: RecordName::new("Storage")?,
            incarnation: 1,
            requested_roles: roles,
            wrapping_public_key: [19; 32],
            private_endpoint: "127.0.0.1:4401".to_owned(),
            certificate_fingerprint: Sha256::digest(&certificate).into(),
            certificate_der: certificate,
            certificate_valid_until: UnixMicros::new(500),
        }),
        AuthoritativeCommand::ActivateNode(ActivateNode {
            node_id: fixture.storage,
            incarnation: 1,
            private_endpoint: "127.0.0.1:4401".to_owned(),
            capability_digest: [20; 32],
        }),
    ];
    for (offset, command) in commands.into_iter().enumerate() {
        let entry = propose(&mut fixture.source, 2 + u8::try_from(offset)?, &command)?;
        fixture
            .source
            .apply_authoritative_committed(&entry, UnixMicros::new(50))?;
    }
    Ok(())
}

#[tokio::test]
async fn metadata_replica_real_quinn_applies_authorised_storage_history_and_reopens() -> TestResult
{
    let TransferFixture {
        state,
        source: _source,
        client,
        mut incoming,
    } = TransferFixture::new().await?;
    let cursor = state.replica.cursor()?;
    let fetch = client.fetch_metadata_replica_page(
        state.voter,
        cursor,
        OperationId::from_bytes([81; 16])?,
        UnixMicros::new(100),
    );
    let serve = async {
        let mut incoming = incoming.recv().await.ok_or("missing stream")?;
        let Some(Message::FetchMetadataReplicaPage(request)) =
            receive_data_control(&mut incoming.stream.receive, incoming.limits)
                .await?
                .into_inner()
                .message
        else {
            return Err("wrong request".into());
        };
        incoming.stream.receive.read_to_end(0).await?;
        let peer = incoming.peer;
        let limits = incoming.limits;
        let prepared = tokio::task::spawn_blocking(move || {
            let repo = state.source.persistence();
            let after =
                admit_metadata_replica_request(repo, peer, 1, &request, UnixMicros::new(100))
                    .map_err(|e| e.to_string())?;
            assert_eq!(after, cursor);
            assert!(
                admit_metadata_replica_request(repo, peer, 2, &request, UnixMicros::new(100))
                    .is_err()
            );
            assert!(
                admit_metadata_replica_request(repo, peer, 1, &request, UnixMicros::new(501))
                    .is_err()
            );
            let page = state
                .source
                .metadata_replica_page(after)
                .map_err(|e| e.to_string())?;
            assert_eq!(page.entries.len(), 5);
            let prepared = PreparedMetadataReplicaPage::new(request, &page, limits)
                .map_err(|e| e.to_string())?;
            Ok::<_, String>((state, prepared))
        })
        .await??;
        send_metadata_replica_page(incoming.stream, prepared.1, limits).await?;
        Ok::<_, Box<dyn std::error::Error>>(prepared.0)
    };
    let (transfer, state) = Box::pin(tokio::time::timeout(Duration::from_secs(10), async {
        tokio::try_join!(async { fetch.await.map_err(Into::into) }, serve)
    }))
    .await??;
    assert_eq!(transfer.source.node_id(), state.voter);
    tokio::task::spawn_blocking(move || {
        let mut state = state;
        state
            .replica
            .apply(
                transfer.source.node_id(),
                transfer.source.incarnation(),
                &transfer.page,
                UnixMicros::new(101),
            )
            .map_err(|e| e.to_string())?;
        state.reopen().map_err(|e| e.to_string())?;
        assert_eq!(
            state
                .replica
                .cursor()
                .map_err(|e| e.to_string())?
                .applied
                .index,
            5
        );
        assert_eq!(
            state
                .replica
                .repository()
                .current_revision()
                .map_err(|e| e.to_string())?,
            Revision::new(5)
        );
        assert!(!state.replica.plan.members().contains(&state.storage));
        assert_eq!(state.replica.durable.voted_for, None);
        Ok::<_, String>(())
    })
    .await??;
    Ok(())
}
