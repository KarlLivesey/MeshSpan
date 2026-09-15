// SPDX-License-Identifier: GPL-2.0-only

//! Committed peers must be installed before storage startup returns to its HTTPS owner.

use meshspan_domain::{HostId, JoinGrantId, NodeId, UnixMicros};
use meshspan_metadata::{
    ActivateNode, AuthoritativeCommand, ConsumeJoinGrant, IssueJoinGrant, JoinRoles, RecordName,
};
use sha2::{Digest, Sha256};
use std::error::Error;

use super::super::{
    OperatingSystemRandom, ShutdownOutcome, certificate_name, compose_appliance_services,
    current_time, initialise_daemon_node, private_network_bootstrap, random_maintenance_context,
    start_private_authority, storage_node_runtime,
};
use super::maintenance::setup::save_and_verify_maintenance_recovery;
use super::{configure_lifecycle_mesh_with_response, lifecycle_config_with_private_address};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn storage_startup_installs_committed_peer_before_periodic_maintenance()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let https = std::net::TcpListener::bind("127.0.0.1:0")?;
    let config = lifecycle_config_with_private_address(
        directory.path(),
        "127.0.0.1:0",
        &https.local_addr()?.to_string(),
        "127.0.0.1:0",
        "127.0.0.1:64000",
    )?;
    let now = current_time()?;
    let mut node = initialise_daemon_node(&config, now).await?;
    let private = start_private_authority(&mut node, &config, now).await?;
    let (restart, _requests) = tokio::sync::mpsc::unbounded_channel();
    let services = compose_appliance_services(&mut node, &private, &config, restart, now)?;
    let (administrator, created) =
        configure_lifecycle_mesh_with_response(&node, services.router.clone()).await?;
    save_and_verify_maintenance_recovery(&services.router, &created).await?;
    let peer = NodeId::from_bytes([123; 16])?;
    let certificate = meshspan_test_certificates::CertificateAuthority::new()?
        .issue_node(&certificate_name(peer))?;
    let certificate_der = certificate.certificate_der().to_vec();
    let peer_socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let endpoint = peer_socket.local_addr()?.to_string();
    let admitted = async {
        for (step, command) in admission_commands(peer, &endpoint, &certificate_der)?
            .into_iter()
            .enumerate()
        {
            let context = random_maintenance_context(
                &mut OperatingSystemRandom,
                administrator,
                current_time()?,
            )
            .map_err(|()| "admission command identity")?;
            private
                .authority
                .commit_or_resolve(context, command)
                .await
                .map_err(|error| format!("admit fixture peer command {step}: {error:?}"))?;
        }
        Ok::<_, Box<dyn Error>>(())
    }
    .await;
    let mut cleanup = ShutdownOutcome::default();
    private.drain(&mut cleanup).await;
    drop(services);
    drop(node);
    cleanup.finish()?;
    admitted?;

    let now = current_time()?;
    let mut node = initialise_daemon_node(&config, now).await?;
    let network_config = private_network_bootstrap::configuration(
        node.local_state.state_directory(),
        node.local_state.node_id(),
        node.local_state.node_identity_private_key_pkcs8(),
        config.private_listen(),
        now,
    )?;
    assert!(
        network_config.peers.is_empty(),
        "bootstrap delegates committed route installation to startup"
    );
    let (network, messages, controls) =
        storage_node_runtime::start_network(&mut node, network_config).await?;
    // No StorageCycle, replica or periodic reconcile task has been started.
    let routes = network.peer_routes();
    let stopped = network.shutdown().await;
    drop((messages, controls, network, node));
    stopped?;
    let routes = routes?;
    assert_eq!(
        routes.len(),
        1,
        "startup must install the already committed peer before returning"
    );
    let route = routes.first().ok_or("committed peer route missing")?;
    assert_eq!(route.node_id, peer);
    assert_eq!(route.incarnation, 1);
    assert_eq!(route.address, endpoint.parse()?);
    assert_eq!(route.certificate_der, certificate_der);
    assert_eq!(route.certificate_name, certificate_name(peer));
    Ok(())
}

fn admission_commands(
    peer: NodeId,
    endpoint: &str,
    certificate_der: &[u8],
) -> Result<[AuthoritativeCommand; 3], Box<dyn Error>> {
    let grant = JoinGrantId::from_bytes([122; 16])?;
    let roles = JoinRoles::new(JoinRoles::STORAGE)?;
    Ok([
        AuthoritativeCommand::IssueJoinGrant(IssueJoinGrant {
            join_grant_id: grant,
            secret_digest: [121; 32],
            allowed_roles: roles,
            maximum_uses: 1,
            expires_at: UnixMicros::new(i64::MAX),
        }),
        AuthoritativeCommand::ConsumeJoinGrant(ConsumeJoinGrant {
            join_grant_id: grant,
            secret_digest: [121; 32],
            host_id: HostId::from_bytes([120; 16])?,
            new_host_name: Some(RecordName::new("Admitted peer host")?),
            node_id: peer,
            node_name: RecordName::new("Admitted peer")?,
            incarnation: 1,
            requested_roles: roles,
            wrapping_public_key: [119; 32],
            private_endpoint: endpoint.to_owned(),
            certificate_fingerprint: Sha256::digest(certificate_der).into(),
            certificate_der: certificate_der.to_vec(),
            certificate_valid_until: UnixMicros::new(i64::MAX),
        }),
        AuthoritativeCommand::ActivateNode(ActivateNode {
            node_id: peer,
            incarnation: 1,
            private_endpoint: endpoint.to_owned(),
            capability_digest: [118; 32],
        }),
    ])
}
