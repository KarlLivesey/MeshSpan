// SPDX-License-Identifier: GPL-2.0-only

//! Real daemon renewal with a fixture-shortened scheduling deadline, not a month-long sleep.

use meshspan_domain::NodeId;
use meshspan_metadata::{ActiveNodeCertificate, NodeCertificateRotationState};
use meshspan_transport::{NodeCredentials, PeerBinding, PeerRegistry, TransportLimits};
use rustls::pki_types::PrivatePkcs8KeyDer;

use super::*;

#[tokio::test]
async fn private_node_renewal_runs_automatically_and_survives_restart_and_join()
-> Result<(), Box<dyn Error>> {
    let root = ProcessFixture::new()?;
    let peer = ProcessFixture::new()?;
    let mut processes = vec![root.start()?];
    let proof: Result<(), Box<dyn Error>> = async {
        let claim = wait_for_claim(&root.claim_path).await?;
        let client = wait_for_client(&root.identity_path).await?;
        wait_for_status(root.address, &client, "claim_required").await?;
        web_panel::verify(root.address, &client).await?;
        let created = create_process_mesh(&root, &client, &claim).await?;
        let api_key = created["api_key"].as_str().ok_or("missing API key")?;
        save_and_verify_recovery_bundle(&root, &client, api_key, &created).await?;
        let root_node = node_id(&root)?;
        let partition = InitialBootstrapMaterial::root_partition_id(root_node)?;
        let repository = repository(&root, partition)?;
        let before = repository
            .active_node_certificate(root_node)?
            .ok_or("missing initial certificate")?;
        assert_eq!(before.generation, 1);
        let identity_before = fs::read(&root.identity_path)?;
        make_initial_renewal_due(&root)?;
        let installed = wait_for_renewal(&repository, root_node).await?;
        assert_ne!(installed.certificate_der, before.certificate_der);
        assert_eq!(fs::read(&root.identity_path)?, identity_before);
        // Public HTTPS credentials are unaffected by private transport renewal.
        wait_for_status(root.address, &client, "configured").await?;
        let join = issue_join_code(&root, &client, api_key).await?;
        processes.push(peer.start_join(&join)?);
        let peer_client = wait_for_client(&peer.identity_path).await?;
        wait_for_status(peer.address, &peer_client, "configured").await?;
        web_panel::verify(peer.address, &peer_client).await?;
        prove_private_leaf(&root, &peer, partition, &installed).await?;
        processes[0].kill()?;
        processes[0].wait()?;
        processes[0] = root.start()?;
        wait_for_status(root.address, &client, "configured").await?;
        prove_private_leaf(&root, &peer, partition, &installed).await?;
        assert_eq!(
            repository.active_node_certificate(root_node)?,
            Some(installed)
        );
        assert_eq!(fs::read(&root.identity_path)?, identity_before);
        Ok(())
    }
    .await;
    stop_processes(&mut processes);
    retain_failure_state(proof, [root.temporary, peer.temporary])
}

fn node_id(fixture: &ProcessFixture) -> Result<NodeId, Box<dyn Error>> {
    let identity = LocalNodeIdentity::open(&fixture.identity_path, CERTIFICATE_NAME)?;
    Ok(InitialBootstrapMaterial::node_id(
        identity.public_key_fingerprint(),
    )?)
}

fn repository(
    fixture: &ProcessFixture,
    partition: PartitionId,
) -> Result<AuthoritativeRepository, Box<dyn Error>> {
    Ok(AuthoritativeRepository::new(PartitionDatabase::open(
        &fixture.state_path.join("root-authority.sqlite3"),
        partition,
        UnixMicros::new(1),
    )?))
}

fn make_initial_renewal_due(fixture: &ProcessFixture) -> Result<(), Box<dyn Error>> {
    let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros())?;
    let database = rusqlite::Connection::open(fixture.state_path.join("root-authority.sqlite3"))?;
    // Single-node fixture only: shorten the scheduling metadata, leaving the real TLS
    // key/leaf untouched. Production scheduling and signing still run unmodified.
    assert_eq!(
        database.execute(
            "UPDATE node_certificates SET valid_until = ?1 WHERE generation = 1 AND state = 1",
            [now + 60_000_000],
        )?,
        1
    );
    Ok(())
}

async fn wait_for_renewal(
    repository: &AuthoritativeRepository,
    node: NodeId,
) -> Result<ActiveNodeCertificate, Box<dyn Error>> {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        if let Some(rotation) = repository.node_certificate_rotation(node)?
            && rotation.state == NodeCertificateRotationState::Installed
        {
            let active = repository
                .active_node_certificate(node)?
                .ok_or("missing selected leaf")?;
            assert_eq!(rotation.generation, 2);
            assert_eq!(active.generation, 2);
            assert_eq!(active.certificate_der, rotation.certificate_der);
            assert!(rotation.retire_after.is_some());
            return Ok(active);
        }
        if Instant::now() >= deadline {
            return Err("daemon did not automatically install its due private renewal".into());
        }
        sleep(RETRY_INTERVAL).await;
    }
}

async fn prove_private_leaf(
    root: &ProcessFixture,
    peer: &ProcessFixture,
    partition: PartitionId,
    expected: &ActiveNodeCertificate,
) -> Result<(), Box<dyn Error>> {
    let repository = repository(peer, partition)?;
    let mesh = repository.local_mesh_id()?.ok_or("missing mesh")?;
    let certificate = repository
        .active_node_certificate(node_id(peer)?)?
        .ok_or("missing peer certificate")?;
    let issuer = repository
        .online_certificate_authority(mesh)?
        .ok_or("missing online authority")?;
    let root_authority = repository
        .mesh_recovery_authority(mesh)?
        .ok_or("missing root authority")?;
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(root_authority.root_certificate_der))?;
    let limits = TransportLimits::new(
        meshspan_protocol::WireLimits::new(64 * 1024, 64 * 1024, 256, 4096)?,
        128,
        64 * 1024,
        4 * 1024 * 1024,
    )?;
    let endpoint = meshspan_transport::client_endpoint(
        "127.0.0.1:0".parse()?,
        NodeCredentials::new(
            vec![
                CertificateDer::from(certificate.certificate_der),
                CertificateDer::from(issuer.certificate_der),
            ],
            PrivatePkcs8KeyDer::from(fs::read(&peer.identity_path)?).into(),
        )?,
        roots,
        limits,
    )?;
    let name = format!(
        "node-{}.meshspan.internal",
        node_id(root)?.to_string().replace('-', "")
    );
    let connection =
        tokio::time::timeout(WAIT_LIMIT, endpoint.connect(root.private_address, &name)?).await??;
    let trusted = PeerRegistry::new([PeerBinding {
        node_id: node_id(root)?,
        incarnation: expected.incarnation,
        certificate_fingerprint: expected.certificate_fingerprint,
    }])?;
    assert_eq!(
        trusted
            .authenticate_connection(&connection)?
            .certificate_fingerprint(),
        expected.certificate_fingerprint
    );
    connection.close(0_u32.into(), b"proof complete");
    endpoint.close(0_u32.into(), b"proof complete");
    Ok(())
}
