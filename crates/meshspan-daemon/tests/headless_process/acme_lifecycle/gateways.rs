// SPDX-License-Identifier: GPL-2.0-only

//! A CA must reach every gateway, independently of which daemon claims its order.

use super::*;

#[tokio::test]
async fn http01_challenge_is_available_on_both_gateways_before_ca_validation()
-> Result<(), Box<dyn Error>> {
    let mut root = ProcessFixture::new()?;
    let mut peer = ProcessFixture::new()?;
    root.smb_address.set_port(0);
    peer.smb_address.set_port(0);
    let ca = authority::TestAuthority::start(challenge::ValidationTarget::Http01Gateways([
        root.http01_address,
        peer.http01_address,
    ]))
    .await?;
    let trust_file = root.temporary.path().join("test-ca.pem");
    fs::write(&trust_file, &ca.anchor_pem)?;
    let mut processes = vec![root.command().env("SSL_CERT_FILE", &trust_file).spawn()?];
    let result = prove_shared_challenge(&root, &peer, &ca, &mut processes).await;
    stop_processes(&mut processes);
    let observations = ca.observations();
    ca.stop().await?;
    result.map_err(|error| {
        let topology = persisted_routes(&peer);
        let root_evidence = root.temporary.keep();
        let peer_evidence = peer.temporary.keep();
        format!("{error}; CA observations {observations:?}; peer persisted routes {topology:?}; retained root evidence {root_evidence:?}; peer evidence {peer_evidence:?}").into()
    })
}

fn persisted_routes(peer: &ProcessFixture) -> Result<Vec<String>, Box<dyn Error>> {
    let repository = meshspan_metadata::AuthoritativeRepository::new(
        meshspan_metadata::PartitionDatabase::open_existing(
            &peer.state_path.join("root-authority.sqlite3"),
            meshspan_domain::UnixMicros::new(1),
        )?,
    );
    let page = repository.topology_nodes(None, meshspan_metadata::PageLimit::new(16)?)?;
    page.items
        .into_iter()
        .map(|node| {
            Ok(format!(
                "node={} state={} endpoint={:?} certificate={}",
                node.node_id,
                node.state,
                node.private_endpoint,
                repository.active_node_certificate(node.node_id)?.is_some()
            ))
        })
        .collect()
}

async fn prove_shared_challenge(
    root: &ProcessFixture,
    peer: &ProcessFixture,
    ca: &authority::TestAuthority,
    processes: &mut Vec<Child>,
) -> Result<(), Box<dyn Error>> {
    let claim = wait_for_claim(&root.claim_path).await?;
    let bootstrap = wait_for_client(&root.identity_path).await?;
    wait_for_status(root.address, &bootstrap, "claim_required").await?;
    let created = create_process_mesh(root, &bootstrap, &claim).await?;
    let key = created["api_key"].as_str().ok_or("missing API key")?;
    save_and_verify_recovery_bundle(root, &bootstrap, key, &created).await?;
    let invitation = issue_join_code(root, &bootstrap, key).await?;
    processes.push(
        peer.command()
            .env("SSL_CERT_FILE", root.temporary.path().join("test-ca.pem"))
            .arg("--join-code")
            .arg(invitation)
            .spawn()?,
    );
    let peer_bootstrap = wait_for_client(&peer.identity_path).await?;
    wait_for_status(peer.address, &peer_bootstrap, "configured").await?;
    let body = serde_json::to_vec(&json!({
        "operation_id": "00000000-0000-4000-8000-000000000201",
        "directory_url": format!("{}/directory", ca.endpoint),
        "certificate_names": [CERTIFICATE_NAME],
        "challenge": {"kind": "http01"}
    }))?;
    let authorization = format!("Bearer {key}");
    let response = request_with_headers(
        root.address,
        &bootstrap,
        "POST",
        "/api/latest/admin/certificates/acme",
        Some(&body),
        &[("Authorization", &authorization)],
    )
    .await?;
    require_status(&response, "201 Created", "queue shared ACME certificate")?;
    let issued = client_config(&ca.anchor_der)?;
    wait_for_active(root.address, &issued, key, 2).await?;
    wait_for_active(peer.address, &issued, key, 2).await?;
    ca.assert_challenge_removed()
        .await
        .map_err(|error| format!("pre-restart cleanup: {error}"))?;
    ca.assert_issued_once()?;
    processes[1].kill()?;
    processes[1].wait()?;
    processes[1] = peer
        .command()
        .env("SSL_CERT_FILE", root.temporary.path().join("test-ca.pem"))
        .spawn()?;
    wait_for_active(peer.address, &issued, key, 2).await?;
    challenge::wait_for_removed_after_restart(peer.http01_address)
        .await
        .map_err(|error| error.to_string())?;
    ca.assert_challenge_removed()
        .await
        .map_err(|error| format!("post-restart cleanup: {error}"))?;
    ca.assert_issued_once()?;
    Ok(())
}
