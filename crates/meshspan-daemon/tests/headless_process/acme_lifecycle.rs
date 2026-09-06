// SPDX-License-Identifier: GPL-2.0-only

//! Real daemon issuance against a local TLS CA, without exporting the endpoint private key.

#[path = "acme_lifecycle/authority.rs"]
mod authority;
#[path = "acme_lifecycle/challenge.rs"]
mod challenge;
// Reuse the independent signed-DNS transcript verifier, without a production fixture export.
#[path = "../../../meshspan-acme/src/rfc2136_test_server.rs"]
mod rfc2136_test_server;

use meshspan_api_contract::{
    CertificateOperationalState, CertificateStatusResponse, CertificateStatusSource,
};
use serde_json::json;

use super::*;

#[tokio::test]
async fn http01_issuance_survives_restart_and_gateway_join_without_another_order()
-> Result<(), Box<dyn Error>> {
    let root = ProcessFixture::new()?;
    let target = challenge::ValidationTarget::Http01(root.http01_address);
    prove_lifecycle(root, target, json!({"kind": "http01"})).await
}

#[tokio::test]
async fn dns01_issuance_survives_restart_and_gateway_join_without_another_order()
-> Result<(), Box<dyn Error>> {
    let dns = rfc2136_test_server::Rfc2136TestServer::start(CERTIFICATE_NAME, 60, 2, None)
        .await
        .map_err(|error| error.to_string())?;
    let target = challenge::ValidationTarget::Dns01(dns.address());
    let settings = json!({
        "kind": "dns01_rfc2136",
        "server": dns.address().to_string(),
        "zone": CERTIFICATE_NAME,
        "key_name": "meshspan-key.example.test",
        "algorithm": "hmac_sha256",
        "secret": "0123456789abcdef0123456789abcdef"
    });
    let proof = prove_lifecycle(ProcessFixture::new()?, target, settings).await;
    let dns_result = dns.finish().await.map_err(|error| error.to_string());
    proof.map_err(|error| format!("{error}; DNS transcript result: {dns_result:?}"))?;
    dns_result?;
    Ok(())
}

async fn prove_lifecycle(
    mut root: ProcessFixture,
    target: challenge::ValidationTarget,
    settings: serde_json::Value,
) -> Result<(), Box<dyn Error>> {
    let mut peer = ProcessFixture::new()?;
    // This proof never connects to SMB. Bind it atomically to an OS-selected port instead of
    // leaving an unnecessary probe-to-child-start gap for an unused fixed listener address.
    root.smb_address.set_port(0);
    peer.smb_address.set_port(0);
    let ca = authority::TestAuthority::start(target).await?;
    let trust_file = root.temporary.path().join("test-ca.pem");
    fs::write(&trust_file, &ca.anchor_pem)?;
    let mut processes = vec![root.command().env("SSL_CERT_FILE", &trust_file).spawn()?];
    let proof: Result<(), Box<dyn Error>> = async {
        let claim = wait_for_claim(&root.claim_path).await?;
        let bootstrap = wait_for_client(&root.identity_path).await?;
        wait_for_status(root.address, &bootstrap, "claim_required").await?;
        let created = create_process_mesh(&root, &bootstrap, &claim).await?;
        let key = created["api_key"].as_str().ok_or("missing API key")?;
        save_and_verify_recovery_bundle(&root, &bootstrap, key, &created).await?;
        let body = serde_json::to_vec(&json!({
            "operation_id": "00000000-0000-4000-8000-000000000201",
            "directory_url": format!("{}/directory", ca.endpoint),
            "certificate_names": [CERTIFICATE_NAME],
            "challenge": settings
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
        require_status(&response, "201 Created", "queue ACME certificate")?;
        let issued = client_config(&ca.anchor_der)?;
        wait_for_active(root.address, &issued, key, 1).await?;
        ca.assert_issued_once()?;
        ca.assert_challenge_removed().await?;

        processes[0].kill()?;
        processes[0].wait()?;
        processes[0] = root.command().env("SSL_CERT_FILE", &trust_file).spawn()?;
        wait_for_active(root.address, &issued, key, 1).await?;
        let invitation = issue_join_code(&root, &issued, key).await?;
        processes.push(
            peer.command()
                .env("SSL_CERT_FILE", &trust_file)
                .arg("--join-code")
                .arg(invitation)
                .spawn()?,
        );
        wait_for_active(peer.address, &issued, key, 2).await?;
        wait_for_active(root.address, &issued, key, 2).await?;
        ca.assert_issued_once()?;
        Ok(())
    }
    .await;
    let proof = proof.map_err(|error| {
        let exits = processes
            .iter_mut()
            .map(|child| format!("{:?}", child.try_wait()))
            .collect::<Vec<_>>();
        format!(
            "{error}; root listeners HTTPS={} HTTP01={} SMB={} QUIC={}; peer listeners HTTPS={} HTTP01={} SMB={} QUIC={}; child exits {exits:?}; CA observations {:?}",
            root.address, root.http01_address, root.smb_address, root.private_address,
            peer.address, peer.http01_address, peer.smb_address, peer.private_address,
            ca.observations()
        )
        .into()
    });
    stop_processes(&mut processes);
    ca.stop().await?;
    proof
}

async fn wait_for_active(
    address: SocketAddr,
    client: &ClientConfig,
    key: &str,
    gateways: u64,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + WAIT_LIMIT;
    let authorization = format!("Bearer {key}");
    loop {
        let response = tokio::time::timeout_at(
            deadline.into(),
            request_with_headers(
                address,
                client,
                "GET",
                "/api/latest/admin/certificates/status",
                None,
                &[("Authorization", &authorization)],
            ),
        )
        .await;
        let observation = match response {
            Ok(Ok(response)) => {
                require_status(&response, "200 OK", "read ACME installation")?;
                let status: CertificateStatusResponse =
                    serde_json::from_str(response_body(&response)?)?;
                if status.certificate.as_ref().is_some_and(|certificate| {
                    certificate.source == CertificateStatusSource::Acme
                        && certificate.state == CertificateOperationalState::Active
                        && certificate.required_gateway_count == gateways
                        && certificate.installed_gateway_count == gateways
                }) {
                    return Ok(());
                }
                format!("{:?}", status.certificate)
            }
            Ok(Err(error)) => error.to_string(),
            Err(_) => "TLS status deadline elapsed".to_owned(),
        };
        if Instant::now() >= deadline {
            return Err(format!("ACME installation at {address}: {observation}").into());
        }
        sleep(RETRY_INTERVAL).await;
    }
}
