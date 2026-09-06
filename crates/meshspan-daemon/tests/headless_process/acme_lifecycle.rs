// SPDX-License-Identifier: GPL-2.0-only

//! Real daemon issuance against a local TLS CA, without exporting the endpoint private key.

#[path = "acme_lifecycle/authority.rs"]
mod authority;

use meshspan_api_contract::{
    CertificateOperationalState, CertificateStatusResponse, CertificateStatusSource,
};
use serde_json::json;

use super::*;

#[tokio::test]
async fn http01_issuance_survives_restart_and_gateway_join_without_another_order()
-> Result<(), Box<dyn Error>> {
    let root = ProcessFixture::new()?;
    let peer = ProcessFixture::new()?;
    let ca = authority::TestAuthority::start(root.http01_address).await?;
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
        require_status(&response, "201 Created", "queue ACME certificate")?;
        let issued = client_config(&ca.anchor_der)?;
        wait_for_active(root.address, &issued, key, 1).await?;
        ca.assert_issued_once()?;
        assert_challenge_removed(root.http01_address).await?;

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
            "{error}; child exits {exits:?}; CA observations {:?}",
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

async fn assert_challenge_removed(address: SocketAddr) -> Result<(), Box<dyn Error>> {
    let response = authority::read_challenge(address)
        .await
        .map_err(|error| error.to_string())?;
    require_status(&response, "404 Not Found", "completed challenge cleanup")
}
