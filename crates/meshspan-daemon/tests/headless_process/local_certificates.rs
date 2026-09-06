// SPDX-License-Identifier: GPL-2.0-only

//! Domain-free HTTPS proof using only the public provisioning API and real TLS clients.

use meshspan_api_contract::{
    CertificateOperationalState, CertificateStatusResponse, CertificateStatusSource,
    ProvisionMeshLocalCertificateResponse,
};
use rustls::pki_types::pem::PemObject as _;
use serde_json::json;

use super::{
    CERTIFICATE_NAME, CertificateDer, ClientConfig, Error, Instant, LocalNodeIdentity,
    ProcessFixture, RETRY_INTERVAL, SocketAddr, WAIT_LIMIT, request_with_headers, require_status,
    response_body, sleep,
};

const PROVISION: &str = "/api/latest/admin/certificates/local";
const STATUS: &str = "/api/latest/admin/certificates/status";

#[tokio::test]
async fn local_trust_survives_restart_join_and_certificate_rotation() -> Result<(), Box<dyn Error>>
{
    let root = ProcessFixture::new()?;
    let peer = ProcessFixture::new()?;
    let mut processes = vec![root.start()?];
    let proof: Result<(), Box<dyn Error>> = async {
        let claim = super::wait_for_claim(&root.claim_path).await?;
        let bootstrap_client = super::wait_for_client(&root.identity_path).await?;
        super::wait_for_status(root.address, &bootstrap_client, "claim_required").await?;
        let root_identity = identity_fingerprint(&root)?;
        let created = super::create_process_mesh(&root, &bootstrap_client, &claim).await?;
        let api_key = created["api_key"]
            .as_str()
            .ok_or("missing bootstrap API key")?;
        super::save_and_verify_recovery_bundle(&root, &bootstrap_client, api_key, &created).await?;
        let issued = provision(root.address, &bootstrap_client, api_key, 1).await?;
        assert_eq!(issued.generation.value(), Some(1));
        assert_eq!(issued.certificate_names, [CERTIFICATE_NAME]);
        let anchor = CertificateDer::from_pem_slice(issued.trust_anchor_pem.as_bytes())?;
        let local_client = super::client_config(anchor.as_ref())?;
        wait_for_installation(root.address, &local_client, api_key, 1).await?;
        assert_untrusted(root.address, &bootstrap_client).await?;

        processes[0].kill()?;
        processes[0].wait()?;
        processes[0] = root.start()?;
        wait_for_installation(root.address, &local_client, api_key, 1)
            .await
            .map_err(|error| format!("root restart: {error}"))?;
        assert_eq!(
            provision(root.address, &local_client, api_key, 1).await?,
            issued
        );
        assert_eq!(identity_fingerprint(&root)?, root_identity);

        let join_code = super::issue_join_code(&root, &local_client, api_key).await?;
        processes.push(peer.start_join(&join_code)?);
        let peer_bootstrap = super::wait_for_client(&peer.identity_path).await?;
        let peer_identity = identity_fingerprint(&peer)?;
        wait_for_installation(peer.address, &local_client, api_key, 2)
            .await
            .map_err(|error| format!("joined gateway: {error}"))?;
        assert_untrusted(peer.address, &peer_bootstrap).await?;
        assert_eq!(identity_fingerprint(&peer)?, peer_identity);

        let rotated = provision(root.address, &local_client, api_key, 2).await?;
        assert_eq!(rotated.authority_id, issued.authority_id);
        assert_eq!(rotated.trust_anchor_pem, issued.trust_anchor_pem);
        assert_eq!(rotated.generation.value(), Some(2));
        assert_ne!(rotated.certificate_id, issued.certificate_id);
        wait_for_source(root.address, &local_client, api_key, &rotated)
            .await
            .map_err(|error| format!("root rotation: {error}"))?;
        wait_for_source(peer.address, &local_client, api_key, &rotated)
            .await
            .map_err(|error| format!("peer rotation: {error}"))?;
        processes[1].kill()?;
        processes[1].wait()?;
        processes[1] = peer.start()?;
        wait_for_source(peer.address, &local_client, api_key, &rotated)
            .await
            .map_err(|error| format!("peer restart: {error}"))?;
        assert_eq!(identity_fingerprint(&peer)?, peer_identity);
        assert_eq!(identity_fingerprint(&root)?, root_identity);
        Ok(())
    }
    .await;
    let proof = proof.map_err(|error| {
        let states = processes
            .iter_mut()
            .map(|process| format!("{:?}", process.try_wait()))
            .collect::<Vec<_>>();
        format!("{error}; child exit observations (root, peer): {states:?}").into()
    });
    super::stop_processes(&mut processes);
    proof
}

fn identity_fingerprint(fixture: &ProcessFixture) -> Result<[u8; 32], Box<dyn Error>> {
    Ok(LocalNodeIdentity::open(&fixture.identity_path, CERTIFICATE_NAME)?.public_key_fingerprint())
}

async fn provision(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
    operation: u8,
) -> Result<ProvisionMeshLocalCertificateResponse, Box<dyn Error>> {
    let body = serde_json::to_vec(&json!({
        "operation_id": format!("00000000-0000-4000-8000-0000000001{operation:02x}"),
        "certificate_names": [CERTIFICATE_NAME]
    }))?;
    let authorization = format!("Bearer {api_key}");
    let response = tokio::time::timeout(
        WAIT_LIMIT,
        request_with_headers(
            address,
            client,
            "POST",
            PROVISION,
            Some(&body),
            &[("Authorization", &authorization)],
        ),
    )
    .await??;
    require_status(&response, "201 Created", "provision mesh-local certificate")?;
    Ok(serde_json::from_str(response_body(&response)?)?)
}

async fn wait_for_installation(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
    gateways: u64,
) -> Result<(), Box<dyn Error>> {
    wait_for_certificate(address, client, api_key, |status| {
        status.certificate.as_ref().is_some_and(|certificate| {
            certificate.source == CertificateStatusSource::MeshLocal
                && certificate.state == CertificateOperationalState::Active
                && certificate.required_gateway_count == gateways
                && certificate.installed_gateway_count == gateways
        })
    })
    .await
}

async fn wait_for_source(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
    expected: &ProvisionMeshLocalCertificateResponse,
) -> Result<(), Box<dyn Error>> {
    let encoded_source = serde_json::to_value(&expected.issuance_id)?;
    let expected_source = encoded_source
        .as_str()
        .ok_or("issuance identity is not text")?;
    wait_for_certificate(address, client, api_key, |status| {
        status.certificate.as_ref().is_some_and(|certificate| {
            certificate.source == CertificateStatusSource::MeshLocal
                && certificate.source_id == expected_source
                && certificate.state == CertificateOperationalState::Active
                && certificate.required_gateway_count == 2
                && certificate.installed_gateway_count == 2
        })
    })
    .await
}

async fn wait_for_certificate(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
    accepted: impl Fn(&CertificateStatusResponse) -> bool,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + WAIT_LIMIT;
    let authorization = format!("Bearer {api_key}");
    loop {
        let response = tokio::time::timeout(
            deadline.saturating_duration_since(Instant::now()),
            request_with_headers(
                address,
                client,
                "GET",
                STATUS,
                None,
                &[("Authorization", &authorization)],
            ),
        )
        .await;
        let observation = match response {
            Ok(Ok(response)) => {
                require_status(&response, "200 OK", "read mesh-local certificate status")?;
                let status: CertificateStatusResponse =
                    serde_json::from_str(response_body(&response)?)?;
                if accepted(&status) {
                    return Ok(());
                }
                format!("{:?}", status.certificate)
            }
            Ok(Err(error)) => error.to_string(),
            Err(_) => "TLS status request timed out".to_owned(),
        };
        if Instant::now() >= deadline {
            return Err(
                format!("mesh-local HTTPS at {address} did not install: {observation}").into(),
            );
        }
        sleep(RETRY_INTERVAL).await;
    }
}

async fn assert_untrusted(
    address: SocketAddr,
    client: &ClientConfig,
) -> Result<(), Box<dyn Error>> {
    let stream = super::TcpStream::connect(address).await?;
    let mut fresh = client.clone();
    // A resumed bootstrap session does not validate the newly selected leaf.
    // This assertion concerns a new trust decision, so require a full handshake.
    fresh.resumption = rustls::client::Resumption::disabled();
    let connector = super::TlsConnector::from(super::Arc::new(fresh));
    let name = super::ServerName::try_from(CERTIFICATE_NAME)?.to_owned();
    let result = tokio::time::timeout(WAIT_LIMIT, connector.connect(name, stream)).await?;
    let error = result
        .err()
        .ok_or("bootstrap-only trust accepted the mesh-local leaf")?;
    assert!(
        matches!(
            error
                .get_ref()
                .and_then(|error| error.downcast_ref::<rustls::Error>()),
            Some(rustls::Error::InvalidCertificate(_))
        ),
        "expected certificate rejection at {address}, got {error}"
    );
    Ok(())
}
