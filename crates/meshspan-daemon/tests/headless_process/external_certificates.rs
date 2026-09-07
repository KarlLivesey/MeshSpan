// SPDX-License-Identifier: GPL-2.0-only

//! Automated issuer → encrypted distribution → real gateway TLS, with no CA service.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use meshspan_api_contract::{
    CertificateOperationalState, CertificateStatusResponse, CertificateStatusSource,
    PublishExternalCertificateResponse,
};
use meshspan_certificates::{
    CertificateAuthority, ExternalCertificateRequestKey, NodePublicIdentity,
};
use p256::pkcs8::DecodePrivateKey as _;
use serde_json::{Value, json};

use super::*;

const PUBLISH: &str = "/api/latest/admin/certificates/external";

#[tokio::test]
async fn external_issuer_distribution_replay_and_interrupted_rollover_use_real_https()
-> Result<(), Box<dyn Error>> {
    let root = ProcessFixture::new()?;
    let peer = ProcessFixture::new()?;
    let mut processes = vec![root.start()?];
    let proof: Result<(), Box<dyn Error>> = async {
        let claim = wait_for_claim(&root.claim_path).await?;
        let bootstrap = wait_for_client(&root.identity_path).await?;
        wait_for_status(root.address, &bootstrap, "claim_required").await?;
        let created = create_process_mesh(&root, &bootstrap, &claim).await?;
        let key = created["api_key"].as_str().ok_or("missing API key")?;
        save_and_verify_recovery_bundle(&root, &bootstrap, key, &created).await?;
        let authority = CertificateAuthority::new()?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let first = IssuedMaterial::new(&authority, 1, now - 60, now + 86_400)?;
        let second = IssuedMaterial::new(&authority, 2, now - 60, now + 172_800)?;
        let issued_client = client_config(authority.certificate_der())?;
        let publication = publish(root.address, &bootstrap, key, &first.request).await?;
        wait_for_installed(&root, &issued_client, key, &first, &publication, 1).await?;
        assert_eq!(
            publish(root.address, &issued_client, key, &first.request).await?,
            publication
        );

        let join = issue_join_code(&root, &issued_client, key).await?;
        processes.push(peer.start_join(&join)?);
        wait_for_installed(&peer, &issued_client, key, &first, &publication, 2).await?;
        reject_invalid_publications(root.address, &issued_client, key, &first, &second).await?;
        let expired = IssuedMaterial::new(&authority, 3, now - 120, now - 60)?;
        reject(
            root.address,
            &issued_client,
            key,
            &expired.request,
            "400 Bad Request",
        )
        .await?;

        let rotated = publish(root.address, &issued_client, key, &second.request).await?;
        assert_eq!(rotated.generation.value(), Some(2));
        assert_ne!(rotated.certificate_id, publication.certificate_id);
        // Interrupt delivery after the durable publication, before waiting for installation.
        processes[1].kill()?;
        processes[1].wait()?;
        processes[1] = peer.start()?;
        wait_for_installed(&root, &issued_client, key, &second, &rotated, 2).await?;
        wait_for_installed(&peer, &issued_client, key, &second, &rotated, 2).await?;
        assert_eq!(
            publish(peer.address, &issued_client, key, &second.request).await?,
            rotated
        );
        assert_eq!(
            publish(root.address, &issued_client, key, &first.request).await?,
            publication
        );
        // Replaying an older operation must not roll the selected certificate back.
        wait_for_installed(&root, &issued_client, key, &second, &rotated, 2).await?;
        Ok(())
    }
    .await;
    stop_processes(&mut processes);
    retain_failure_state(proof, [root.temporary, peer.temporary])
}

struct IssuedMaterial {
    request: Value,
    leaf: Vec<u8>,
}

impl IssuedMaterial {
    fn new(
        authority: &CertificateAuthority,
        generation: u8,
        not_before: u64,
        not_after: u64,
    ) -> Result<Self, Box<dyn Error>> {
        let key = ExternalCertificateRequestKey::generate()?;
        let private = p256::SecretKey::from_pkcs8_der(key.private_key_pkcs8())?;
        let public = NodePublicIdentity::from_sec1(&private.public_key().to_sec1_bytes())?;
        let leaf = authority.sign_public_endpoint_identity(
            &public,
            &[CERTIFICATE_NAME.to_owned()],
            not_before,
            not_after,
        )?;
        Ok(Self {
            request: json!({
                "operation_id": format!("00000000-0000-4000-8000-0000000003{generation:02x}"),
                "generation": generation.to_string(),
                "certificate_names": [CERTIFICATE_NAME],
                "certificate_chain_pem": format!("{}{}", pem("CERTIFICATE", &leaf), pem("CERTIFICATE", authority.certificate_der())),
                "private_key_pkcs8_pem": pem("PRIVATE KEY", key.private_key_pkcs8())
            }),
            leaf,
        })
    }
}

async fn publish(
    address: SocketAddr,
    client: &ClientConfig,
    key: &str,
    body: &Value,
) -> Result<PublishExternalCertificateResponse, Box<dyn Error>> {
    let response = publication_request(address, client, key, body).await?;
    require_status(&response, "201 Created", "publish external certificate")?;
    assert!(!response.contains("PRIVATE KEY"));
    assert!(!response.contains("certificate_chain_pem"));
    Ok(serde_json::from_str(response_body(&response)?)?)
}

async fn reject(
    address: SocketAddr,
    client: &ClientConfig,
    key: &str,
    body: &Value,
    expected: &str,
) -> Result<(), Box<dyn Error>> {
    let response = publication_request(address, client, key, body).await?;
    require_status(&response, expected, "reject external certificate")?;
    assert!(!response.contains("PRIVATE KEY"));
    Ok(())
}

async fn publication_request(
    address: SocketAddr,
    client: &ClientConfig,
    key: &str,
    body: &Value,
) -> Result<String, Box<dyn Error>> {
    tokio::time::timeout(
        WAIT_LIMIT,
        request_with_headers(
            address,
            client,
            "POST",
            PUBLISH,
            Some(&serde_json::to_vec(body)?),
            &[("Authorization", &format!("Bearer {key}"))],
        ),
    )
    .await?
}

async fn reject_invalid_publications(
    address: SocketAddr,
    client: &ClientConfig,
    key: &str,
    first: &IssuedMaterial,
    second: &IssuedMaterial,
) -> Result<(), Box<dyn Error>> {
    let mut changed = first.request.clone();
    changed["certificate_names"] = json!(["wrong.example.test"]);
    reject(address, client, key, &changed, "400 Bad Request").await?;
    changed = first.request.clone();
    changed["private_key_pkcs8_pem"] = second.request["private_key_pkcs8_pem"].clone();
    reject(address, client, key, &changed, "400 Bad Request").await?;
    changed = first.request.clone();
    changed["certificate_chain_pem"] = json!("not a certificate".repeat(5));
    reject(address, client, key, &changed, "400 Bad Request").await?;
    changed = second.request.clone();
    changed["generation"] = json!("1");
    reject(address, client, key, &changed, "409 Conflict").await?;
    changed = second.request.clone();
    changed["operation_id"] = first.request["operation_id"].clone();
    reject(address, client, key, &changed, "409 Conflict").await?;
    Ok(())
}

async fn wait_for_installed(
    fixture: &ProcessFixture,
    client: &ClientConfig,
    key: &str,
    expected: &IssuedMaterial,
    publication: &PublishExternalCertificateResponse,
    gateways: u64,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + WAIT_LIMIT;
    let expected_source: String =
        serde_json::from_value(serde_json::to_value(&publication.publication_id)?)?;
    loop {
        let response = tokio::time::timeout_at(
            deadline.into(),
            request_with_headers(
                fixture.address,
                client,
                "GET",
                "/api/latest/admin/certificates/status",
                None,
                &[("Authorization", &format!("Bearer {key}"))],
            ),
        )
        .await;
        if let Ok(Ok(response)) = response {
            require_status(&response, "200 OK", "read external installation")?;
            let value: CertificateStatusResponse = serde_json::from_str(response_body(&response)?)?;
            if value.certificate.is_some_and(|value| {
                value.source == CertificateStatusSource::External
                    && value.source_id == expected_source
                    && value.state == CertificateOperationalState::Active
                    && value.required_gateway_count == gateways
                    && value.installed_gateway_count == gateways
            }) {
                return verify_selected_leaf(fixture.address, client, &expected.leaf).await;
            }
        }
        if Instant::now() >= deadline {
            return Err(
                format!("external certificate not installed at {}", fixture.address).into(),
            );
        }
        sleep(RETRY_INTERVAL).await;
    }
}

async fn verify_selected_leaf(
    address: SocketAddr,
    client: &ClientConfig,
    expected: &[u8],
) -> Result<(), Box<dyn Error>> {
    tokio::time::timeout(WAIT_LIMIT, async {
        let socket = TcpStream::connect(address).await?;
        let mut fresh_client = client.clone();
        // A resumed TLS session retains its original peer identity. Inspect a full
        // handshake to prove which leaf the resolver currently selects.
        fresh_client.resumption = rustls::client::Resumption::disabled();
        let connector = TlsConnector::from(Arc::new(fresh_client));
        let connection = connector
            .connect(ServerName::try_from(CERTIFICATE_NAME)?.to_owned(), socket)
            .await?;
        let certificates = connection
            .get_ref()
            .1
            .peer_certificates()
            .ok_or("missing TLS chain")?;
        if certificates.first().ok_or("empty TLS chain")?.as_ref() != expected {
            return Err("fresh TLS handshake selected a different external certificate".into());
        }
        Ok::<_, Box<dyn Error>>(())
    })
    .await?
}

fn pem(label: &str, bytes: &[u8]) -> String {
    let mut value = format!("-----BEGIN {label}-----\n");
    for line in STANDARD.encode(bytes).as_bytes().chunks(64) {
        value.extend(line.iter().copied().map(char::from));
        value.push('\n');
    }
    value.push_str("-----END ");
    value.push_str(label);
    value.push_str("-----\n");
    value
}
