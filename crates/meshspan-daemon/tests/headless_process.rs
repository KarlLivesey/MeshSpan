// SPDX-License-Identifier: GPL-2.0-only

//! Real-process proof for headless startup, HTTPS setup and durable restart.

#[path = "support/passkey.rs"]
mod passkey_support;

use std::error::Error;
use std::fs;
use std::fs::OpenOptions;
use std::net::{SocketAddr, TcpListener as StandardTcpListener, UdpSocket as StandardUdpSocket};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use meshspan_consensus::ActiveQuorumPlan;
use meshspan_daemon::{ClaimFile, LocalNodeIdentity, LocalWrappingKey};
use meshspan_domain::{InitialBootstrapMaterial, OperationId, PartitionId, UnixMicros};
use meshspan_metadata::{AuthoritativeRepository, PartitionDatabase};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use sha1::Sha1;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::time::sleep;
use tokio_rustls::TlsConnector;

const CERTIFICATE_NAME: &str = "meshspan.local";
const WAIT_LIMIT: Duration = Duration::from_secs(15);
const RETRY_INTERVAL: Duration = Duration::from_millis(50);

#[tokio::test]
async fn three_headless_daemons_commit_after_original_node_loss() -> Result<(), Box<dyn Error>> {
    let root = ProcessFixture::new()?;
    let second = ProcessFixture::new()?;
    let third = ProcessFixture::new()?;
    let mut processes = Vec::new();
    let proof = async {
        processes.push(root.start()?);
        let claim = wait_for_claim(&root.claim_path).await?;
        let root_client = wait_for_client(&root.identity_path).await?;
        wait_for_status(root.address, &root_client, "claim_required").await?;
        let administrator_id = bootstrap_administrator_id(&claim, &root.identity_path)?;
        let created = create_process_mesh(&root, &root_client, &claim).await?;
        let api_key = created["api_key"]
            .as_str()
            .ok_or("setup response omitted the API key")?;
        save_and_verify_recovery_bundle(&root, &root_client, api_key, &created).await?;
        let join_code = issue_join_code(&root, &root_client, api_key).await?;

        processes.push(second.start_join(&join_code)?);
        let second_client = wait_for_client(&second.identity_path).await?;
        wait_for_status(second.address, &second_client, "configured").await?;
        wait_for_live_provider(&second).await?;
        processes.push(third.start_join(&join_code)?);
        let third_client = wait_for_client(&third.identity_path).await?;
        wait_for_status(third.address, &third_client, "configured").await?;
        wait_for_live_provider(&third).await?;
        wait_for_three_voters([&root, &second, &third], &root.identity_path).await?;
        let group_id = create_group(second.address, &second_client, api_key).await?;
        wait_for_group_visibility(third.address, &third_client, api_key).await?;

        processes[0].kill()?;
        processes[0].wait()?;
        let user_id = wait_for_user_creation(second.address, &second_client, api_key).await?;
        wait_for_user_visibility(third.address, &third_client, api_key).await?;
        add_group_member(third.address, &third_client, api_key, &group_id, &user_id).await?;
        wait_for_group_membership(second.address, &second_client, api_key, &group_id, &user_id)
            .await?;
        let volume_id =
            create_volume(second.address, &second_client, api_key, &administrator_id).await?;
        let content = b"survivor gateway exact native bytes";
        upload_file(second.address, &second_client, api_key, &volume_id, content).await?;
        wait_for_file_surfaces(third.address, &third_client, api_key, &volume_id, content).await
    }
    .await;
    stop_processes(&mut processes);
    proof
}

async fn create_process_mesh(
    fixture: &ProcessFixture,
    client: &ClientConfig,
    claim: &meshspan_domain::ClaimBundle,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let encoded_claim = claim.expose_encoded();
    let body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000001",
        "claim": encoded_claim.as_str(),
        "mesh_name": "Three node process mesh",
        "administrator_name": "Administrator",
        "host_name": "Root host",
        "node_name": "Root node"
    }))?;
    let response = request(
        fixture.address,
        client,
        "POST",
        "/api/latest/setup/meshes",
        Some(&body),
    )
    .await?;
    require_status(&response, "201 Created", "create three-node mesh")?;
    Ok(serde_json::from_str(response_body(&response)?)?)
}

async fn issue_join_code(
    fixture: &ProcessFixture,
    client: &ClientConfig,
    api_key: &str,
) -> Result<String, Box<dyn Error>> {
    let body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000020",
        "enrolment_endpoint": format!("https://{}", fixture.address),
        "allowed_roles": ["storage", "gateway", "metadata_eligible"],
        "maximum_uses": 2,
        "valid_for_seconds": 3600
    }))?;
    let authorization = format!("Bearer {api_key}");
    let response = request_with_headers(
        fixture.address,
        client,
        "POST",
        "/api/latest/admin/node-join-grants",
        Some(&body),
        &[("Authorization", authorization.as_str())],
    )
    .await?;
    require_status(&response, "201 Created", "issue two-use node join code")?;
    let response: serde_json::Value = serde_json::from_str(response_body(&response)?)?;
    response["join_code"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "join-grant response omitted the join code".into())
}

async fn wait_for_three_voters(
    fixtures: [&ProcessFixture; 3],
    root_identity_path: &Path,
) -> Result<(), Box<dyn Error>> {
    let root_identity = LocalNodeIdentity::open(root_identity_path, CERTIFICATE_NAME)?;
    let root_node = InitialBootstrapMaterial::node_id(root_identity.public_key_fingerprint())?;
    let partition_id = InitialBootstrapMaterial::root_partition_id(root_node)?;
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        let all_ready = fixtures
            .iter()
            .all(|fixture| has_three_voters(&fixture.state_path, partition_id).unwrap_or(false));
        if all_ready {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("three-daemon mesh did not converge to three metadata voters".into());
        }
        sleep(RETRY_INTERVAL).await;
    }
}

fn has_three_voters(state_path: &Path, partition_id: PartitionId) -> Result<bool, Box<dyn Error>> {
    let database = PartitionDatabase::open(
        &state_path.join("root-authority.sqlite3"),
        partition_id,
        UnixMicros::new(1),
    )?;
    let active = AuthoritativeRepository::new(database).load_active_consensus_quorum_plan()?;
    Ok(matches!(
        active,
        Some(ActiveQuorumPlan::Stable(plan)) if plan.spec().voters.len() == 3
    ))
}

async fn wait_for_user_creation(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
) -> Result<String, Box<dyn Error>> {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        let error = match create_user(address, client, api_key).await {
            Ok(principal_id) => return Ok(principal_id),
            Err(error) => error,
        };
        if Instant::now() >= deadline {
            return Err(format!(
                "surviving daemon never accepted a committed metadata write: {}",
                error
            )
            .into());
        }
        sleep(RETRY_INTERVAL).await;
    }
}

async fn wait_for_user_visibility(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        if assert_user_visible(address, client, api_key).await.is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("committed survivor write never became visible on the other node".into());
        }
        sleep(RETRY_INTERVAL).await;
    }
}

async fn wait_for_group_visibility(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        if assert_group_visible(address, client, api_key).await.is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("committed follower-created group never became visible".into());
        }
        sleep(RETRY_INTERVAL).await;
    }
}

async fn wait_for_group_membership(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
    group_id: &str,
    user_id: &str,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        if assert_group_membership(address, client, api_key, group_id, user_id)
            .await
            .is_ok()
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("committed cross-gateway group membership never became visible".into());
        }
        sleep(RETRY_INTERVAL).await;
    }
}

async fn wait_for_file_surfaces(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
    volume_id: &str,
    content: &[u8],
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        let error = match assert_file_surfaces(address, client, api_key, volume_id, content).await {
            Ok(()) => return Ok(()),
            Err(error) => error,
        };
        if Instant::now() >= deadline {
            return Err(format!(
                "native survivor bytes never became readable through the peer gateway: {}",
                error
            )
            .into());
        }
        sleep(RETRY_INTERVAL).await;
    }
}

fn stop_processes(processes: &mut [Child]) {
    for process in processes {
        let _killed = process.kill();
        let _waited = process.wait();
    }
}

#[tokio::test]
async fn real_headless_process_creates_mesh_over_https_and_restarts() -> Result<(), Box<dyn Error>>
{
    let fixture = ProcessFixture::new()?;
    let mut process = fixture.start()?;
    let claim = wait_for_claim(&fixture.claim_path).await?;
    let client = wait_for_client(&fixture.identity_path).await?;
    let administrator_id = bootstrap_administrator_id(&claim, &fixture.identity_path)?;
    wait_for_status(fixture.address, &client, "claim_required").await?;

    let encoded_claim = claim.expose_encoded();
    let body = serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000001",
        "claim": encoded_claim.as_str(),
        "mesh_name": "Process mesh",
        "administrator_name": "Administrator",
        "host_name": "Test host",
        "node_name": "Test node"
    });
    let response = request(
        fixture.address,
        &client,
        "POST",
        "/api/latest/setup/meshes",
        Some(&serde_json::to_vec(&body)?),
    )
    .await?;
    assert!(response.starts_with("HTTP/1.1 201 Created\r\n"));
    assert!(response.contains("\"api_key\":\"meshspan-key-v1."));
    let created: serde_json::Value = serde_json::from_str(response_body(&response)?)?;
    let api_key = created["api_key"]
        .as_str()
        .ok_or("setup response omitted the API key")?;
    save_and_verify_recovery_bundle(&fixture, &client, api_key, &created).await?;
    let session_body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000002",
        "authentication": { "method": "api_key", "secret": api_key },
        "client_label": null,
        "remember": false
    }))?;
    assert!(!fixture.claim_path.exists());
    wait_for_status(fixture.address, &client, "configured").await?;
    let target_marker = wait_for_storage_marker(&fixture.storage_path).await?;
    let provider_journal = wait_for_live_provider(&fixture).await?;
    assert_wrapping_key_committed(&fixture)?;
    assert_eq!(
        fs::read(fixture.storage_path.join("operator-file.txt"))?,
        b"untouched"
    );
    let browser_session = create_browser_session(fixture.address, &client, &session_body).await?;
    assert_live_totp_verifier_rejects_unknown_factor(fixture.address, &client, api_key).await?;
    let totp_secret = enrol_totp(fixture.address, &client, api_key, &browser_session).await?;
    let passkey = enrol_passkey(fixture.address, &client, api_key, &browser_session).await?;
    assert_api_key_lifecycle(fixture.address, &client, api_key, &browser_session).await?;
    assert_volume_inventory_empty(fixture.address, &client, api_key).await?;
    create_user(fixture.address, &client, api_key).await?;
    let volume_id = create_volume(fixture.address, &client, api_key, &administrator_id).await?;
    assert_volume_visible(fixture.address, &client, api_key).await?;
    let content = b"headless native file bytes";
    upload_file(fixture.address, &client, api_key, &volume_id, content).await?;
    assert_file_surfaces(fixture.address, &client, api_key, &volume_id, content).await?;

    process.kill()?;
    process.wait()?;
    process = fixture.start()?;
    wait_for_status(fixture.address, &client, "configured").await?;
    assert_eq!(
        wait_for_storage_marker(&fixture.storage_path).await?,
        target_marker
    );
    assert_eq!(wait_for_live_provider(&fixture).await?, provider_journal);
    assert_wrapping_key_committed(&fixture)?;
    create_browser_session(fixture.address, &client, &session_body).await?;
    assert_passkey_session(fixture.address, &client, &passkey).await?;
    let multi_factor_session =
        create_totp_browser_session(fixture.address, &client, api_key, &totp_secret).await?;
    assert_recovery_code_lifecycle(fixture.address, &client, api_key, &multi_factor_session)
        .await?;
    assert_volume_visible(fixture.address, &client, api_key).await?;
    assert_user_visible(fixture.address, &client, api_key).await?;
    assert_file_surfaces(fixture.address, &client, api_key, &volume_id, content).await?;
    process.kill()?;
    process.wait()?;
    Ok(())
}

struct RegisteredPasskey {
    user_handle: String,
}

async fn enrol_passkey(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
    session: &BrowserSessionHeaders,
) -> Result<RegisteredPasskey, Box<dyn Error>> {
    let challenge_body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000012"
    }))?;
    let challenge = request_with_headers(
        address,
        client,
        "POST",
        "/api/latest/users/current/authentication-methods/passkeys/registration-challenges",
        Some(&challenge_body),
        &session.mutation_headers(),
    )
    .await?;
    require_status(
        &challenge,
        "201 Created",
        "create passkey registration challenge",
    )?;
    let challenge: serde_json::Value = serde_json::from_str(response_body(&challenge)?)?;
    let challenge_id = challenge["challenge_id"]
        .as_str()
        .ok_or("passkey registration challenge omitted its identity")?;
    let challenge_value = challenge["challenge"]
        .as_str()
        .ok_or("passkey registration challenge omitted its value")?;
    let relying_party_id = challenge["relying_party_id"]
        .as_str()
        .ok_or("passkey registration challenge omitted its relying party")?;
    let user_handle = challenge["user_id"]
        .as_str()
        .ok_or("passkey registration challenge omitted its user handle")?
        .to_owned();
    let origin = passkey_origin(address);
    let evidence = passkey_support::registration(challenge_value, relying_party_id, &origin)?;
    let registration_body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000013",
        "challenge_id": challenge_id,
        "label": "Headless process passkey",
        "credential_id": evidence.credential_id,
        "client_data_json": evidence.client_data_json,
        "attestation_object": evidence.attestation_object,
        "transports": ["internal"]
    }))?;
    let registered = request_with_headers(
        address,
        client,
        "POST",
        "/api/latest/users/current/authentication-methods/passkeys",
        Some(&registration_body),
        &session.mutation_headers(),
    )
    .await?;
    require_status(&registered, "201 Created", "register passkey")?;

    let authorization = format!("Bearer {api_key}");
    let methods = request_with_headers(
        address,
        client,
        "GET",
        "/api/latest/users/current/authentication-methods?limit=100",
        None,
        &[("Authorization", authorization.as_str())],
    )
    .await?;
    require_status(&methods, "200 OK", "list enrolled passkey method")?;
    if !response_body(&methods)?.contains("Headless process passkey") {
        return Err("authentication-method inventory omitted the enrolled passkey".into());
    }
    Ok(RegisteredPasskey { user_handle })
}

async fn assert_passkey_session(
    address: SocketAddr,
    client: &ClientConfig,
    passkey: &RegisteredPasskey,
) -> Result<(), Box<dyn Error>> {
    let challenge_body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000014"
    }))?;
    let challenge = request(
        address,
        client,
        "POST",
        "/api/latest/sessions/passkey/challenges",
        Some(&challenge_body),
    )
    .await?;
    require_status(
        &challenge,
        "201 Created",
        "create passkey authentication challenge",
    )?;
    let challenge: serde_json::Value = serde_json::from_str(response_body(&challenge)?)?;
    let challenge_id = challenge["challenge_id"]
        .as_str()
        .ok_or("passkey authentication challenge omitted its identity")?;
    let challenge_value = challenge["challenge"]
        .as_str()
        .ok_or("passkey authentication challenge omitted its value")?;
    let relying_party_id = challenge["relying_party_id"]
        .as_str()
        .ok_or("passkey authentication challenge omitted its relying party")?;
    let origin = passkey_origin(address);
    let evidence = passkey_support::assertion(
        challenge_value,
        relying_party_id,
        &origin,
        &passkey.user_handle,
    )?;
    let session_body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000015",
        "authentication": {
            "method": "passkey",
            "challenge_id": challenge_id,
            "credential_id": evidence.credential_id,
            "client_data_json": evidence.client_data_json,
            "authenticator_data": evidence.authenticator_data,
            "signature": evidence.signature,
            "user_handle": evidence.user_handle
        },
        "client_label": "Restarted passkey proof",
        "remember": false
    }))?;
    let session = request(
        address,
        client,
        "POST",
        "/api/latest/sessions",
        Some(&session_body),
    )
    .await?;
    require_status(
        &session,
        "201 Created",
        "authenticate with passkey after restart",
    )
}

fn passkey_origin(address: SocketAddr) -> String {
    if address.port() == 443 {
        format!("https://{CERTIFICATE_NAME}")
    } else {
        format!("https://{CERTIFICATE_NAME}:{}", address.port())
    }
}

async fn enrol_totp(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
    session: &BrowserSessionHeaders,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let challenge_body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-00000000000c",
        "label": "Headless process authenticator"
    }))?;
    let challenge = request_with_headers(
        address,
        client,
        "POST",
        "/api/latest/users/current/authentication-methods/totp/registration-challenges",
        Some(&challenge_body),
        &session.mutation_headers(),
    )
    .await?;
    require_status(
        &challenge,
        "201 Created",
        "create TOTP registration challenge",
    )?;
    let challenge: serde_json::Value = serde_json::from_str(response_body(&challenge)?)?;
    let challenge_id = challenge["challenge_id"]
        .as_str()
        .ok_or("TOTP challenge omitted its identity")?;
    let secret = decode_base32(
        challenge["secret"]
            .as_str()
            .ok_or("TOTP challenge omitted its secret")?,
    )?;
    let code = current_totp_code(&secret)?;
    let confirmation_body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-00000000000d",
        "challenge_id": challenge_id,
        "code": code
    }))?;
    let confirmed = request_with_headers(
        address,
        client,
        "POST",
        "/api/latest/users/current/authentication-methods/totp",
        Some(&confirmation_body),
        &session.mutation_headers(),
    )
    .await?;
    require_status(&confirmed, "201 Created", "confirm TOTP registration")?;

    let authorization = format!("Bearer {api_key}");
    let methods = request_with_headers(
        address,
        client,
        "GET",
        "/api/latest/users/current/authentication-methods?limit=100",
        None,
        &[("Authorization", authorization.as_str())],
    )
    .await?;
    require_status(&methods, "200 OK", "list enrolled TOTP method")?;
    if !response_body(&methods)?.contains("Headless process authenticator") {
        return Err("authentication-method inventory omitted the enrolled TOTP method".into());
    }
    Ok(secret)
}

async fn create_totp_browser_session(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
    secret: &[u8],
) -> Result<BrowserSessionHeaders, Box<dyn Error>> {
    let code = current_totp_code(secret)?;
    let body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-00000000000e",
        "authentication": { "method": "api_key", "secret": api_key },
        "additional_factor": { "method": "totp", "code": code },
        "client_label": "Restarted TOTP proof",
        "remember": false
    }))?;
    let response = request(address, client, "POST", "/api/latest/sessions", Some(&body)).await?;
    require_status(
        &response,
        "201 Created",
        "authenticate with TOTP after restart",
    )?;
    browser_session_headers(&response)
}

async fn assert_recovery_code_lifecycle(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
    session: &BrowserSessionHeaders,
) -> Result<(), Box<dyn Error>> {
    let issue_body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-00000000000f",
        "label": "Headless process recovery codes"
    }))?;
    let issued = request_with_headers(
        address,
        client,
        "POST",
        "/api/latest/users/current/authentication-methods/recovery-codes",
        Some(&issue_body),
        &session.mutation_headers(),
    )
    .await?;
    require_status(&issued, "201 Created", "issue protected recovery codes")?;
    let issued: serde_json::Value = serde_json::from_str(response_body(&issued)?)?;
    let codes = issued["codes"]
        .as_array()
        .ok_or("recovery-code issuance omitted its codes")?;
    if codes.len() != 10 {
        return Err("recovery-code issuance did not return exactly ten codes".into());
    }
    let code = codes[0]
        .as_str()
        .ok_or("recovery-code issuance returned a non-text code")?;
    let recovery_session_body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000010",
        "authentication": { "method": "api_key", "secret": api_key },
        "additional_factor": { "method": "recovery_code", "code": code },
        "client_label": "Recovery code proof",
        "remember": false
    }))?;
    let consumed = request(
        address,
        client,
        "POST",
        "/api/latest/sessions",
        Some(&recovery_session_body),
    )
    .await?;
    require_status(&consumed, "201 Created", "consume one recovery code")?;
    let replay = request(
        address,
        client,
        "POST",
        "/api/latest/sessions",
        Some(&recovery_session_body),
    )
    .await?;
    require_status(&replay, "201 Created", "replay exact recovery-code session")?;

    let reuse_body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000011",
        "authentication": { "method": "api_key", "secret": api_key },
        "additional_factor": { "method": "recovery_code", "code": code },
        "client_label": "Forbidden recovery-code reuse",
        "remember": false
    }))?;
    let rejected = request(
        address,
        client,
        "POST",
        "/api/latest/sessions",
        Some(&reuse_body),
    )
    .await?;
    require_status(
        &rejected,
        "401 Unauthorized",
        "reject recovery-code reuse under another operation",
    )
}

fn current_totp_code(secret: &[u8]) -> Result<String, Box<dyn Error>> {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let counter = (seconds / 30).to_be_bytes();
    let mut mac = <Hmac<Sha1> as hmac::digest::KeyInit>::new_from_slice(secret)?;
    mac.update(&counter);
    let output = mac.finalize().into_bytes();
    let offset = usize::from(output[output.len() - 1] & 0x0f);
    let selected = output
        .get(offset..offset + 4)
        .ok_or("TOTP HMAC truncation was invalid")?;
    let binary = (u32::from(selected[0] & 0x7f) << 24)
        | (u32::from(selected[1]) << 16)
        | (u32::from(selected[2]) << 8)
        | u32::from(selected[3]);
    Ok(format!("{:06}", binary % 1_000_000))
}

fn decode_base32(encoded: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut output = Vec::with_capacity(encoded.len() * 5 / 8);
    let mut bits = 0_u32;
    let mut bit_count = 0_u8;
    for byte in encoded.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return Err("TOTP secret was not canonical base32".into()),
        };
        bits = (bits << 5) | u32::from(value);
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            output.push(
                u8::try_from(bits >> bit_count)
                    .map_err(|_| "TOTP base32 decoder overflowed one byte")?,
            );
            bits &= (1_u32 << bit_count) - 1;
        }
    }
    if bit_count != 0 && bits != 0 {
        return Err("TOTP secret had non-zero base32 padding bits".into());
    }
    Ok(output)
}

async fn assert_live_totp_verifier_rejects_unknown_factor(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
) -> Result<(), Box<dyn Error>> {
    let body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000009",
        "authentication": { "method": "api_key", "secret": api_key },
        "additional_factor": { "method": "totp", "code": "000000" },
        "client_label": null,
        "remember": false
    }))?;
    let response = request(address, client, "POST", "/api/latest/sessions", Some(&body)).await?;
    if response.starts_with("HTTP/1.1 401 Unauthorized\r\n")
        && response_body(&response)?.contains("authentication was rejected")
    {
        Ok(())
    } else {
        Err(format!(
            "live protected TOTP verifier returned {}: {}",
            response.lines().next().unwrap_or("an invalid response"),
            response_body(&response).unwrap_or("invalid response")
        )
        .into())
    }
}

async fn assert_api_key_lifecycle(
    address: SocketAddr,
    client: &ClientConfig,
    bootstrap_api_key: &str,
    session: &BrowserSessionHeaders,
) -> Result<(), Box<dyn Error>> {
    let issue_body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-00000000000a",
        "label": "Headless process automation",
        "scopes": ["headless_api"]
    }))?;
    let issued = request_with_headers(
        address,
        client,
        "POST",
        "/api/latest/users/current/authentication-methods/api-keys",
        Some(&issue_body),
        &session.mutation_headers(),
    )
    .await?;
    require_status(&issued, "201 Created", "issue protected API key")?;
    let issued: serde_json::Value = serde_json::from_str(response_body(&issued)?)?;
    let method_id = issued["method_id"]
        .as_str()
        .ok_or("API-key issuance omitted its method identity")?;
    let issued_key = issued["secret"]
        .as_str()
        .ok_or("API-key issuance omitted its one-time secret")?;

    let issued_authorization = format!("Bearer {issued_key}");
    let inventory = request_with_headers(
        address,
        client,
        "GET",
        "/api/latest/users/current/authentication-methods?limit=100",
        None,
        &[("Authorization", issued_authorization.as_str())],
    )
    .await?;
    require_status(&inventory, "200 OK", "list methods with issued API key")?;
    if !response_body(&inventory)?.contains("Headless process automation") {
        return Err("authentication-method inventory omitted the issued key".into());
    }

    let revoke_body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-00000000000b",
        "reason": "Real-process lifecycle proof"
    }))?;
    let revoked = request_with_headers(
        address,
        client,
        "POST",
        &format!("/api/latest/users/current/authentication-methods/{method_id}/revocations"),
        Some(&revoke_body),
        &session.mutation_headers(),
    )
    .await?;
    require_status(&revoked, "200 OK", "revoke issued API key")?;

    let rejected = request_with_headers(
        address,
        client,
        "GET",
        "/api/latest/users/current/authentication-methods?limit=100",
        None,
        &[("Authorization", issued_authorization.as_str())],
    )
    .await?;
    require_status(
        &rejected,
        "401 Unauthorized",
        "reject revoked issued API key",
    )?;
    let bootstrap_authorization = format!("Bearer {bootstrap_api_key}");
    let retained = request_with_headers(
        address,
        client,
        "GET",
        "/api/latest/users/current/authentication-methods?limit=100",
        None,
        &[("Authorization", bootstrap_authorization.as_str())],
    )
    .await?;
    require_status(&retained, "200 OK", "list retained revoked method")?;
    if !response_body(&retained)?.contains("Headless process automation")
        || !response_body(&retained)?.contains("\"state\":\"revoked\"")
    {
        return Err("revoked authentication method was not retained as evidence".into());
    }
    Ok(())
}

fn assert_wrapping_key_committed(fixture: &ProcessFixture) -> Result<(), Box<dyn Error>> {
    let identity = LocalNodeIdentity::open(&fixture.identity_path, CERTIFICATE_NAME)?;
    let node_id = InitialBootstrapMaterial::node_id(identity.public_key_fingerprint())?;
    let local_key =
        LocalWrappingKey::open(&fixture.state_path.join("secrets/node-wrapping-key.x25519"))?;
    let database = PartitionDatabase::open(
        &fixture.state_path.join("root-authority.sqlite3"),
        InitialBootstrapMaterial::root_partition_id(node_id)?,
        UnixMicros::new(1),
    )?;
    let repository = AuthoritativeRepository::new(database);
    let stored = repository
        .node_wrapping_key(node_id)?
        .ok_or("authoritative node wrapping key missing")?;
    assert_eq!(stored.public_key, local_key.public_key());
    assert_eq!(stored.generation, 1);
    let recipients = repository.volume_key_recipients()?;
    assert_eq!(recipients.len(), 2);
    assert!(recipients.contains(&local_key.public_key()));
    Ok(())
}

async fn assert_volume_inventory_empty(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
) -> Result<(), Box<dyn Error>> {
    let authorization = format!("Bearer {api_key}");
    let response = request_with_headers(
        address,
        client,
        "GET",
        "/api/latest/volumes?limit=100",
        None,
        &[("Authorization", authorization.as_str())],
    )
    .await?;
    if response.starts_with("HTTP/1.1 200 OK\r\n") && response.contains("\"volumes\":[]") {
        Ok(())
    } else {
        Err("headless process did not return its authorised volume inventory".into())
    }
}

async fn save_and_verify_recovery_bundle(
    fixture: &ProcessFixture,
    client: &ClientConfig,
    api_key: &str,
    setup: &serde_json::Value,
) -> Result<(), Box<dyn Error>> {
    let recovery_bundle = setup["recovery_bundle"]
        .as_str()
        .ok_or("setup response omitted the recovery bundle")?;
    let recovery_code = setup["recovery_code"]
        .as_str()
        .ok_or("setup response omitted the recovery code")?;
    let recovery_challenge = setup["recovery_challenge"]
        .as_str()
        .ok_or("setup response omitted the recovery challenge")?;
    let mesh_id = setup["mesh_id"]
        .as_str()
        .ok_or("setup response omitted the mesh identity")?;
    write_private(
        &fixture.saved_recovery_bundle_path,
        recovery_bundle.as_bytes(),
    )?;
    write_private(&fixture.saved_recovery_code_path, recovery_code.as_bytes())?;
    let body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000005",
        "mesh_id": mesh_id,
        "recovery_challenge": recovery_challenge
    }))?;
    let authorization = format!("Bearer {api_key}");
    let response = request_with_headers(
        fixture.address,
        client,
        "POST",
        "/api/latest/admin/recovery-bundle-verifications",
        Some(&body),
        &[("Authorization", authorization.as_str())],
    )
    .await?;
    if !response.starts_with("HTTP/1.1 200 OK\r\n") {
        return Err(format!(
            "headless recovery verification returned {}: {}",
            response.lines().next().unwrap_or("an invalid response"),
            response_body(&response).unwrap_or("invalid response")
        )
        .into());
    }
    if fixture.pending_recovery_bundle_path.exists()
        || fs::read_to_string(&fixture.saved_recovery_bundle_path)? != recovery_bundle
        || fs::read_to_string(&fixture.saved_recovery_code_path)? != recovery_code
    {
        return Err("headless recovery save verification did not preserve the offline copy".into());
    }
    Ok(())
}

fn write_private(file_path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(file_path)?;
    std::io::Write::write_all(&mut file, bytes)?;
    file.sync_all()?;
    Ok(())
}

async fn create_volume(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
    owner_principal_id: &str,
) -> Result<String, Box<dyn Error>> {
    let body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000004",
        "name": "Process files",
        "owner_principal_ids": [owner_principal_id]
    }))?;
    let authorization = format!("Bearer {api_key}");
    let response = request_with_headers(
        address,
        client,
        "POST",
        "/api/latest/admin/volumes",
        Some(&body),
        &[("Authorization", authorization.as_str())],
    )
    .await?;
    if !response.starts_with("HTTP/1.1 201 Created\r\n")
        || !response.contains("\"name\":\"Process files\"")
    {
        Err(format!(
            "headless process volume creation returned {}: {}",
            response.lines().next().unwrap_or("an invalid response"),
            response_body(&response).unwrap_or("invalid response")
        )
        .into())
    } else {
        let created: serde_json::Value = serde_json::from_str(response_body(&response)?)?;
        created["volume_id"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| "headless volume creation omitted its identity".into())
    }
}

async fn upload_file(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
    volume_id: &str,
    content: &[u8],
) -> Result<(), Box<dyn Error>> {
    let authorization = format!("Bearer {api_key}");
    let begin_body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000006",
        "path": "process-proof.bin",
        "disposition": { "mode": "create_new" },
        "maximum_bytes": 1024
    }))?;
    let begin_response = request_with_headers(
        address,
        client,
        "POST",
        &format!("/api/latest/volumes/{volume_id}/uploads"),
        Some(&begin_body),
        &[("Authorization", authorization.as_str())],
    )
    .await?;
    require_status(&begin_response, "201 Created", "begin native upload")?;
    let begin_payload: serde_json::Value = serde_json::from_str(response_body(&begin_response)?)?;
    let upload_id = begin_payload["upload_id"]
        .as_str()
        .ok_or("native upload begin omitted its identity")?;
    let stage_fence = begin_payload["stage_fence"]
        .as_u64()
        .ok_or("native upload begin omitted its fence")?;
    let digest = blake3::hash(content).to_hex().to_string();
    let stage_fence = stage_fence.to_string();
    let write = request_with_content_type(
        address,
        client,
        "PUT",
        &format!("/api/latest/uploads/{upload_id}/ranges/0"),
        Some(content),
        "application/octet-stream",
        &[
            ("Authorization", authorization.as_str()),
            (
                "MeshSpan-Operation-Id",
                "00000000-0000-4000-8000-000000000007",
            ),
            ("MeshSpan-Stage-Fence", stage_fence.as_str()),
            ("MeshSpan-Content-BLAKE3", digest.as_str()),
        ],
    )
    .await?;
    require_status(&write, "200 OK", "write native upload range")?;
    let written: serde_json::Value = serde_json::from_str(response_body(&write)?)?;
    let checkpoint = written["checkpoint_sequence"]
        .as_u64()
        .ok_or("native range write omitted its checkpoint")?;
    let stage_fence = written["stage_fence"]
        .as_u64()
        .ok_or("native range write omitted its fence")?;
    let commit_body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000008",
        "stage_fence": stage_fence,
        "expected_sequence": checkpoint,
        "final_length": content.len(),
        "sparse": false,
        "expected_blake3": digest
    }))?;
    let commit = request_with_headers(
        address,
        client,
        "POST",
        &format!("/api/latest/uploads/{upload_id}/commits"),
        Some(&commit_body),
        &[("Authorization", authorization.as_str())],
    )
    .await?;
    require_status(&commit, "200 OK", "commit native upload")?;
    if !response_body(&commit)?.contains("\"state\":\"committed\"") {
        return Err("native upload did not return a committed file".into());
    }
    Ok(())
}

async fn assert_file_surfaces(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
    volume_id: &str,
    content: &[u8],
) -> Result<(), Box<dyn Error>> {
    let authorization = format!("Bearer {api_key}");
    let headers = [("Authorization", authorization.as_str())];
    let listing = request_with_headers(
        address,
        client,
        "GET",
        &format!("/api/latest/volumes/{volume_id}/directory-entries?limit=100"),
        None,
        &headers,
    )
    .await?;
    require_status(&listing, "200 OK", "list native directory")?;
    if !response_body(&listing)?.contains("\"name\":\"process-proof.bin\"") {
        return Err("native directory listing omitted the uploaded file".into());
    }
    let stat = request_with_headers(
        address,
        client,
        "GET",
        &format!("/api/latest/volumes/{volume_id}/objects?path=process-proof.bin"),
        None,
        &headers,
    )
    .await?;
    require_status(&stat, "200 OK", "stat native object")?;
    let expected_length = format!("\"logical_length\":{}", content.len());
    if !response_body(&stat)?.contains(&expected_length) {
        return Err("native object stat returned the wrong logical length".into());
    }
    let read = request_with_headers(
        address,
        client,
        "GET",
        &format!(
            "/api/latest/volumes/{volume_id}/file-content?path=process-proof.bin&offset=5&length=12"
        ),
        None,
        &headers,
    )
    .await?;
    require_status(&read, "200 OK", "read native file range")?;
    if response_body(&read)?.as_bytes() != &content[5..17] {
        return Err("native file range returned different bytes".into());
    }
    let download = request_with_headers(
        address,
        client,
        "GET",
        &format!(
            "/api/latest/volumes/{volume_id}/file-content?path=process-proof.bin&offset=0&length={}",
            content.len()
        ),
        None,
        &headers,
    )
    .await?;
    require_status(&download, "200 OK", "download native file")?;
    if response_body(&download)?.as_bytes() != content {
        return Err("native full-file download returned different bytes".into());
    }
    Ok(())
}

fn require_status(response: &str, expected: &str, operation: &str) -> Result<(), Box<dyn Error>> {
    if response.starts_with(&format!("HTTP/1.1 {expected}\r\n")) {
        Ok(())
    } else {
        Err(format!(
            "{operation} returned {}: {}",
            response.lines().next().unwrap_or("an invalid response"),
            response_body(response).unwrap_or("invalid response")
        )
        .into())
    }
}

async fn assert_volume_visible(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
) -> Result<(), Box<dyn Error>> {
    let authorization = format!("Bearer {api_key}");
    let response = request_with_headers(
        address,
        client,
        "GET",
        "/api/latest/volumes?limit=100",
        None,
        &[("Authorization", authorization.as_str())],
    )
    .await?;
    if response.starts_with("HTTP/1.1 200 OK\r\n")
        && response.contains("\"name\":\"Process files\"")
    {
        Ok(())
    } else {
        Err(format!(
            "headless process did not return its committed volume: {}",
            response_body(&response).unwrap_or("invalid response")
        )
        .into())
    }
}

async fn create_user(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
) -> Result<String, Box<dyn Error>> {
    let body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000003",
        "display_name": "Managed user"
    }))?;
    let authorization = format!("Bearer {api_key}");
    let response = request_with_headers(
        address,
        client,
        "POST",
        "/api/latest/admin/users",
        Some(&body),
        &[("Authorization", authorization.as_str())],
    )
    .await?;
    require_status(&response, "201 Created", "create managed user")?;
    principal_id(&response)
}

async fn create_group(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
) -> Result<String, Box<dyn Error>> {
    let body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000030",
        "display_name": "Managed group"
    }))?;
    let authorization = format!("Bearer {api_key}");
    let response = request_with_headers(
        address,
        client,
        "POST",
        "/api/latest/admin/groups",
        Some(&body),
        &[("Authorization", authorization.as_str())],
    )
    .await?;
    require_status(&response, "201 Created", "create managed group")?;
    principal_id(&response)
}

fn principal_id(response: &str) -> Result<String, Box<dyn Error>> {
    let body: serde_json::Value = serde_json::from_str(response_body(response)?)?;
    body["principal"]["principal_id"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "principal creation response omitted its identity".into())
}

async fn add_group_member(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
    group_id: &str,
    user_id: &str,
) -> Result<(), Box<dyn Error>> {
    let body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000031",
        "member_principal_id": user_id,
        "activation_required": false
    }))?;
    let authorization = format!("Bearer {api_key}");
    let response = request_with_headers(
        address,
        client,
        "POST",
        &format!("/api/latest/admin/groups/{group_id}/members"),
        Some(&body),
        &[("Authorization", authorization.as_str())],
    )
    .await?;
    require_status(&response, "201 Created", "add managed group member")
}

fn bootstrap_administrator_id(
    claim: &meshspan_domain::ClaimBundle,
    identity_path: &Path,
) -> Result<String, Box<dyn Error>> {
    let identity = LocalNodeIdentity::open(identity_path, CERTIFICATE_NAME)?;
    let node_id = InitialBootstrapMaterial::node_id(identity.public_key_fingerprint())?;
    let mut operation = [0_u8; 16];
    operation[6] = 0x40;
    operation[8] = 0x80;
    operation[15] = 1;
    let material =
        InitialBootstrapMaterial::derive(claim, OperationId::from_bytes(operation)?, node_id)?;
    Ok(uuid_text(material.administrator_id.as_bytes()))
}

fn uuid_text(bytes: [u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

async fn assert_user_visible(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
) -> Result<(), Box<dyn Error>> {
    let authorization = format!("Bearer {api_key}");
    let response = request_with_headers(
        address,
        client,
        "GET",
        "/api/latest/admin/users?limit=100",
        None,
        &[("Authorization", authorization.as_str())],
    )
    .await?;
    if response.starts_with("HTTP/1.1 200 OK\r\n") && response.contains("Managed user") {
        Ok(())
    } else {
        Err("restarted process did not return the committed user".into())
    }
}

async fn assert_group_visible(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
) -> Result<(), Box<dyn Error>> {
    let authorization = format!("Bearer {api_key}");
    let response = request_with_headers(
        address,
        client,
        "GET",
        "/api/latest/admin/groups?limit=100",
        None,
        &[("Authorization", authorization.as_str())],
    )
    .await?;
    require_status(&response, "200 OK", "list managed groups")?;
    if response_body(&response)?.contains("Managed group") {
        Ok(())
    } else {
        Err("group inventory omitted the committed group".into())
    }
}

async fn assert_group_membership(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
    group_id: &str,
    user_id: &str,
) -> Result<(), Box<dyn Error>> {
    let authorization = format!("Bearer {api_key}");
    let response = request_with_headers(
        address,
        client,
        "GET",
        &format!("/api/latest/admin/groups/{group_id}/members?limit=100"),
        None,
        &[("Authorization", authorization.as_str())],
    )
    .await?;
    require_status(&response, "200 OK", "list managed group members")?;
    if response_body(&response)?.contains(user_id) {
        Ok(())
    } else {
        Err("group-membership inventory omitted the committed user".into())
    }
}

struct BrowserSessionHeaders {
    cookie: String,
    csrf: String,
}

impl BrowserSessionHeaders {
    fn mutation_headers(&self) -> [(&str, &str); 2] {
        [
            ("Cookie", self.cookie.as_str()),
            ("MeshSpan-CSRF-Token", self.csrf.as_str()),
        ]
    }
}

async fn create_browser_session(
    address: SocketAddr,
    client: &ClientConfig,
    body: &[u8],
) -> Result<BrowserSessionHeaders, Box<dyn Error>> {
    let response = request(address, client, "POST", "/api/latest/sessions", Some(body)).await?;
    require_status(&response, "201 Created", "create browser session")?;
    browser_session_headers(&response)
}

fn browser_session_headers(response: &str) -> Result<BrowserSessionHeaders, Box<dyn Error>> {
    if response.contains("set-cookie: meshspan_session=")
        && response.contains("meshspan-csrf-token:")
    {
        let cookie = response_header(response, "set-cookie")?
            .split(';')
            .next()
            .ok_or("session cookie was empty")?
            .to_owned();
        let csrf = response_header(response, "meshspan-csrf-token")?.to_owned();
        Ok(BrowserSessionHeaders { cookie, csrf })
    } else {
        Err("headless process did not create the expected HTTPS session".into())
    }
}

fn response_header<'a>(response: &'a str, name: &str) -> Result<&'a str, Box<dyn Error>> {
    response
        .split_once("\r\n\r\n")
        .map(|(headers, _)| headers)
        .and_then(|headers| {
            headers.lines().skip(1).find_map(|line| {
                let (candidate, value) = line.split_once(':')?;
                candidate
                    .eq_ignore_ascii_case(name)
                    .then_some(value.trim_start())
            })
        })
        .ok_or_else(|| format!("HTTP response omitted the {name} header").into())
}

fn response_body(response: &str) -> Result<&str, Box<dyn Error>> {
    response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .ok_or_else(|| "HTTP response omitted its body boundary".into())
}

struct ProcessFixture {
    _temporary: TempDir,
    address: SocketAddr,
    private_address: SocketAddr,
    claim_path: PathBuf,
    identity_path: PathBuf,
    state_path: PathBuf,
    storage_path: PathBuf,
    pending_recovery_bundle_path: PathBuf,
    saved_recovery_bundle_path: PathBuf,
    saved_recovery_code_path: PathBuf,
}

impl ProcessFixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let temporary = TempDir::new()?;
        let state_path = temporary.path().join("state");
        let storage_path = temporary.path().join("storage");
        fs::create_dir(&storage_path)?;
        fs::write(storage_path.join("operator-file.txt"), b"untouched")?;
        Ok(Self {
            address: unused_address()?,
            private_address: unused_udp_address()?,
            claim_path: state_path.join("first-boot.claim"),
            identity_path: state_path.join("secrets/node-identity.pk8"),
            state_path,
            storage_path,
            pending_recovery_bundle_path: temporary
                .path()
                .join("state/secrets/pending-offline-recovery.bundle"),
            saved_recovery_bundle_path: temporary.path().join("offline-recovery.bundle"),
            saved_recovery_code_path: temporary.path().join("offline-recovery.code"),
            _temporary: temporary,
        })
    }

    fn start(&self) -> Result<Child, Box<dyn Error>> {
        self.command().spawn().map_err(Into::into)
    }

    fn start_join(&self, join_code: &str) -> Result<Child, Box<dyn Error>> {
        let mut command = self.command();
        command.arg("--join-code").arg(join_code);
        command.spawn().map_err(Into::into)
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_meshspan-daemon"));
        command
            .arg("--daemon-state-dir")
            .arg(&self.state_path)
            .arg("--storage-path")
            .arg(&self.storage_path)
            .arg("--https-listen")
            .arg(self.address.to_string())
            .arg("--private-listen")
            .arg(self.private_address.to_string())
            .arg("--private-endpoint")
            .arg(self.private_address.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }
}

async fn wait_for_storage_marker(storage_path: &Path) -> Result<Vec<u8>, Box<dyn Error>> {
    let marker_path = storage_path.join(".meshspan/target.marker");
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        match fs::read(&marker_path) {
            Ok(marker) => return Ok(marker),
            Err(_) if Instant::now() < deadline => sleep(RETRY_INTERVAL).await,
            Err(error) => return Err(error.into()),
        }
    }
}

async fn wait_for_live_provider(fixture: &ProcessFixture) -> Result<PathBuf, Box<dyn Error>> {
    let pack = fixture
        .storage_path
        .join(".meshspan/packs/0000000000000001.sqlite3");
    let journals = fixture.state_path.join("storage-targets");
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        let journal = fs::read_dir(&journals).ok().and_then(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .find(|path| {
                    path.extension()
                        .is_some_and(|extension| extension == "sqlite3")
                })
        });
        if pack.is_file()
            && let Some(journal) = journal
        {
            return Ok(journal);
        }
        if Instant::now() >= deadline {
            return Err("registered storage folder never became a live provider".into());
        }
        sleep(RETRY_INTERVAL).await;
    }
}

async fn wait_for_claim(file_path: &Path) -> Result<meshspan_domain::ClaimBundle, Box<dyn Error>> {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        match ClaimFile::read(file_path) {
            Ok(claim) => return Ok(claim),
            Err(_) if Instant::now() < deadline => sleep(RETRY_INTERVAL).await,
            Err(error) => return Err(error.into()),
        }
    }
}

async fn wait_for_client(file_path: &Path) -> Result<ClientConfig, Box<dyn Error>> {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        match LocalNodeIdentity::open(file_path, CERTIFICATE_NAME) {
            Ok(identity) => return client_config(identity.bootstrap_certificate_der()),
            Err(_) if Instant::now() < deadline => sleep(RETRY_INTERVAL).await,
            Err(error) => return Err(error.into()),
        }
    }
}

fn client_config(certificate: &[u8]) -> Result<ClientConfig, Box<dyn Error>> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(certificate.to_vec()))?;
    Ok(
        ClientConfig::builder_with_provider(Arc::new(meshspan_rustls_provider::provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

async fn wait_for_status(
    address: SocketAddr,
    client: &ClientConfig,
    expected: &str,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        let response = request(address, client, "GET", "/api/latest/setup/status", None).await;
        if response
            .as_ref()
            .is_ok_and(|response| response.contains(&format!("\"state\":\"{expected}\"")))
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("headless process did not reach the expected setup state".into());
        }
        sleep(RETRY_INTERVAL).await;
    }
}

async fn request(
    address: SocketAddr,
    client: &ClientConfig,
    method: &str,
    target: &str,
    body: Option<&[u8]>,
) -> Result<String, Box<dyn Error>> {
    request_with_headers(address, client, method, target, body, &[]).await
}

async fn request_with_headers(
    address: SocketAddr,
    client: &ClientConfig,
    method: &str,
    target: &str,
    body: Option<&[u8]>,
    additional_headers: &[(&str, &str)],
) -> Result<String, Box<dyn Error>> {
    request_with_content_type(
        address,
        client,
        method,
        target,
        body,
        "application/json",
        additional_headers,
    )
    .await
}

async fn request_with_content_type(
    address: SocketAddr,
    client: &ClientConfig,
    method: &str,
    target: &str,
    body: Option<&[u8]>,
    content_type: &str,
    additional_headers: &[(&str, &str)],
) -> Result<String, Box<dyn Error>> {
    let stream = TcpStream::connect(address).await?;
    let connector = TlsConnector::from(Arc::new(client.clone()));
    let name = ServerName::try_from(CERTIFICATE_NAME)?.to_owned();
    let mut stream = connector.connect(name, stream).await?;
    let body = body.unwrap_or_default();
    let mut headers = format!(
        "{method} {target} HTTP/1.1\r\nHost: {CERTIFICATE_NAME}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let insertion = headers
        .len()
        .checked_sub(2)
        .ok_or("HTTP header construction underflowed")?;
    for (name, value) in additional_headers.iter().rev() {
        headers.insert_str(insertion, &format!("{name}: {value}\r\n"));
    }
    stream.write_all(headers.as_bytes()).await?;
    stream.write_all(body).await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    Ok(String::from_utf8(response)?)
}

fn unused_address() -> Result<SocketAddr, std::io::Error> {
    StandardTcpListener::bind("127.0.0.1:0")?.local_addr()
}

fn unused_udp_address() -> Result<SocketAddr, std::io::Error> {
    StandardUdpSocket::bind("127.0.0.1:0")?.local_addr()
}
