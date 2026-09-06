// SPDX-License-Identifier: GPL-2.0-only

//! Real-process proof for headless startup, HTTPS setup and durable restart.

#[path = "headless_process/acme_lifecycle.rs"]
mod acme_lifecycle;
#[path = "headless_process/backup_history.rs"]
mod backup_history;
#[path = "headless_process/diagnostics.rs"]
mod diagnostics;
#[path = "headless_process/local_certificates.rs"]
mod local_certificates;
#[path = "headless_process/metrics.rs"]
mod metrics;
#[path = "support/passkey.rs"]
mod passkey_support;
#[path = "headless_process/stage10.rs"]
mod stage10;
#[path = "headless_process/stage8.rs"]
mod stage8;
#[path = "headless_process/web_panel.rs"]
mod web_panel;

use std::error::Error;
use std::fs;
use std::fs::OpenOptions;
use std::net::SocketAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use meshspan_consensus::ActiveQuorumPlan;
use meshspan_daemon::{ClaimFile, LocalNodeIdentity, LocalWrappingKey};
use meshspan_domain::{InitialBootstrapMaterial, OperationId, PartitionId, UnixMicros};
use meshspan_metadata::{
    AUTHENTICATION_ROOT_KEY_SECRET_KIND, AuthoritativeRepository, PartitionDatabase,
};
use meshspan_secret_envelope::SecretContext;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use sha1::Sha1;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::time::sleep;
use tokio_rustls::TlsConnector;

const CERTIFICATE_NAME: &str = "meshspan.local";
#[path = "headless_process/ports.rs"]
mod ports;
const WAIT_LIMIT: Duration = Duration::from_secs(15);
const RETRY_INTERVAL: Duration = Duration::from_millis(50);
const SMB_CLIENT_IMAGE: &str = "meshspan-smbclient-test:bookworm";

#[tokio::test]
#[ignore = "requires the local pinned smbclient container image"]
async fn real_smb311_clients_round_trip_one_volume_through_three_gateways()
-> Result<(), Box<dyn Error>> {
    let root = ProcessFixture::new()?;
    let second = ProcessFixture::new()?;
    let third = ProcessFixture::new()?;
    let mut processes = vec![root.start()?];
    let proof = async {
        let claim = wait_for_claim(&root.claim_path).await?;
        let client = wait_for_client(&root.identity_path).await?;
        let administrator_id = bootstrap_administrator_id(&claim, &root.identity_path)?;
        wait_for_status(root.address, &client, "claim_required").await?;
        let created = create_process_mesh(&root, &client, &claim).await?;
        let api_key = created["api_key"]
            .as_str()
            .ok_or("setup response omitted the API key")?;
        save_and_verify_recovery_bundle(&root, &client, api_key, &created).await?;
        let join_code = issue_join_code(&root, &client, api_key).await?;
        processes.push(second.start_join(&join_code)?);
        let second_client = wait_for_client(&second.identity_path).await?;
        wait_for_status(second.address, &second_client, "configured").await?;
        processes.push(third.start_join(&join_code)?);
        let third_client = wait_for_client(&third.identity_path).await?;
        wait_for_status(third.address, &third_client, "configured").await?;
        wait_for_three_voters([&root, &second, &third], &root.identity_path).await?;
        let volume =
            create_volume_details(root.address, &client, api_key, &administrator_id).await?;
        publish_smb_export(root.address, &client, api_key, &volume).await?;
        wait_for_smb_export_visibility([&root, &second, &third], &root.identity_path).await?;
        wait_for_authentication_root_access([&root, &second, &third], &root.identity_path).await?;
        for fixture in [&root, &second, &third] {
            wait_for_smb_listener(fixture.smb_address).await?;
        }
        run_cross_gateway_smb_cycle(
            [&root, &second, &third],
            [&client, &second_client, &third_client],
            api_key,
            &volume.volume_id,
        )
        .await?;
        exercise_smb_process_failures(
            [&root, &second, &third],
            &mut processes,
            api_key.to_owned(),
            &root.identity_path,
        )
        .await?;
        Ok(())
    }
    .await;
    stop_processes(&mut processes);
    proof
}

async fn run_cross_gateway_smb_cycle(
    fixtures: [&ProcessFixture; 3],
    clients: [&ClientConfig; 3],
    api_key: &str,
    volume_id: &str,
) -> Result<(), Box<dyn Error>> {
    let exchange = TempDir::new()?;
    let expected = b"exact external SMB 3.1.1 bytes";
    fs::write(exchange.path().join("upload.bin"), expected)?;
    fs::write(
        exchange.path().join("remote-source.bin"),
        b"acknowledged bytes owned by the storage process",
    )?;
    run_real_smb_command(
        fixtures[0].smb_address.port(),
        api_key.to_owned(),
        exchange.path(),
        "put /proof/upload.bin proof.bin",
    )
    .await?;
    wait_for_named_file_length(
        fixtures[1].address,
        clients[1],
        api_key,
        volume_id,
        "proof.bin",
        expected.len(),
    )
    .await
    .map_err(|error| format!("gateway two did not import proof.bin: {error}"))?;
    run_real_smb_command(
        fixtures[1].smb_address.port(),
        api_key.to_owned(),
        exchange.path(),
        "get proof.bin /proof/gateway-two.bin; rename proof.bin renamed.bin",
    )
    .await?;
    run_real_smb_command(
        fixtures[1].smb_address.port(),
        api_key.to_owned(),
        exchange.path(),
        "put /proof/remote-source.bin remote-only.bin",
    )
    .await?;
    wait_for_named_file_length(
        fixtures[1].address,
        clients[1],
        api_key,
        volume_id,
        "remote-only.bin",
        b"acknowledged bytes owned by the storage process".len(),
    )
    .await
    .map_err(|error| format!("gateway two did not retain remote-only.bin: {error}"))?;
    if fs::read(exchange.path().join("gateway-two.bin"))? != expected {
        return Err("gateway two returned different bytes".into());
    }
    wait_for_named_file_length(
        fixtures[2].address,
        clients[2],
        api_key,
        volume_id,
        "remote-only.bin",
        b"acknowledged bytes owned by the storage process".len(),
    )
    .await?;
    wait_for_named_file_length(
        fixtures[2].address,
        clients[2],
        api_key,
        volume_id,
        "renamed.bin",
        expected.len(),
    )
    .await?;
    run_real_smb_command(
        fixtures[2].smb_address.port(),
        api_key.to_owned(),
        exchange.path(),
        "get renamed.bin /proof/gateway-three.bin; del renamed.bin",
    )
    .await?;
    if fs::read(exchange.path().join("gateway-three.bin"))? != expected {
        return Err("gateway three returned different bytes".into());
    }
    wait_for_named_file_listing_state(
        fixtures[1].address,
        clients[1],
        api_key,
        volume_id,
        "renamed.bin",
        false,
    )
    .await
}

async fn exercise_smb_process_failures(
    fixtures: [&ProcessFixture; 3],
    processes: &mut [Child],
    api_key: String,
    root_identity_path: &Path,
) -> Result<(), Box<dyn Error>> {
    wait_for_root_leadership(fixtures, root_identity_path).await?;
    let exchange = TempDir::new()?;
    fs::write(
        exchange.path().join("survivor-source.bin"),
        b"exact acknowledged bytes retained by the surviving gateway",
    )?;

    let proof_directory = exchange.path().to_path_buf();
    let proof_port = fixtures[2].smb_address.port();
    let proof = tokio::task::spawn_blocking(move || {
        smb_client_process(
            proof_port,
            api_key,
            Some(&proof_directory),
            smb_resilience_client_script(),
        )
        .output()
    });
    wait_for_file(&exchange.path().join("ready-for-leader-loss")).await?;
    processes[0].kill()?;
    processes[0].wait()?;
    fs::write(exchange.path().join("leader-lost"), [])?;
    wait_for_file(&exchange.path().join("read-after-leader-loss")).await?;
    processes[1].kill()?;
    processes[1].wait()?;
    fs::write(exchange.path().join("storage-lost"), [])?;
    let proof = proof.await??;
    require_smb_client_success(&proof)?;
    Ok(())
}

async fn wait_for_named_file_length(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
    volume_id: &str,
    name: &str,
    expected_length: usize,
) -> Result<(), Box<dyn Error>> {
    let authorization = format!("Bearer {api_key}");
    let expected = format!("\"logical_length\":{expected_length}");
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        let response = request_with_headers(
            address,
            client,
            "GET",
            &format!("/api/latest/volumes/{volume_id}/objects?path={name}"),
            None,
            &[("Authorization", authorization.as_str())],
        )
        .await?;
        if response.starts_with("HTTP/1.1 200 OK\r\n")
            && response_body(&response)?.contains(&expected)
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "expected {name} length {expected_length} did not converge at {address}: {}",
                response_body(&response).unwrap_or("invalid response")
            )
            .into());
        }
        sleep(RETRY_INTERVAL).await;
    }
}

async fn wait_for_named_file_listing_state(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
    volume_id: &str,
    name: &str,
    expected_presence: bool,
) -> Result<(), Box<dyn Error>> {
    let authorization = format!("Bearer {api_key}");
    let expected = format!("\"name\":\"{name}\"");
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        let response = request_with_headers(
            address,
            client,
            "GET",
            &format!("/api/latest/volumes/{volume_id}/directory-entries?limit=100"),
            None,
            &[("Authorization", authorization.as_str())],
        )
        .await?;
        if response.starts_with("HTTP/1.1 200 OK\r\n") {
            let present = response_body(&response)?.contains(&expected);
            if present == expected_presence {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "expected presence {expected_presence} for {name} did not converge at {address}"
            )
            .into());
        }
        sleep(RETRY_INTERVAL).await;
    }
}

async fn wait_for_root_leadership(
    fixtures: [&ProcessFixture; 3],
    root_identity_path: &Path,
) -> Result<(), Box<dyn Error>> {
    let identity = LocalNodeIdentity::open(root_identity_path, CERTIFICATE_NAME)?;
    let root_node = InitialBootstrapMaterial::node_id(identity.public_key_fingerprint())?;
    let partition_id = InitialBootstrapMaterial::root_partition_id(root_node)?;
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        let observed_votes = fixtures
            .iter()
            .map(|fixture| {
                durable_vote(&fixture.state_path, partition_id).map_err(|error| error.to_string())
            })
            .collect::<Vec<_>>();
        let root_term = observed_votes
            .first()
            .and_then(|vote| vote.as_ref().ok())
            .filter(|(_, vote)| *vote == Some(root_node))
            .map(|(term, _)| *term);
        let root_is_only_candidate = root_term.is_some_and(|root_term| {
            observed_votes.iter().all(|vote| {
                vote.as_ref().is_ok_and(|(term, candidate)| {
                    *term == root_term && candidate.is_none_or(|candidate| candidate == root_node)
                })
            })
        });
        if root_is_only_candidate {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "initial metadata leader lacked a durable vote majority: {observed_votes:?}"
            )
            .into());
        }
        sleep(RETRY_INTERVAL).await;
    }
}

fn durable_vote(
    state_path: &Path,
    partition_id: PartitionId,
) -> Result<(u64, Option<meshspan_domain::NodeId>), Box<dyn Error>> {
    let database = PartitionDatabase::open(
        &state_path.join("root-authority.sqlite3"),
        partition_id,
        UnixMicros::new(1),
    )?;
    let repository = AuthoritativeRepository::new(database);
    let plan = repository
        .load_active_consensus_quorum_plan()?
        .ok_or("active quorum plan missing")?;
    let state = repository.load_consensus_state(plan.membership_epoch())?;
    Ok((state.current_term, state.voted_for))
}

async fn wait_for_file(path: &Path) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        if path.is_file() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("SMB failure proof did not create {}", path.display()).into());
        }
        sleep(RETRY_INTERVAL).await;
    }
}

async fn wait_for_authentication_root_access(
    fixtures: [&ProcessFixture; 3],
    root_identity_path: &Path,
) -> Result<(), Box<dyn Error>> {
    let root_identity = LocalNodeIdentity::open(root_identity_path, CERTIFICATE_NAME)?;
    let root_node = InitialBootstrapMaterial::node_id(root_identity.public_key_fingerprint())?;
    let partition_id = InitialBootstrapMaterial::root_partition_id(root_node)?;
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        let all_accessible = fixtures
            .iter()
            .all(|fixture| has_authentication_root_access(fixture, partition_id).unwrap_or(false));
        if all_accessible {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("authentication root did not become accessible to every gateway".into());
        }
        sleep(RETRY_INTERVAL).await;
    }
}

fn has_authentication_root_access(
    fixture: &ProcessFixture,
    partition_id: PartitionId,
) -> Result<bool, Box<dyn Error>> {
    let database = PartitionDatabase::open(
        &fixture.state_path.join("root-authority.sqlite3"),
        partition_id,
        UnixMicros::new(1),
    )?;
    let repository = AuthoritativeRepository::new(database);
    let Some(mesh_id) = repository.local_mesh_id()? else {
        return Ok(false);
    };
    let Some(generation) = repository.latest_authentication_root_generation(mesh_id)? else {
        return Ok(false);
    };
    let context = SecretContext::new(
        AUTHENTICATION_ROOT_KEY_SECRET_KIND,
        mesh_id.as_bytes(),
        generation,
    )?;
    let Some(record) = repository.secret_generation(context)? else {
        return Ok(false);
    };
    let wrapping_key =
        LocalWrappingKey::open(&fixture.state_path.join("secrets/node-wrapping-key.x25519"))?;
    let public_key = wrapping_key.public_key();
    let Some(recipient) = record
        .recipients
        .iter()
        .find(|recipient| recipient.recipient_public_key().ok() == Some(public_key))
    else {
        return Ok(false);
    };
    Ok(wrapping_key
        .decrypt_secret(&record.secret, recipient)
        .is_ok())
}

async fn wait_for_smb_export_visibility(
    fixtures: [&ProcessFixture; 3],
    root_identity_path: &Path,
) -> Result<(), Box<dyn Error>> {
    let root_identity = LocalNodeIdentity::open(root_identity_path, CERTIFICATE_NAME)?;
    let root_node = InitialBootstrapMaterial::node_id(root_identity.public_key_fingerprint())?;
    let partition_id = InitialBootstrapMaterial::root_partition_id(root_node)?;
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        let all_visible = fixtures.iter().all(|fixture| {
            has_smb_export(&fixture.state_path, &fixture.identity_path, partition_id)
                .unwrap_or(false)
        });
        if all_visible {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("published SMB export did not converge to every gateway".into());
        }
        sleep(RETRY_INTERVAL).await;
    }
}

fn has_smb_export(
    state_path: &Path,
    identity_path: &Path,
    partition_id: PartitionId,
) -> Result<bool, Box<dyn Error>> {
    let identity = LocalNodeIdentity::open(identity_path, CERTIFICATE_NAME)?;
    let node_id = InitialBootstrapMaterial::node_id(identity.public_key_fingerprint())?;
    let database = PartitionDatabase::open(
        &state_path.join("root-authority.sqlite3"),
        partition_id,
        UnixMicros::new(1),
    )?;
    let exports = AuthoritativeRepository::new(database).smb_exports_for_gateway(node_id)?;
    Ok(exports
        .iter()
        .any(|export| export.display_name == "process-files"))
}

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
        let elected_candidate =
            wait_for_survivor_vote_convergence([&second, &third], &root.identity_path).await?;
        let second_node = fixture_node_id(&second)?;
        let (write_address, write_client, visibility_address, visibility_client) =
            if elected_candidate == second_node {
                (third.address, &third_client, second.address, &second_client)
            } else {
                (second.address, &second_client, third.address, &third_client)
            };
        let user_id = wait_for_user_creation(
            write_address,
            write_client,
            api_key,
            [&second, &third],
            &root.identity_path,
        )
        .await?;
        wait_for_user_visibility(visibility_address, visibility_client, api_key).await?;
        add_group_member(third.address, &third_client, api_key, &group_id, &user_id).await?;
        wait_for_group_membership(second.address, &second_client, api_key, &group_id, &user_id)
            .await?;
        let volume_id =
            create_volume(second.address, &second_client, api_key, &administrator_id).await?;
        wait_for_volume_visibility(third.address, &third_client, api_key).await?;
        create_volume_permission_grant(
            third.address,
            &third_client,
            api_key,
            &volume_id,
            &group_id,
        )
        .await?;
        wait_for_permission_visibility(
            second.address,
            &second_client,
            api_key,
            &volume_id,
            &group_id,
        )
        .await?;
        let content = b"survivor gateway exact native bytes";
        upload_file(second.address, &second_client, api_key, &volume_id, content).await?;
        wait_for_file_surfaces(third.address, &third_client, api_key, &volume_id, content).await
    }
    .await;
    let proof = proof.map_err(|error| -> Box<dyn Error> {
        let observations = processes.iter_mut()
            .map(|process| (process.id(), process.try_wait()))
            .collect::<Vec<_>>();
        format!("{error}; root/second/third HTTPS: {:?}; child exit states before cleanup: {observations:?}",
            [root.address, second.address, third.address]).into()
    });
    stop_processes(&mut processes);
    retain_failure_state(proof, [root.temporary, second.temporary, third.temporary])
}

async fn wait_for_survivor_vote_convergence(
    survivors: [&ProcessFixture; 2],
    root_identity_path: &Path,
) -> Result<meshspan_domain::NodeId, Box<dyn Error>> {
    let root_identity = LocalNodeIdentity::open(root_identity_path, CERTIFICATE_NAME)?;
    let root_node = InitialBootstrapMaterial::node_id(root_identity.public_key_fingerprint())?;
    let partition_id = InitialBootstrapMaterial::root_partition_id(root_node)?;
    let survivor_ids = survivors
        .map(fixture_node_id)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        let votes = survivors
            .map(|fixture| durable_vote(&fixture.state_path, partition_id))
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
        if let [(left_term, Some(left)), (right_term, Some(right))] = votes.as_slice()
            && left_term == right_term
            && left == right
            && survivor_ids.contains(left)
        {
            return Ok(*left);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "survivors did not converge on one surviving candidate; votes: {votes:?}"
            )
            .into());
        }
        sleep(RETRY_INTERVAL).await;
    }
}

fn fixture_node_id(fixture: &ProcessFixture) -> Result<meshspan_domain::NodeId, Box<dyn Error>> {
    let identity = LocalNodeIdentity::open(&fixture.identity_path, CERTIFICATE_NAME)?;
    InitialBootstrapMaterial::node_id(identity.public_key_fingerprint()).map_err(Into::into)
}

#[tokio::test]
async fn clean_machine_operator_flow_uses_only_cli_and_public_https() -> Result<(), Box<dyn Error>>
{
    let root = ProcessFixture::new()?;
    let peer = ProcessFixture::new()?;
    let mut processes = Vec::new();
    let proof = async {
        // This working directory has no application sources or compiled web assets.
        processes.push(root.command().current_dir(root.temporary.path()).spawn()?);
        let claim = wait_for_claim(&root.claim_path).await?;
        let root_client = wait_for_client(&root.identity_path).await?;
        wait_for_status(root.address, &root_client, "claim_required").await?;
        web_panel::verify(root.address, &root_client).await?;
        let administrator_id = bootstrap_administrator_id(&claim, &root.identity_path)?;
        let created = create_process_mesh(&root, &root_client, &claim).await?;
        let api_key = created["api_key"]
            .as_str()
            .ok_or("setup response omitted the API key")?;
        save_and_verify_recovery_bundle(&root, &root_client, api_key, &created).await?;

        let join_code = issue_join_code(&root, &root_client, api_key).await?;
        processes.push(peer.start_join(&join_code)?);
        let peer_client = wait_for_client(&peer.identity_path).await?;
        wait_for_status(peer.address, &peer_client, "configured").await?;
        web_panel::verify(peer.address, &peer_client).await?;
        wait_for_storage_folder_visibility(&root, &root_client, api_key).await?;
        wait_for_storage_folder_visibility(&peer, &peer_client, api_key).await?;
        stage10::backup_destination_controls(root.address, &root_client, api_key).await?;
        register_storage_folder(
            root.address,
            &root_client,
            api_key,
            &root.additional_storage_path,
        )
        .await?;

        let group_id = create_group(root.address, &root_client, api_key).await?;
        let user_id = create_user(root.address, &root_client, api_key).await?;
        add_group_member(root.address, &root_client, api_key, &group_id, &user_id).await?;
        let volume_id =
            create_volume(root.address, &root_client, api_key, &administrator_id).await?;
        create_volume_permission_grant(root.address, &root_client, api_key, &volume_id, &group_id)
            .await?;

        let content = b"clean machine native HTTPS round trip";
        upload_file(root.address, &root_client, api_key, &volume_id, content).await?;
        wait_for_file_surfaces(peer.address, &peer_client, api_key, &volume_id, content).await?;
        diagnostics::verify(root.address, &root_client, api_key).await?;
        diagnostics::verify(peer.address, &peer_client, api_key).await?;
        processes[0].kill()?;
        processes[0].wait()?;
        assert_file_surfaces(peer.address, &peer_client, api_key, &volume_id, content).await?;
        diagnostics::verify(peer.address, &peer_client, api_key).await
    }
    .await;
    let proof = proof.map_err(|error| -> Box<dyn Error> {
        let observations = processes
            .iter_mut()
            .map(|process| (process.id(), process.try_wait()))
            .collect::<Vec<_>>();
        format!("{error}; child exit states before cleanup: {observations:?}").into()
    });
    stop_processes(&mut processes);
    retain_failure_state(proof, [root.temporary, peer.temporary])
}

// Private test-only state is retained on failure for diagnosis, never copied into the repository
// or release artefacts. Successful cases still remove every owned temporary directory.
fn retain_failure_state<const N: usize>(
    result: Result<(), Box<dyn Error>>,
    directories: [TempDir; N],
) -> Result<(), Box<dyn Error>> {
    result.map_err(|error| {
        let retained = directories.map(TempDir::keep);
        format!("{error}; private test fixture state retained at {retained:?}").into()
    })
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
    survivors: [&ProcessFixture; 2],
    root_identity_path: &Path,
) -> Result<String, Box<dyn Error>> {
    let root_identity = LocalNodeIdentity::open(root_identity_path, CERTIFICATE_NAME)?;
    let root_node = InitialBootstrapMaterial::node_id(root_identity.public_key_fingerprint())?;
    let partition_id = InitialBootstrapMaterial::root_partition_id(root_node)?;
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        let error = match create_user(address, client, api_key).await {
            Ok(principal_id) => return Ok(principal_id),
            Err(error) => error,
        };
        if Instant::now() >= deadline {
            let durable_states = survivors.map(|fixture| {
                durable_state_summary(fixture, partition_id)
                    .unwrap_or_else(|error| error.to_string())
            });
            return Err(format!(
                "surviving daemon never accepted a committed metadata write; durable states: {durable_states:?}; last response: {error}"
            )
            .into());
        }
        sleep(RETRY_INTERVAL).await;
    }
}

fn durable_state_summary(
    fixture: &ProcessFixture,
    partition_id: PartitionId,
) -> Result<String, Box<dyn Error>> {
    let identity = LocalNodeIdentity::open(&fixture.identity_path, CERTIFICATE_NAME)?;
    let node_id = InitialBootstrapMaterial::node_id(identity.public_key_fingerprint())?;
    let database = PartitionDatabase::open(
        &fixture.state_path.join("root-authority.sqlite3"),
        partition_id,
        UnixMicros::new(1),
    )?;
    let repository = AuthoritativeRepository::new(database);
    let plan = repository
        .load_active_consensus_quorum_plan()?
        .ok_or("active quorum plan missing")?;
    let state = repository.load_consensus_state(plan.membership_epoch())?;
    let operation_id =
        OperationId::from_bytes([0, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 3])?;
    let operation_committed = repository.resolve_operation(operation_id)?.is_some();
    Ok(format!(
        "node={node_id:?}, term={}, voted_for={:?}, log_length={}, last_log={:?}, applied_index={}, operation_committed={operation_committed}",
        state.current_term,
        state.voted_for,
        state.log.len(),
        state.log.last().map(|entry| entry.position),
        state.applied_index,
    ))
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

async fn wait_for_volume_visibility(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        if assert_volume_visible(address, client, api_key)
            .await
            .is_ok()
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("committed volume never became visible on the peer gateway".into());
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

async fn wait_for_permission_visibility(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
    volume_id: &str,
    group_id: &str,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        if assert_permission_visible(address, client, api_key, volume_id, group_id)
            .await
            .is_ok()
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("committed cross-gateway permission never became visible".into());
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
                "native survivor bytes never became readable through the peer gateway: {error}"
            )
            .into());
        }
        sleep(RETRY_INTERVAL).await;
    }
}

async fn wait_for_storage_folder_visibility(
    fixture: &ProcessFixture,
    client: &ClientConfig,
    api_key: &str,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        let error = match assert_storage_folder_visible(fixture, client, api_key).await {
            Ok(()) => return Ok(()),
            Err(error) => error,
        };
        if Instant::now() >= deadline {
            return Err(format!(
                "CLI storage-folder registration never became visible over HTTPS at {}: {}",
                fixture.address, error
            )
            .into());
        }
        sleep(RETRY_INTERVAL).await;
    }
}

async fn assert_storage_folder_visible(
    fixture: &ProcessFixture,
    client: &ClientConfig,
    api_key: &str,
) -> Result<(), Box<dyn Error>> {
    let authorization = format!("Bearer {api_key}");
    let response = request_with_headers(
        fixture.address,
        client,
        "GET",
        "/api/latest/admin/storage-folders?limit=100",
        None,
        &[("Authorization", authorization.as_str())],
    )
    .await?;
    require_status(&response, "200 OK", "list CLI-registered storage folder")?;
    let payload: serde_json::Value = serde_json::from_str(response_body(&response)?)?;
    // Registration reports the canonical folder: macOS commonly supplies /var in TMPDIR
    // although the same directory is reached through /private/var after canonicalisation.
    let canonical_storage_path = fs::canonicalize(&fixture.storage_path)?;
    let expected_path = canonical_storage_path
        .to_str()
        .ok_or("temporary storage path was not UTF-8")?;
    let visible = payload["folders"].as_array().is_some_and(|folders| {
        folders.iter().any(|folder| {
            folder["path"].as_str() == Some(expected_path)
                && folder["state"].as_str() == Some("active")
        })
    });
    visible.then_some(()).ok_or_else(|| {
        format!(
            "public storage-folder inventory omitted active path {expected_path}; returned {}",
            payload["folders"]
        )
        .into()
    })
}

async fn register_storage_folder(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
    folder_path: &Path,
) -> Result<(), Box<dyn Error>> {
    let path = folder_path
        .to_str()
        .ok_or("additional storage path was not UTF-8")?;
    let body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000033",
        "path": path,
        "usage_limit": { "kind": "percent", "percent": 90 }
    }))?;
    let authorization = format!("Bearer {api_key}");
    let response = request_with_headers(
        address,
        client,
        "POST",
        "/api/latest/admin/storage-folders",
        Some(&body),
        &[("Authorization", authorization.as_str())],
    )
    .await?;
    require_status(
        &response,
        "201 Created",
        "register storage folder over HTTPS",
    )?;
    let payload: serde_json::Value = serde_json::from_str(response_body(&response)?)?;
    let canonical_folder_path = fs::canonicalize(folder_path)?;
    if payload["folder"]["path"].as_str().map(Path::new) == Some(canonical_folder_path.as_path())
        && payload["folder"]["state"].as_str() == Some("active")
    {
        Ok(())
    } else {
        Err("storage-folder registration returned the wrong active path".into())
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
    assign_single_node_strong_acknowledgement(fixture.address, &client, api_key, &volume_id)
        .await?;
    assert_volume_visible(fixture.address, &client, api_key).await?;
    let content = b"headless native file bytes";
    let committed = upload_file(fixture.address, &client, api_key, &volume_id, content).await?;
    if committed["acknowledgement"]["configured_consistency"] != "strong"
        || committed["acknowledgement"]["acknowledged_consistency"] != "strong"
        || committed["acknowledgement"]["durability_scope"] != "globally_converged"
        || committed["acknowledgement"]["policy_committed"] != true
    {
        return Err("strong upload returned no globally converged acknowledgement".into());
    }
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
    Ok(
        create_volume_details(address, client, api_key, owner_principal_id)
            .await?
            .volume_id,
    )
}

struct CreatedVolume {
    root_object_id: String,
    volume_id: String,
}

async fn create_volume_details(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
    owner_principal_id: &str,
) -> Result<CreatedVolume, Box<dyn Error>> {
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
        let volume_id = created["volume_id"]
            .as_str()
            .map(str::to_owned)
            .ok_or("headless volume creation omitted its identity")?;
        let root_object_id = created["root_object_id"]
            .as_str()
            .map(str::to_owned)
            .ok_or("headless volume creation omitted its root identity")?;
        Ok(CreatedVolume {
            root_object_id,
            volume_id,
        })
    }
}

async fn publish_smb_export(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
    volume: &CreatedVolume,
) -> Result<(), Box<dyn Error>> {
    let body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000040",
        "root_object_id": volume.root_object_id,
        "share_name": "process-files",
        "gateways": { "kind": "all_eligible" },
        "encryption_required": true
    }))?;
    let authorization = format!("Bearer {api_key}");
    let response = request_with_headers(
        address,
        client,
        "POST",
        &format!("/api/latest/admin/volumes/{}/smb-exports", volume.volume_id),
        Some(&body),
        &[("Authorization", authorization.as_str())],
    )
    .await?;
    require_status(&response, "201 Created", "publish SMB export")
}

async fn wait_for_smb_listener(address: SocketAddr) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        if TcpStream::connect(address).await.is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("embedded SMB listener did not accept TCP connections".into());
        }
        sleep(RETRY_INTERVAL).await;
    }
}

async fn run_real_smb_command(
    port: u16,
    api_key: String,
    exchange: &Path,
    smb_command: &str,
) -> Result<(), Box<dyn Error>> {
    let exchange = exchange.to_path_buf();
    let smb_command = smb_command.to_owned();
    let output = tokio::task::spawn_blocking(move || {
        let mut process =
            smb_client_process(port, api_key, Some(&exchange), real_smb_command_script());
        process.env("MESHSPAN_SMB_COMMAND", smb_command).output()
    })
    .await??;
    require_smb_client_success(&output)
}

fn smb_client_process(
    port: u16,
    api_key: String,
    exchange: Option<&Path>,
    script: &str,
) -> Command {
    let mut process = Command::new("docker");
    process.args([
        "run",
        "--rm",
        "--entrypoint",
        "/bin/sh",
        "--env",
        "MESHSPAN_SMB_PASSWORD",
        "--env",
        "MESHSPAN_SMB_COMMAND",
    ]);
    if let Some(exchange) = exchange {
        process
            .arg("--volume")
            .arg(format!("{}:/proof", exchange.as_os_str().to_string_lossy()));
    }
    process
        .arg(SMB_CLIENT_IMAGE)
        .args(["-ec", script, "smb-proof", &port.to_string()])
        .env("MESHSPAN_SMB_PASSWORD", api_key)
        .env("MESHSPAN_SMB_COMMAND", "");
    process
}

fn require_smb_client_success(output: &std::process::Output) -> Result<(), Box<dyn Error>> {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if output.status.success() && !stdout.contains("NT_STATUS_") && !stderr.contains("NT_STATUS_") {
        return Ok(());
    }
    Err(format!("real SMB 3.1.1 client failed; stdout: {stdout}; stderr: {stderr}").into())
}

const fn real_smb_command_script() -> &'static str {
    r#"
set -eu
port="$1"
printf 'username = Administrator\npassword = %s\n' "$MESHSPAN_SMB_PASSWORD" > /tmp/credentials
chmod 600 /tmp/credentials
smbclient '//host.docker.internal/process-files' \
  --port "$port" \
  --max-protocol SMB3 \
  --option 'client min protocol=SMB3_11' \
  --option 'client max protocol=SMB3_11' \
  --client-protection encrypt \
  --authentication-file /tmp/credentials \
  --command "$MESHSPAN_SMB_COMMAND"
"#
}

const fn smb_resilience_client_script() -> &'static str {
    r#"
set -eu
port="$1"
printf 'username = Administrator\npassword = %s\n' "$MESHSPAN_SMB_PASSWORD" > /tmp/credentials
chmod 600 /tmp/credentials
smb() {
  smbclient '//host.docker.internal/process-files' \
    --port "$port" \
    --max-protocol SMB3 \
    --option 'client min protocol=SMB3_11' \
    --option 'client max protocol=SMB3_11' \
    --client-protection encrypt \
    --authentication-file /tmp/credentials \
    --command "$1"
}
smb 'put /proof/survivor-source.bin survivor.bin'
touch /proof/ready-for-leader-loss
while test ! -f /proof/leader-lost; do sleep 0.05; done
smb 'get survivor.bin /proof/after-leader.bin'
cmp /proof/survivor-source.bin /proof/after-leader.bin
touch /proof/read-after-leader-loss
while test ! -f /proof/storage-lost; do sleep 0.05; done
smb 'get survivor.bin /proof/after-storage.bin'
cmp /proof/survivor-source.bin /proof/after-storage.bin
"#
}

async fn create_volume_permission_grant(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
    volume_id: &str,
    group_id: &str,
) -> Result<(), Box<dyn Error>> {
    let body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000032",
        "subject_principal_id": group_id,
        "rights": [
            "traverse",
            "list",
            "read_data",
            "create_child",
            "write_data",
            "read_attributes"
        ],
        "inheritance": "object_and_descendants",
        "valid_from_epoch_micros": null,
        "valid_until_epoch_micros": null,
        "activation": null
    }))?;
    let authorization = format!("Bearer {api_key}");
    let response = request_with_headers(
        address,
        client,
        "POST",
        &format!("/api/latest/admin/volumes/{volume_id}/permission-grants"),
        Some(&body),
        &[("Authorization", authorization.as_str())],
    )
    .await?;
    require_status(&response, "201 Created", "grant group volume access")?;
    if !response_body(&response)?.contains(group_id) {
        return Err("volume permission creation returned the wrong subject".into());
    }
    Ok(())
}

async fn assert_permission_visible(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
    volume_id: &str,
    group_id: &str,
) -> Result<(), Box<dyn Error>> {
    let authorization = format!("Bearer {api_key}");
    let response = request_with_headers(
        address,
        client,
        "GET",
        &format!("/api/latest/admin/volumes/{volume_id}/permission-grants?limit=100"),
        None,
        &[("Authorization", authorization.as_str())],
    )
    .await?;
    require_status(&response, "200 OK", "list committed volume permissions")?;
    if response_body(&response)?.contains(group_id) {
        Ok(())
    } else {
        Err("volume permission inventory omitted the group grant".into())
    }
}

async fn upload_file(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
    volume_id: &str,
    content: &[u8],
) -> Result<serde_json::Value, Box<dyn Error>> {
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
    let committed: serde_json::Value = serde_json::from_str(response_body(&commit)?)?;
    if committed["upload"]["state"] != "committed" {
        return Err("native upload did not return a committed file".into());
    }
    Ok(committed)
}

async fn assign_single_node_strong_acknowledgement(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
    volume_id: &str,
) -> Result<(), Box<dyn Error>> {
    let authorization = format!("Bearer {api_key}");
    let create_body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000060",
        "name": "Single node strong proof",
        "consistency": "strong",
        "minimum_durable_targets": 1,
        "minimum_distinct_nodes": 1,
        "strong_wait_micros": 5_000_000,
        "fallback": "remain_pending",
        "required_scenario_ids": [],
        "cells": []
    }))?;
    let created = request_with_headers(
        address,
        client,
        "POST",
        "/api/latest/admin/acknowledgement-policies",
        Some(&create_body),
        &[("Authorization", authorization.as_str())],
    )
    .await?;
    require_status(
        &created,
        "201 Created",
        "create strong acknowledgement policy",
    )?;
    let created: serde_json::Value = serde_json::from_str(response_body(&created)?)?;
    let policy_id = created["policy"]["policy_id"]
        .as_str()
        .ok_or("strong acknowledgement policy omitted its identity")?;
    let assign_body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000061"
    }))?;
    let assigned = request_with_headers(
        address,
        client,
        "PUT",
        &format!("/api/latest/admin/volumes/{volume_id}/acknowledgement-policies/{policy_id}"),
        Some(&assign_body),
        &[("Authorization", authorization.as_str())],
    )
    .await?;
    require_status(&assigned, "200 OK", "assign strong acknowledgement policy")?;
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
    temporary: TempDir,
    address: SocketAddr,
    http01_address: SocketAddr,
    smb_address: SocketAddr,
    private_address: SocketAddr,
    claim_path: PathBuf,
    identity_path: PathBuf,
    state_path: PathBuf,
    storage_path: PathBuf,
    additional_storage_path: PathBuf,
    pending_recovery_bundle_path: PathBuf,
    saved_recovery_bundle_path: PathBuf,
    saved_recovery_code_path: PathBuf,
}

impl ProcessFixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let temporary = TempDir::new()?;
        let state_path = temporary.path().join("state");
        let storage_path = temporary.path().join("storage");
        let additional_storage_path = temporary.path().join("additional-storage");
        fs::create_dir(&storage_path)?;
        fs::create_dir(&additional_storage_path)?;
        fs::write(storage_path.join("operator-file.txt"), b"untouched")?;
        Ok(Self {
            address: unused_address()?,
            http01_address: unused_address()?,
            smb_address: unused_address()?,
            private_address: unused_udp_address()?,
            claim_path: state_path.join("first-boot.claim"),
            identity_path: state_path.join("secrets/node-identity.pk8"),
            state_path,
            storage_path,
            additional_storage_path,
            pending_recovery_bundle_path: temporary
                .path()
                .join("state/secrets/pending-offline-recovery.bundle"),
            saved_recovery_bundle_path: temporary.path().join("offline-recovery.bundle"),
            saved_recovery_code_path: temporary.path().join("offline-recovery.code"),
            temporary,
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
            .arg("--http01-listen")
            .arg(self.http01_address.to_string())
            .arg("--smb-listen")
            .arg(self.smb_address.to_string())
            .arg("--private-listen")
            .arg(self.private_address.to_string())
            .arg("--private-endpoint")
            .arg(self.private_address.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            // The executable reports its terminal error on stderr. Keep it visible so a
            // refused connection is not mistaken for a slow startup. Claim output stays hidden.
            .stderr(Stdio::inherit());
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
        let last_observation = match response {
            Ok(response) => {
                if response.contains(&format!("\"state\":\"{expected}\"")) {
                    return Ok(());
                }
                response
                    .split_once("\r\n\r\n")
                    .map_or(response.as_str(), |(_, body)| body)
                    .chars()
                    .take(512)
                    .collect()
            }
            Err(error) => error.to_string(),
        };
        if Instant::now() >= deadline {
            return Err(format!(
                "headless process at {address} did not reach setup state {expected:?}; last observation: {last_observation}"
            )
            .into());
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
    .map_err(|error| format!("native HTTPS {method} {target}: {error}").into())
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
    ports::tcp()
}

fn unused_udp_address() -> Result<SocketAddr, std::io::Error> {
    ports::udp()
}
