// SPDX-License-Identifier: GPL-2.0-only

//! Automatic self-exec and cold-launch recovery with explicit interruption consent.
//! No private command or metadata edit drives preparation, admission or completion.

use super::super as fixture;
use super::{Error, ProcessFixture, UpdateApi, candidate_artifact, pin};
use meshspan_certificates::NodeIdentityKey;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::fmt::Write as _;

#[tokio::test]
async fn selected_update_automatically_replaces_two_processes_and_cold_launcher_retains_installation()
-> Result<(), Box<dyn Error>> {
    let root = ProcessFixture::new()?;
    let peer = ProcessFixture::new()?;
    let executable = std::fs::read(root.command().get_program())?;
    let mut digest = String::new();
    for byte in Sha256::digest(&executable) {
        write!(&mut digest, "{byte:02x}")?;
    }
    let mut processes = vec![root.start()?];
    let proof = async {
        let claim = fixture::wait_for_claim(&root.claim_path).await?;
        let client = fixture::wait_for_client(&root.identity_path).await?;
        fixture::wait_for_status(root.address, &client, "claim_required").await?;
        let created = fixture::create_process_mesh(&root, &client, &claim).await?;
        let key = created["api_key"].as_str().ok_or("bootstrap key absent")?;
        fixture::save_and_verify_recovery_bundle(&root, &client, key, &created).await?;
        processes.push(peer.start_join(&fixture::issue_join_code(&root, &client, key).await?)?);
        let peer_client = fixture::wait_for_client(&peer.identity_path).await?;
        fixture::wait_for_status(peer.address, &peer_client, "configured").await?;
        let api = UpdateApi {
            root: &root,
            client: &client,
            key,
        };
        let signer = NodeIdentityKey::generate()?;
        api.manage(&pin(&signer), "200 OK").await?;
        let mut candidate = candidate_artifact(&root, &signer, executable.len(), &digest)?;
        candidate["action"]["allow_service_interruption"] = json!(true);
        // Prepare real untrusted cache bytes before selecting the candidate. The daemon must
        // still authenticate/hash/probe them, advertise each source and commit staging itself.
        // Upload and distribution are separate proofs, not this process-replacement fixture.
        cache_candidate(&root, &executable, &digest)?;
        cache_candidate(&peer, &executable, &digest)?;
        api.manage(&candidate, "200 OK").await?;
        let completed = match wait_for_verified(&api, &[&root, &peer]).await {
            Ok(completed) => completed,
            Err(error) => return Err(format!(
                "{error}; root image: {:?}; peer image: {:?}; root readiness: {:?}; peer readiness: {:?}",
                assert_process_image(processes[0].id(), &root, &digest),
                assert_process_image(processes[1].id(), &peer, &digest),
                observe_readiness(&peer, &root).await,
                observe_readiness(&root, &peer).await,
            ).into()),
        };
        assert_installation(&root, &digest)?;
        assert_process_image(processes[0].id(), &root, &digest)?;
        assert_eq!(completed["rollout"]["state"], "completed");
        assert_eq!(completed["rollout"]["progress"]["unresolved_restarts"], "0");
        assert_installation(&peer, &digest)?;
        assert_peer_witness(&peer, &root)?;
        assert_process_image(processes[1].id(), &peer, &digest)?;
        // Start the ORIGINAL command after power-loss simulation, not the selected cache path.
        processes[0].kill()?;
        processes[0].wait()?;
        processes[0] = root.start()?;
        // Cold launch reauthenticates the retained full executable before binding services.
        fixture::wait_for_status_with_limit(root.address, &client, "configured", super::ARTIFACT_OPERATION_WAIT).await?;
        assert_eq!(api.status(true).await?["rollout"], completed["rollout"]);
        assert_installation(&root, &digest)?;
        assert_process_image(processes[0].id(), &root, &digest)?;
        Ok::<_, Box<dyn Error>>(())
    }
    .await;
    fixture::stop_processes(&mut processes);
    fixture::retain_failure_state(proof, [root.temporary, peer.temporary])
}

#[tokio::test]
async fn uninterrupted_update_prepares_and_keeps_the_only_file_copy_online()
-> Result<(), Box<dyn Error>> {
    let root = ProcessFixture::new()?;
    let executable = std::fs::read(root.command().get_program())?;
    let mut digest = String::new();
    for byte in Sha256::digest(&executable) {
        write!(&mut digest, "{byte:02x}")?;
    }
    let mut processes = vec![root.start()?];
    let proof = async {
        let claim = fixture::wait_for_claim(&root.claim_path).await?;
        let client = fixture::wait_for_client(&root.identity_path).await?;
        fixture::wait_for_status(root.address, &client, "claim_required").await?;
        let administrator = fixture::bootstrap_administrator_id(&claim, &root.identity_path)?;
        let created = fixture::create_process_mesh(&root, &client, &claim).await?;
        let key = created["api_key"].as_str().ok_or("bootstrap key absent")?;
        fixture::save_and_verify_recovery_bundle(&root, &client, key, &created).await?;
        fixture::wait_for_storage_folder_visibility(&root, &client, key).await?;
        let volume = fixture::create_volume(root.address, &client, key, &administrator).await?;
        fixture::upload_file(root.address, &client, key, &volume, b"only surviving copy").await?;
        let api = UpdateApi {
            root: &root,
            client: &client,
            key,
        };
        let signer = NodeIdentityKey::generate()?;
        api.manage(&pin(&signer), "200 OK").await?;
        cache_candidate(&root, &executable, &digest)?;
        let candidate = candidate_artifact(&root, &signer, executable.len(), &digest)?;
        assert_eq!(candidate["action"]["allow_service_interruption"], false);
        api.manage(&candidate, "200 OK").await?;
        let observed = wait_for_workload(&root, "local_content_unavailable", 1).await?;
        assert_eq!(observed["scope"], "local_committed_content_catalogue");
        assert_eq!(observed["restart_authorised"], false);
        assert_eq!(observed["stripes_checked"], 0);
        assert_eq!(observed["current_volume_id"], volume);
        assert_eq!(observed["excluded_targets"], 1);
        assert!(
            observed["preparation_log_index"]
                .as_u64()
                .is_some_and(|value| value > 0)
        );
        let status = api.status(true).await?;
        assert_eq!(status["rollout"]["progress"]["restarting"], "0");
        assert_eq!(status["rollout"]["progress"]["verified"], "0");
        assert_eq!(status["rollout"]["state"], "running");
        assert!(processes[0].try_wait()?.is_none());
        fixture::assert_file_surfaces(root.address, &client, key, &volume, b"only surviving copy")
            .await?;
        Ok::<_, Box<dyn Error>>(())
    }
    .await;
    fixture::stop_processes(&mut processes);
    fixture::retain_failure_state(proof, [root.temporary])
}

#[tokio::test]
async fn authenticated_peer_reports_the_exact_uninterrupted_preparation()
-> Result<(), Box<dyn Error>> {
    let root = ProcessFixture::new()?;
    let peer = ProcessFixture::new()?;
    let executable = std::fs::read(root.command().get_program())?;
    let mut digest = String::new();
    for byte in Sha256::digest(&executable) {
        write!(&mut digest, "{byte:02x}")?;
    }
    let mut processes = vec![root.start()?];
    let proof = async {
        let claim = fixture::wait_for_claim(&root.claim_path).await?;
        let client = fixture::wait_for_client(&root.identity_path).await?;
        fixture::wait_for_status(root.address, &client, "claim_required").await?;
        let created = fixture::create_process_mesh(&root, &client, &claim).await?;
        let key = created["api_key"].as_str().ok_or("bootstrap key absent")?;
        fixture::save_and_verify_recovery_bundle(&root, &client, key, &created).await?;
        processes.push(peer.start_join(&fixture::issue_join_code(&root, &client, key).await?)?);
        let peer_client = fixture::wait_for_client(&peer.identity_path).await?;
        fixture::wait_for_status(peer.address, &peer_client, "configured").await?;
        let api = UpdateApi {
            root: &root,
            client: &client,
            key,
        };
        let signer = NodeIdentityKey::generate()?;
        api.manage(&pin(&signer), "200 OK").await?;
        cache_candidate(&root, &executable, &digest)?;
        cache_candidate(&peer, &executable, &digest)?;
        api.manage(
            &candidate_artifact(&root, &signer, executable.len(), &digest)?,
            "200 OK",
        )
        .await?;
        let local = wait_for_workload(&root, "local_content_checked", 2).await?;
        let scan = wait_for_peer_scan(&peer, &root).await?;
        assert_eq!(
            scan.state,
            i32::from(meshspan_protocol::v1::UpdateWorkloadState::LocalContentChecked)
        );
        assert_eq!(scan.volumes_checked, 0);
        assert_eq!(scan.publications_checked, 0);
        assert_eq!(scan.stripes_checked, 0);
        assert_eq!(scan.excluded_node_incarnation, 1);
        assert_eq!(
            scan.preparation_sequence,
            local["preparation_sequence"]
                .as_u64()
                .ok_or("sequence absent")?
        );
        assert_eq!(
            scan.preparation_log_index,
            local["preparation_log_index"]
                .as_u64()
                .ok_or("barrier absent")?
        );
        let id = meshspan_domain::NodeId::from_bytes(scan.excluded_node_id.as_slice().try_into()?)?;
        assert_eq!(
            id.to_string(),
            local["excluded_node_id"]
                .as_str()
                .ok_or("candidate absent")?
                .replace('-', "")
        );
        assert_eq!(
            api.status(true).await?["rollout"]["progress"]["restarting"],
            "0"
        );
        Ok::<_, Box<dyn Error>>(())
    }
    .await;
    fixture::stop_processes(&mut processes);
    fixture::retain_failure_state(proof, [root.temporary, peer.temporary])
}

async fn wait_for_peer_scan(
    source: &ProcessFixture,
    target: &ProcessFixture,
) -> Result<meshspan_protocol::v1::UpdateWorkloadObservation, Box<dyn Error>> {
    let repository = super::readiness::repository(source)?;
    let plan = repository
        .load_active_consensus_quorum_plan()?
        .ok_or("missing plan")?;
    let network = super::readiness::network(source, target)?;
    let deadline = tokio::time::Instant::now() + fixture::WAIT_LIMIT;
    loop {
        let result = super::readiness::probe(
            &network,
            fixture::fixture_node_id(target)?,
            plan.proof_digest(),
            0,
        )
        .await?;
        if let Some(scan) = result.local_content_scan
            && scan.state
                == i32::from(meshspan_protocol::v1::UpdateWorkloadState::LocalContentChecked)
        {
            return Ok(scan);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("peer did not expose its current preparation observation".into());
        }
        tokio::time::sleep(fixture::RETRY_INTERVAL).await;
    }
}

async fn wait_for_workload(
    root: &ProcessFixture,
    expected: &str,
    participants: u8,
) -> Result<Value, Box<dyn Error>> {
    let deadline = tokio::time::Instant::now() + super::ARTIFACT_OPERATION_WAIT;
    let repository = super::readiness::repository(root)?;
    let mut progress = 0;
    loop {
        if let Some((rollout, counts)) = repository.update_administration_snapshot(None)?.rollout {
            let sources = repository.update_artifact_sources(
                rollout.rollout_id,
                &super::target(),
                None,
                meshspan_metadata::PageLimit::new(usize::from(participants))?,
            )?;
            let current = counts.staged + u64::try_from(sources.len())?;
            assert!(
                current >= progress && current <= u64::from(participants) * 2,
                "invalid preparation progress"
            );
            // Keep progress diagnostic and bounded; it cannot extend the absolute deadline.
            progress = current;
        }
        match std::fs::read(root.state_path.join("update-workload.json")) {
            Ok(bytes) => {
                let observation: Value = serde_json::from_slice(&bytes)?;
                if observation["state"] == expected {
                    return Ok(observation);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!("updater did not retain its expected workload observation; preparation progress {progress}/{}", u64::from(participants) * 2).into());
        }
        tokio::time::sleep(fixture::RETRY_INTERVAL).await;
    }
}

fn cache_candidate(
    node: &ProcessFixture,
    bytes: &[u8],
    digest: &str,
) -> Result<(), Box<dyn Error>> {
    use std::{
        io::Write as _,
        os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    };
    let directory = node.state_path.join("update-artifacts");
    std::fs::create_dir(&directory)?;
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(directory.join(digest))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::File::open(directory)?.sync_all()?;
    Ok(())
}

async fn observe_readiness(
    source: &ProcessFixture,
    target: &ProcessFixture,
) -> Result<Value, Box<dyn Error>> {
    let repository = super::readiness::repository(source)?;
    let plan = repository
        .load_active_consensus_quorum_plan()?
        .ok_or("missing plan")?;
    let network = super::readiness::network(source, target)?;
    let result = super::readiness::probe(
        &network,
        fixture::fixture_node_id(target)?,
        plan.proof_digest(),
        0,
    )
    .await?;
    Ok(
        json!({"listeners":result.listeners_bound, "persistence_blocked":result.persistence_blocked,
        "applied":result.applied_index, "committed":result.committed_index}),
    )
}

async fn wait_for_verified(
    api: &UpdateApi<'_>,
    nodes: &[&ProcessFixture],
) -> Result<Value, Box<dyn Error>> {
    let count = u64::try_from(nodes.len())?;
    let mut selections = vec![false; nodes.len()];
    let deadline = tokio::time::Instant::now() + super::ARTIFACT_OPERATION_WAIT;
    let mut progress = 0;
    let expected = count.to_string();
    loop {
        // Connection loss during self-exec is expected under this explicit interruption policy.
        let result = tokio::time::timeout_at(deadline, api.status(true))
            .await
            .map_err(|_| {
                format!("installation did not verify {count} nodes before HTTP deadline")
            })?;
        if let Ok(status) = &result {
            let current = status["rollout"]["progress"]["verified"]
                .as_str()
                .ok_or("verified count absent")?
                .parse::<u64>()?;
            let staged = status["rollout"]["progress"]["staged"]
                .as_str()
                .ok_or("staged count absent")?
                .parse::<u64>()?;
            let restarting = status["rollout"]["progress"]["restarting"]
                .as_str()
                .ok_or("restart count absent")?
                .parse::<u64>()?;
            assert!(
                current <= count && staged <= count && restarting <= 1,
                "invalid update counts"
            );
            let milestone =
                current * 3 + restarting * 2 + staged + observe_selections(nodes, &mut selections)?;
            assert!(
                milestone >= progress && milestone <= count * 4,
                "invalid update progress"
            );
            // Durable image selection is progress between admission and verification.
            // The absolute artifact-operation deadline never moves.
            progress = milestone;
            if status["rollout"]["progress"]["verified"].as_str() == Some(expected.as_str()) {
                return Ok(status.clone());
            }
            if status["rollout"]["state"] == "paused" {
                return Err(format!("installation paused: {status}").into());
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!("installation did not verify {count} nodes: {result:?}").into());
        }
        tokio::time::sleep(fixture::RETRY_INTERVAL).await;
    }
}

fn observe_selections(nodes: &[&ProcessFixture], seen: &mut [bool]) -> Result<u64, Box<dyn Error>> {
    for (node, observed) in nodes.iter().zip(seen.iter_mut()) {
        if *observed {
            continue;
        }
        let bytes = match std::fs::read(node.state_path.join("installed-update.json")) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        let selection: Value = serde_json::from_slice(&bytes)?;
        if selection["node_id"] != json!(fixture::fixture_node_id(node)?.as_bytes())
            || selection["rollout_id"]
                != json!(0x0000_0000_0000_4000_8000_0000_0000_0402_u128.to_be_bytes())
            || selection["incarnation"] != 1
            || selection["restart_sequence"]
                .as_u64()
                .is_none_or(|value| value < 4)
        {
            return Err("installation progress belongs to another node or rollout".into());
        }
        *observed = true;
    }
    Ok(u64::try_from(seen.iter().filter(|value| **value).count())?)
}

fn assert_installation(node: &ProcessFixture, digest: &str) -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt as _;
    let selected = node.state_path.join("installed-update.json");
    assert_eq!(
        std::fs::metadata(&selected)?.permissions().mode() & 0o777,
        0o600
    );
    let selection: Value = serde_json::from_slice(&std::fs::read(selected)?)?;
    assert_eq!(
        selection["node_id"],
        json!(fixture::fixture_node_id(node)?.as_bytes())
    );
    let mut installed = false;
    for report in super::published_reports(&node.state_path.join("update-evidence"))? {
        if report["phase"] == "installed" {
            assert_eq!(report["sha256"], digest);
            assert_eq!(report["runtime"]["target"], super::target());
            assert_eq!(report["runtime"]["licence"], "GPL-2.0-only");
            assert_eq!(report["applied_index"], report["committed_index"]);
            installed = true;
        }
    }
    assert!(installed, "no new-process verification evidence");
    Ok(())
}

fn assert_peer_witness(peer: &ProcessFixture, root: &ProcessFixture) -> Result<(), Box<dyn Error>> {
    let root_id = fixture::fixture_node_id(root)?.to_string();
    for report in super::published_reports(&peer.state_path.join("update-evidence"))? {
        if report["phase"] != 3 {
            continue;
        }
        let barrier = report["preparation_log_index"]
            .as_u64()
            .ok_or("barrier absent")?;
        for witness in report["ready_nodes"]
            .as_array()
            .ok_or("witness list absent")?
        {
            if witness["node_id"]
                .as_str()
                .ok_or("witness node absent")?
                .replace('-', "")
                == root_id
            {
                assert_eq!(witness["incarnation"], 1);
                assert!(
                    witness["applied_index"]
                        .as_u64()
                        .ok_or("witness index absent")?
                        >= barrier
                );
                return Ok(());
            }
        }
    }
    Err("automatic admission did not retain the live root's readiness witness".into())
}

fn assert_process_image(
    pid: u32,
    node: &ProcessFixture,
    digest: &str,
) -> Result<(), Box<dyn Error>> {
    // Observe the executable, never argv: a fixture's original join command contains a secret.
    let observed = if cfg!(target_os = "linux") {
        std::fs::read_link(format!("/proc/{pid}/exe"))?
    } else {
        let output = std::process::Command::new("/bin/ps")
            .args(["-ww", "-p", &pid.to_string(), "-o", "comm="])
            .output()?;
        if !output.status.success() {
            return Err("installed process absent".into());
        }
        std::path::PathBuf::from(String::from_utf8(output.stdout)?.trim())
    };
    let expected = node
        .state_path
        .join("update-artifacts")
        .join(digest)
        .canonicalize()?;
    if observed.canonicalize()? != expected {
        return Err(format!(
            "process {pid} still runs {} instead of the selected image",
            observed.display()
        )
        .into());
    }
    Ok(())
}
