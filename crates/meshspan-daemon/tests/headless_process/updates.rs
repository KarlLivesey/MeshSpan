// SPDX-License-Identifier: GPL-2.0-only

//! Native HTTPS update selection and controls across a real daemon restart; no installation claim.

use super::{Error, ProcessFixture, request_with_headers, require_status, response_body};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use meshspan_certificates::{NodeIdentityKey, UPDATE_SIGNATURE_DOMAIN};
use meshspan_domain::UnixMicros;
use meshspan_metadata::PartitionDatabase;
use rustls::ClientConfig;
use serde_json::{Value, json};

const API: &str = "/api/latest/admin/updates";
const SIGNER: &str = "00000000-0000-4000-8000-000000000401";
const ROLLOUT: &str = "00000000-0000-4000-8000-000000000402";
const ARTIFACT_DIGEST: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

#[path = "update_readiness.rs"]
mod readiness;

#[tokio::test]
async fn update_administration_preserves_trust_selection_and_exact_retry_after_restart()
-> Result<(), Box<dyn Error>> {
    let root = ProcessFixture::new()?;
    let mut processes = vec![root.command().spawn()?];
    let proof = async {
        let claim = super::wait_for_claim(&root.claim_path).await?;
        let client = super::wait_for_client(&root.identity_path).await?;
        super::wait_for_status(root.address, &client, "claim_required").await?;
        let created = super::create_process_mesh(&root, &client, &claim).await?;
        let key = created["api_key"].as_str().ok_or("bootstrap key absent")?;
        super::save_and_verify_recovery_bundle(&root, &client, key, &created).await?;
        super::wait_for_storage_folder_visibility(&root, &client, key).await?;
        let api = UpdateApi { root: &root, client: &client, key };
        let signer = NodeIdentityKey::generate()?;
        let pin = pin(&signer);
        let pin_receipt = api.manage(&pin, "200 OK").await?;
        let anonymous = request_with_headers(root.address, &client, "PUT", API, Some(b"not JSON"), &[]).await?;
        require_status(&anonymous, "401 Unauthorized", "authenticate before update JSON")?;
        let candidate = candidate(&root, &signer)?;
        let selected = api.manage(&candidate, "200 OK").await?;
        assert_eq!(selected["resource_id"], ROLLOUT);
        let sequence = api.status(false).await?["rollout"]["sequence"].as_u64().ok_or("sequence absent")?;
        // This test isolates upload/retry semantics; dummy bytes must not be probed.
        api.manage(&control("pause", sequence, 405), "200 OK").await?;
        let staged = api.stage(b"abc", "200 OK").await?;
        assert_eq!(staged["sha256"], ARTIFACT_DIGEST);
        assert_eq!(staged["byte_length"], "3");
        assert_eq!(std::fs::read(root.state_path.join("update-artifacts").join(ARTIFACT_DIGEST))?, b"abc");
        let status = api.status(false).await?;
        assert_eq!(status["installation_available"], false);
        assert_eq!(status["rollout"]["state"], "paused");
        assert_eq!(status["rollout"]["progress"], json!({"pending":"1", "staged":"0", "restarting":"0", "verified":"0", "failed":"0", "unresolved_restarts":"0"}));
        processes[0].kill()?;
        processes[0].wait()?;
        processes[0] = root.command().spawn()?;
        super::wait_for_status(root.address, &client, "configured").await?;
        assert_eq!(api.manage(&pin, "200 OK").await?, pin_receipt);
        assert_eq!(api.manage(&candidate, "200 OK").await?, selected);
        assert_eq!(api.stage(b"abc", "200 OK").await?, staged);
        api.stage(b"abd", "400 Bad Request").await?;
        let paused = api.status(true).await?;
        assert_eq!(paused["rollout"]["state"], "paused");
        assert_eq!(paused["signers"][0]["sequence"], 1);
        let sequence = paused["rollout"]["sequence"].as_u64().ok_or("sequence absent")?;
        api.manage(&control("resume", sequence, 406), "200 OK").await?;
        api.manage(&control("cancel", sequence + 1, 407), "200 OK").await?;
        assert!(api.status(false).await?["rollout"].is_null());
        assert_eq!(api.status(true).await?["rollout"]["state"], "cancelled");
        let mut changed = candidate;
        changed["action"]["allow_service_interruption"] = json!(true);
        api.manage(&changed, "409 Conflict").await?;
        Ok::<_, Box<dyn Error>>(())
    }.await;
    super::stop_processes(&mut processes);
    super::retain_failure_state(proof, [root.temporary])
}

#[tokio::test]
async fn signed_candidate_automatically_reaches_three_daemons_and_survives_peer_restart()
-> Result<(), Box<dyn Error>> {
    let executable = vec![0x5a; 3 * 65_536 + 117];
    // Independently calculated with Node's crypto SHA-256, not the transfer implementation.
    let digest = "28e79bfe7296805d79e3b71103b2e1ed68ae85d65fe520a07de2368623434ce9";
    let root = ProcessFixture::new()?;
    let second = ProcessFixture::new()?;
    let third = ProcessFixture::new()?;
    let mut processes = vec![root.start()?];
    let proof = async {
        let claim = super::wait_for_claim(&root.claim_path).await?;
        let client = super::wait_for_client(&root.identity_path).await?;
        super::wait_for_status(root.address, &client, "claim_required").await?;
        let created = super::create_process_mesh(&root, &client, &claim).await?;
        let key = created["api_key"].as_str().ok_or("bootstrap key absent")?;
        super::save_and_verify_recovery_bundle(&root, &client, key, &created).await?;
        let join = super::issue_join_code(&root, &client, key).await?;
        processes.push(second.start_join(&join)?);
        let second_client = super::wait_for_client(&second.identity_path).await?;
        super::wait_for_status(second.address, &second_client, "configured").await?;
        processes.push(third.start_join(&join)?);
        let third_client = super::wait_for_client(&third.identity_path).await?;
        super::wait_for_status(third.address, &third_client, "configured").await?;
        super::wait_for_three_voters([&root, &second, &third], &root.identity_path).await?;
        let api = UpdateApi {
            root: &root,
            client: &client,
            key,
        };
        let signer = NodeIdentityKey::generate()?;
        api.manage(&pin(&signer), "200 OK").await?;
        api.manage(
            &candidate_artifact(&root, &signer, executable.len(), digest)?,
            "200 OK",
        )
        .await?;
        api.stage(&executable, "200 OK").await?;
        wait_for_sources([&root, &second, &third], &executable, digest).await?;
        let status = api.wait_for("paused", "failed", None).await?;
        assert_eq!(status["rollout"]["progress"]["staged"], "0");
        assert_eq!(status["rollout"]["progress"]["restarting"], "0");
        processes[1].kill()?;
        processes[1].wait()?;
        processes[1] = second.command().spawn()?;
        super::wait_for_status(second.address, &second_client, "configured").await?;
        wait_for_sources([&root, &second, &third], &executable, digest).await?;
        assert_eq!(api.status(false).await?["installation_available"], false);
        Ok::<_, Box<dyn Error>>(())
    }
    .await;
    super::stop_processes(&mut processes);
    super::retain_failure_state(proof, [root.temporary, second.temporary, third.temporary])
}

async fn wait_for_sources(
    fixtures: [&ProcessFixture; 3],
    expected: &[u8],
    digest: &str,
) -> Result<(), Box<dyn Error>> {
    use meshspan_metadata::{AuthoritativeRepository, PageLimit};
    let rollout = meshspan_domain::WorkId::from_bytes(
        0x0000_0000_0000_4000_8000_0000_0000_0402_u128.to_be_bytes(),
    )?;
    let deadline = tokio::time::Instant::now() + super::WAIT_LIMIT;
    loop {
        let mut ready = true;
        for fixture in fixtures {
            let database = PartitionDatabase::open_existing(
                &fixture.state_path.join("root-authority.sqlite3"),
                UnixMicros::new(1),
            )?;
            let repository = AuthoritativeRepository::new(database);
            if repository.update_rollout(rollout)?.is_none() {
                ready = false;
                continue;
            }
            let sources =
                repository.update_artifact_sources(rollout, &target(), None, PageLimit::new(3)?)?;
            ready &= sources.len() == 3;
            match std::fs::read(fixture.state_path.join("update-artifacts").join(digest)) {
                Ok(bytes) => assert_eq!(bytes, expected),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => ready = false,
                Err(error) => return Err(error.into()),
            }
        }
        if ready {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("verified candidate sources did not reach all three nodes".into());
        }
        tokio::time::sleep(super::RETRY_INTERVAL).await;
    }
}

#[tokio::test]
async fn real_signed_executable_passes_runtime_probe_and_retains_staging_after_restart()
-> Result<(), Box<dyn Error>> {
    use sha2::{Digest as _, Sha256};
    use std::fmt::Write as _;
    let root = ProcessFixture::new()?;
    let executable = std::fs::read(root.command().get_program())?;
    let mut digest = String::new();
    for byte in Sha256::digest(&executable) {
        write!(&mut digest, "{byte:02x}")?;
    }
    let mut processes = vec![root.start()?];
    let proof = async {
        let claim = super::wait_for_claim(&root.claim_path).await?;
        let client = super::wait_for_client(&root.identity_path).await?;
        super::wait_for_status(root.address, &client, "claim_required").await?;
        let created = super::create_process_mesh(&root, &client, &claim).await?;
        let key = created["api_key"].as_str().ok_or("bootstrap key absent")?;
        super::save_and_verify_recovery_bundle(&root, &client, key, &created).await?;
        let api = UpdateApi { root: &root, client: &client, key };
        let signer = NodeIdentityKey::generate()?;
        api.manage(&pin(&signer), "200 OK").await?;
        api.manage(&candidate_artifact(&root, &signer, executable.len(), &digest)?, "200 OK").await?;
        api.stage(&executable, "200 OK").await?;
        // GNU development binaries are not the signed static-musl distribution target.
        if cfg!(all(target_os = "linux", not(target_env = "musl"))) {
            let refused = api.wait_for("paused", "failed", Some("1")).await?;
            assert_eq!(refused["rollout"]["progress"]["staged"], "0");
            return Ok(());
        }
        let staged = api.wait_for("running", "staged", Some("1")).await?;
        assert_eq!(staged["rollout"]["progress"], json!({"pending":"0", "staged":"1", "restarting":"0", "verified":"0", "failed":"0", "unresolved_restarts":"0"}));
        let evidence = std::fs::read_dir(root.state_path.join("update-evidence"))?.collect::<Result<Vec<_>,_>>()?;
        assert_eq!(evidence.len(), 1);
        let report: Value = serde_json::from_slice(&std::fs::read(evidence[0].path())?)?;
        assert_eq!(report["accepted"], true);
        assert_eq!(report["runtime"]["licence"], "GPL-2.0-only");
        assert_eq!(report["runtime"]["version"], "0.1.0");
        assert_eq!(report["runtime"]["target"], target());
        processes[0].kill()?;
        processes[0].wait()?;
        processes[0] = root.start()?;
        super::wait_for_status(root.address, &client, "configured").await?;
        assert_eq!(api.status(false).await?["rollout"], staged["rollout"]);
        Ok::<_, Box<dyn Error>>(())
    }.await;
    super::stop_processes(&mut processes);
    super::retain_failure_state(proof, [root.temporary])
}

fn pin(signer: &NodeIdentityKey) -> Value {
    json!({"operation_id":"00000000-0000-4000-8000-000000000403", "action": {
        "kind":"configure_signer", "signer_id":SIGNER, "expected_sequence":0,
        "public_key":STANDARD.encode(signer.public_key_sec1()), "enabled":true }})
}

fn target() -> String {
    let operating_system = if std::env::consts::OS == "macos" {
        "apple-darwin"
    } else {
        "unknown-linux-musl"
    };
    format!("{}-{operating_system}", std::env::consts::ARCH)
}

fn candidate(root: &ProcessFixture, signer: &NodeIdentityKey) -> Result<Value, Box<dyn Error>> {
    candidate_artifact(root, signer, 3, ARTIFACT_DIGEST)
}

fn candidate_artifact(
    root: &ProcessFixture,
    signer: &NodeIdentityKey,
    length: usize,
    digest: &str,
) -> Result<Value, Box<dyn Error>> {
    let schema = PartitionDatabase::open_existing(
        &root.state_path.join("root-authority.sqlite3"),
        UnixMicros::new(1),
    )?
    .schema_version();
    let manifest = serde_json::to_vec(
        &json!({"format":1, "licence":"GPL-2.0-only", "version":"0.1.0",
        "source_commit":"a".repeat(40), "api_sha256":meshspan_api_contract::generate_openapi()?.digest().strip_prefix("sha256:").ok_or("missing API digest prefix")?,
        "compatibility":{"private_protocol_major":1, "partition_schema_min":schema, "partition_schema_max":schema,
            "partition_schema_target":schema, "rollback_supported":false},
        "artifacts":[{"target":target(), "size":length.to_string(), "sha256":digest}]}),
    )?;
    let mut transcript = UPDATE_SIGNATURE_DOMAIN.to_vec();
    transcript.extend_from_slice(&manifest);
    let signature = signer.sign_enrolment_transcript(&transcript)?;
    Ok(
        json!({"operation_id":"00000000-0000-4000-8000-000000000404", "action": {
        "kind":"select_candidate", "rollout_id":ROLLOUT, "signer_id":SIGNER, "signer_sequence":1,
        "manifest":STANDARD.encode(manifest), "signature":STANDARD.encode(signature), "allow_service_interruption":false }}),
    )
}

fn control(action: &str, sequence: u64, operation: u16) -> Value {
    json!({"operation_id":format!("00000000-0000-4000-8000-{operation:012}"), "action": {
        "kind":"control", "rollout_id":ROLLOUT, "expected_sequence":sequence, "control":action }})
}

struct UpdateApi<'a> {
    root: &'a ProcessFixture,
    client: &'a ClientConfig,
    key: &'a str,
}

impl UpdateApi<'_> {
    async fn wait_for(
        &self,
        state: &str,
        phase: &str,
        count: Option<&str>,
    ) -> Result<Value, Box<dyn Error>> {
        let deadline = tokio::time::Instant::now() + super::WAIT_LIMIT;
        loop {
            let status = self.status(false).await?;
            let observed = status["rollout"]["progress"][phase]
                .as_str()
                .ok_or("progress absent")?;
            if status["rollout"]["state"] == state
                && count.map_or(observed != "0", |count| observed == count)
            {
                return Ok(status);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(format!("update did not reach {state}/{phase}: {status}").into());
            }
            tokio::time::sleep(super::RETRY_INTERVAL).await;
        }
    }

    async fn stage(&self, bytes: &[u8], expected: &str) -> Result<Value, Box<dyn Error>> {
        let endpoint = format!("{API}/{ROLLOUT}/artifacts/{}", target());
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            super::request_with_content_type(
                self.root.address,
                self.client,
                "PUT",
                &endpoint,
                Some(bytes),
                "application/octet-stream",
                &[
                    ("Authorization", &format!("Bearer {}", self.key)),
                    (
                        "MeshSpan-Operation-Id",
                        "00000000-0000-4000-8000-000000000408",
                    ),
                ],
            ),
        )
        .await
        .map_err(|_| "signed executable upload timed out")??;
        require_status(&response, expected, "stage exact signed executable")?;
        Ok(serde_json::from_str(response_body(&response)?)?)
    }

    async fn manage(&self, request: &Value, expected: &str) -> Result<Value, Box<dyn Error>> {
        let bytes = serde_json::to_vec(request)?;
        let response = request_with_headers(
            self.root.address,
            self.client,
            "PUT",
            API,
            Some(&bytes),
            &[("Authorization", &format!("Bearer {}", self.key))],
        )
        .await?;
        require_status(&response, expected, "manage software update")?;
        Ok(serde_json::from_str(response_body(&response)?)?)
    }

    async fn status(&self, retained: bool) -> Result<Value, Box<dyn Error>> {
        let endpoint = if retained {
            format!("{API}?rollout_id={ROLLOUT}")
        } else {
            API.to_owned()
        };
        let response = request_with_headers(
            self.root.address,
            self.client,
            "GET",
            &endpoint,
            None,
            &[("Authorization", &format!("Bearer {}", self.key))],
        )
        .await?;
        require_status(&response, "200 OK", "read update state")?;
        Ok(serde_json::from_str(response_body(&response)?)?)
    }
}
