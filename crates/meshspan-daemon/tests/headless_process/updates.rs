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
        let pin = json!({"operation_id":"00000000-0000-4000-8000-000000000403", "action": {
            "kind":"configure_signer", "signer_id":SIGNER, "expected_sequence":0,
            "public_key":STANDARD.encode(signer.public_key_sec1()), "enabled":true }});
        let pin_receipt = api.manage(&pin, "200 OK").await?;
        let anonymous = request_with_headers(root.address, &client, "PUT", API, Some(b"not JSON"), &[]).await?;
        require_status(&anonymous, "401 Unauthorized", "authenticate before update JSON")?;
        let candidate = candidate(&root, &signer)?;
        let selected = api.manage(&candidate, "200 OK").await?;
        assert_eq!(selected["resource_id"], ROLLOUT);
        let staged = api.stage(b"abc", "200 OK").await?;
        assert_eq!(staged["sha256"], ARTIFACT_DIGEST);
        assert_eq!(staged["byte_length"], "3");
        assert_eq!(std::fs::read(root.state_path.join("update-artifacts").join(ARTIFACT_DIGEST))?, b"abc");
        let status = api.status(false).await?;
        assert_eq!(status["installation_available"], false);
        assert_eq!(status["rollout"]["state"], "running");
        assert_eq!(status["rollout"]["progress"], json!({"pending":"1", "staged":"0", "restarting":"0", "verified":"0", "failed":"0", "unresolved_restarts":"0"}));
        let sequence = status["rollout"]["sequence"].as_u64().ok_or("sequence absent")?;
        api.manage(&control("pause", sequence, 405), "200 OK").await?;
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

fn candidate(root: &ProcessFixture, signer: &NodeIdentityKey) -> Result<Value, Box<dyn Error>> {
    let schema = PartitionDatabase::open_existing(
        &root.state_path.join("root-authority.sqlite3"),
        UnixMicros::new(1),
    )?
    .schema_version();
    let manifest = serde_json::to_vec(
        &json!({"format":1, "licence":"GPL-2.0-only", "version":"0.1.0",
        "source_commit":"a".repeat(40), "api_sha256":"b".repeat(64),
        "compatibility":{"private_protocol_major":1, "partition_schema_min":schema, "partition_schema_max":schema,
            "partition_schema_target":schema, "rollback_supported":false},
        "artifacts":[{"target":"aarch64-apple-darwin", "size":"3", "sha256":ARTIFACT_DIGEST}]}),
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
    async fn stage(&self, bytes: &[u8], expected: &str) -> Result<Value, Box<dyn Error>> {
        let endpoint = format!("{API}/{ROLLOUT}/artifacts/aarch64-apple-darwin");
        let response = super::request_with_content_type(
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
        )
        .await?;
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
