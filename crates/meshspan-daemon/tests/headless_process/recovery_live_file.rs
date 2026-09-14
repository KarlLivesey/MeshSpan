// SPDX-License-Identifier: GPL-2.0-only

//! Original client credentials and exact file bytes across offline replacement recovery.

use super::{Error, ProcessFixture};
use std::{fs, io::Write as _, os::unix::fs::OpenOptionsExt as _};

const HTTPS_CREATED: &[u8] = b"New HTTPS bytes acknowledged by the recovered swarm";
const SMB_CREATED: &[u8] = b"New SMB bytes acknowledged by the recovered swarm";

struct ClientState {
    key: String,
    volume: String,
    smb: bool,
}

impl ClientState {
    fn load(root: &ProcessFixture) -> Result<Self, Box<dyn Error>> {
        let value: serde_json::Value = serde_json::from_slice(&fs::read(
            root.temporary.path().join("original-recovery-client.json"),
        )?)?;
        Ok(Self {
            key: value["key"]
                .as_str()
                .ok_or("original client key missing")?
                .to_owned(),
            volume: value["volume"]
                .as_str()
                .ok_or("original volume missing")?
                .to_owned(),
            smb: value["smb"].as_bool().ok_or("client coverage missing")?,
        })
    }
}

/// Test-owned credentials stay in memory and never appear in diagnostics.
pub(super) fn original_credentials(
    root: &ProcessFixture,
) -> Result<(String, String), Box<dyn Error>> {
    let state = ClientState::load(root)?;
    Ok((state.key, state.volume))
}

#[derive(Clone, Copy)]
pub(super) enum Clients {
    Https,
    HttpsAndSmb,
}

impl Clients {
    pub(super) const fn includes_smb(self) -> bool {
        matches!(self, Self::HttpsAndSmb)
    }
}

pub(super) fn remember(
    root: &ProcessFixture,
    key: &str,
    volume: &str,
    clients: Clients,
) -> Result<(), Box<dyn Error>> {
    // Test-only client state, never installed into a replacement daemon or printed on failure.
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.temporary.path().join("original-recovery-client.json"))?;
    file.write_all(&serde_json::to_vec(
        &serde_json::json!({"key": key, "volume": volume, "smb": clients.includes_smb()}),
    )?)?;
    Ok(())
}

pub(super) async fn verify(
    root: &ProcessFixture,
    gateway: &ProcessFixture,
) -> Result<(), Box<dyn Error>> {
    assert!(
        !root.storage_path.exists(),
        "original storage must be unavailable during live recovery"
    );
    assert!(!root.state_path.join("filesystem").exists());
    assert!(!root.state_path.join("storage-targets").exists());
    let client_state = ClientState::load(root)?;
    let client = super::wait_for_client(&gateway.identity_path).await?;
    super::assert_file_surfaces(
        gateway.address,
        &client,
        &client_state.key,
        &client_state.volume,
        b"Recovery must retain this file's history and content-key envelope",
    )
    .await?;
    if client_state.smb {
        super::wait_for_smb_listener(gateway.smb_address).await?;
        let exchange = tempfile::tempdir()?;
        super::run_real_smb_command(
            gateway.smb_address.port(),
            client_state.key,
            exchange.path(),
            "get process-proof.bin /proof/recovered.bin",
        )
        .await?;
        assert_eq!(
            fs::read(exchange.path().join("recovered.bin"))?,
            b"Recovery must retain this file's history and content-key envelope"
        );
    }
    Ok(())
}

/// Mutations use the original credential and recovered namespace, not recreated access grants.
pub(super) async fn create_new_files(
    root: &ProcessFixture,
    gateway: &ProcessFixture,
) -> Result<(), Box<dyn Error>> {
    let state = ClientState::load(root)?;
    let client = super::wait_for_client(&gateway.identity_path).await?;
    super::upload_named_file(
        gateway.address,
        &client,
        &state.key,
        &state.volume,
        super::FileUploadProof {
            path: "recovery-https.bin",
            content: HTTPS_CREATED,
            operation_base: 0x900,
        },
    )
    .await?;
    if state.smb {
        let exchange = tempfile::tempdir()?;
        fs::write(exchange.path().join("new-smb.bin"), SMB_CREATED)?;
        super::run_real_smb_command(
            gateway.smb_address.port(),
            state.key,
            exchange.path(),
            "put /proof/new-smb.bin recovery-smb.bin",
        )
        .await?;
    }
    verify_new_files(root, gateway).await
}

/// This is read-only: after restart it cannot repair a lost write by uploading again.
pub(super) async fn verify_new_files(
    root: &ProcessFixture,
    gateway: &ProcessFixture,
) -> Result<(), Box<dyn Error>> {
    let state = ClientState::load(root)?;
    let client = super::wait_for_client(&gateway.identity_path).await?;
    let authorization = format!("Bearer {}", state.key);
    for (name, expected) in [
        ("recovery-https.bin", HTTPS_CREATED),
        ("recovery-smb.bin", SMB_CREATED),
    ] {
        if name == "recovery-smb.bin" && !state.smb {
            continue;
        }
        let response = super::request_with_headers(
            gateway.address,
            &client,
            "GET",
            &format!(
                "/api/latest/volumes/{}/file-content?path={name}&offset=0&length={}",
                state.volume,
                expected.len()
            ),
            None,
            &[("Authorization", authorization.as_str())],
        )
        .await?;
        super::require_status(&response, "200 OK", "read post-recovery file")?;
        assert_eq!(super::response_body(&response)?.as_bytes(), expected);
    }
    if state.smb {
        super::wait_for_smb_listener(gateway.smb_address).await?;
        let exchange = tempfile::tempdir()?;
        super::run_real_smb_command(
            gateway.smb_address.port(),
            state.key,
            exchange.path(),
            "get recovery-https.bin /proof/https.bin; get recovery-smb.bin /proof/smb.bin",
        )
        .await?;
        assert_eq!(fs::read(exchange.path().join("https.bin"))?, HTTPS_CREATED);
        assert_eq!(fs::read(exchange.path().join("smb.bin"))?, SMB_CREATED);
    }
    Ok(())
}
