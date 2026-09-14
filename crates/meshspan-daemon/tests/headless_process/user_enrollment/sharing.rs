// SPDX-License-Identifier: GPL-2.0-only

//! Native two-user file sharing through HTTPS and encrypted SMB, including restart.

use super::*;

const HTTPS_BYTES: &[u8] = b"Bob's exact HTTPS bytes for the administrator";
const ADMIN_BYTES: &[u8] = b"Administrator content which requires an explicit grant";
const SMB_BYTES: &[u8] = b"after lease renewal!";

#[tokio::test]
#[ignore = "65-second two-user proof using the local SMB image and optional Samba helper"]
async fn enrolled_bob_shares_exact_https_and_smb_bytes_after_restart() -> Result<(), Box<dyn Error>>
{
    let helper = PathBuf::from(
        std::env::var_os("MESHSPAN_SMB_LEASE_CLIENT")
            .ok_or("set MESHSPAN_SMB_LEASE_CLIENT to the optional local helper binary")?,
    );
    if !helper.is_absolute() || !helper.is_file() {
        return Err("SMB lease helper must be an existing absolute path".into());
    }
    let mut fixture = ProcessFixture::new()?;
    // Preserve private evidence if an assertion unwinds before the result handler.
    fixture.temporary.disable_cleanup(true);
    let mut processes = ProcessCleanup(vec![fixture.start()?]);
    let proof = tokio::time::timeout(Duration::from_secs(180), async {
        let client = wait_for_client(&fixture.identity_path).await?;
        let enrolled = enroll_bob(&fixture, &client).await?;
        let session = assert_independent_sign_in(
            fixture.address,
            &client,
            &enrolled.bob,
            &enrolled.receipt,
            606,
        )
        .await?;
        let smb = issue_bob_smb_key(fixture.address, &client, &session).await?;
        let files = prepare_shared_files(&fixture, &client, &enrolled, secret(&smb)?).await?;
        run_retained_bob_handle(&fixture, secret(&smb)?, &helper).await?;
        assert_shared_outcomes(&fixture, &client, &enrolled, &smb, &files).await?;
        stop_processes(&mut processes.0);
        processes.0.push(fixture.start()?);
        wait_for_status(fixture.address, &client, "configured").await?;
        wait_for_smb_listener(fixture.smb_address).await?;
        assert_independent_sign_in(
            fixture.address,
            &client,
            &enrolled.bob,
            &enrolled.receipt,
            607,
        )
        .await?;
        assert_shared_outcomes(&fixture, &client, &enrolled, &smb, &files).await?;
        Ok::<_, Box<dyn Error>>(())
    })
    .await
    .map_err(|_| -> Box<dyn Error> { "two-user sharing exceeded its 180s deadline".into() })
    .and_then(std::convert::identity);
    drop(processes);
    fixture.temporary.disable_cleanup(false);
    retain_failure_state(proof, [fixture.temporary])
}

struct SharedFiles {
    volume: CreatedVolume,
    upload: CommittedUploadProof,
    exchange: TempDir,
}

async fn prepare_shared_files(
    fixture: &ProcessFixture,
    client: &ClientConfig,
    enrolled: &EnrolledBob,
    smb_key: &str,
) -> Result<SharedFiles, Box<dyn Error>> {
    let volume = create_volume_details(
        fixture.address,
        client,
        &enrolled.administrator_key,
        &enrolled.administrator_id,
    )
    .await?;
    wait_for_storage_folder_visibility(fixture, client, &enrolled.administrator_key).await?;
    publish_smb_export(
        fixture.address,
        client,
        &enrolled.administrator_key,
        &volume,
    )
    .await?;
    wait_for_smb_listener(fixture.smb_address).await?;
    upload_named_file(
        fixture.address,
        client,
        &enrolled.administrator_key,
        &volume.volume_id,
        FileUploadProof {
            path: "admin-seed.bin",
            content: ADMIN_BYTES,
            operation_base: 0x630,
        },
    )
    .await?;
    assert_https_bytes(
        fixture.address,
        client,
        &enrolled.administrator_key,
        &volume.volume_id,
        ("admin-seed.bin", ADMIN_BYTES),
    )
    .await?;
    let bob_key = secret(&enrolled.receipt)?;
    assert_access_denied(fixture, client, enrolled, &volume, smb_key).await?;
    create_volume_permission_grant(
        fixture.address,
        client,
        &enrolled.administrator_key,
        &volume.volume_id,
        &enrolled.bob.principal_id,
    )
    .await?;
    let upload = upload_named_file_with_receipt(
        fixture.address,
        client,
        bob_key,
        &volume.volume_id,
        FileUploadProof {
            path: "process-proof.bin",
            content: HTTPS_BYTES,
            operation_base: 0x620,
        },
    )
    .await?;
    assert_eq!(upload.response["upload"]["state"], "committed");
    assert_eq!(
        upload.response["acknowledgement"]["durability_scope"],
        "node_local"
    );
    assert_eq!(
        upload.response["acknowledgement"]["configured_consistency"],
        "eventual"
    );
    assert_eq!(
        upload.response["acknowledgement"]["acknowledged_consistency"],
        "eventual"
    );
    assert_eq!(upload.response["acknowledgement"]["policy_committed"], true);
    assert_eq!(
        upload.response["acknowledgement"]["fallback_applied"],
        false
    );
    assert_commit_replay(fixture.address, client, bob_key, &upload).await?;
    Ok(SharedFiles {
        volume,
        upload,
        exchange: TempDir::new()?,
    })
}

async fn assert_shared_outcomes(
    fixture: &ProcessFixture,
    client: &ClientConfig,
    enrolled: &EnrolledBob,
    smb: &serde_json::Value,
    files: &SharedFiles,
) -> Result<(), Box<dyn Error>> {
    let bob_key = secret(&enrolled.receipt)?;
    assert_own_method_inventory(fixture.address, client, bob_key, &[&enrolled.receipt, smb])
        .await?;
    assert_shared_bytes(fixture, client, enrolled, files).await?;
    let output = bob_smb_command(
        fixture,
        secret(smb)?,
        "Bob",
        Some(files.exchange.path()),
        "get bob-retained.bin /proof/bob-read.bin; get admin-seed.bin /proof/bob-admin.bin; get process-proof.bin /proof/bob-https.bin",
    )
    .await?;
    require_smb_client_success(&output)?;
    assert_eq!(
        fs::read(files.exchange.path().join("bob-read.bin"))?,
        SMB_BYTES
    );
    assert_eq!(
        fs::read(files.exchange.path().join("bob-admin.bin"))?,
        ADMIN_BYTES
    );
    assert_eq!(
        fs::read(files.exchange.path().join("bob-https.bin"))?,
        HTTPS_BYTES
    );
    assert_commit_replay(fixture.address, client, bob_key, &files.upload).await
}

fn secret(receipt: &serde_json::Value) -> Result<&str, Box<dyn Error>> {
    receipt["secret"]
        .as_str()
        .ok_or_else(|| "missing issued key".into())
}

async fn assert_access_denied(
    fixture: &ProcessFixture,
    client: &ClientConfig,
    enrolled: &EnrolledBob,
    volume: &CreatedVolume,
    smb_key: &str,
) -> Result<(), Box<dyn Error>> {
    let bob_key = secret(&enrolled.receipt)?;
    let response = request_with_headers(
        fixture.address,
        client,
        "GET",
        &format!(
            "/api/latest/volumes/{}/directory-entries?limit=100",
            volume.volume_id
        ),
        None,
        &[("Authorization", &format!("Bearer {bob_key}"))],
    )
    .await?;
    require_redacted_status(&response, "401 Unauthorized", "deny Bob HTTPS before grant")?;
    let denial: serde_json::Value = serde_json::from_str(response_body(&response)?)?;
    assert_eq!(denial["code"], "unauthenticated");
    assert!(denial.get("entries").is_none());
    let response = request_with_headers(
        fixture.address,
        client,
        "GET",
        &format!(
            "/api/latest/volumes/{}/file-content?path=admin-seed.bin&offset=0&length={}",
            volume.volume_id,
            ADMIN_BYTES.len()
        ),
        None,
        &[("Authorization", &format!("Bearer {bob_key}"))],
    )
    .await?;
    require_redacted_status(
        &response,
        "401 Unauthorized",
        "deny Bob existing file before grant",
    )?;
    let denial: serde_json::Value = serde_json::from_str(response_body(&response)?)?;
    assert_eq!(denial["code"], "unauthenticated");
    assert_smb_access_denied(fixture, enrolled, smb_key).await
}

async fn assert_smb_access_denied(
    fixture: &ProcessFixture,
    enrolled: &EnrolledBob,
    smb_key: &str,
) -> Result<(), Box<dyn Error>> {
    let exchange = TempDir::new()?;
    let output = bob_smb_command(
        fixture,
        &enrolled.administrator_key,
        "Administrator",
        Some(exchange.path()),
        "get admin-seed.bin /proof/admin-seed.bin",
    )
    .await?;
    require_smb_client_success(&output)?;
    assert_eq!(
        fs::read(exchange.path().join("admin-seed.bin"))?,
        ADMIN_BYTES
    );
    let output = bob_smb_command(
        fixture,
        smb_key,
        "Bob",
        Some(exchange.path()),
        "get admin-seed.bin /proof/bob-denied.bin",
    )
    .await?;
    assert_smb_denied(&output, "NT_STATUS_ACCESS_DENIED")?;
    let denied_file = exchange.path().join("bob-denied.bin");
    if denied_file.exists() {
        assert!(
            fs::read(denied_file)?.is_empty(),
            "denied SMB read revealed bytes"
        );
    }
    let output = bob_smb_command(fixture, smb_key, "Administrator", None, "pwd").await?;
    assert_smb_denied(&output, "NT_STATUS_LOGON_FAILURE")
}

fn assert_smb_denied(output: &std::process::Output, status: &str) -> Result<(), Box<dyn Error>> {
    if !output.status.success()
        && (String::from_utf8_lossy(&output.stdout).contains(status)
            || String::from_utf8_lossy(&output.stderr).contains(status))
    {
        Ok(())
    } else {
        let text = format!(
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let statuses = text
            .split_ascii_whitespace()
            .filter(|word| {
                word.starts_with("NT_STATUS_")
                    && word
                        .bytes()
                        .all(|byte| byte.is_ascii_uppercase() || byte == b'_')
            })
            .take(8)
            .collect::<Vec<_>>();
        Err(format!(
            "SMB expected {status}; exit={:?}; status tokens={statuses:?}",
            output.status.code()
        )
        .into())
    }
}

async fn bob_smb_command(
    fixture: &ProcessFixture,
    key: &str,
    username: &str,
    exchange: Option<&Path>,
    command: &str,
) -> Result<std::process::Output, Box<dyn Error>> {
    // Container timeout bounds the client even if cancellation kills its Docker parent.
    let script = real_smb_command_script().replace("smbclient '", "timeout 25 smbclient '");
    let mut process = smb_client_process(
        fixture.smb_address.port(),
        key.to_owned(),
        exchange,
        &script,
    )?;
    process
        .env("MESHSPAN_SMB_USERNAME", username)
        .env("MESHSPAN_SMB_COMMAND", command);
    bounded_client_output(&process, 30).await
}

async fn bounded_client_output(
    process: &Command,
    seconds: u64,
) -> Result<std::process::Output, Box<dyn Error>> {
    let mut bounded = Command::new("timeout");
    bounded
        .args(["--kill-after=5s", &format!("{seconds}s")])
        .arg(process.get_program())
        .args(process.get_args());
    for (name, value) in process.get_envs() {
        match value {
            Some(value) => {
                bounded.env(name, value);
            }
            None => {
                bounded.env_remove(name);
            }
        }
    }
    // Match the harness's blocking process owner; timeout bounds the child process group.
    Ok(tokio::task::spawn_blocking(move || bounded.output()).await??)
}

async fn run_retained_bob_handle(
    fixture: &ProcessFixture,
    key: &str,
    helper: &Path,
) -> Result<(), Box<dyn Error>> {
    let url = format!(
        "smb://127.0.0.1:{}/process-files/bob-retained.bin",
        fixture.smb_address.port()
    );
    let started = Instant::now();
    let mut process = Command::new(helper);
    process
        .arg(url)
        .env("MESHSPAN_SMB_PASSWORD", key)
        .env("MESHSPAN_SMB_USERNAME", "Bob");
    let output = bounded_client_output(&process, 100).await?;
    require_smb_client_success(&output)?;
    assert!(started.elapsed() >= Duration::from_secs(65));
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("RETAINED_HANDLE_READ_WRITE_CLOSE_VERIFIED")
    );
    Ok(())
}

async fn assert_shared_bytes(
    fixture: &ProcessFixture,
    client: &ClientConfig,
    enrolled: &EnrolledBob,
    files: &SharedFiles,
) -> Result<(), Box<dyn Error>> {
    let volume = &files.volume;
    let exchange = &files.exchange;
    for key in [&enrolled.administrator_key, secret(&enrolled.receipt)?] {
        assert_file_surfaces(fixture.address, client, key, &volume.volume_id, HTTPS_BYTES).await?;
        assert_https_bytes(
            fixture.address,
            client,
            key,
            &volume.volume_id,
            ("bob-retained.bin", SMB_BYTES),
        )
        .await?;
        assert_https_bytes(
            fixture.address,
            client,
            key,
            &volume.volume_id,
            ("admin-seed.bin", ADMIN_BYTES),
        )
        .await?;
    }
    let output = bob_smb_command(
        fixture,
        &enrolled.administrator_key,
        "Administrator",
        Some(exchange.path()),
        "get process-proof.bin /proof/admin-https.bin; get bob-retained.bin /proof/admin-smb.bin",
    )
    .await?;
    require_smb_client_success(&output)?;
    assert_eq!(
        fs::read(exchange.path().join("admin-https.bin"))?,
        HTTPS_BYTES
    );
    assert_eq!(fs::read(exchange.path().join("admin-smb.bin"))?, SMB_BYTES);
    Ok(())
}

async fn assert_https_bytes(
    address: SocketAddr,
    client: &ClientConfig,
    key: &str,
    volume_id: &str,
    file: (&str, &[u8]),
) -> Result<(), Box<dyn Error>> {
    let (path, bytes) = file;
    let authorization = format!("Bearer {key}");
    let headers = [("Authorization", authorization.as_str())];
    let stat = request_with_headers(
        address,
        client,
        "GET",
        &format!("/api/latest/volumes/{volume_id}/objects?path={path}"),
        None,
        &headers,
    )
    .await?;
    require_redacted_status(&stat, "200 OK", "stat shared file over HTTPS")?;
    let stat: meshspan_api_contract::GetObjectResponse =
        serde_json::from_str(response_body(&stat)?)?;
    assert_eq!(
        stat.object.logical_length,
        Some(i64::try_from(bytes.len())?)
    );
    let response = request_with_headers(
        address,
        client,
        "GET",
        &format!(
            "/api/latest/volumes/{volume_id}/file-content?path={path}&offset=0&length={}",
            bytes.len()
        ),
        None,
        &headers,
    )
    .await?;
    require_redacted_status(&response, "200 OK", "read shared bytes over HTTPS")?;
    assert_eq!(response_body(&response)?.as_bytes(), bytes);
    Ok(())
}

async fn assert_commit_replay(
    address: SocketAddr,
    client: &ClientConfig,
    bob_key: &str,
    upload: &CommittedUploadProof,
) -> Result<(), Box<dyn Error>> {
    let response = request_with_headers(
        address,
        client,
        "POST",
        &upload.path,
        Some(&upload.request),
        &[("Authorization", &format!("Bearer {bob_key}"))],
    )
    .await?;
    require_redacted_status(&response, "200 OK", "recover exact Bob upload commit")?;
    let recovered: serde_json::Value = serde_json::from_str(response_body(&response)?)?;
    assert_eq!(
        recovered, upload.response,
        "exact upload commit changed after replay"
    );
    let mut changed: serde_json::Value = serde_json::from_slice(&upload.request)?;
    changed["final_length"] = serde_json::json!(HTTPS_BYTES.len() + 1);
    let changed = serde_json::to_vec(&changed)?;
    let response = request_with_headers(
        address,
        client,
        "POST",
        &upload.path,
        Some(&changed),
        &[("Authorization", &format!("Bearer {bob_key}"))],
    )
    .await?;
    require_redacted_status(
        &response,
        "409 Conflict",
        "reject changed upload commit replay",
    )
}
