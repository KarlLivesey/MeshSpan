// SPDX-License-Identifier: GPL-2.0-only

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;

use meshspan_domain::UnixMicros;
use meshspan_metadata::LocalClaimState;
use tempfile::tempdir;

use crate::{
    ClaimEnsureDisposition, ClaimFile, DaemonLocalState, DaemonLocalStateError,
    HeadlessDaemonConfig,
};

#[test]
fn first_start_and_restart_preserve_one_locked_identity_and_claim()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let state_path = directory.path().join("state");
    let storage_path = directory.path().join("storage");
    fs::create_dir(&storage_path)?;
    let config = config(&state_path, &storage_path)?;

    let first = DaemonLocalState::open(&config, UnixMicros::new(10))?;
    assert_eq!(
        first.claim_outcome().disposition,
        ClaimEnsureDisposition::Created
    );
    assert_eq!(
        fs::metadata(first.state_directory())?.permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(first.claim_output_path())?
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let node_id = first.node_id();
    let fingerprint = first.public_key_fingerprint();
    let wrapping_public_key = first.wrapping_public_key();
    assert_eq!(
        fs::metadata(state_path.join("secrets/node-wrapping-key.x25519"))?
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(state_path.join("secrets/totp-ceremony.key"))?
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    first.open_totp_ceremony_key()?;
    assert_eq!(
        fs::metadata(state_path.join("secrets/passkey-ceremony.key"))?
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    first.open_passkey_ceremony_key()?;
    let claim = ClaimFile::read(first.claim_output_path())?;
    let record = first
        .local_database()
        .local_claim_record(claim.claim_id())?
        .ok_or("claim record missing")?;
    assert_eq!(record.node_public_key_fingerprint, fingerprint);
    assert!(first.bootstrap_server_config().is_ok());
    assert!(matches!(
        DaemonLocalState::open(&config, UnixMicros::new(11)),
        Err(DaemonLocalStateError::AlreadyRunning)
    ));
    drop(first);

    let reopened = DaemonLocalState::open(&config, UnixMicros::new(12))?;
    assert_eq!(reopened.node_id(), node_id);
    assert_eq!(reopened.public_key_fingerprint(), fingerprint);
    assert_eq!(reopened.wrapping_public_key(), wrapping_public_key);
    assert_eq!(
        reopened.claim_outcome().disposition,
        ClaimEnsureDisposition::Existing
    );
    Ok(())
}

#[test]
fn missing_restart_stable_totp_ceremony_key_fails_closed() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let state_path = directory.path().join("state");
    let storage_path = directory.path().join("storage");
    fs::create_dir(&storage_path)?;
    let config = config(&state_path, &storage_path)?;
    let state = DaemonLocalState::open(&config, UnixMicros::new(10))?;
    drop(state);
    fs::remove_file(state_path.join("secrets/totp-ceremony.key"))?;
    assert!(matches!(
        DaemonLocalState::open(&config, UnixMicros::new(11)),
        Err(DaemonLocalStateError::TotpCeremonyKey(_))
    ));
    Ok(())
}

#[test]
fn missing_restart_stable_passkey_ceremony_key_fails_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let state_path = directory.path().join("state");
    let storage_path = directory.path().join("storage");
    fs::create_dir(&storage_path)?;
    let config = config(&state_path, &storage_path)?;
    let state = DaemonLocalState::open(&config, UnixMicros::new(10))?;
    drop(state);
    fs::remove_file(state_path.join("secrets/passkey-ceremony.key"))?;
    assert!(matches!(
        DaemonLocalState::open(&config, UnixMicros::new(11)),
        Err(DaemonLocalStateError::PasskeyCeremonyKey(_))
    ));
    Ok(())
}

#[test]
fn consumed_claim_stays_inactive_after_restart() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let state_path = directory.path().join("state");
    let storage_path = directory.path().join("storage");
    fs::create_dir(&storage_path)?;
    let config = config(&state_path, &storage_path)?;
    let mut state = DaemonLocalState::open(&config, UnixMicros::new(10))?;
    let claim = ClaimFile::read(state.claim_output_path())?;
    let encoded = claim.expose_encoded();
    let claim_id = claim.claim_id();
    crate::FirstBootClaimService::consume(
        state.local_database_mut(),
        &encoded,
        &state_path.join("first-boot.claim"),
        UnixMicros::new(20),
    )?;
    assert!(!state.claim_output_path().exists());
    assert_eq!(
        state
            .local_database()
            .local_claim_record(claim_id)?
            .ok_or("claim record missing")?
            .state,
        LocalClaimState::Consumed
    );
    drop(state);

    let reopened = DaemonLocalState::open(&config, UnixMicros::new(30))?;
    assert_eq!(
        reopened.claim_outcome().disposition,
        ClaimEnsureDisposition::Inactive
    );
    assert!(!reopened.claim_output_path().exists());
    Ok(())
}

#[test]
fn overlap_and_permissive_state_directories_fail_closed() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let storage_path = directory.path().join("storage");
    fs::create_dir(&storage_path)?;
    let nested_state = storage_path.join("state");
    let overlap = config(&nested_state, &storage_path)?;
    assert!(matches!(
        DaemonLocalState::open(&overlap, UnixMicros::new(10)),
        Err(DaemonLocalStateError::StateStorageOverlap)
    ));

    let permissive_state = directory.path().join("permissive");
    fs::create_dir(&permissive_state)?;
    fs::set_permissions(&permissive_state, fs::Permissions::from_mode(0o755))?;
    let permissive = config(&permissive_state, &storage_path)?;
    assert!(matches!(
        DaemonLocalState::open(&permissive, UnixMicros::new(20)),
        Err(DaemonLocalStateError::UnsafeStateDirectory)
    ));
    Ok(())
}

fn config(
    state_path: &std::path::Path,
    storage_path: &std::path::Path,
) -> Result<HeadlessDaemonConfig, crate::HeadlessDaemonConfigError> {
    HeadlessDaemonConfig::parse([
        OsString::from("--daemon-state-dir"),
        state_path.as_os_str().to_owned(),
        OsString::from("--storage-path"),
        storage_path.as_os_str().to_owned(),
        OsString::from("--https-listen"),
        OsString::from("127.0.0.1:0"),
    ])
}
