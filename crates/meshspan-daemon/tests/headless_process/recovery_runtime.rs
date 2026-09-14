// SPDX-License-Identifier: GPL-2.0-only

//! Actual replacement admission, interrupted-intent recovery and normal HTTPS startup.

use super::{Error, ProcessCleanup, ProcessFixture};
use meshspan_daemon::{
    ClaimEnsureDisposition, DaemonLocalState, HeadlessDaemonConfig, OperatingSystemClock,
};
use meshspan_domain::Clock as _;
use std::{
    fs,
    net::UdpSocket,
    path::Path,
    process::{Child, Command},
};

pub(super) async fn admit_and_start(
    root: &ProcessFixture,
    directory: &Path,
    permission: &Path,
    reservations: [UdpSocket; 2],
) -> Result<(), Box<dyn Error>> {
    let fixtures = prepare_admitted_fixtures(root, directory, permission, &reservations).await?;
    // These ports were reserved before signing selection and are released only for the daemons.
    drop(reservations);
    let mut processes = ProcessCleanup(Vec::new());
    for fixture in &fixtures {
        processes.0.push(fixture.start()?);
    }
    for (fixture, process) in fixtures.iter().zip(&mut processes.0) {
        wait_for_configured(fixture, process).await?;
    }
    let storage = fixtures.get(1).ok_or("storage fixture missing")?;
    let target = wait_for_registered_storage(storage).await?;
    let gateway = fixtures.first().ok_or("gateway fixture missing")?;
    let repository = meshspan_metadata::AuthoritativeRepository::new(
        meshspan_metadata::PartitionDatabase::open_existing(
            &gateway.state_path.join("root-authority.sqlite3"),
            OperatingSystemClock.now(),
        )?,
    );
    assert!(
        repository
            .storage_target_provider_context(target.intent.node_id, target.intent.target_id)?
            .is_some()
    );
    assert!(
        !repository
            .load_active_consensus_quorum_plan()?
            .ok_or("missing plan")?
            .members()
            .contains(&target.intent.node_id)
    );
    drop(repository);
    super::recovery_storage_control::reject_returning_identity(root, gateway, storage).await?;
    super::recovery_storage_control::prove(gateway, storage, &target).await?;
    super::recovery_live_file::verify(root, gateway).await?;
    super::recovery_live_file::create_new_files(root, gateway).await?;
    super::private_certificates::renew_storage_node(gateway, storage).await?;
    super::recovery_storage_io::prove(
        gateway,
        storage,
        &target,
        super::recovery_storage_io::Scenario::RoundTrip,
    )
    .await?;
    let process = processes.0.get_mut(1).ok_or("storage process missing")?;
    restart(storage, process).await?;
    let reopened = wait_for_registered_storage(storage).await?;
    assert_eq!(reopened.intent.target_id, target.intent.target_id);
    super::recovery_storage_io::prove(
        gateway,
        storage,
        &target,
        super::recovery_storage_io::Scenario::RetainedRead,
    )
    .await?;
    let process = processes.0.first_mut().ok_or("gateway process missing")?;
    restart(gateway, process).await?;
    super::private_certificates::verify_storage_node(gateway, storage).await?;
    super::recovery_storage_control::prove(gateway, storage, &reopened).await?;
    super::recovery_storage_control::reject_returning_identity(root, gateway, storage).await?;
    super::recovery_live_file::verify(root, gateway).await?;
    super::recovery_live_file::verify_new_files(root, gateway).await?;
    super::recovery_storage_io::prove_committed_cleanup(
        root,
        gateway,
        storage,
        &target,
        processes.0.get_mut(1).ok_or("storage process missing")?,
    )
    .await?;
    super::stop_processes(&mut processes.0);
    Ok(())
}

/// Readiness observes premature exit and the same admission invariants on initial boot/restart.
async fn wait_for_configured(
    fixture: &ProcessFixture,
    process: &mut Child,
) -> Result<(), Box<dyn Error>> {
    let client = super::wait_for_client(&fixture.identity_path).await?;
    let ready = super::wait_for_status(fixture.address, &client, "configured");
    tokio::pin!(ready);
    let mut poll = tokio::time::interval(super::RETRY_INTERVAL);
    loop {
        tokio::select! {
            result = &mut ready => { result?; break; }
            _ = poll.tick() => {
                if let Some(exit) = process.try_wait()? {
                    return Err(format!("recovered daemon {} exited before HTTPS readiness: {exit}", fixture.state_path.display()).into());
                }
            }
        }
    }
    assert!(!fixture.claim_path.exists());
    assert!(fixture.state_path.join("state.auth").exists());
    assert!(fixture.state_path.join("consensus.permission").exists());
    Ok(())
}

pub(super) async fn restart(
    fixture: &ProcessFixture,
    process: &mut Child,
) -> Result<(), Box<dyn Error>> {
    process.kill()?;
    process.wait()?;
    *process = fixture.start()?;
    wait_for_configured(fixture, process).await
}

/// Offline admission/reopen invariants complete before any replacement process starts.
async fn prepare_admitted_fixtures(
    root: &ProcessFixture,
    directory: &Path,
    permission: &Path,
    reservations: &[UdpSocket; 2],
) -> Result<Vec<ProcessFixture>, Box<dyn Error>> {
    let mut fixtures = Vec::new();
    for (label, reservation) in ["gateway", "storage"].into_iter().zip(reservations) {
        let mut fixture = ProcessFixture::new()?;
        fixture.daemon_binary = root.daemon_binary.clone();
        fixture.state_path = directory.join(format!("installed-{label}"));
        fixture.storage_path = directory.join(format!("runtime-storage-{label}"));
        fs::create_dir(&fixture.storage_path)?;
        fixture.identity_path = fixture.state_path.join("secrets/node-identity.pk8");
        fixture.claim_path = fixture.state_path.join("first-boot.claim");
        fixture.private_address = reservation.local_addr()?;
        if label == "gateway" {
            interrupted_admission(&fixture, permission).await?;
        } else {
            let report =
                super::recovery_state_set::accepted(admit_command(&fixture, permission)).await?;
            assert_eq!(report["consensus_admitted"], true);
        }
        let config = HeadlessDaemonConfig::parse(
            fixture
                .command()
                .get_args()
                .map(std::ffi::OsStr::to_os_string),
        )?;
        for _ in 0..2 {
            let local = DaemonLocalState::open(&config, OperatingSystemClock.now())?;
            assert_eq!(
                local.claim_outcome().disposition,
                ClaimEnsureDisposition::RecoveryAuthorized
            );
            assert_eq!(local.claim_outcome().claim_id, None);
            assert!(local.local_database().latest_local_claim()?.is_none());
            assert!(local.local_database().local_setup()?.is_none());
        }
        fixtures.push(fixture);
    }
    Ok(fixtures)
}

async fn wait_for_registered_storage(
    fixture: &ProcessFixture,
) -> Result<meshspan_metadata::LocalTargetRecord, Box<dyn Error>> {
    let directory = fixture.state_path.clone();
    let expected = fs::canonicalize(&fixture.storage_path)?;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
    let mut tick = tokio::time::interval(super::RETRY_INTERVAL);
    loop {
        tick.tick().await;
        let directory = directory.clone();
        let expected = expected.clone();
        let record = tokio::task::spawn_blocking(move || {
            use std::os::unix::ffi::OsStrExt as _;
            let database = meshspan_metadata::LocalDatabase::open_existing(
                &directory.join("local.sqlite3"),
                OperatingSystemClock.now(),
            )
            .map_err(|e| e.to_string())?;
            let record = database
                .local_targets()
                .map_err(|e| e.to_string())?
                .into_iter()
                .find(|record| {
                    record.state == meshspan_metadata::LocalTargetState::Active
                        && record.intent.canonical_path == expected.as_os_str().as_bytes()
                });
            if let Some(record) = &record {
                let repository = meshspan_metadata::AuthoritativeRepository::new(
                    meshspan_metadata::PartitionDatabase::open_existing(
                        &directory.join("root-authority.sqlite3"),
                        OperatingSystemClock.now(),
                    )
                    .map_err(|e| e.to_string())?,
                );
                assert!(
                    repository
                        .resolve_operation(record.intent.registration_operation_id)
                        .map_err(|e| e.to_string())?
                        .is_some()
                );
                assert!(
                    !repository
                        .load_active_consensus_quorum_plan()
                        .map_err(|e| e.to_string())?
                        .ok_or("missing plan")?
                        .members()
                        .contains(&record.intent.node_id)
                );
            }
            Ok::<_, String>(record)
        })
        .await??;
        if let Some(record) = record {
            return Ok(record);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(
                "storage-only daemon did not complete remote-authority folder registration".into(),
            );
        }
    }
}

async fn interrupted_admission(
    fixture: &ProcessFixture,
    permission: &Path,
) -> Result<(), Box<dyn Error>> {
    let database = fixture.state_path.join("root-authority.sqlite3");
    let held = fixture.state_path.join("held-root.sqlite3");
    // No connection is live: the preceding installer and inspection have completed.
    assert!(
        !fixture
            .state_path
            .join("root-authority.sqlite3-wal")
            .exists()
    );
    fs::rename(&database, &held)?;
    let result = super::offline_backup::run_command(admit_command(fixture, permission)).await?;
    fs::rename(&held, &database)?;
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert_eq!(
        fs::read(fixture.state_path.join("consensus.permission"))?,
        fs::read(permission)?
    );
    assert!(!fixture.claim_path.exists());
    // Normal opening, not a second admission command, resumes the durable signed intent.
    Ok(())
}

fn admit_command(fixture: &ProcessFixture, permission: &Path) -> Command {
    let mut command = Command::new(&fixture.daemon_binary);
    command
        .arg("admit-recovery-state")
        .arg(&fixture.state_path)
        .arg(permission);
    command
}
