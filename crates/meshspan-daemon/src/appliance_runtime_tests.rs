// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::backup_export_service::BackupExportProviders;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authority_restart_uses_the_committed_local_incarnation()
-> Result<(), Box<dyn std::error::Error>> {
    use meshspan_domain::{ApiKeyBundle, AuditEventId, MeshId};
    use meshspan_metadata::CommandContext;

    let directory = tempfile::tempdir()?;
    let storage = directory.path().join("storage");
    std::fs::create_dir(&storage)?;
    let config = HeadlessDaemonConfig::parse([
        OsString::from("--daemon-state-dir"),
        directory.path().join("state").into_os_string(),
        OsString::from("--storage-path"),
        storage.into_os_string(),
    ])?;
    let now = current_time()?;
    let local = DaemonLocalState::open(&config, now)?;
    let transport: Arc<dyn meshspan_cluster::ConsensusMessageTransport> = Arc::new(|_, _| {});
    let (authority, task, _) = start_root_authority(&local, now, Arc::clone(&transport))?;
    authority.begin_election().await?;
    let key = ApiKeyBundle::generate(&mut OperatingSystemRandom)?;
    let command = crate::consensus_authentication_authority_tests::bootstrap_command_with_mesh(
        local.node_id(),
        PrincipalId::from_bytes([2; 16])?,
        &key,
        local.wrapping_public_key(),
        MeshId::from_bytes([4; 16])?,
    )?;
    let committed = authority
        .commit_or_resolve(
            CommandContext {
                operation_id: OperationId::from_bytes([1; 16])?,
                actor_principal_id: PrincipalId::from_bytes([2; 16])?,
                audit_event_id: AuditEventId::from_bytes([3; 16])?,
                occurred_at: now,
                expected_revision: Some(Revision::ZERO),
            },
            command,
        )
        .await;
    authority.shutdown().await?;
    task.await??;
    committed?;
    // Model an already admitted successor projection, not the recovery admission operation.
    // No production caller can use this fixture mutation to bypass that separate barrier.
    let file = local.state_directory().join(ROOT_AUTHORITY_DATABASE);
    let connection = rusqlite::Connection::open(&file)?;
    assert_eq!(
        connection.execute(
            "UPDATE nodes SET current_incarnation = 2 WHERE node_id = ?1",
            [local.node_id().as_bytes().as_slice()],
        )?,
        1
    );
    drop(connection);
    let (authority, task, _) = start_root_authority(&local, now, transport)?;
    let elected = authority.begin_election().await;
    authority.shutdown().await?;
    task.await??;
    elected?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backup_provider_snapshot_is_independent_of_storage_maintenance_lock()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let storage = directory.path().join("storage");
    std::fs::create_dir(&storage)?;
    let config = HeadlessDaemonConfig::parse([
        OsString::from("--daemon-state-dir"),
        directory.path().join("state").into_os_string(),
        OsString::from("--storage-path"),
        storage.into_os_string(),
        OsString::from("--private-endpoint"),
        OsString::from("127.0.0.1:64000"),
    ])?;
    let now = current_time()?;
    let mut node = initialise_daemon_node(&config, now).await?;
    let authority = start_private_authority(&mut node, &config, now).await?;
    let proof = (|| -> Result<(), Box<dyn std::error::Error>> {
        let runtime = compose_storage_runtime(
            &node.local_state,
            &authority.authority,
            &node.private_network,
            authority.removal_authority_epoch,
            config.storage().storage_paths().to_vec(),
            now,
        )?;
        let snapshot = BackupExportTargetSnapshot::from_runtime(&runtime.targets)?;
        // This is the real runtime's mutex, also held during repair and backup work.
        // Obtaining a provider inventory must neither wait for it nor report Busy.
        let _maintenance = runtime.targets.lock().map_err(|_| "runtime poisoned")?;
        assert!(snapshot.snapshot()?.is_empty());
        let startup = Arc::clone(&snapshot.startup);
        let deadline = now
            .checked_add(DurationMicros::new(5_000_000))
            .ok_or("deadline overflow")?;
        let waiter = std::thread::spawn(move || snapshot.wait_until_initialised(deadline));
        // Signal while maintenance is still locked: export admission must not acquire it.
        startup.finish_scan()?;
        waiter.join().map_err(|_| "export waiter panicked")??;
        Ok(())
    })();
    let shutdown = authority.authority.shutdown().await;
    let stopped = authority.authority_task.await;
    shutdown?;
    stopped??;
    proof
}

#[test]
fn maintenance_claims_preserve_the_live_worker_incarnation()
-> Result<(), Box<dyn std::error::Error>> {
    let worker = (NodeId::from_bytes([101; 16])?, 7);
    let actor = PrincipalId::from_bytes([102; 16])?;
    let target_id = TargetId::from_bytes([103; 16])?;
    let now = UnixMicros::new(1_000_000);
    let work_id = meshspan_domain::WorkId::from_bytes([104; 16])?;
    let assignment = |subject| crate::MaintenanceDispatchAssignment {
        work_id,
        subject,
        demand: meshspan_work::WorkDemand {
            in_flight_bytes: 4096,
        },
        priority: 1,
        claim_generation: 3,
    };
    let scrub = maintenance_verification_execution(
        assignment(WorkSubject::Scrub {
            target_id,
            target_generation: 2,
        }),
        WorkKind::Scrub,
        worker,
        actor,
        now,
    )
    .map_err(|()| "scrub execution rejected")?;
    let reconcile = maintenance_verification_execution(
        assignment(WorkSubject::Reconcile {
            target_id,
            target_generation: 2,
        }),
        WorkKind::Reconcile,
        worker,
        actor,
        now,
    )
    .map_err(|()| "reconciliation execution rejected")?;
    let drain = maintenance_target_drain_execution(
        assignment(WorkSubject::Drain(meshspan_work::DrainScope::Target {
            target_id,
            target_generation: 2,
        })),
        worker,
        actor,
        Revision::new(8),
        now,
    )
    .map_err(|()| "drain execution rejected")?;
    for claim in [scrub.claim, reconcile.claim, drain.claim] {
        assert_eq!(claim.worker_node_id, worker.0);
        assert_eq!(claim.worker_incarnation, 7);
        assert_eq!(claim.claim_generation, 3);
    }
    Ok(())
}

#[test]
fn backup_provider_startup_retains_completion_and_bounds_waiting()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::backup_export_service::BackupProviderStartup;
    let startup = BackupProviderStartup::default();
    let now = current_time()?;
    assert_eq!(
        startup.wait(now),
        Err(crate::BackupExportError::Unavailable)
    );
    let deadline = now
        .checked_add(DurationMicros::new(1_000))
        .ok_or("deadline overflow")?;
    assert_eq!(
        startup.wait(deadline),
        Err(crate::BackupExportError::Unavailable)
    );
    startup.finish_scan()?;
    let deadline = current_time()?
        .checked_add(DurationMicros::new(5_000_000))
        .ok_or("deadline overflow")?;
    // Completion is retained for later exports; no notification has to be in flight.
    startup.wait(deadline)?;
    startup.wait(deadline)?;
    Ok(())
}
