// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::backup_export_service::BackupExportProviders;
use std::path::Path;

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
        waiter
            .join()
            .map_err(|_| "export waiter panicked")?
            .map_err(|error| {
                format!(
                    "export startup wait at {:?}, deadline {deadline:?}: {error}",
                    current_time()
                )
            })?;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn service_failure_drains_owned_blocking_receipt_before_returning()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let config = lifecycle_config(directory.path(), "127.0.0.1:0")?;
    let local = DaemonLocalState::open(&config, current_time()?)?;
    let (authority, authority_task, _) =
        start_root_authority(&local, current_time()?, Arc::new(|_, _| {}))?;
    let readiness =
        crate::update_readiness::UpdateReadiness::new(local.state_directory(), authority.clone())
            .map_err(|()| "readiness setup failed")?;
    let receipt = directory.path().join("committed-receipt");
    let (mut tasks, started, release, completed) = blocked_receipt_writer(receipt.clone());
    tokio::time::timeout(Duration::from_secs(5), started).await??;
    let failed = tasks.spawn(async { Err(DaemonProcessError::PrivateNetworkState) });
    tokio::time::timeout(Duration::from_secs(5), async {
        while !failed.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let (stop, _) = tokio::sync::watch::channel(false);
    let cleanup_stop = stop.subscribe();
    tasks.spawn(async move {
        wait_for_shutdown(cleanup_stop).await;
        Err(DaemonProcessError::Clock)
    });
    let supervision = supervise_services(tasks, stop, std::future::pending(), readiness.serving());
    tokio::pin!(supervision);
    // Both the primary failure and the still-running blocking writer are now deterministic.
    let immediate = std::future::poll_fn(|context| {
        std::task::Poll::Ready(match supervision.as_mut().poll(context) {
            std::task::Poll::Ready(result) => Some(result),
            std::task::Poll::Pending => None,
        })
    })
    .await;
    let returned_before_durable_completion = immediate.is_some();
    let readiness_withdrawn = readiness.local_ready().await.is_err();
    release.send(())?;
    tokio::time::timeout(Duration::from_secs(5), completed).await??;
    let result = match immediate {
        Some(result) => result,
        None => tokio::time::timeout(Duration::from_secs(5), supervision).await?,
    };
    authority.shutdown().await?;
    authority_task.await??;
    assert!(matches!(result, Err(DaemonProcessError::Shutdown {
        primary, additional_failures: 1,
    }) if matches!(*primary, DaemonProcessError::PrivateNetworkState)));
    assert_eq!(std::fs::read(receipt)?, b"durable-operation-7");
    assert!(!returned_before_durable_completion);
    assert!(readiness_withdrawn);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_public_listener_bind_stops_and_joins_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let config = lifecycle_config(directory.path(), &occupied.local_addr()?.to_string())?;
    let now = current_time()?;
    let mut node = initialise_daemon_node(&config, now).await?;
    let private = start_private_authority(&mut node, &config, now).await?;
    let observer = private.authority.clone();
    let (restart, requests) = tokio::sync::mpsc::unbounded_channel();
    let services = compose_appliance_services(&mut node, &private, &config, restart, now)?;
    let shutdown = std::future::pending();
    tokio::pin!(shutdown);
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        serve_daemon_cycle(
            &config,
            services,
            private.authority,
            private.authority_task,
            requests,
            shutdown,
        ),
    )
    .await?;
    let authority_survived = observer.observe().await.is_ok();
    if authority_survived {
        observer.shutdown().await?;
    }
    assert!(matches!(result, Err(DaemonProcessError::Http01(_))));
    assert!(!authority_survived);
    Ok(())
}

fn lifecycle_config(
    directory: &Path,
    http01: &str,
) -> Result<HeadlessDaemonConfig, Box<dyn std::error::Error>> {
    let storage = directory.join("storage");
    std::fs::create_dir(&storage)?;
    Ok(HeadlessDaemonConfig::parse([
        OsString::from("--storage-path"),
        storage.into_os_string(),
        OsString::from("--daemon-state-dir"),
        directory.join("state").into_os_string(),
        OsString::from("--http01-listen"),
        OsString::from(http01),
        OsString::from("--https-listen"),
        OsString::from(http01),
        OsString::from("--smb-listen"),
        OsString::from("127.0.0.1:0"),
        OsString::from("--private-listen"),
        OsString::from("127.0.0.1:0"),
        OsString::from("--private-endpoint"),
        OsString::from("127.0.0.1:64000"),
    ])?)
}

type BlockedReceiptWriter = (
    tokio::task::JoinSet<Result<(), DaemonProcessError>>,
    tokio::sync::oneshot::Receiver<()>,
    std::sync::mpsc::Sender<()>,
    tokio::sync::oneshot::Receiver<()>,
);

fn blocked_receipt_writer(path: PathBuf) -> BlockedReceiptWriter {
    let (started, startup) = tokio::sync::oneshot::channel();
    let (release, released) = std::sync::mpsc::channel();
    let (completed, completion) = tokio::sync::oneshot::channel();
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(async move {
        tokio::task::spawn_blocking(move || {
            started
                .send(())
                .map_err(|()| DaemonProcessError::StorageTargetTaskStopped)?;
            released
                .recv()
                .map_err(|_| DaemonProcessError::StorageTargetTaskStopped)?;
            std::fs::write(&path, b"durable-operation-7")
                .map_err(|_| DaemonProcessError::LocalStateWorker)?;
            std::fs::File::open(path)
                .and_then(|file| file.sync_all())
                .map_err(|_| DaemonProcessError::LocalStateWorker)?;
            completed
                .send(())
                .map_err(|()| DaemonProcessError::StorageTargetTaskStopped)
        })
        .await
        .map_err(|_| DaemonProcessError::StorageTargetTaskStopped)?
    });
    (tasks, startup, release, completion)
}
