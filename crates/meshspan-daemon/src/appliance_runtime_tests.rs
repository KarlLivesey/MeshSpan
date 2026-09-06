// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::backup_export_service::BackupExportProviders;

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
        Ok(())
    })();
    let shutdown = authority.authority.shutdown().await;
    let stopped = authority.authority_task.await;
    shutdown?;
    stopped??;
    proof
}
