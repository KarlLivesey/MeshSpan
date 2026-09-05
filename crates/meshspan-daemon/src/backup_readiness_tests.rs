// SPDX-License-Identifier: GPL-2.0-only

use crate::backup_readiness_service::BackupReadinessService;
use crate::backup_readiness_workspace::ReadinessWorkspace;
use crate::{BackupExportController, BackupExportError, BackupExportRequest, LocalWrappingKey};
use axum::{
    body::Body,
    http::{HeaderMap, Request, StatusCode},
};
use meshspan_backup::{BackupFileEvidence, BackupSourceManifest, VerifiedBackupExport};
use meshspan_contracts::BackupReadReceipt;
use meshspan_domain::{BackupId, MeshId, NodeId, PartitionId, UnixMicros, uuid_v8};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tower::ServiceExt;

const BACKUP: &str = "11111111-1111-4111-8111-111111111111";

struct Unrestorable {
    reads: Arc<AtomicUsize>,
    pause: Option<std::sync::Mutex<std::sync::mpsc::Receiver<()>>>,
}
impl BackupExportController for Unrestorable {
    fn authenticate(&self, headers: &HeaderMap, _: UnixMicros) -> Result<(), BackupExportError> {
        if headers
            .get("x-test-auth")
            .is_some_and(|value| value == "yes")
        {
            Ok(())
        } else {
            Err(BackupExportError::Unauthenticated)
        }
    }
    fn prepare(
        &self,
        headers: &HeaderMap,
        backup_id: BackupId,
        now: UnixMicros,
    ) -> Result<BackupFileEvidence, BackupExportError> {
        self.authenticate(headers, now)?;
        Ok(BackupFileEvidence {
            source: BackupSourceManifest {
                backup_id,
                partition_id: PartitionId::from_bytes(uuid_v8([2; 16]))
                    .map_err(|_| BackupExportError::Failed)?,
                mesh_id: MeshId::from_bytes(uuid_v8([3; 16]))
                    .map_err(|_| BackupExportError::Failed)?,
                last_log_index: 1,
                last_log_term: 1,
                state_revision: 1,
                schema_version: 1,
                byte_length: 1,
                digest: [4; 32],
                created_at: UnixMicros::new(1),
            },
            byte_length: 3,
            digest: Sha256::digest([1, 2, 3]).into(),
        })
    }
    fn stream(
        &self,
        request: &BackupExportRequest,
        sink: &mut VerifiedBackupExport<&mut dyn Write>,
    ) -> Result<BackupReadReceipt, BackupExportError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if let Some(pause) = &self.pause {
            let _bounded_wait = pause
                .lock()
                .map_err(|_| BackupExportError::Failed)?
                .recv_timeout(Duration::from_secs(3));
        }
        sink.write_all(&[1, 2, 3])
            .map_err(|_| BackupExportError::Failed)?;
        Ok(BackupReadReceipt {
            operation_id: request.operation_id,
            byte_length: 3,
            digest: request.evidence.digest,
        })
    }
}

#[tokio::test]
async fn restore_checks_reject_before_io_and_do_not_confuse_valid_ciphertext_hash_with_recovery()
-> Result<(), Box<dyn std::error::Error>> {
    let state = tempfile::tempdir()?;
    let reads = Arc::new(AtomicUsize::new(0));
    let service = BackupReadinessService::new(
        Unrestorable {
            reads: Arc::clone(&reads),
            pause: None,
        },
        LocalWrappingKey::open_or_create(&state.path().join("key"))?,
        NodeId::from_bytes(uuid_v8([4; 16]))?,
        state.path(),
    )?;
    let router = crate::backup_readiness_api::router(service, Duration::from_secs(30))?;
    for (id, query, authenticated, expected) in [
        ("invalid", "?bad=true", false, StatusCode::UNAUTHORIZED),
        ("invalid", "", true, StatusCode::BAD_REQUEST),
        (BACKUP, "?bad=true", true, StatusCode::BAD_REQUEST),
        (BACKUP, "", true, StatusCode::CONFLICT),
    ] {
        let mut request = Request::builder().uri(format!(
            "/api/latest/admin/backups/{id}/restore-readiness{query}"
        ));
        if authenticated {
            request = request.header("x-test-auth", "yes");
        }
        let response = router.clone().oneshot(request.body(Body::empty())?).await?;
        assert_eq!(response.status(), expected);
        assert_eq!(
            std::fs::read_dir(state.path().join("backup-readiness"))?.count(),
            0
        );
        assert_eq!(
            reads.load(Ordering::SeqCst),
            usize::from(expected == StatusCode::CONFLICT)
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_restore_releases_its_private_files_and_worker_capacity()
-> Result<(), Box<dyn std::error::Error>> {
    let state = tempfile::tempdir()?;
    let reads = Arc::new(AtomicUsize::new(0));
    let (release, pause) = std::sync::mpsc::channel();
    let service = BackupReadinessService::new(
        Unrestorable {
            reads: Arc::clone(&reads),
            pause: Some(std::sync::Mutex::new(pause)),
        },
        LocalWrappingKey::open_or_create(&state.path().join("key"))?,
        NodeId::from_bytes(uuid_v8([4; 16]))?,
        state.path(),
    )?;
    let router = crate::backup_readiness_api::router(service, Duration::from_secs(30))?;
    let active = tokio::spawn(router.clone().oneshot(check_request(BACKUP)?));
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while reads.load(Ordering::SeqCst) == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "restore worker did not start"
        );
        tokio::task::yield_now().await;
    }
    assert_eq!(
        router
            .clone()
            .oneshot(check_request("invalid")?)
            .await?
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    active.abort();
    assert!(active.await.is_err());
    release.send(())?;
    loop {
        let response = router.clone().oneshot(check_request("invalid")?).await?;
        if response.status() == StatusCode::BAD_REQUEST {
            break;
        }
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            std::time::Instant::now() < deadline,
            "cancelled worker retained capacity"
        );
        tokio::task::yield_now().await;
    }
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    assert_eq!(
        std::fs::read_dir(state.path().join("backup-readiness"))?.count(),
        0
    );
    Ok(())
}

fn check_request(backup_id: &str) -> Result<Request<Body>, axum::http::Error> {
    Request::builder()
        .uri(format!(
            "/api/latest/admin/backups/{backup_id}/restore-readiness"
        ))
        .header("x-test-auth", "yes")
        .body(Body::empty())
}

#[test]
fn restore_workspaces_clean_crash_residue_and_preserve_siblings()
-> Result<(), Box<dyn std::error::Error>> {
    let state = tempfile::tempdir()?;
    let sibling = state.path().join("keep");
    std::fs::write(&sibling, b"untouched")?;
    let root = ReadinessWorkspace::prepare_root(state.path())?;
    let operation = meshspan_domain::OperationId::from_bytes(uuid_v8([5; 16]))?;
    let workspace = ReadinessWorkspace::create(&root, operation)?;
    assert!(ReadinessWorkspace::create(&root, operation).is_err());
    for name in [
        "container.msb",
        "plaintext.sqlite3",
        "restored.sqlite3-wal",
        "restored.sqlite3-shm",
    ] {
        std::fs::write(workspace.file(name), b"disposable")?;
    }
    std::mem::forget(workspace); // Simulates the destructor not running during process loss.
    assert_eq!(ReadinessWorkspace::prepare_root(state.path())?, root);
    assert_eq!(std::fs::read_dir(&root)?.count(), 0);
    assert_eq!(std::fs::read(sibling)?, b"untouched");
    Ok(())
}

#[test]
fn restore_workspaces_do_not_follow_a_substituted_root() -> Result<(), Box<dyn std::error::Error>> {
    let state = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    std::fs::write(outside.path().join("keep"), b"untouched")?;
    std::os::unix::fs::symlink(outside.path(), state.path().join("backup-readiness"))?;
    assert!(ReadinessWorkspace::prepare_root(state.path()).is_err());
    assert_eq!(std::fs::read(outside.path().join("keep"))?, b"untouched");
    Ok(())
}

#[test]
fn restore_workspaces_recover_interrupted_owner_publication()
-> Result<(), Box<dyn std::error::Error>> {
    let state = tempfile::tempdir()?;
    let root = ReadinessWorkspace::prepare_root(state.path())?;
    let workspace = ReadinessWorkspace::create(
        &root,
        meshspan_domain::OperationId::from_bytes(uuid_v8([6; 16]))?,
    )?;
    std::fs::remove_file(workspace.file("owner"))?;
    std::fs::write(workspace.file(".owner.meshspan-0.tmp"), b"partial marker")?;
    std::mem::forget(workspace);
    ReadinessWorkspace::prepare_root(state.path())?;
    assert_eq!(std::fs::read_dir(root)?.count(), 0);
    Ok(())
}
