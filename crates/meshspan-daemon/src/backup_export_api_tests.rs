// SPDX-License-Identifier: GPL-2.0-only

use crate::{
    BackupExportController, BackupExportError, BackupExportRequest, backup_export_api_router,
};
use axum::{
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode},
};
use meshspan_backup::{BackupFileEvidence, BackupSourceManifest, VerifiedBackupExport};
use meshspan_contracts::BackupReadReceipt;
use meshspan_domain::{BackupId, MeshId, PartitionId, UnixMicros};
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    num::NonZeroUsize,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use tower::ServiceExt;

const BACKUP: &str = "11111111-1111-4111-8111-111111111111";

#[derive(Clone, Copy)]
enum Behaviour {
    Exact,
    Short,
    Corrupt,
    WrongReceipt,
    Revoke,
    InvalidEvidence,
}

struct Controller {
    behaviour: Behaviour,
    revoked: AtomicBool,
}
impl Controller {
    fn new(behaviour: Behaviour) -> Self {
        Self {
            behaviour,
            revoked: AtomicBool::new(false),
        }
    }
}
impl BackupExportController for Controller {
    fn authenticate(&self, headers: &HeaderMap, _: UnixMicros) -> Result<(), BackupExportError> {
        if self.revoked.load(Ordering::SeqCst)
            || headers
                .get("x-test-auth")
                .is_none_or(|value| value != "yes")
        {
            return Err(BackupExportError::Unauthenticated);
        }
        Ok(())
    }
    fn prepare(
        &self,
        headers: &HeaderMap,
        backup_id: BackupId,
        now: UnixMicros,
    ) -> Result<BackupFileEvidence, BackupExportError> {
        self.authenticate(headers, now)?;
        let source = BackupSourceManifest {
            backup_id,
            partition_id: PartitionId::from_bytes([2; 16])
                .map_err(|_| BackupExportError::Failed)?,
            mesh_id: MeshId::from_bytes([3; 16]).map_err(|_| BackupExportError::Failed)?,
            last_log_index: 1,
            last_log_term: 1,
            state_revision: 1,
            schema_version: 1,
            byte_length: 1,
            digest: [4; 32],
            created_at: UnixMicros::new(1),
        };
        Ok(BackupFileEvidence {
            source,
            byte_length: if matches!(self.behaviour, Behaviour::InvalidEvidence) {
                0
            } else {
                200_000
            },
            digest: Sha256::digest(vec![42; 200_000]).into(),
        })
    }
    fn stream(
        &self,
        request: &BackupExportRequest,
        sink: &mut VerifiedBackupExport<&mut dyn Write>,
    ) -> Result<BackupReadReceipt, BackupExportError> {
        let source = match self.behaviour {
            Behaviour::Short => vec![42; 199_999],
            Behaviour::Corrupt => vec![43; 200_000],
            _ => vec![42; 200_000],
        };
        sink.write_all(&source)
            .map_err(|_| BackupExportError::Unavailable)?;
        if matches!(self.behaviour, Behaviour::Revoke) {
            self.revoked.store(true, Ordering::SeqCst);
        }
        Ok(BackupReadReceipt {
            operation_id: request.operation_id,
            byte_length: request.evidence.byte_length,
            digest: if matches!(self.behaviour, Behaviour::WrongReceipt) {
                [9; 32]
            } else {
                request.evidence.digest
            },
        })
    }
}

#[tokio::test]
async fn backup_export_checks_auth_before_path_and_rejects_bad_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    for (identifier, query, authenticated, behaviour, expected) in [
        (
            "invalid",
            "?unexpected=true",
            false,
            Behaviour::Exact,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "invalid",
            "",
            true,
            Behaviour::Exact,
            StatusCode::BAD_REQUEST,
        ),
        (
            BACKUP,
            "?unexpected=true",
            true,
            Behaviour::Exact,
            StatusCode::BAD_REQUEST,
        ),
        (
            BACKUP,
            "",
            true,
            Behaviour::InvalidEvidence,
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
    ] {
        let router = backup_export_api_router(
            Controller::new(behaviour),
            NonZeroUsize::MIN,
            Duration::from_secs(5),
        )?;
        let mut request = Request::get(format!(
            "/api/latest/admin/backups/{identifier}/export{query}"
        ));
        if authenticated {
            request = request.header("x-test-auth", "yes");
        }
        let response = router.oneshot(request.body(Body::empty())?).await?;
        assert_eq!(response.status(), expected);
        assert_eq!(response.headers()["content-type"], "application/json");
        assert!(!response.headers().contains_key("meshspan-backup-id"));
    }
    Ok(())
}

#[tokio::test]
async fn backup_export_only_completes_exact_authorised_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    for behaviour in [
        Behaviour::Exact,
        Behaviour::Short,
        Behaviour::Corrupt,
        Behaviour::WrongReceipt,
        Behaviour::Revoke,
    ] {
        let router = backup_export_api_router(
            Controller::new(behaviour),
            NonZeroUsize::MIN,
            Duration::from_secs(5),
        )?;
        let response = router
            .oneshot(
                Request::get(format!("/api/latest/admin/backups/{BACKUP}/export"))
                    .header("x-test-auth", "yes")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-length"], "200000");
        assert_eq!(response.headers()["meshspan-backup-id"], BACKUP);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let received = to_bytes(response.into_body(), 200_001).await;
        if matches!(behaviour, Behaviour::Exact) {
            assert_eq!(received?, vec![42; 200_000]);
        } else {
            assert!(received.is_err());
        }
    }
    Ok(())
}
