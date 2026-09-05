// SPDX-License-Identifier: GPL-2.0-only

//! A current gateway proves decryption and isolated SQLite recovery, not offline-key custody.

use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Instant;

use axum::http::HeaderMap;
use meshspan_backup::{BackupExportEvidence, BackupFileEvidence, VerifiedBackupExport};
use meshspan_domain::{BackupId, NodeId, OperationId, Revision, UnixMicros};
use meshspan_metadata::{LogPosition, PartitionBackupManifest, restore_partition_backup};

use crate::backup_readiness_workspace::ReadinessWorkspace;
use crate::{BackupExportController, BackupExportError, BackupExportRequest, LocalWrappingKey};

pub(crate) struct BackupReadinessService<C> {
    pub(crate) export: C,
    key: LocalWrappingKey,
    node_id: NodeId,
    workspace_root: PathBuf,
}

impl<C: BackupExportController> BackupReadinessService<C> {
    pub(crate) fn new(
        export: C,
        key: LocalWrappingKey,
        node_id: NodeId,
        state_directory: &std::path::Path,
    ) -> io::Result<Self> {
        Ok(Self {
            export,
            key,
            node_id,
            workspace_root: ReadinessWorkspace::prepare_root(state_directory)?,
        })
    }

    pub(crate) fn check(
        &self,
        request: &BackupReadinessRequest,
    ) -> Result<meshspan_api_contract::BackupReadinessResponse, BackupExportError> {
        request.budget.check()?;
        let now = current_time()?;
        let evidence = self
            .export
            .prepare(&request.headers, request.backup_id, now)?;
        if evidence.source.backup_id != request.backup_id {
            return Err(BackupExportError::Failed);
        }
        evidence
            .source
            .validate()
            .map_err(|_| BackupExportError::Failed)?;
        let workspace = ReadinessWorkspace::create(&self.workspace_root, request.operation_id)
            .map_err(|_| BackupExportError::Failed)?;
        let result = self.check_workspace(request, evidence, &workspace);
        workspace.cleanup().map_err(|_| BackupExportError::Failed)?;
        result
    }

    fn check_workspace(
        &self,
        request: &BackupReadinessRequest,
        evidence: BackupFileEvidence,
        workspace: &ReadinessWorkspace,
    ) -> Result<meshspan_api_contract::BackupReadinessResponse, BackupExportError> {
        self.download(request, evidence, workspace)?;
        request.budget.check()?;
        self.key
            .restore_backup(
                &workspace.file("container.msb"),
                &workspace.file("plaintext.sqlite3"),
                evidence,
            )
            .map_err(|_| BackupExportError::NotReady)?;
        request.budget.check()?;
        let source = evidence.source;
        let manifest = PartitionBackupManifest {
            backup_id: source.backup_id,
            partition_id: source.partition_id,
            mesh_id: source.mesh_id,
            applied_position: LogPosition {
                index: source.last_log_index,
                term: source.last_log_term,
            },
            state_revision: Revision::new(source.state_revision),
            schema_version: source.schema_version,
            byte_length: source.byte_length,
            digest: source.digest,
            created_at: source.created_at,
        };
        let restored = restore_partition_backup(
            &workspace.file("plaintext.sqlite3"),
            &workspace.file("restored.sqlite3"),
            manifest,
            current_time()?,
        )
        .map_err(|_| BackupExportError::NotReady)?;
        drop(restored);
        request.budget.check()?;
        let now = current_time()?;
        if self
            .export
            .prepare(&request.headers, request.backup_id, now)?
            != evidence
        {
            return Err(BackupExportError::Unavailable);
        }
        Ok(meshspan_api_contract::BackupReadinessResponse {
            backup_id: crate::create_mesh_setup::format_uuid(source.backup_id.as_bytes()),
            checked_by_node_id: crate::create_mesh_setup::format_uuid(self.node_id.as_bytes()),
            partition_id: crate::create_mesh_setup::format_uuid(source.partition_id.as_bytes()),
            source_log_index: source.last_log_index.to_string(),
            source_log_term: source.last_log_term.to_string(),
            state_revision: source.state_revision.to_string(),
            checked_at_epoch_micros: now.get(),
            verification: meshspan_api_contract::BackupReadinessVerification::GatewayKey,
        })
    }

    fn download(
        &self,
        request: &BackupReadinessRequest,
        evidence: BackupFileEvidence,
        workspace: &ReadinessWorkspace,
    ) -> Result<(), BackupExportError> {
        let mut file = workspace
            .encrypted_file()
            .map_err(|_| BackupExportError::Failed)?;
        let mut sink = CheckedSink {
            file: &mut file,
            budget: &request.budget,
        };
        let mut verified = VerifiedBackupExport::from_evidence(
            &mut sink as &mut dyn Write,
            BackupExportEvidence {
                operation_id: request.operation_id,
                byte_length: evidence.byte_length,
                digest: evidence.digest,
            },
        )
        .map_err(|_| BackupExportError::Failed)?;
        let receipt = self.export.stream(
            &BackupExportRequest {
                headers: request.headers.clone(),
                evidence,
                operation_id: request.operation_id,
                deadline: request.deadline,
            },
            &mut verified,
        )?;
        verified
            .finish(receipt)
            .map_err(|_| BackupExportError::NotReady)?;
        file.sync_all().map_err(|_| BackupExportError::Failed)
    }
}

pub(crate) struct BackupReadinessRequest {
    pub(crate) headers: HeaderMap,
    pub(crate) backup_id: BackupId,
    pub(crate) operation_id: OperationId,
    pub(crate) deadline: UnixMicros,
    pub(crate) budget: ReadinessBudget,
}

#[derive(Clone)]
pub(crate) struct ReadinessBudget {
    pub(crate) cancelled: Arc<AtomicBool>,
    pub(crate) deadline: Instant,
}
impl ReadinessBudget {
    pub(crate) fn check(&self) -> Result<(), BackupExportError> {
        if self.cancelled.load(Ordering::Acquire) || Instant::now() >= self.deadline {
            Err(BackupExportError::Unavailable)
        } else {
            Ok(())
        }
    }
}

struct CheckedSink<'a> {
    file: &'a mut std::fs::File,
    budget: &'a ReadinessBudget,
}
impl Write for CheckedSink<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.budget
            .check()
            .map_err(|_| io::Error::other("restore check cancelled or expired"))?;
        self.file.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

fn current_time() -> Result<UnixMicros, BackupExportError> {
    crate::api_http::current_time().ok_or(BackupExportError::Unavailable)
}
