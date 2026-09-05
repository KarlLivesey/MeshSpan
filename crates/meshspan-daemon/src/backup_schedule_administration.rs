// SPDX-License-Identifier: GPL-2.0-only

//! Manager-only backup policy over the existing authoritative schedule state machine.

use axum::http::HeaderMap;
use meshspan_api_contract::{
    BackupSchedulePolicy, BackupScheduleResponse, BackupScheduleStatus,
    ConfigureBackupScheduleRequest, ConfigureBackupScheduleResponse,
};
use meshspan_domain::{AuditEventId, DurationMicros, OperationId, UnixMicros, uuid_v8};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, CommandReceipt, ConfigureMetadataBackupSchedule,
    EntityKind, RepositoryError,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    ConsensusAuthenticationAuthority, GatewaySessionIdentity, IdentityAdministrator,
    SystemManagerAuthenticationError, authenticate_system_manager,
    authenticate_system_manager_read,
};

/// Replaceable synchronous controller invoked on the HTTP blocking pool.
pub trait BackupScheduleController: Send + 'static {
    /// Checks credentials and manager authority before consuming any mutation body.
    ///
    /// # Errors
    /// Rejects stale, ambiguous or insufficient credentials and missing CSRF protection.
    fn authenticate(&self, headers: &HeaderMap, now: UnixMicros)
    -> Result<(), BackupScheduleError>;

    /// Authenticates and reads the current authoritative schedule.
    ///
    /// # Errors
    /// Rejects unavailable authority and malformed persisted policy.
    fn read(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<BackupScheduleResponse, BackupScheduleError>;

    /// Reauthenticates and commits one complete policy, or resolves its original receipt.
    ///
    /// # Errors
    /// Rejects changed retries, stale sequences, revoked credentials and unavailable authority.
    fn configure(
        &mut self,
        headers: &HeaderMap,
        now: UnixMicros,
        request: ConfigureBackupScheduleRequest,
    ) -> Result<ConfigureBackupScheduleResponse, BackupScheduleError>;
}

/// Backup administration composed with the common swarm identity and consensus authority.
pub struct BackupScheduleService {
    authority: ConsensusAuthenticationAuthority,
    gateway: GatewaySessionIdentity,
}

impl BackupScheduleService {
    /// Binds one authoritative partition and gateway authentication identity.
    #[must_use]
    pub const fn new(
        authority: ConsensusAuthenticationAuthority,
        gateway: GatewaySessionIdentity,
    ) -> Self {
        Self { authority, gateway }
    }

    fn configure_authorised(
        &self,
        administrator: IdentityAdministrator,
        request: &ConfigureBackupScheduleRequest,
    ) -> Result<ConfigureBackupScheduleResponse, BackupScheduleError> {
        // The service independently validates callers which bypass HTTP decoding.
        let bytes = serde_json::to_vec(request).map_err(|_| BackupScheduleError::InvalidInput)?;
        meshspan_api_contract::decode_configure_backup_schedule_request(&bytes)
            .map_err(|_| BackupScheduleError::InvalidInput)?;
        let operation = OperationId::from_bytes(
            crate::create_mesh_setup::parse_uuid(request.operation_id.as_str())
                .map_err(|_| BackupScheduleError::InvalidInput)?,
        )
        .map_err(|_| BackupScheduleError::InvalidInput)?;
        if let Some(response) = self.resolve(administrator, operation, request)? {
            return Ok(response);
        }
        let (context, command) = self.command(administrator, operation, request)?;
        match self.authority.commit_authoritative(context, &command) {
            Ok(receipt) => self.response(request, context, &command, receipt),
            Err(error) => self
                .resolve(administrator, operation, request)?
                .map_or_else(|| Err(map_commit_error(error)), Ok),
        }
    }

    fn resolve(
        &self,
        mut administrator: IdentityAdministrator,
        operation: OperationId,
        request: &ConfigureBackupScheduleRequest,
    ) -> Result<Option<ConfigureBackupScheduleResponse>, BackupScheduleError> {
        let Some(receipt) = self
            .authority
            .reader()
            .resolve_operation(operation)
            .map_err(|error| map_repository_error(&error))?
        else {
            return Ok(None);
        };
        let original = self
            .authority
            .reader()
            .operation_status(operation)
            .map_err(|error| map_repository_error(&error))?
            .ok_or(BackupScheduleError::Failed)?;
        if original.actor_principal_id != Some(administrator.principal_id) {
            return Err(BackupScheduleError::Conflict);
        }
        administrator.now = original.started_at;
        let (context, command) = self.command(administrator, operation, request)?;
        self.response(request, context, &command, receipt).map(Some)
    }

    fn command(
        &self,
        administrator: IdentityAdministrator,
        operation: OperationId,
        request: &ConfigureBackupScheduleRequest,
    ) -> Result<(CommandContext, AuthoritativeCommand), BackupScheduleError> {
        let mut digest = Sha256::new();
        digest.update(b"meshspan.backup-schedule.audit.v1\0");
        digest.update(operation.as_bytes());
        let hash = digest.finalize();
        let mut audit_bytes = [0; 16];
        audit_bytes.copy_from_slice(&hash[..16]);
        let audit = AuditEventId::from_bytes(uuid_v8(audit_bytes))
            .map_err(|_| BackupScheduleError::Failed)?;
        let policy = &request.policy;
        Ok((
            CommandContext {
                operation_id: operation,
                actor_principal_id: administrator.principal_id,
                audit_event_id: audit,
                occurred_at: administrator.now,
                expected_revision: None,
            },
            AuthoritativeCommand::ConfigureMetadataBackupSchedule(
                ConfigureMetadataBackupSchedule {
                    partition_id: self.authority.reader().partition_id(),
                    expected_schedule_sequence: request.expected_sequence,
                    interval: DurationMicros::new(u64::from(policy.interval_seconds) * 1_000_000),
                    retained_generations: policy.retained_generations,
                    minimum_verified_copies: policy.minimum_verified_copies,
                    minimum_independent_copies: policy.minimum_independent_copies,
                    enabled: policy.enabled,
                    next_due_at: administrator.now,
                },
            ),
        ))
    }

    fn response(
        &self,
        request: &ConfigureBackupScheduleRequest,
        context: CommandContext,
        command: &AuthoritativeCommand,
        receipt: CommandReceipt,
    ) -> Result<ConfigureBackupScheduleResponse, BackupScheduleError> {
        if receipt.operation_id != context.operation_id
            || receipt.request_digest != command.request_digest(context)
            || receipt.entity.kind != EntityKind::MetadataBackupSchedule
            || receipt.entity.id != self.authority.reader().partition_id().as_bytes()
        {
            return Err(BackupScheduleError::Conflict);
        }
        if receipt.result_digest == [0; 32] || receipt.committed_revision.get() == 0 {
            return Err(BackupScheduleError::Failed);
        }
        let response = ConfigureBackupScheduleResponse {
            operation_id: request.operation_id.clone(),
            sequence: request
                .expected_sequence
                .checked_add(1)
                .ok_or(BackupScheduleError::Failed)?,
            committed_revision: receipt.committed_revision.get(),
        };
        meshspan_api_contract::encode_configure_backup_schedule_response(&response)
            .map_err(|_| BackupScheduleError::Failed)?;
        Ok(response)
    }
}

impl BackupScheduleController for BackupScheduleService {
    fn authenticate(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<(), BackupScheduleError> {
        authenticate_system_manager(&self.authority, self.gateway, headers, now)
            .map(|_| ())
            .map_err(map_authentication_error)
    }

    fn read(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<BackupScheduleResponse, BackupScheduleError> {
        authenticate_system_manager_read(&self.authority, self.gateway, headers, now)
            .map_err(map_authentication_error)?;
        let schedule = self
            .authority
            .reader()
            .metadata_backup_schedule()
            .map_err(|error| map_repository_error(&error))?
            .map(|schedule| {
                if schedule.interval.get() % 1_000_000 != 0 {
                    return Err(BackupScheduleError::Failed);
                }
                Ok(BackupScheduleStatus {
                    sequence: schedule.sequence,
                    policy: BackupSchedulePolicy {
                        interval_seconds: u32::try_from(schedule.interval.get() / 1_000_000)
                            .map_err(|_| BackupScheduleError::Failed)?,
                        retained_generations: schedule.retained_generations,
                        minimum_verified_copies: schedule.minimum_verified_copies,
                        minimum_independent_copies: schedule.minimum_independent_copies,
                        enabled: schedule.enabled,
                    },
                    next_due_at_epoch_micros: schedule.next_due_at.get(),
                })
            })
            .transpose()?;
        let response = BackupScheduleResponse {
            partition_id: crate::create_mesh_setup::format_uuid(
                self.authority.reader().partition_id().as_bytes(),
            ),
            schedule,
        };
        meshspan_api_contract::encode_backup_schedule_response(&response)
            .map_err(|_| BackupScheduleError::Failed)?;
        Ok(response)
    }

    fn configure(
        &mut self,
        headers: &HeaderMap,
        now: UnixMicros,
        request: ConfigureBackupScheduleRequest,
    ) -> Result<ConfigureBackupScheduleResponse, BackupScheduleError> {
        let administrator =
            authenticate_system_manager(&self.authority, self.gateway, headers, now)
                .map_err(map_authentication_error)?;
        self.configure_authorised(administrator, &request)
    }
}

fn map_authentication_error(error: SystemManagerAuthenticationError) -> BackupScheduleError {
    match error {
        SystemManagerAuthenticationError::Rejected => BackupScheduleError::Unauthenticated,
        SystemManagerAuthenticationError::Forbidden => BackupScheduleError::Forbidden,
        SystemManagerAuthenticationError::Unavailable => BackupScheduleError::Unavailable,
        SystemManagerAuthenticationError::Failed => BackupScheduleError::Failed,
    }
}

fn map_repository_error(error: &RepositoryError) -> BackupScheduleError {
    match error {
        RepositoryError::Sqlite(_) | RepositoryError::Store(_) | RepositoryError::Io(_) => {
            BackupScheduleError::Unavailable
        }
        _ => BackupScheduleError::Failed,
    }
}

fn map_commit_error(error: meshspan_cluster::MetadataAuthorityRequestError) -> BackupScheduleError {
    use meshspan_cluster::MetadataAuthorityRequestError as Error;
    match error {
        Error::Rejected | Error::Conflict => BackupScheduleError::Conflict,
        Error::NotLeader { .. } | Error::Unavailable => BackupScheduleError::Unavailable,
        Error::Unsupported | Error::Failed => BackupScheduleError::Failed,
    }
}

/// Closed, secret-free backup policy failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BackupScheduleError {
    /// Request structure or policy thresholds are invalid.
    #[error("backup policy input is invalid")]
    InvalidInput,
    /// Credentials or request protection were rejected.
    #[error("backup policy authentication was rejected")]
    Unauthenticated,
    /// The authenticated principal is not a system manager.
    #[error("backup policy requires system-manager authority")]
    Forbidden,
    /// A sequence or exact operation replay conflicts.
    #[error("backup policy conflicts with committed state")]
    Conflict,
    /// Current authority cannot be reached.
    #[error("backup policy authority is unavailable")]
    Unavailable,
    /// Retained evidence or output failed validation.
    #[error("backup policy failed closed")]
    Failed,
}
