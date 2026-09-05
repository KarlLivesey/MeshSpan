// SPDX-License-Identifier: GPL-2.0-only

//! Manager-only destination configuration through consensus and exact receipts.

use axum::http::HeaderMap;
use meshspan_api_contract::{
    ConfigureBackupDestinationRequest, ConfigureBackupDestinationResponse,
    ListBackupDestinationsQuery, ListBackupDestinationsResponse,
};
use meshspan_domain::{
    AuditEventId, BackupDestinationId, OperationId, Revision, TargetId, UnixMicros, uuid_v8,
};
use meshspan_metadata::{
    AuthoritativeCommand, BackupDestinationBinding, BackupFailureRelationship, CommandContext,
    CommandReceipt, ConfigureBackupDestination, EntityKind, RecordName,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::create_mesh_setup::parse_uuid;
use crate::{
    ConsensusAuthenticationAuthority, GatewaySessionIdentity, IdentityAdministrator,
    SystemManagerAuthenticationError, authenticate_system_manager,
    authenticate_system_manager_read,
};

#[path = "backup_destination_inventory.rs"]
pub(crate) mod inventory;

/// Synchronous boundary called on the HTTP blocking pool.
pub trait BackupDestinationController: Send + 'static {
    /// Rejects unauthorised requests before reading mutation bodies or querying inventory.
    ///
    /// # Errors
    /// Rejects invalid credentials, missing mutation CSRF and unavailable manager authority.
    fn authenticate(
        &self,
        headers: &HeaderMap,
        mutation: bool,
        now: UnixMicros,
    ) -> Result<(), BackupDestinationError>;
    /// Returns a bounded live page under current manager permissions.
    ///
    /// # Errors
    /// Rejects malformed or substituted cursors and untrustworthy metadata.
    fn list(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
        query: ListBackupDestinationsQuery,
    ) -> Result<ListBackupDestinationsResponse, BackupDestinationError>;
    /// Commits exact-retry settings, rechecking current permissions.
    ///
    /// # Errors
    /// Rejects stale revisions, changed retries, invalid targets and provider rebinding.
    fn configure(
        &mut self,
        headers: &HeaderMap,
        now: UnixMicros,
        request: ConfigureBackupDestinationRequest,
    ) -> Result<ConfigureBackupDestinationResponse, BackupDestinationError>;
}

/// Destination controls over the common swarm authentication and authoritative metadata.
pub struct BackupDestinationService {
    authority: ConsensusAuthenticationAuthority,
    gateway: GatewaySessionIdentity,
}

impl BackupDestinationService {
    /// Binds a gateway to the partition which owns backup configuration.
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
        request: &ConfigureBackupDestinationRequest,
    ) -> Result<ConfigureBackupDestinationResponse, BackupDestinationError> {
        let bytes =
            serde_json::to_vec(request).map_err(|_| BackupDestinationError::InvalidInput)?;
        meshspan_api_contract::decode_configure_backup_destination_request(&bytes)
            .map_err(|_| BackupDestinationError::InvalidInput)?;
        let operation = OperationId::from_bytes(
            parse_uuid(request.operation_id.as_str())
                .map_err(|_| BackupDestinationError::InvalidInput)?,
        )
        .map_err(|_| BackupDestinationError::InvalidInput)?;
        if let Some(receipt) = self.resolve(administrator, operation, request)? {
            return Ok(receipt);
        }
        let (context, command) = command(administrator, operation, request)?;
        match self.authority.commit_authoritative(context, &command) {
            Ok(receipt) => response(request, context, &command, receipt),
            Err(error) => self
                .resolve(administrator, operation, request)?
                .map_or_else(|| Err(map_commit_error(error)), Ok),
        }
    }

    fn resolve(
        &self,
        mut administrator: IdentityAdministrator,
        operation: OperationId,
        request: &ConfigureBackupDestinationRequest,
    ) -> Result<Option<ConfigureBackupDestinationResponse>, BackupDestinationError> {
        let Some(receipt) = self
            .authority
            .reader()
            .resolve_operation(operation)
            .map_err(|_| BackupDestinationError::Unavailable)?
        else {
            return Ok(None);
        };
        let original = self
            .authority
            .reader()
            .operation_status(operation)
            .map_err(|_| BackupDestinationError::Unavailable)?
            .ok_or(BackupDestinationError::Failed)?;
        if original.actor_principal_id != Some(administrator.principal_id) {
            return Err(BackupDestinationError::Conflict);
        }
        administrator.now = original.started_at;
        let (context, command) = command(administrator, operation, request)?;
        response(request, context, &command, receipt).map(Some)
    }
}

impl BackupDestinationController for BackupDestinationService {
    fn authenticate(
        &self,
        headers: &HeaderMap,
        mutation: bool,
        now: UnixMicros,
    ) -> Result<(), BackupDestinationError> {
        if mutation {
            authenticate_system_manager(&self.authority, self.gateway, headers, now)
        } else {
            authenticate_system_manager_read(&self.authority, self.gateway, headers, now)
        }
        .map(|_| ())
        .map_err(map_authentication_error)
    }

    fn list(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
        query: ListBackupDestinationsQuery,
    ) -> Result<ListBackupDestinationsResponse, BackupDestinationError> {
        let administrator =
            authenticate_system_manager_read(&self.authority, self.gateway, headers, now)
                .map_err(map_authentication_error)?;
        inventory::list(self.authority.reader(), administrator.principal_id, &query)
    }

    fn configure(
        &mut self,
        headers: &HeaderMap,
        now: UnixMicros,
        request: ConfigureBackupDestinationRequest,
    ) -> Result<ConfigureBackupDestinationResponse, BackupDestinationError> {
        let administrator =
            authenticate_system_manager(&self.authority, self.gateway, headers, now)
                .map_err(map_authentication_error)?;
        self.configure_authorised(administrator, &request)
    }
}

fn command(
    administrator: IdentityAdministrator,
    operation: OperationId,
    request: &ConfigureBackupDestinationRequest,
) -> Result<(CommandContext, AuthoritativeCommand), BackupDestinationError> {
    let destination_id = BackupDestinationId::from_bytes(
        parse_uuid(&request.destination_id).map_err(|_| BackupDestinationError::InvalidInput)?,
    )
    .map_err(|_| BackupDestinationError::InvalidInput)?;
    let target_id = TargetId::from_bytes(
        parse_uuid(&request.target_id).map_err(|_| BackupDestinationError::InvalidInput)?,
    )
    .map_err(|_| BackupDestinationError::InvalidInput)?;
    let mut audit = Sha256::new();
    audit.update(b"meshspan.backup-destination.audit.v1\0");
    audit.update(operation.as_bytes());
    let hash = audit.finalize();
    let mut audit_bytes = [0; 16];
    audit_bytes.copy_from_slice(&hash[..16]);
    let mut evidence = Sha256::new();
    evidence.update(b"meshspan.backup-destination.unassessed.v1\0");
    evidence.update(target_id.as_bytes());
    let target_generation = request
        .target_generation
        .parse::<u64>()
        .map_err(|_| BackupDestinationError::InvalidInput)?;
    evidence.update(target_generation.to_be_bytes());
    Ok((
        CommandContext {
            operation_id: operation,
            actor_principal_id: administrator.principal_id,
            audit_event_id: AuditEventId::from_bytes(uuid_v8(audit_bytes))
                .map_err(|_| BackupDestinationError::Failed)?,
            occurred_at: administrator.now,
            expected_revision: None,
        },
        AuthoritativeCommand::ConfigureBackupDestination(ConfigureBackupDestination {
            destination_id,
            expected_destination_revision: Revision::new(request.expected_revision),
            name: RecordName::new(&request.name)
                .map_err(|_| BackupDestinationError::InvalidInput)?,
            binding: BackupDestinationBinding::RegisteredTarget {
                target_id,
                target_generation,
            },
            failure_relationship: BackupFailureRelationship::Unknown,
            failure_evidence_digest: evidence.finalize().into(),
            enabled: request.enabled,
        }),
    ))
}

fn response(
    request: &ConfigureBackupDestinationRequest,
    context: CommandContext,
    command: &AuthoritativeCommand,
    receipt: CommandReceipt,
) -> Result<ConfigureBackupDestinationResponse, BackupDestinationError> {
    if receipt.operation_id != context.operation_id
        || receipt.request_digest != command.request_digest(context)
        || receipt.entity.kind != EntityKind::BackupDestination
        || receipt.entity.id
            != parse_uuid(&request.destination_id)
                .map_err(|_| BackupDestinationError::InvalidInput)?
    {
        return Err(BackupDestinationError::Conflict);
    }
    if receipt.result_digest == [0; 32] || receipt.committed_revision.get() == 0 {
        return Err(BackupDestinationError::Failed);
    }
    let response = ConfigureBackupDestinationResponse {
        operation_id: request.operation_id.clone(),
        destination_id: request.destination_id.clone(),
        committed_revision: receipt.committed_revision.get(),
    };
    meshspan_api_contract::encode_configure_backup_destination_response(&response)
        .map_err(|_| BackupDestinationError::Failed)?;
    Ok(response)
}

fn map_authentication_error(error: SystemManagerAuthenticationError) -> BackupDestinationError {
    match error {
        SystemManagerAuthenticationError::Rejected => BackupDestinationError::Unauthenticated,
        SystemManagerAuthenticationError::Forbidden => BackupDestinationError::Forbidden,
        SystemManagerAuthenticationError::Unavailable => BackupDestinationError::Unavailable,
        SystemManagerAuthenticationError::Failed => BackupDestinationError::Failed,
    }
}

fn map_commit_error(
    error: meshspan_cluster::MetadataAuthorityRequestError,
) -> BackupDestinationError {
    use meshspan_cluster::MetadataAuthorityRequestError as Error;
    match error {
        Error::Rejected | Error::Conflict => BackupDestinationError::Conflict,
        Error::NotLeader { .. } | Error::Unavailable => BackupDestinationError::Unavailable,
        Error::Unsupported | Error::Failed => BackupDestinationError::Failed,
    }
}

/// Closed, secret-free destination administration failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BackupDestinationError {
    /// Invalid structure, cursor or target settings.
    #[error("backup destination input is invalid")]
    InvalidInput,
    /// Rejected credentials or request protection.
    #[error("backup destination authentication rejected")]
    Unauthenticated,
    /// Missing current manager authority.
    #[error("backup destination requires system-manager authority")]
    Forbidden,
    /// Stale revision, changed retry or immutable binding conflict.
    #[error("backup destination conflicts with committed state")]
    Conflict,
    /// Authority cannot currently be reached.
    #[error("backup destination authority is unavailable")]
    Unavailable,
    /// Untrustworthy stored evidence or output.
    #[error("backup destination failed closed")]
    Failed,
}
