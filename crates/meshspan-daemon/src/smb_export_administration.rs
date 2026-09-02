// SPDX-License-Identifier: GPL-2.0-only

//! Manager-authorised explicit SMB-export publication over replicated metadata.

use axum::http::HeaderMap;
use axum::http::header::{AUTHORIZATION, COOKIE};
use meshspan_api_contract::{
    PublishSmbExportRequest, PublishSmbExportResponse,
    SmbExportGatewaySelection as ApiGatewaySelection, SmbExportId as ApiSmbExportId,
    WithdrawSmbExportRequest, WithdrawSmbExportResponse,
};
use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    AuditEventId, NodeId, ObjectId, OperationId, PrincipalId, Revision, SmbExportId, UnixMicros,
    VolumeId, uuid_v8,
};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, CommandReceipt, EntityKind, PublishSmbExport, RecordName,
    SmbExportGatewaySelection, WithdrawSmbExport,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::create_mesh_setup::parse_uuid;
use crate::{
    BrowserRequestProtection, BrowserSessionAuthenticator, BrowserSessionAuthority,
    FileApiAuthenticationError, GatewaySessionIdentity, IdentityAdministrator,
    NativeApiKeyAuthenticator, NativeApiKeyAuthority,
};

const EXPORT_ID_DOMAIN: &[u8] = b"meshspan.smb-export-administration.export-id.v1\0";
const AUDIT_ID_DOMAIN: &[u8] = b"meshspan.smb-export-administration.audit-id.v1\0";
const MAXIMUM_GATEWAYS: usize = 1_024;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Replicated reads and consensus mutation needed by SMB-export administration.
pub trait SmbExportAdministrationAuthority:
    BrowserSessionAuthority + NativeApiKeyAuthority
{
    /// Reports current system-manager authority.
    ///
    /// # Errors
    ///
    /// Fails closed when current replicated authority cannot be established.
    fn is_system_manager(
        &self,
        principal_id: PrincipalId,
        now: UnixMicros,
    ) -> Result<bool, SmbExportAdministrationAuthorityError>;

    /// Resolves one prior operation from authoritative retained evidence.
    ///
    /// # Errors
    ///
    /// Fails closed when retained operation evidence cannot be read safely.
    fn resolve_smb_export_operation(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<CommandReceipt>, SmbExportAdministrationAuthorityError>;

    /// Commits one exact export mutation or resolves its exact replay.
    ///
    /// # Errors
    ///
    /// Rejects conflicts and fails when the authoritative write cannot complete.
    fn commit_smb_export_operation(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, SmbExportAdministrationAuthorityError>;
}

/// Synchronous controller run by the HTTP boundary on Tokio's blocking pool.
pub trait SmbExportAdministrationController: Send + 'static {
    /// Authenticates current manager authority before consuming a body.
    ///
    /// # Errors
    ///
    /// Rejects absent or invalid credentials and unavailable authority.
    fn authenticate(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<IdentityAdministrator, SmbExportAdministrationError>;

    /// Publishes one existing directory explicitly.
    ///
    /// # Errors
    ///
    /// Rejects invalid input, insufficient authority, conflicts and failed commits.
    fn publish(
        &mut self,
        administrator: IdentityAdministrator,
        volume_id: &str,
        request: PublishSmbExportRequest,
    ) -> Result<PublishSmbExportResponse, SmbExportAdministrationError>;

    /// Withdraws one active export explicitly.
    ///
    /// # Errors
    ///
    /// Rejects invalid input, insufficient authority, conflicts and failed commits.
    fn withdraw(
        &mut self,
        administrator: IdentityAdministrator,
        export_id: &str,
        request: WithdrawSmbExportRequest,
    ) -> Result<WithdrawSmbExportResponse, SmbExportAdministrationError>;
}

/// Complete explicit export administration service.
pub struct SmbExportAdministrationService<A> {
    authority: A,
    gateway: GatewaySessionIdentity,
}

impl<A> SmbExportAdministrationService<A> {
    /// Binds manager authentication to one consensus-backed authority.
    #[must_use]
    pub const fn new(authority: A, gateway: GatewaySessionIdentity) -> Self {
        Self { authority, gateway }
    }
}

impl<A> SmbExportAdministrationController for SmbExportAdministrationService<A>
where
    A: SmbExportAdministrationAuthority + Send + 'static,
{
    fn authenticate(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<IdentityAdministrator, SmbExportAdministrationError> {
        let principal_id = authenticate_principal(&self.authority, self.gateway, headers, now)?;
        if !self
            .authority
            .is_system_manager(principal_id, now)
            .map_err(map_authority_error)?
        {
            return Err(SmbExportAdministrationError::Forbidden);
        }
        Ok(IdentityAdministrator { principal_id, now })
    }

    fn publish(
        &mut self,
        administrator: IdentityAdministrator,
        volume_id: &str,
        request: PublishSmbExportRequest,
    ) -> Result<PublishSmbExportResponse, SmbExportAdministrationError> {
        let operation_id = domain_operation(request.operation_id.as_str())?;
        let export_id = derived_export_id(operation_id)?;
        let volume_id = domain_volume(volume_id)?;
        let root_object_id = domain_object(request.root_object_id.as_str())?;
        let share_name = RecordName::new(request.share_name.as_str())
            .map_err(|_| SmbExportAdministrationError::InvalidInput)?;
        let gateways = domain_gateways(&request.gateways)?;
        let command = AuthoritativeCommand::PublishSmbExport(PublishSmbExport {
            export_id,
            volume_id,
            root_object_id,
            share_name,
            gateways,
            encryption_required: request.encryption_required,
        });
        let context = command_context(operation_id, administrator)?;
        let receipt = self.commit_or_resolve(context, &command)?;
        validate_receipt(&receipt, context, &command, export_id)?;
        response_from_publication(request, receipt.committed_revision, export_id, volume_id)
    }

    fn withdraw(
        &mut self,
        administrator: IdentityAdministrator,
        export_id: &str,
        request: WithdrawSmbExportRequest,
    ) -> Result<WithdrawSmbExportResponse, SmbExportAdministrationError> {
        let operation_id = domain_operation(request.operation_id.as_str())?;
        let export_id = domain_export(export_id)?;
        if request.reason.trim().is_empty() {
            return Err(SmbExportAdministrationError::InvalidInput);
        }
        let command = AuthoritativeCommand::WithdrawSmbExport(WithdrawSmbExport {
            export_id,
            reason: request.reason,
        });
        let context = command_context(operation_id, administrator)?;
        let receipt = self.commit_or_resolve(context, &command)?;
        validate_receipt(&receipt, context, &command, export_id)?;
        safe_revision(receipt.committed_revision)?;
        Ok(WithdrawSmbExportResponse {
            operation_id: request.operation_id,
            export_id: ApiSmbExportId::from_uuid_bytes(export_id.as_bytes())
                .ok_or(SmbExportAdministrationError::Failed)?,
            revision: receipt.committed_revision.get(),
        })
    }
}

impl<A> SmbExportAdministrationService<A>
where
    A: SmbExportAdministrationAuthority,
{
    fn commit_or_resolve(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, SmbExportAdministrationError> {
        if let Some(receipt) = self
            .authority
            .resolve_smb_export_operation(context.operation_id)
            .map_err(map_authority_error)?
        {
            return Ok(receipt);
        }
        match self.authority.commit_smb_export_operation(context, command) {
            Ok(receipt) => Ok(receipt),
            Err(error) => self
                .authority
                .resolve_smb_export_operation(context.operation_id)
                .map_err(map_authority_error)?
                .ok_or_else(|| map_authority_error(error)),
        }
    }
}

fn authenticate_principal<A: BrowserSessionAuthority + NativeApiKeyAuthority>(
    authority: &A,
    gateway: GatewaySessionIdentity,
    headers: &HeaderMap,
    now: UnixMicros,
) -> Result<PrincipalId, SmbExportAdministrationError> {
    let has_authorization = headers.contains_key(AUTHORIZATION);
    if has_authorization && headers.contains_key(COOKIE) {
        return Err(SmbExportAdministrationError::Unauthenticated);
    }
    if has_authorization {
        return NativeApiKeyAuthenticator::new(authority, gateway)
            .authenticate_principal(headers, now)
            .map_err(map_file_authentication_error);
    }
    BrowserSessionAuthenticator::new(authority, gateway)
        .authenticate(
            headers,
            BrowserRequestProtection::Mutation,
            meshspan_domain::AssuranceLevel::SingleFactor,
            now,
        )
        .map(|session| session.principal_id)
        .map_err(|error| match error {
            crate::BrowserAuthenticationError::Rejected => {
                SmbExportAdministrationError::Unauthenticated
            }
            crate::BrowserAuthenticationError::Authority(
                crate::BrowserSessionAuthorityError::Unavailable,
            ) => SmbExportAdministrationError::Unavailable,
            crate::BrowserAuthenticationError::InvalidGateway
            | crate::BrowserAuthenticationError::Authority(
                crate::BrowserSessionAuthorityError::Failed,
            ) => SmbExportAdministrationError::Failed,
        })
}

fn response_from_publication(
    request: PublishSmbExportRequest,
    revision: Revision,
    export_id: SmbExportId,
    volume_id: VolumeId,
) -> Result<PublishSmbExportResponse, SmbExportAdministrationError> {
    safe_revision(revision)?;
    Ok(PublishSmbExportResponse {
        operation_id: request.operation_id,
        export_id: ApiSmbExportId::from_uuid_bytes(export_id.as_bytes())
            .ok_or(SmbExportAdministrationError::Failed)?,
        volume_id: meshspan_api_contract::VolumeId::from_uuid_bytes(volume_id.as_bytes())
            .ok_or(SmbExportAdministrationError::Failed)?,
        root_object_id: request.root_object_id,
        share_name: request.share_name,
        gateways: request.gateways,
        encryption_required: request.encryption_required,
        revision: revision.get(),
    })
}

fn validate_receipt(
    receipt: &CommandReceipt,
    context: CommandContext,
    command: &AuthoritativeCommand,
    export_id: SmbExportId,
) -> Result<(), SmbExportAdministrationError> {
    if receipt.operation_id != context.operation_id
        || receipt.request_digest != command.request_digest(context)
        || receipt.entity.kind != EntityKind::SmbExport
        || receipt.entity.id != export_id.as_bytes()
    {
        return Err(SmbExportAdministrationError::Conflict);
    }
    safe_revision(receipt.committed_revision)
}

fn command_context(
    operation_id: OperationId,
    administrator: IdentityAdministrator,
) -> Result<CommandContext, SmbExportAdministrationError> {
    let mut digest = Sha256::new();
    digest.update(AUDIT_ID_DOMAIN);
    digest.update(operation_id.as_bytes());
    let bytes: [u8; 32] = digest.finalize().into();
    let audit_event_id = AuditEventId::from_bytes(uuid_v8(
        bytes[..16]
            .try_into()
            .map_err(|_| SmbExportAdministrationError::Failed)?,
    ))
    .map_err(|_| SmbExportAdministrationError::Failed)?;
    Ok(CommandContext {
        operation_id,
        actor_principal_id: administrator.principal_id,
        audit_event_id,
        occurred_at: administrator.now,
        expected_revision: None,
    })
}

fn derived_export_id(
    operation_id: OperationId,
) -> Result<SmbExportId, SmbExportAdministrationError> {
    let mut digest = Sha256::new();
    digest.update(EXPORT_ID_DOMAIN);
    digest.update(operation_id.as_bytes());
    let bytes: [u8; 32] = digest.finalize().into();
    SmbExportId::from_bytes(uuid_v8(
        bytes[..16]
            .try_into()
            .map_err(|_| SmbExportAdministrationError::Failed)?,
    ))
    .map_err(|_| SmbExportAdministrationError::Failed)
}

fn domain_gateways(
    gateways: &ApiGatewaySelection,
) -> Result<SmbExportGatewaySelection, SmbExportAdministrationError> {
    let Some(node_ids) = gateways.selected_node_ids() else {
        return Ok(SmbExportGatewaySelection::AllEligible);
    };
    let nodes = node_ids
        .iter()
        .map(|node| {
            NodeId::from_bytes(
                parse_uuid(node).map_err(|_| SmbExportAdministrationError::InvalidInput)?,
            )
            .map_err(|_| SmbExportAdministrationError::InvalidInput)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SmbExportGatewaySelection::Selected(
        BoundedItems::new(nodes, MAXIMUM_GATEWAYS)
            .map_err(|_| SmbExportAdministrationError::InvalidInput)?,
    ))
}

fn domain_operation(value: &str) -> Result<OperationId, SmbExportAdministrationError> {
    OperationId::from_bytes(
        parse_uuid(value).map_err(|_| SmbExportAdministrationError::InvalidInput)?,
    )
    .map_err(|_| SmbExportAdministrationError::InvalidInput)
}

fn domain_volume(value: &str) -> Result<VolumeId, SmbExportAdministrationError> {
    VolumeId::from_bytes(parse_uuid(value).map_err(|_| SmbExportAdministrationError::InvalidInput)?)
        .map_err(|_| SmbExportAdministrationError::InvalidInput)
}

fn domain_object(value: &str) -> Result<ObjectId, SmbExportAdministrationError> {
    ObjectId::from_bytes(parse_uuid(value).map_err(|_| SmbExportAdministrationError::InvalidInput)?)
        .map_err(|_| SmbExportAdministrationError::InvalidInput)
}

fn domain_export(value: &str) -> Result<SmbExportId, SmbExportAdministrationError> {
    SmbExportId::from_bytes(
        parse_uuid(value).map_err(|_| SmbExportAdministrationError::InvalidInput)?,
    )
    .map_err(|_| SmbExportAdministrationError::InvalidInput)
}

fn safe_revision(revision: Revision) -> Result<(), SmbExportAdministrationError> {
    (revision.get() <= MAX_SAFE_INTEGER)
        .then_some(())
        .ok_or(SmbExportAdministrationError::Failed)
}

fn map_file_authentication_error(
    error: FileApiAuthenticationError,
) -> SmbExportAdministrationError {
    match error {
        FileApiAuthenticationError::InvalidGateway
        | FileApiAuthenticationError::AuthorityFailed => SmbExportAdministrationError::Failed,
        FileApiAuthenticationError::Rejected => SmbExportAdministrationError::Unauthenticated,
        FileApiAuthenticationError::AuthorityUnavailable => {
            SmbExportAdministrationError::Unavailable
        }
    }
}

fn map_authority_error(
    error: SmbExportAdministrationAuthorityError,
) -> SmbExportAdministrationError {
    match error {
        SmbExportAdministrationAuthorityError::Conflict => SmbExportAdministrationError::Conflict,
        SmbExportAdministrationAuthorityError::Unavailable => {
            SmbExportAdministrationError::Unavailable
        }
        SmbExportAdministrationAuthorityError::Failed => SmbExportAdministrationError::Failed,
    }
}

/// Closed consensus/repository failure categories.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SmbExportAdministrationAuthorityError {
    /// Exact operation or desired state conflicts.
    #[error("SMB export authority reported a conflict")]
    Conflict,
    /// Current authority is temporarily unavailable.
    #[error("SMB export authority is unavailable")]
    Unavailable,
    /// Retained evidence failed closed.
    #[error("SMB export authority failed closed")]
    Failed,
}

/// Non-secret public SMB-export administration failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SmbExportAdministrationError {
    /// An identifier, name, selection or reason is invalid.
    #[error("SMB export input is invalid")]
    InvalidInput,
    /// Authentication was rejected.
    #[error("SMB export authentication was rejected")]
    Unauthenticated,
    /// Current principal lacks manager authority.
    #[error("SMB export authority was denied")]
    Forbidden,
    /// Exact retry or desired state conflicts.
    #[error("SMB export operation conflicts")]
    Conflict,
    /// Current authority is temporarily unavailable.
    #[error("SMB export authority is unavailable")]
    Unavailable,
    /// State or output verification failed closed.
    #[error("SMB export administration failed closed")]
    Failed,
}
