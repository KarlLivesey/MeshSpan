// SPDX-License-Identifier: GPL-2.0-only

//! Manager commands use the same replicated trust and rollout owner as installation workers.

use crate::{
    ConsensusAuthenticationAuthority, GatewaySessionIdentity, IdentityAdministrator,
    SystemManagerAuthenticationError, authenticate_system_manager,
    authenticate_system_manager_read,
};
use axum::http::HeaderMap;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use meshspan_api_contract::{
    ManageUpdateRequest, ManageUpdateResponse, UpdateAction, UpdateControl, UpdateIdentifier,
    UpdateSignerStatus, UpdatesResponse,
};
use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_domain::{
    AuditEventId, ComponentInstanceId, OperationId, UnixMicros, WorkId, uuid_v8,
};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, CommandReceipt, ConfigureUpdateSigner,
    ControlUpdateRollout, EntityKind, StartUpdateRollout, UpdateRolloutControl,
};
use sha2::{Digest as _, Sha256};

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum UpdateError {
    #[error("update input is invalid")]
    Invalid,
    #[error("update authentication is required")]
    Unauthenticated,
    #[error("update administration is not granted")]
    Forbidden,
    #[error("update command conflicts with current state or its original request")]
    Conflict,
    #[error(
        "update authority is unavailable; retry the unchanged operation to resolve its outcome"
    )]
    Unavailable,
    #[error("update evidence failed validation")]
    Failed,
    #[error("update body exceeds its limit")]
    BodyTooLarge,
    #[error("update management requires JSON")]
    MediaType,
}

pub(crate) struct UpdateService {
    authority: ConsensusAuthenticationAuthority,
    gateway: GatewaySessionIdentity,
}

impl UpdateService {
    pub(crate) const fn new(
        authority: ConsensusAuthenticationAuthority,
        gateway: GatewaySessionIdentity,
    ) -> Self {
        Self { authority, gateway }
    }

    pub(crate) fn authenticate(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
        mutation: bool,
    ) -> Result<IdentityAdministrator, UpdateError> {
        let result = if mutation {
            authenticate_system_manager(&self.authority, self.gateway, headers, now)
        } else {
            authenticate_system_manager_read(&self.authority, self.gateway, headers, now)
        };
        result.map_err(|error| match error {
            SystemManagerAuthenticationError::Rejected => UpdateError::Unauthenticated,
            SystemManagerAuthenticationError::Forbidden => UpdateError::Forbidden,
            SystemManagerAuthenticationError::Unavailable => UpdateError::Unavailable,
            SystemManagerAuthenticationError::Failed => UpdateError::Failed,
        })
    }

    pub(crate) fn status(&self, rollout: Option<WorkId>) -> Result<UpdatesResponse, UpdateError> {
        let repository = self.authority.reader();
        let signers = repository
            .update_signers()
            .map_err(|_| UpdateError::Unavailable)?
            .into_iter()
            .map(|signer| UpdateSignerStatus {
                signer_id: identifier(signer.signer_id.as_bytes()),
                sequence: signer.sequence,
                public_key: STANDARD.encode(signer.public_key),
                enabled: signer.enabled,
            })
            .collect();
        let record = match rollout {
            Some(id) => repository.update_rollout(id),
            None => repository.active_update_rollout(),
        }
        .map_err(|_| UpdateError::Unavailable)?;
        let rollout = record
            .map(|record| crate::update_status::rollout(repository, &record))
            .transpose()?;
        Ok(UpdatesResponse {
            signers,
            rollout,
            installation_available: false,
        })
    }

    pub(crate) fn manage(
        &self,
        administrator: IdentityAdministrator,
        request: &ManageUpdateRequest,
    ) -> Result<ManageUpdateResponse, UpdateError> {
        meshspan_api_contract::decode_manage_update_request(
            &serde_json::to_vec(request).map_err(|_| UpdateError::Invalid)?,
        )
        .map_err(|_| UpdateError::Invalid)?;
        let operation = OperationId::from_bytes(parse(request.operation_id.as_str())?)
            .map_err(|_| UpdateError::Invalid)?;
        let command = command(&request.action)?;
        let original = self
            .authority
            .reader()
            .resolve_operation(operation)
            .map_err(|_| UpdateError::Unavailable)?;
        if let Some(receipt) = original {
            return self.retry(administrator, request, &command, receipt);
        }
        let context = context(administrator, operation)?;
        let receipt = match self.authority.commit_authoritative(context, &command) {
            Ok(receipt) => receipt,
            Err(error) => {
                if let Some(receipt) = self
                    .authority
                    .reader()
                    .resolve_operation(operation)
                    .map_err(|_| UpdateError::Unavailable)?
                {
                    return self.retry(administrator, request, &command, receipt);
                }
                return Err(match error {
                    MetadataAuthorityRequestError::Conflict
                    | MetadataAuthorityRequestError::Rejected => UpdateError::Conflict,
                    MetadataAuthorityRequestError::Unsupported => UpdateError::Invalid,
                    MetadataAuthorityRequestError::NotLeader { .. }
                    | MetadataAuthorityRequestError::Unavailable
                    | MetadataAuthorityRequestError::Failed => UpdateError::Unavailable,
                });
            }
        };
        verify_receipt(request, context, &command, receipt)
    }

    fn retry(
        &self,
        mut administrator: IdentityAdministrator,
        request: &ManageUpdateRequest,
        command: &AuthoritativeCommand,
        receipt: CommandReceipt,
    ) -> Result<ManageUpdateResponse, UpdateError> {
        let operation = OperationId::from_bytes(parse(request.operation_id.as_str())?)
            .map_err(|_| UpdateError::Invalid)?;
        let status = self
            .authority
            .reader()
            .operation_status(operation)
            .map_err(|_| UpdateError::Unavailable)?
            .ok_or(UpdateError::Failed)?;
        if status.actor_principal_id != Some(administrator.principal_id) {
            return Err(UpdateError::Conflict);
        }
        administrator.now = status.started_at;
        verify_receipt(
            request,
            context(administrator, operation)?,
            command,
            receipt,
        )
    }
}

pub(crate) fn parse(value: &str) -> Result<[u8; 16], UpdateError> {
    if meshspan_api_contract::OperationId::parse(value).is_none() {
        return Err(UpdateError::Invalid);
    }
    crate::create_mesh_setup::parse_uuid(value).map_err(|_| UpdateError::Invalid)
}

pub(crate) fn identifier(bytes: [u8; 16]) -> UpdateIdentifier {
    UpdateIdentifier(crate::create_mesh_setup::format_uuid(bytes))
}

fn decoded(value: &str, maximum: usize) -> Result<Vec<u8>, UpdateError> {
    let bytes = STANDARD.decode(value).map_err(|_| UpdateError::Invalid)?;
    if bytes.is_empty() || bytes.len() > maximum || STANDARD.encode(&bytes) != value {
        return Err(UpdateError::Invalid);
    }
    Ok(bytes)
}

fn command(action: &UpdateAction) -> Result<AuthoritativeCommand, UpdateError> {
    Ok(match action {
        UpdateAction::ConfigureSigner {
            signer_id,
            expected_sequence,
            public_key,
            enabled,
        } => AuthoritativeCommand::ConfigureUpdateSigner(ConfigureUpdateSigner {
            signer_id: ComponentInstanceId::from_bytes(parse(&signer_id.0)?)
                .map_err(|_| UpdateError::Invalid)?,
            expected_sequence: *expected_sequence,
            public_key: decoded(public_key, 65)?
                .try_into()
                .map_err(|_| UpdateError::Invalid)?,
            enabled: *enabled,
        }),
        UpdateAction::SelectCandidate {
            rollout_id,
            signer_id,
            signer_sequence,
            manifest,
            signature,
            allow_service_interruption,
        } => AuthoritativeCommand::StartUpdateRollout(StartUpdateRollout {
            rollout_id: WorkId::from_bytes(parse(&rollout_id.0)?)
                .map_err(|_| UpdateError::Invalid)?,
            signer_id: ComponentInstanceId::from_bytes(parse(&signer_id.0)?)
                .map_err(|_| UpdateError::Invalid)?,
            signer_sequence: *signer_sequence,
            manifest: decoded(manifest, 16_384)?,
            signature: decoded(signature, 72)?,
            allow_service_interruption: *allow_service_interruption,
        }),
        UpdateAction::Control {
            rollout_id,
            expected_sequence,
            control,
        } => AuthoritativeCommand::ControlUpdateRollout(ControlUpdateRollout {
            rollout_id: WorkId::from_bytes(parse(&rollout_id.0)?)
                .map_err(|_| UpdateError::Invalid)?,
            expected_sequence: *expected_sequence,
            action: match control {
                UpdateControl::Pause => UpdateRolloutControl::Pause,
                UpdateControl::Resume => UpdateRolloutControl::Resume,
                UpdateControl::Cancel => UpdateRolloutControl::Cancel,
            },
        }),
    })
}

fn context(
    administrator: IdentityAdministrator,
    operation: OperationId,
) -> Result<CommandContext, UpdateError> {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.update.manage.audit.v1\0");
    digest.update(operation.as_bytes());
    let audit = digest.finalize()[..16]
        .try_into()
        .map_err(|_| UpdateError::Failed)?;
    Ok(CommandContext {
        operation_id: operation,
        actor_principal_id: administrator.principal_id,
        audit_event_id: AuditEventId::from_bytes(uuid_v8(audit))
            .map_err(|_| UpdateError::Failed)?,
        occurred_at: administrator.now,
        expected_revision: None,
    })
}

fn verify_receipt(
    request: &ManageUpdateRequest,
    context: CommandContext,
    command: &AuthoritativeCommand,
    receipt: CommandReceipt,
) -> Result<ManageUpdateResponse, UpdateError> {
    let (kind, id) = match &request.action {
        UpdateAction::ConfigureSigner { signer_id, .. } => (EntityKind::UpdateSigner, signer_id),
        UpdateAction::SelectCandidate { rollout_id, .. }
        | UpdateAction::Control { rollout_id, .. } => (EntityKind::UpdateRollout, rollout_id),
    };
    if receipt.operation_id != context.operation_id
        || receipt.request_digest != command.request_digest(context)
        || receipt.entity.kind != kind
        || receipt.entity.id != parse(&id.0)?
        || receipt.result_digest == [0; 32]
    {
        return Err(UpdateError::Conflict);
    }
    Ok(ManageUpdateResponse {
        operation_id: request.operation_id.clone(),
        resource_id: id.clone(),
        committed_revision: receipt.committed_revision.get(),
    })
}
