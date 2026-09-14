// SPDX-License-Identifier: GPL-2.0-only

//! Provider offer administration; consumer data authority is never implied by capacity.

mod commands;
mod view;

use super::{FederationPairingService, PairingError, auth_error, commit_error};
use crate::create_mesh_setup::{format_uuid, parse_uuid};
use crate::{IdentityAdministrator, authenticate_system_manager, authenticate_system_manager_read};
use axum::http::HeaderMap;
use meshspan_api_contract::{
    ConfigureFederationStorageGrantRequest, ConfigureFederationStorageGrantResponse,
};
use meshspan_domain::{
    AuditEventId, FederationGrantId, OperationId, Revision, UnixMicros, uuid_v8,
};
use meshspan_metadata::{AuthoritativeCommand, CommandContext, CommandReceipt, EntityKind};
use sha2::{Digest, Sha256};

impl FederationPairingService {
    pub(crate) fn authenticate_storage_read(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<(), PairingError> {
        authenticate_system_manager_read(&self.authority, self.gateway, headers, now)
            .map(|_| ())
            .map_err(auth_error)
    }

    pub(crate) fn configure_storage_grant(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
        request: &ConfigureFederationStorageGrantRequest,
    ) -> Result<ConfigureFederationStorageGrantResponse, PairingError> {
        let mut administrator =
            authenticate_system_manager(&self.authority, self.gateway, headers, now)
                .map_err(auth_error)?;
        let bytes = serde_json::to_vec(request).map_err(|_| PairingError::Invalid)?;
        meshspan_api_contract::decode_federation_storage_grant_request(&bytes)
            .map_err(|_| PairingError::Invalid)?;
        let operation = OperationId::from_bytes(
            parse_uuid(request.operation_id.as_str()).map_err(|_| PairingError::Invalid)?,
        )
        .map_err(|_| PairingError::Invalid)?;
        let reader = self.authority.reader();
        let previous = reader
            .resolve_operation(operation)
            .map_err(|_| PairingError::Unavailable)?;
        if previous.is_some() {
            let original = reader
                .operation_status(operation)
                .map_err(|_| PairingError::Unavailable)?
                .ok_or(PairingError::Failed)?;
            if original.actor_principal_id != Some(administrator.principal_id) {
                return Err(PairingError::Conflict);
            }
            administrator.now = original.started_at;
        } else if reader
            .current_revision()
            .map_err(|_| PairingError::Unavailable)?
            .get()
            != request.expected_metadata_revision
        {
            return Err(PairingError::Conflict);
        }
        let context = context(administrator, operation, request.expected_metadata_revision)?;
        let (id, command) = commands::prepare(
            reader,
            &request.change,
            administrator.now,
            previous.is_some(),
        )?;
        let receipt = match previous {
            Some(receipt) => receipt,
            None => match self.authority.commit_authoritative(context, &command) {
                Ok(receipt) => receipt,
                Err(error) => reader
                    .resolve_operation(operation)
                    .map_err(|_| PairingError::Unavailable)?
                    .ok_or_else(|| commit_error(error))?,
            },
        };
        validate_receipt(context, &command, receipt, id)?;
        let response = ConfigureFederationStorageGrantResponse {
            operation_id: request.operation_id.clone(),
            grant_id: meshspan_api_contract::OperationId::parse(&format_uuid(id.as_bytes()))
                .ok_or(PairingError::Failed)?,
            committed_revision: receipt.committed_revision.get(),
        };
        meshspan_api_contract::encode_federation_storage_grant_receipt(&response)
            .map_err(|_| PairingError::Failed)?;
        Ok(response)
    }
}

fn context(
    administrator: IdentityAdministrator,
    operation: OperationId,
    revision: u64,
) -> Result<CommandContext, PairingError> {
    let mut hash = Sha256::new();
    hash.update(b"meshspan.federation.storage-grant.administration.v1\0");
    hash.update(operation.as_bytes());
    let mut audit = [0; 16];
    audit.copy_from_slice(&hash.finalize()[..16]);
    Ok(CommandContext {
        operation_id: operation,
        actor_principal_id: administrator.principal_id,
        audit_event_id: AuditEventId::from_bytes(uuid_v8(audit))
            .map_err(|_| PairingError::Failed)?,
        occurred_at: administrator.now,
        expected_revision: Some(Revision::new(revision)),
    })
}

fn validate_receipt(
    context: CommandContext,
    command: &AuthoritativeCommand,
    receipt: CommandReceipt,
    id: FederationGrantId,
) -> Result<(), PairingError> {
    if receipt.operation_id != context.operation_id
        || receipt.request_digest != command.request_digest(context)
        || receipt.entity.kind != EntityKind::FederationGrant
        || receipt.entity.id != id.as_bytes()
    {
        return Err(PairingError::Conflict);
    }
    if receipt.result_digest == [0; 32] || receipt.committed_revision.get() == 0 {
        return Err(PairingError::Failed);
    }
    Ok(())
}
