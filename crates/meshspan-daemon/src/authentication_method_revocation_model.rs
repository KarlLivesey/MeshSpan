// SPDX-License-Identifier: GPL-2.0-only

//! Canonical authentication-method revocation command and response construction.

use meshspan_api_contract::{
    AuthenticationMethodId as PublicMethodId, RevokeAuthenticationMethodRequest,
    RevokeAuthenticationMethodResponse,
};
use meshspan_domain::{AuditEventId, AuthenticationMethodId, OperationId, PrincipalId, UnixMicros};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext,
    RevokeAuthenticationMethod as RevokeAuthenticationMethodCommand,
};
use sha2::{Digest, Sha256};

use crate::create_mesh_setup::parse_uuid;
use crate::{AuthenticationMethodRevocationCommit, AuthenticationMethodRevocationError};

const AUDIT_ID_DOMAIN: &[u8] = b"meshspan.authentication.method-revocation-audit-id.v1\0";

pub(crate) fn operation_id(
    request: &RevokeAuthenticationMethodRequest,
) -> Result<OperationId, AuthenticationMethodRevocationError> {
    OperationId::from_bytes(
        parse_uuid(request.operation_id.as_str())
            .map_err(|_| AuthenticationMethodRevocationError::InvalidRequest)?,
    )
    .map_err(|_| AuthenticationMethodRevocationError::InvalidRequest)
}

pub(crate) fn method_id(
    method_id: &PublicMethodId,
) -> Result<AuthenticationMethodId, AuthenticationMethodRevocationError> {
    let bytes = parse_uuid(method_id.as_str())
        .map_err(|_| AuthenticationMethodRevocationError::InvalidRequest)?;
    if !(1..=8).contains(&(bytes[6] >> 4)) || bytes[8] >> 6 != 2 {
        return Err(AuthenticationMethodRevocationError::InvalidRequest);
    }
    AuthenticationMethodId::from_bytes(bytes)
        .map_err(|_| AuthenticationMethodRevocationError::InvalidRequest)
}

pub(crate) fn command(
    request: &RevokeAuthenticationMethodRequest,
    method_id: AuthenticationMethodId,
    principal_id: PrincipalId,
) -> Result<AuthoritativeCommand, AuthenticationMethodRevocationError> {
    let reason = request.reason.as_str();
    let count = reason.chars().count();
    if count == 0
        || count > 1_024
        || reason.trim() != reason
        || reason.chars().any(char::is_control)
    {
        return Err(AuthenticationMethodRevocationError::InvalidRequest);
    }
    Ok(AuthoritativeCommand::RevokeAuthenticationMethod(
        RevokeAuthenticationMethodCommand {
            method_id,
            principal_id,
            reason: reason.to_owned(),
        },
    ))
}

pub(crate) fn context(
    operation_id: OperationId,
    principal_id: PrincipalId,
    method_id: AuthenticationMethodId,
    occurred_at: UnixMicros,
) -> Result<CommandContext, AuthenticationMethodRevocationError> {
    let mut digest = Sha256::new();
    digest.update(AUDIT_ID_DOMAIN);
    digest.update(operation_id.as_bytes());
    digest.update(principal_id.as_bytes());
    digest.update(method_id.as_bytes());
    let mut bytes: [u8; 16] = digest.finalize()[..16]
        .try_into()
        .map_err(|_| AuthenticationMethodRevocationError::InvalidReceipt)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(CommandContext {
        operation_id,
        actor_principal_id: principal_id,
        audit_event_id: AuditEventId::from_bytes(bytes)
            .map_err(|_| AuthenticationMethodRevocationError::InvalidReceipt)?,
        occurred_at,
        expected_revision: None,
    })
}

pub(crate) fn validate_commit(
    commit: AuthenticationMethodRevocationCommit,
    expected_request_digest: [u8; 32],
    method_id: AuthenticationMethodId,
    principal_id: PrincipalId,
) -> Result<(), AuthenticationMethodRevocationError> {
    if commit.request_digest != expected_request_digest
        || commit.result_digest == [0; 32]
        || commit.method_id != method_id
        || commit.principal_id != principal_id
        || commit.actor_principal_id != principal_id
    {
        Err(AuthenticationMethodRevocationError::Conflict)
    } else {
        Ok(())
    }
}

pub(crate) fn response(
    request: &RevokeAuthenticationMethodRequest,
    commit: AuthenticationMethodRevocationCommit,
) -> Result<RevokeAuthenticationMethodResponse, AuthenticationMethodRevocationError> {
    Ok(RevokeAuthenticationMethodResponse {
        operation_id: request.operation_id.clone(),
        method_id: PublicMethodId::from_uuid_bytes(commit.method_id.as_bytes())
            .ok_or(AuthenticationMethodRevocationError::InvalidReceipt)?,
        revoked_at_epoch_micros: commit.revoked_at.get(),
    })
}
