// SPDX-License-Identifier: GPL-2.0-only

//! Canonical recovery-code issuance command and public response construction.

use meshspan_api_contract::{
    AuthenticationMethodId as PublicMethodId, CreateRecoveryCodesRequest,
    CreateRecoveryCodesResponse, RECOVERY_CODES_PER_SET, RecoveryCode as PublicRecoveryCode,
};
use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    AuditEventId, AuthenticationMethodId, AuthenticationService, OperationId, PrincipalId,
    RecoveryCodeBundle, RecoveryCodeIssuanceKey, UnixMicros,
};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, CreateAuthenticationMethod, NewAuthenticationCredential,
    NewRecoveryCode,
};
use sha2::{Digest, Sha256};

use crate::create_mesh_setup::parse_uuid;
use crate::{RecoveryCodeIssuanceCommit, RecoveryCodeIssuanceError};

const METHOD_ID_DOMAIN: &[u8] = b"meshspan.authentication.recovery-code-method-id.v1\0";
const AUDIT_ID_DOMAIN: &[u8] = b"meshspan.authentication.recovery-code-audit-id.v1\0";

pub(crate) fn operation_id(
    request: &CreateRecoveryCodesRequest,
) -> Result<OperationId, RecoveryCodeIssuanceError> {
    OperationId::from_bytes(
        parse_uuid(request.operation_id.as_str())
            .map_err(|_| RecoveryCodeIssuanceError::InvalidRequest)?,
    )
    .map_err(|_| RecoveryCodeIssuanceError::InvalidRequest)
}

pub(crate) fn derive_codes(
    key: &RecoveryCodeIssuanceKey,
    principal_id: PrincipalId,
    operation_id: OperationId,
) -> Result<Vec<RecoveryCodeBundle>, RecoveryCodeIssuanceError> {
    (1..=RECOVERY_CODES_PER_SET)
        .map(|sequence| {
            RecoveryCodeBundle::derive_issued(
                key,
                principal_id,
                operation_id,
                u8::try_from(sequence).map_err(|_| RecoveryCodeIssuanceError::Material)?,
            )
            .map_err(|_| RecoveryCodeIssuanceError::Material)
        })
        .collect()
}

pub(crate) fn method_id(
    principal_id: PrincipalId,
    operation_id: OperationId,
) -> Result<AuthenticationMethodId, RecoveryCodeIssuanceError> {
    let mut digest = Sha256::new();
    digest.update(METHOD_ID_DOMAIN);
    digest.update(principal_id.as_bytes());
    digest.update(operation_id.as_bytes());
    let mut bytes: [u8; 16] = digest.finalize()[..16]
        .try_into()
        .map_err(|_| RecoveryCodeIssuanceError::Material)?;
    version_uuid(&mut bytes);
    AuthenticationMethodId::from_bytes(bytes).map_err(|_| RecoveryCodeIssuanceError::Material)
}

pub(crate) fn command(
    request: &CreateRecoveryCodesRequest,
    codes: &[RecoveryCodeBundle],
    method_id: AuthenticationMethodId,
    principal_id: PrincipalId,
) -> Result<AuthoritativeCommand, RecoveryCodeIssuanceError> {
    let codes = codes
        .iter()
        .map(|code| NewRecoveryCode {
            code_id: code.code_id(),
            code_digest: code.secret_digest(),
        })
        .collect();
    Ok(AuthoritativeCommand::CreateAuthenticationMethod(
        CreateAuthenticationMethod {
            method_id,
            principal_id,
            label: request.label.as_str().to_owned(),
            service_scope: AuthenticationService::Https.scope_bit(),
            expires_at: None,
            credential: NewAuthenticationCredential::RecoveryCodes {
                codes: BoundedItems::new(codes, 64)
                    .map_err(|_| RecoveryCodeIssuanceError::Material)?,
            },
        },
    ))
}

pub(crate) fn context(
    operation_id: OperationId,
    principal_id: PrincipalId,
    method_id: AuthenticationMethodId,
    occurred_at: UnixMicros,
) -> Result<CommandContext, RecoveryCodeIssuanceError> {
    let mut digest = Sha256::new();
    digest.update(AUDIT_ID_DOMAIN);
    digest.update(operation_id.as_bytes());
    digest.update(principal_id.as_bytes());
    digest.update(method_id.as_bytes());
    let mut bytes: [u8; 16] = digest.finalize()[..16]
        .try_into()
        .map_err(|_| RecoveryCodeIssuanceError::Material)?;
    version_uuid(&mut bytes);
    Ok(CommandContext {
        operation_id,
        actor_principal_id: principal_id,
        audit_event_id: AuditEventId::from_bytes(bytes)
            .map_err(|_| RecoveryCodeIssuanceError::Material)?,
        occurred_at,
        expected_revision: None,
    })
}

pub(crate) fn validate_commit(
    commit: RecoveryCodeIssuanceCommit,
    expected_request_digest: [u8; 32],
    method_id: AuthenticationMethodId,
    principal_id: PrincipalId,
) -> Result<(), RecoveryCodeIssuanceError> {
    if commit.request_digest != expected_request_digest
        || commit.result_digest == [0; 32]
        || commit.method_id != method_id
        || commit.principal_id != principal_id
    {
        Err(RecoveryCodeIssuanceError::Conflict)
    } else {
        Ok(())
    }
}

pub(crate) fn response(
    request: &CreateRecoveryCodesRequest,
    codes: &[RecoveryCodeBundle],
    commit: RecoveryCodeIssuanceCommit,
) -> Result<CreateRecoveryCodesResponse, RecoveryCodeIssuanceError> {
    let codes = codes
        .iter()
        .map(|code| PublicRecoveryCode::from_canonical(code.expose_encoded().to_string()))
        .collect::<Vec<_>>();
    if codes.len() != RECOVERY_CODES_PER_SET {
        return Err(RecoveryCodeIssuanceError::InvalidReceipt);
    }
    Ok(CreateRecoveryCodesResponse {
        operation_id: request.operation_id.clone(),
        method_id: PublicMethodId::from_uuid_bytes(commit.method_id.as_bytes())
            .ok_or(RecoveryCodeIssuanceError::InvalidReceipt)?,
        codes,
        created_at_epoch_micros: commit.created_at.get(),
    })
}

const fn version_uuid(bytes: &mut [u8; 16]) {
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
}
