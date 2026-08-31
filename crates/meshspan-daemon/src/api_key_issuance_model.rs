// SPDX-License-Identifier: GPL-2.0-only

//! Canonical API-key issuance command and public response construction.

use std::collections::BTreeSet;

use meshspan_api_contract::{
    ApiKeyId as PublicApiKeyId, ApiKeyScope, AuthenticationMethodId as PublicMethodId,
    CreateApiKeyRequest, CreateApiKeyResponse, NullableField,
};
use meshspan_domain::{
    ApiKeyBundle, AuditEventId, AuthenticationMethodId, AuthenticationService, DurationMicros,
    OperationId, PrincipalId, UnixMicros,
};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, CreateAuthenticationMethod, NewAuthenticationCredential,
};
use sha2::{Digest, Sha256};

use crate::create_mesh_setup::parse_uuid;
use crate::{ApiKeyIssuanceCommit, ApiKeyIssuanceError};

const DEFAULT_LIFETIME_MICROS: u64 = 90 * 24 * 60 * 60 * 1_000_000;
const MAXIMUM_LIFETIME_MICROS: u64 = 10 * 366 * 24 * 60 * 60 * 1_000_000;
const METHOD_ID_DOMAIN: &[u8] = b"meshspan.authentication.api-key-method-id.v1\0";
const AUDIT_ID_DOMAIN: &[u8] = b"meshspan.authentication.api-key-audit-id.v1\0";

pub(crate) struct NormalizedIssuance {
    pub(crate) operation_id: OperationId,
    pub(crate) scopes: Vec<ApiKeyScope>,
    pub(crate) scope_bits: u64,
    pub(crate) service_scope: u8,
}

pub(crate) fn normalize_request(
    request: &CreateApiKeyRequest,
) -> Result<NormalizedIssuance, ApiKeyIssuanceError> {
    let operation_id = OperationId::from_bytes(
        parse_uuid(request.operation_id.as_str())
            .map_err(|_| ApiKeyIssuanceError::InvalidRequest)?,
    )
    .map_err(|_| ApiKeyIssuanceError::InvalidRequest)?;
    let scopes = request.scopes.iter().copied().collect::<BTreeSet<_>>();
    if scopes.is_empty() || scopes.len() != request.scopes.len() {
        return Err(ApiKeyIssuanceError::InvalidRequest);
    }
    let scopes = scopes.into_iter().collect::<Vec<_>>();
    let (scope_bits, service_scope) = scopes.iter().fold((0_u64, 0_u8), |bits, scope| {
        let service = scope_service(*scope);
        (
            bits.0 | service.api_key_login_scope(),
            bits.1 | service.scope_bit(),
        )
    });
    Ok(NormalizedIssuance {
        operation_id,
        scopes,
        scope_bits,
        service_scope,
    })
}

pub(crate) fn expiry(
    request: &CreateApiKeyRequest,
    created_at: UnixMicros,
) -> Result<Option<UnixMicros>, ApiKeyIssuanceError> {
    let maximum = created_at
        .checked_add(DurationMicros::new(MAXIMUM_LIFETIME_MICROS))
        .ok_or(ApiKeyIssuanceError::InvalidRequest)?;
    match request.expires_at_epoch_micros {
        NullableField::Missing => created_at
            .checked_add(DurationMicros::new(DEFAULT_LIFETIME_MICROS))
            .map(Some)
            .ok_or(ApiKeyIssuanceError::InvalidRequest),
        NullableField::Null => Ok(None),
        NullableField::Value(value) => {
            let expiry = UnixMicros::new(value.epoch_micros());
            if expiry <= created_at || expiry > maximum {
                Err(ApiKeyIssuanceError::InvalidRequest)
            } else {
                Ok(Some(expiry))
            }
        }
    }
}

pub(crate) fn method_id(
    principal_id: PrincipalId,
    operation_id: OperationId,
) -> Result<AuthenticationMethodId, ApiKeyIssuanceError> {
    let mut digest = Sha256::new();
    digest.update(METHOD_ID_DOMAIN);
    digest.update(principal_id.as_bytes());
    digest.update(operation_id.as_bytes());
    let mut bytes: [u8; 16] = digest.finalize()[..16]
        .try_into()
        .map_err(|_| ApiKeyIssuanceError::Material)?;
    version_uuid(&mut bytes);
    AuthenticationMethodId::from_bytes(bytes).map_err(|_| ApiKeyIssuanceError::Material)
}

pub(crate) fn command(
    request: &CreateApiKeyRequest,
    normalized: &NormalizedIssuance,
    key: &ApiKeyBundle,
    method_id: AuthenticationMethodId,
    principal_id: PrincipalId,
    created_at: UnixMicros,
    expires_at: Option<UnixMicros>,
) -> AuthoritativeCommand {
    AuthoritativeCommand::CreateAuthenticationMethod(CreateAuthenticationMethod {
        method_id,
        principal_id,
        label: request.label.as_str().to_owned(),
        service_scope: normalized.service_scope,
        expires_at,
        credential: NewAuthenticationCredential::ApiKey {
            key_id: key.key_id(),
            key_digest: key.secret_digest(),
            scopes: normalized.scope_bits,
            valid_from: created_at,
        },
    })
}

pub(crate) fn context(
    operation_id: OperationId,
    principal_id: PrincipalId,
    key: &ApiKeyBundle,
    occurred_at: UnixMicros,
) -> Result<CommandContext, ApiKeyIssuanceError> {
    let mut digest = Sha256::new();
    digest.update(AUDIT_ID_DOMAIN);
    digest.update(operation_id.as_bytes());
    digest.update(principal_id.as_bytes());
    digest.update(key.key_id().as_bytes());
    let mut bytes: [u8; 16] = digest.finalize()[..16]
        .try_into()
        .map_err(|_| ApiKeyIssuanceError::Material)?;
    version_uuid(&mut bytes);
    Ok(CommandContext {
        operation_id,
        actor_principal_id: principal_id,
        audit_event_id: AuditEventId::from_bytes(bytes)
            .map_err(|_| ApiKeyIssuanceError::Material)?,
        occurred_at,
        expected_revision: None,
    })
}

pub(crate) fn validate_commit(
    commit: ApiKeyIssuanceCommit,
    expected_request_digest: [u8; 32],
    method_id: AuthenticationMethodId,
    principal_id: PrincipalId,
) -> Result<(), ApiKeyIssuanceError> {
    if commit.request_digest != expected_request_digest
        || commit.result_digest == [0; 32]
        || commit.method_id != method_id
        || commit.principal_id != principal_id
    {
        Err(ApiKeyIssuanceError::Conflict)
    } else {
        Ok(())
    }
}

pub(crate) fn response(
    request: &CreateApiKeyRequest,
    normalized: NormalizedIssuance,
    key: &ApiKeyBundle,
    commit: ApiKeyIssuanceCommit,
    expires_at: Option<UnixMicros>,
) -> Result<CreateApiKeyResponse, ApiKeyIssuanceError> {
    Ok(CreateApiKeyResponse {
        operation_id: request.operation_id.clone(),
        method_id: PublicMethodId::from_uuid_bytes(commit.method_id.as_bytes())
            .ok_or(ApiKeyIssuanceError::InvalidReceipt)?,
        key_id: PublicApiKeyId::from_uuid_bytes(key.key_id().as_bytes())
            .ok_or(ApiKeyIssuanceError::InvalidReceipt)?,
        secret: key.expose_encoded().to_string(),
        scopes: normalized.scopes,
        created_at_epoch_micros: commit.created_at.get(),
        valid_from_epoch_micros: commit.created_at.get(),
        expires_at_epoch_micros: expires_at.map(UnixMicros::get),
    })
}

const fn scope_service(scope: ApiKeyScope) -> AuthenticationService {
    match scope {
        ApiKeyScope::HttpsSession => AuthenticationService::Https,
        ApiKeyScope::HeadlessApi => AuthenticationService::HeadlessApi,
        ApiKeyScope::SmbSession => AuthenticationService::Smb,
    }
}

const fn version_uuid(bytes: &mut [u8; 16]) {
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
}
