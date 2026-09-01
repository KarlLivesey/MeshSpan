// SPDX-License-Identifier: GPL-2.0-only

//! Authenticated durable-operation visibility over replicated metadata.

use axum::http::HeaderMap;
use axum::http::header::{AUTHORIZATION, COOKIE};
use meshspan_api_contract::{
    OperationFailure, OperationId as ApiOperationId, OperationKind, OperationRetryClass,
    OperationState, OperationStatusResponse,
};
use meshspan_domain::{AssuranceLevel, OperationId, PrincipalId, UnixMicros};
use meshspan_metadata::{AuthoritativeOperationState, AuthoritativeOperationStatus};
use thiserror::Error;

use crate::create_mesh_setup::parse_uuid;
use crate::{
    BrowserAuthenticationError, BrowserRequestProtection, BrowserSessionAuthenticator,
    BrowserSessionAuthority, FileApiAuthenticationError, GatewaySessionIdentity,
    NativeApiKeyAuthenticator, NativeApiKeyAuthority,
};

const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

/// Replicated reads required to authorise and resolve operation status.
pub trait OperationStatusAuthority: BrowserSessionAuthority + NativeApiKeyAuthority {
    /// Returns one exact operation when it exists.
    fn operation_status(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<AuthoritativeOperationStatus>, OperationStatusAuthorityError>;

    /// Reports current system-manager authority.
    fn is_system_manager(
        &self,
        principal_id: PrincipalId,
        now: UnixMicros,
    ) -> Result<bool, OperationStatusAuthorityError>;
}

/// Synchronous operation-status controller executed on a blocking worker.
pub trait OperationStatusController: Send + 'static {
    /// Authenticates the caller before an operation identifier is resolved.
    fn authenticate(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<OperationStatusViewer, OperationStatusError>;

    /// Returns one operation visible to its actor or a current system manager.
    fn get_operation_status(
        &self,
        viewer: OperationStatusViewer,
        operation_id: &ApiOperationId,
    ) -> Result<OperationStatusResponse, OperationStatusError>;
}

/// Authenticated principal and authoritative instant used for visibility checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationStatusViewer {
    principal_id: PrincipalId,
    now: UnixMicros,
}

/// Complete operation-status application service.
pub struct OperationStatusService<A> {
    authority: A,
    gateway: GatewaySessionIdentity,
}

impl<A> OperationStatusService<A> {
    /// Binds operation visibility to one gateway authority view.
    #[must_use]
    pub const fn new(authority: A, gateway: GatewaySessionIdentity) -> Self {
        Self { authority, gateway }
    }
}

impl<A> OperationStatusController for OperationStatusService<A>
where
    A: OperationStatusAuthority + Send + 'static,
{
    fn authenticate(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<OperationStatusViewer, OperationStatusError> {
        if headers.contains_key(AUTHORIZATION) && headers.contains_key(COOKIE) {
            return Err(OperationStatusError::Unauthenticated);
        }
        let principal_id = if headers.contains_key(AUTHORIZATION) {
            NativeApiKeyAuthenticator::new(&self.authority, self.gateway)
                .authenticate_principal(headers, now)
                .map_err(map_api_key_error)?
        } else {
            BrowserSessionAuthenticator::new(&self.authority, self.gateway)
                .authenticate(
                    headers,
                    BrowserRequestProtection::Read,
                    AssuranceLevel::SingleFactor,
                    now,
                )
                .map_err(map_browser_error)?
                .principal_id
        };
        Ok(OperationStatusViewer { principal_id, now })
    }

    fn get_operation_status(
        &self,
        viewer: OperationStatusViewer,
        api_operation_id: &ApiOperationId,
    ) -> Result<OperationStatusResponse, OperationStatusError> {
        let operation_id = parse_operation_id(api_operation_id)?;
        let record = self
            .authority
            .operation_status(operation_id)
            .map_err(map_authority_error)?
            .ok_or(OperationStatusError::NotFound)?;
        if record.actor_principal_id != Some(viewer.principal_id)
            && !self
                .authority
                .is_system_manager(viewer.principal_id, viewer.now)
                .map_err(map_authority_error)?
        {
            return Err(OperationStatusError::NotFound);
        }
        public_status(record)
    }
}

fn public_status(
    record: AuthoritativeOperationStatus,
) -> Result<OperationStatusResponse, OperationStatusError> {
    let started_at = safe_timestamp(record.started_at)?;
    let completed_at = record.completed_at.map(safe_timestamp).transpose()?;
    let state = match record.state {
        AuthoritativeOperationState::Running => OperationState::Running,
        AuthoritativeOperationState::Succeeded => OperationState::Succeeded,
        AuthoritativeOperationState::Failed => OperationState::Failed,
    };
    let api_operation_id = ApiOperationId::from_uuid_bytes(record.operation_id.as_bytes())
        .ok_or(OperationStatusError::Failed)?;
    let failure = (record.state == AuthoritativeOperationState::Failed).then(|| OperationFailure {
        code: "metadata_operation_failed".to_owned(),
        message: "The committed metadata operation failed.".to_owned(),
        retry: OperationRetryClass::SameOperation,
    });
    Ok(OperationStatusResponse {
        status_url: format!("/api/latest/operations/{}", api_operation_id.as_str()),
        operation_id: api_operation_id,
        kind: OperationKind::MetadataMutation,
        state,
        progress: None,
        cancellation_available: false,
        started_at_epoch_micros: started_at,
        updated_at_epoch_micros: completed_at.unwrap_or(started_at),
        completed_at_epoch_micros: completed_at,
        failure,
        result_url: None,
        revision: record.revision.get(),
    })
}

fn parse_operation_id(value: &ApiOperationId) -> Result<OperationId, OperationStatusError> {
    let bytes = parse_uuid(value.as_str()).map_err(|_| OperationStatusError::InvalidInput)?;
    OperationId::from_bytes(bytes).map_err(|_| OperationStatusError::InvalidInput)
}

fn safe_timestamp(value: UnixMicros) -> Result<i64, OperationStatusError> {
    (0..=MAX_SAFE_INTEGER)
        .contains(&value.get())
        .then_some(value.get())
        .ok_or(OperationStatusError::Failed)
}

const fn map_api_key_error(error: FileApiAuthenticationError) -> OperationStatusError {
    match error {
        FileApiAuthenticationError::Rejected => OperationStatusError::Unauthenticated,
        FileApiAuthenticationError::AuthorityUnavailable => OperationStatusError::Unavailable,
        FileApiAuthenticationError::InvalidGateway
        | FileApiAuthenticationError::AuthorityFailed => OperationStatusError::Failed,
    }
}

const fn map_browser_error(error: BrowserAuthenticationError) -> OperationStatusError {
    match error {
        BrowserAuthenticationError::Rejected => OperationStatusError::Unauthenticated,
        BrowserAuthenticationError::Authority(crate::BrowserSessionAuthorityError::Unavailable) => {
            OperationStatusError::Unavailable
        }
        BrowserAuthenticationError::InvalidGateway
        | BrowserAuthenticationError::Authority(crate::BrowserSessionAuthorityError::Failed) => {
            OperationStatusError::Failed
        }
    }
}

const fn map_authority_error(error: OperationStatusAuthorityError) -> OperationStatusError {
    match error {
        OperationStatusAuthorityError::Unavailable => OperationStatusError::Unavailable,
        OperationStatusAuthorityError::Failed => OperationStatusError::Failed,
    }
}

/// Closed replicated-authority failures safe for public mapping.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum OperationStatusAuthorityError {
    /// Required committed authority cannot currently be reached.
    #[error("operation authority is unavailable")]
    Unavailable,
    /// Persisted or returned authority failed validation.
    #[error("operation authority failed closed")]
    Failed,
}

/// Closed public operation-status failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum OperationStatusError {
    /// The operation identifier was not canonical.
    #[error("operation-status input is invalid")]
    InvalidInput,
    /// Authentication was absent, ambiguous or rejected.
    #[error("operation-status authentication was rejected")]
    Unauthenticated,
    /// The operation does not exist or is not visible to this caller.
    #[error("operation was not found")]
    NotFound,
    /// Required committed authority is temporarily unavailable.
    #[error("operation authority is unavailable")]
    Unavailable,
    /// Persisted or returned evidence failed closed.
    #[error("operation status failed closed")]
    Failed,
}

#[cfg(test)]
mod tests {
    use meshspan_domain::Revision;

    use super::*;

    #[test]
    fn terminal_metadata_status_is_canonical_and_validated() {
        let mut operation_bytes = [23; 16];
        operation_bytes[6] = 0x80;
        operation_bytes[8] = 0x80;
        let record = AuthoritativeOperationStatus {
            operation_id: OperationId::from_bytes(operation_bytes).expect("valid operation id"),
            actor_principal_id: None,
            operation_kind: 1,
            state: AuthoritativeOperationState::Succeeded,
            started_at: UnixMicros::new(100),
            completed_at: Some(UnixMicros::new(120)),
            result: None,
            error_kind: None,
            revision: Revision::new(4),
        };

        let response = public_status(record).expect("valid public status");

        assert_eq!(response.state, OperationState::Succeeded);
        assert_eq!(response.updated_at_epoch_micros, 120);
        assert_eq!(response.completed_at_epoch_micros, Some(120));
        assert_eq!(response.revision, 4);
        meshspan_api_contract::encode_operation_status_response(&response)
            .expect("outgoing status satisfies the generated contract");
    }
}
