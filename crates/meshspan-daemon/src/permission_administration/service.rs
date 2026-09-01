// SPDX-License-Identifier: GPL-2.0-only

//! Complete manager-authorised permission administration service.

use axum::http::HeaderMap;
use axum::http::header::{AUTHORIZATION, COOKIE};
use meshspan_api_contract::{
    CreateVolumePermissionGrantRequest, CreateVolumePermissionGrantResponse,
    ListVolumePermissionGrantsQuery, ListVolumePermissionGrantsResponse, PermissionGrantId,
    RevokePermissionGrantRequest, RevokePermissionGrantResponse, VolumeId as ApiVolumeId,
};
use meshspan_domain::UnixMicros;
use meshspan_metadata::{PageLimit, PermissionScope};

use super::contract::{PermissionAdministrationAuthority, PermissionAdministrationAuthorityError};
use super::model::{
    command_context, create_response, decode_cursor, domain_grant, domain_volume, grant_command,
    list_response, revoke_command, revoke_response, validate_grant, validate_receipt,
};
use super::{PermissionAdministrationController, PermissionAdministrationError};
use crate::{
    BrowserRequestProtection, BrowserSessionAuthenticator, FileApiAuthenticationError,
    GatewaySessionIdentity, IdentityAdministrator, NativeApiKeyAuthenticator,
};

/// Manager-authorised permission administration backed by one replicated authority.
pub struct PermissionAdministrationService<A> {
    authority: A,
    gateway: GatewaySessionIdentity,
}

impl<A> PermissionAdministrationService<A> {
    /// Binds replicated permission authority to one serving gateway.
    #[must_use]
    pub const fn new(authority: A, gateway: GatewaySessionIdentity) -> Self {
        Self { authority, gateway }
    }
}

impl<A> PermissionAdministrationController for PermissionAdministrationService<A>
where
    A: PermissionAdministrationAuthority + Send + 'static,
{
    fn authenticate(
        &self,
        headers: &HeaderMap,
        protection: BrowserRequestProtection,
        now: UnixMicros,
    ) -> Result<IdentityAdministrator, PermissionAdministrationError> {
        let has_authorization = headers.contains_key(AUTHORIZATION);
        if has_authorization && headers.contains_key(COOKIE) {
            return Err(PermissionAdministrationError::Unauthenticated);
        }
        let principal_id = if has_authorization {
            NativeApiKeyAuthenticator::new(&self.authority, self.gateway)
                .authenticate_principal(headers, now)
                .map_err(map_file_authentication_error)?
        } else {
            BrowserSessionAuthenticator::new(&self.authority, self.gateway)
                .authenticate(
                    headers,
                    protection,
                    meshspan_domain::AssuranceLevel::SingleFactor,
                    now,
                )
                .map_err(|error| match error {
                    crate::BrowserAuthenticationError::Rejected => {
                        PermissionAdministrationError::Unauthenticated
                    }
                    crate::BrowserAuthenticationError::Authority(
                        crate::BrowserSessionAuthorityError::Unavailable,
                    ) => PermissionAdministrationError::Unavailable,
                    crate::BrowserAuthenticationError::InvalidGateway
                    | crate::BrowserAuthenticationError::Authority(
                        crate::BrowserSessionAuthorityError::Failed,
                    ) => PermissionAdministrationError::Failed,
                })?
                .principal_id
        };
        if !self
            .authority
            .is_system_manager(principal_id, now)
            .map_err(map_authority_error)?
        {
            return Err(PermissionAdministrationError::Forbidden);
        }
        Ok(IdentityAdministrator { principal_id, now })
    }

    fn list_volume_grants(
        &self,
        _administrator: IdentityAdministrator,
        api_volume_id: &ApiVolumeId,
        query: ListVolumePermissionGrantsQuery,
    ) -> Result<ListVolumePermissionGrantsResponse, PermissionAdministrationError> {
        let volume_id = domain_volume(api_volume_id)?;
        self.require_volume(volume_id)?;
        let after = query
            .cursor
            .as_ref()
            .map(|cursor| decode_cursor(cursor, volume_id))
            .transpose()?;
        let limit = query.limit.unwrap_or(50);
        let page = self
            .authority
            .volume_grants(
                volume_id,
                after,
                PageLimit::new(usize::from(limit))
                    .map_err(|_| PermissionAdministrationError::InvalidInput)?,
            )
            .map_err(map_authority_error)?;
        list_response(api_volume_id.clone(), &query, limit, page)
    }

    fn create_volume_grant(
        &mut self,
        administrator: IdentityAdministrator,
        api_volume_id: &ApiVolumeId,
        request: CreateVolumePermissionGrantRequest,
    ) -> Result<CreateVolumePermissionGrantResponse, PermissionAdministrationError> {
        let volume_id = domain_volume(api_volume_id)?;
        self.require_volume(volume_id)?;
        let (operation_id, grant_id, command) = grant_command(volume_id, &request)?;
        let subject = match &command {
            meshspan_metadata::AuthoritativeCommand::GrantPermission(value) => {
                value.subject_principal_id
            }
            meshspan_metadata::AuthoritativeCommand::GrantPermissionWithActivation(value) => {
                value.grant.subject_principal_id
            }
            _ => return Err(PermissionAdministrationError::Failed),
        };
        if !self
            .authority
            .principal_exists(subject)
            .map_err(map_authority_error)?
        {
            return Err(PermissionAdministrationError::NotFound);
        }
        let existing = self
            .authority
            .resolve_operation(operation_id)
            .map_err(map_authority_error)?;
        let record = self
            .authority
            .grant(grant_id)
            .map_err(map_authority_error)?;
        let occurred_at = record.map_or(administrator.now, |value| value.created_at);
        let context = command_context(operation_id, administrator, occurred_at)?;
        let expected_digest = command.request_digest(context);
        let receipt = match existing {
            Some(receipt) => receipt,
            None => match self.authority.commit_permission(context, &command) {
                Ok(receipt) => receipt,
                Err(commit_error) => self
                    .authority
                    .resolve_operation(operation_id)
                    .map_err(map_authority_error)?
                    .ok_or_else(|| map_authority_error(commit_error))?,
            },
        };
        validate_receipt(receipt, grant_id, expected_digest)?;
        let record = self
            .authority
            .grant(grant_id)
            .map_err(map_authority_error)?
            .ok_or(PermissionAdministrationError::Failed)?;
        validate_grant(record, &command)?;
        create_response(request.operation_id, record)
    }

    fn revoke_grant(
        &mut self,
        administrator: IdentityAdministrator,
        api_volume_id: &ApiVolumeId,
        api_grant_id: &PermissionGrantId,
        request: RevokePermissionGrantRequest,
    ) -> Result<RevokePermissionGrantResponse, PermissionAdministrationError> {
        let volume_id = domain_volume(api_volume_id)?;
        self.require_volume(volume_id)?;
        let grant_id = domain_grant(api_grant_id)?;
        let (operation_id, command) = revoke_command(grant_id, &request)?;
        let existing = self
            .authority
            .resolve_operation(operation_id)
            .map_err(map_authority_error)?;
        let revocation = self
            .authority
            .grant_revocation(grant_id)
            .map_err(map_authority_error)?;
        let occurred_at = revocation.map_or(administrator.now, |value| value.revoked_at);
        let context = command_context(operation_id, administrator, occurred_at)?;
        let expected_digest = command.request_digest(context);
        let receipt = match existing {
            Some(receipt) => receipt,
            None => {
                let active = self
                    .authority
                    .grant(grant_id)
                    .map_err(map_authority_error)?
                    .ok_or(PermissionAdministrationError::NotFound)?;
                if active.scope != PermissionScope::Volume(volume_id) {
                    return Err(PermissionAdministrationError::NotFound);
                }
                match self.authority.commit_permission(context, &command) {
                    Ok(receipt) => receipt,
                    Err(commit_error) => self
                        .authority
                        .resolve_operation(operation_id)
                        .map_err(map_authority_error)?
                        .ok_or_else(|| map_authority_error(commit_error))?,
                }
            }
        };
        validate_receipt(receipt, grant_id, expected_digest)?;
        let revocation = self
            .authority
            .grant_revocation(grant_id)
            .map_err(map_authority_error)?
            .ok_or(PermissionAdministrationError::Failed)?;
        revoke_response(request.operation_id, revocation)
    }
}

impl<A> PermissionAdministrationService<A>
where
    A: PermissionAdministrationAuthority,
{
    fn require_volume(
        &self,
        volume_id: meshspan_domain::VolumeId,
    ) -> Result<(), PermissionAdministrationError> {
        self.authority
            .volume(volume_id)
            .map_err(map_authority_error)?
            .ok_or(PermissionAdministrationError::NotFound)
            .map(|_| ())
    }
}

const fn map_authority_error(
    error: PermissionAdministrationAuthorityError,
) -> PermissionAdministrationError {
    match error {
        PermissionAdministrationAuthorityError::Unavailable => {
            PermissionAdministrationError::Unavailable
        }
        PermissionAdministrationAuthorityError::Conflict => PermissionAdministrationError::Conflict,
        PermissionAdministrationAuthorityError::Failed => PermissionAdministrationError::Failed,
    }
}

const fn map_file_authentication_error(
    error: FileApiAuthenticationError,
) -> PermissionAdministrationError {
    match error {
        FileApiAuthenticationError::Rejected => PermissionAdministrationError::Unauthenticated,
        FileApiAuthenticationError::InvalidGateway
        | FileApiAuthenticationError::AuthorityFailed => PermissionAdministrationError::Failed,
        FileApiAuthenticationError::AuthorityUnavailable => {
            PermissionAdministrationError::Unavailable
        }
    }
}
