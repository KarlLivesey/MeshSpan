// SPDX-License-Identifier: GPL-2.0-only

//! Manager-authorised user/group administration application service.

use axum::http::HeaderMap;
use axum::http::header::{AUTHORIZATION, COOKIE};
use meshspan_api_contract::{
    AddGroupMemberRequest, AddGroupMemberResponse, CreateGroupRequest, CreatePrincipalResponse,
    CreateUserRequest, ListGroupMembershipsQuery, ListGroupMembershipsResponse,
    ListPrincipalsQuery, ListPrincipalsResponse, PrincipalId as ApiPrincipalId,
    PrincipalKind as ApiPrincipalKind, RemoveGroupMemberRequest, RemoveGroupMemberResponse,
    validate_list_group_memberships_query, validate_list_principals_query,
};
use meshspan_domain::{AssuranceLevel, GroupId, OperationId, PrincipalId, UnixMicros};
use meshspan_metadata::{
    AuthoritativeCommand, GroupMembershipEventKind, PageLimit, PrincipalKind, PrincipalRecord,
};

use super::model::{
    add_membership_command, add_membership_response, command_context, creation_response,
    decode_cursor, decode_membership_cursor, domain_group, domain_kind, group_command,
    list_response, membership_list_response, remove_membership_command, remove_membership_response,
    user_command,
};
use super::{
    GroupMembershipAdministrationCommit, IdentityAdministrationAuthority,
    IdentityAdministrationAuthorityError, IdentityAdministrationController,
    IdentityAdministrationError, IdentityAdministrator,
};
use crate::{
    BrowserAuthenticationError, BrowserRequestProtection, BrowserSessionAuthenticator,
    FileApiAuthenticationError, GatewaySessionIdentity, NativeApiKeyAuthenticator,
};

const DEFAULT_PAGE_LIMIT: u16 = 100;

/// Complete identity-administration service over replaceable replicated authority.
pub struct IdentityAdministrationService<A> {
    authority: A,
    gateway: GatewaySessionIdentity,
}

impl<A> IdentityAdministrationService<A> {
    /// Binds manager authentication and identity operations to one gateway authority view.
    #[must_use]
    pub const fn new(authority: A, gateway: GatewaySessionIdentity) -> Self {
        Self { authority, gateway }
    }

    /// Returns the owned authority for process persistence and shutdown composition.
    #[must_use]
    pub fn into_authority(self) -> A {
        self.authority
    }
}

impl<A> IdentityAdministrationController for IdentityAdministrationService<A>
where
    A: IdentityAdministrationAuthority + Send + 'static,
{
    fn authenticate(
        &self,
        headers: &HeaderMap,
        protection: BrowserRequestProtection,
        now: UnixMicros,
    ) -> Result<IdentityAdministrator, IdentityAdministrationError> {
        let has_authorization = headers.contains_key(AUTHORIZATION);
        if has_authorization && headers.contains_key(COOKIE) {
            return Err(IdentityAdministrationError::Unauthenticated);
        }
        if has_authorization {
            let principal_id = NativeApiKeyAuthenticator::new(&self.authority, self.gateway)
                .authenticate_principal(headers, now)
                .map_err(map_file_authentication_error)?;
            let permitted = self
                .authority
                .is_system_manager(principal_id, now)
                .map_err(map_authority_error)?;
            return if permitted {
                Ok(IdentityAdministrator { principal_id, now })
            } else {
                Err(IdentityAdministrationError::Forbidden)
            };
        }
        let capability = BrowserSessionAuthenticator::new(&self.authority, self.gateway)
            .authenticate(headers, protection, AssuranceLevel::SingleFactor, now)
            .map_err(map_authentication_error)?;
        if !capability.is_system_manager() {
            return Err(IdentityAdministrationError::Forbidden);
        }
        Ok(IdentityAdministrator {
            principal_id: capability.principal_id,
            now,
        })
    }

    fn list_principals(
        &self,
        _administrator: IdentityAdministrator,
        api_kind: ApiPrincipalKind,
        query: ListPrincipalsQuery,
    ) -> Result<ListPrincipalsResponse, IdentityAdministrationError> {
        validate_list_principals_query(&query)
            .map_err(|_| IdentityAdministrationError::InvalidInput)?;
        let kind = domain_kind(api_kind);
        let cursor = query
            .cursor
            .as_ref()
            .map(|value| decode_cursor(value, kind))
            .transpose()?;
        let limit = query.limit.unwrap_or(DEFAULT_PAGE_LIMIT);
        let page = self
            .authority
            .principals(
                kind,
                cursor.as_ref(),
                PageLimit::new(usize::from(limit))
                    .map_err(|_| IdentityAdministrationError::InvalidInput)?,
            )
            .map_err(map_authority_error)?;
        list_response(api_kind, &query, limit, page)
    }

    fn create_user(
        &mut self,
        administrator: IdentityAdministrator,
        request: CreateUserRequest,
    ) -> Result<CreatePrincipalResponse, IdentityAdministrationError> {
        let (operation_id, principal_id, command) = user_command(&request)?;
        self.create(
            administrator,
            operation_id,
            principal_id,
            PrincipalKind::User,
            &command,
            &request.operation_id,
        )
    }

    fn create_group(
        &mut self,
        administrator: IdentityAdministrator,
        request: CreateGroupRequest,
    ) -> Result<CreatePrincipalResponse, IdentityAdministrationError> {
        let (operation_id, principal_id, command) = group_command(&request)?;
        self.create(
            administrator,
            operation_id,
            principal_id,
            PrincipalKind::Group,
            &command,
            &request.operation_id,
        )
    }

    fn list_group_memberships(
        &self,
        _administrator: IdentityAdministrator,
        api_group_id: &ApiPrincipalId,
        query: ListGroupMembershipsQuery,
    ) -> Result<ListGroupMembershipsResponse, IdentityAdministrationError> {
        validate_list_group_memberships_query(&query)
            .map_err(|_| IdentityAdministrationError::InvalidInput)?;
        let group_id = domain_group(api_group_id)?;
        self.ensure_group(group_id)?;
        let cursor = query
            .cursor
            .as_ref()
            .map(|value| decode_membership_cursor(value, group_id))
            .transpose()?;
        let limit = query.limit.unwrap_or(DEFAULT_PAGE_LIMIT);
        let page = self
            .authority
            .group_memberships(
                group_id,
                cursor,
                PageLimit::new(usize::from(limit))
                    .map_err(|_| IdentityAdministrationError::InvalidInput)?,
            )
            .map_err(map_authority_error)?;
        membership_list_response(api_group_id, &query, limit, page)
    }

    fn add_group_member(
        &mut self,
        administrator: IdentityAdministrator,
        api_group_id: &ApiPrincipalId,
        request: AddGroupMemberRequest,
    ) -> Result<AddGroupMemberResponse, IdentityAdministrationError> {
        let (operation_id, group_id, member_principal_id, command) =
            add_membership_command(api_group_id, &request)?;
        self.ensure_group(group_id)?;
        let member = self.require_principal(member_principal_id)?;
        let commit = self.membership_commit(
            administrator,
            operation_id,
            group_id,
            member_principal_id,
            GroupMembershipEventKind::Added,
            &command,
        )?;
        add_membership_response(&request.operation_id, &request, commit, member)
    }

    fn remove_group_member(
        &mut self,
        administrator: IdentityAdministrator,
        api_group_id: &ApiPrincipalId,
        api_member_principal_id: &ApiPrincipalId,
        request: RemoveGroupMemberRequest,
    ) -> Result<RemoveGroupMemberResponse, IdentityAdministrationError> {
        let (operation_id, group_id, member_principal_id, command) =
            remove_membership_command(api_group_id, api_member_principal_id, &request)?;
        self.ensure_group(group_id)?;
        let existing = self
            .authority
            .resolve_group_membership_mutation(operation_id)
            .map_err(map_authority_error)?;
        if existing.is_none()
            && self
                .authority
                .group_membership(group_id, member_principal_id)
                .map_err(map_authority_error)?
                .is_none()
        {
            return Err(IdentityAdministrationError::NotFound);
        }
        let commit = self.membership_commit(
            administrator,
            operation_id,
            group_id,
            member_principal_id,
            GroupMembershipEventKind::Removed,
            &command,
        )?;
        remove_membership_response(&request.operation_id, commit, api_member_principal_id)
    }
}

impl<A> IdentityAdministrationService<A>
where
    A: IdentityAdministrationAuthority,
{
    fn create(
        &mut self,
        administrator: IdentityAdministrator,
        operation_id: meshspan_domain::OperationId,
        principal_id: meshspan_domain::PrincipalId,
        kind: PrincipalKind,
        command: &AuthoritativeCommand,
        api_operation_id: &meshspan_api_contract::OperationId,
    ) -> Result<CreatePrincipalResponse, IdentityAdministrationError> {
        let existing = self
            .authority
            .resolve_principal_creation(operation_id, kind)
            .map_err(map_authority_error)?;
        let occurred_at = existing.map_or(administrator.now, |commit| commit.occurred_at);
        let context = command_context(operation_id, administrator, occurred_at)?;
        let expected_digest = command.request_digest(context);
        let commit = match existing {
            Some(commit) => commit,
            None => self
                .authority
                .commit_or_resolve_principal_creation(context, command, kind)
                .map_err(map_authority_error)?,
        };
        if commit.request_digest != expected_digest || commit.principal_id != principal_id {
            return Err(IdentityAdministrationError::Conflict);
        }
        let record = self
            .authority
            .principal(principal_id)
            .map_err(map_authority_error)?
            .ok_or(IdentityAdministrationError::Failed)?;
        if record.kind != kind {
            return Err(IdentityAdministrationError::Failed);
        }
        creation_response(api_operation_id, commit, record)
    }

    fn ensure_group(&self, group_id: GroupId) -> Result<(), IdentityAdministrationError> {
        let principal = self.require_principal(group_id.principal_id())?;
        if principal.kind != PrincipalKind::Group {
            return Err(IdentityAdministrationError::NotFound);
        }
        Ok(())
    }

    fn require_principal(
        &self,
        principal_id: PrincipalId,
    ) -> Result<PrincipalRecord, IdentityAdministrationError> {
        self.authority
            .principal(principal_id)
            .map_err(map_authority_error)?
            .ok_or(IdentityAdministrationError::NotFound)
    }

    fn membership_commit(
        &mut self,
        administrator: IdentityAdministrator,
        operation_id: OperationId,
        group_id: GroupId,
        member_principal_id: PrincipalId,
        mutation_kind: GroupMembershipEventKind,
        command: &AuthoritativeCommand,
    ) -> Result<GroupMembershipAdministrationCommit, IdentityAdministrationError> {
        let existing = self
            .authority
            .resolve_group_membership_mutation(operation_id)
            .map_err(map_authority_error)?;
        let occurred_at = existing.map_or(administrator.now, |commit| commit.occurred_at);
        let context = command_context(operation_id, administrator, occurred_at)?;
        let expected_digest = command.request_digest(context);
        let commit = match existing {
            Some(commit) => commit,
            None => self
                .authority
                .commit_or_resolve_group_membership_mutation(context, command)
                .map_err(map_authority_error)?,
        };
        if commit.request_digest != expected_digest
            || commit.group_id != group_id
            || commit.member_principal_id != member_principal_id
            || commit.mutation_kind != mutation_kind
            || commit.actor_principal_id != administrator.principal_id
        {
            return Err(IdentityAdministrationError::Conflict);
        }
        Ok(commit)
    }
}

const fn map_authority_error(
    error: IdentityAdministrationAuthorityError,
) -> IdentityAdministrationError {
    match error {
        IdentityAdministrationAuthorityError::Unavailable => {
            IdentityAdministrationError::Unavailable
        }
        IdentityAdministrationAuthorityError::Conflict => IdentityAdministrationError::Conflict,
        IdentityAdministrationAuthorityError::Failed => IdentityAdministrationError::Failed,
    }
}

const fn map_authentication_error(
    error: BrowserAuthenticationError,
) -> IdentityAdministrationError {
    match error {
        BrowserAuthenticationError::Rejected => IdentityAdministrationError::Unauthenticated,
        BrowserAuthenticationError::InvalidGateway => IdentityAdministrationError::Failed,
        BrowserAuthenticationError::Authority(crate::BrowserSessionAuthorityError::Unavailable) => {
            IdentityAdministrationError::Unavailable
        }
        BrowserAuthenticationError::Authority(crate::BrowserSessionAuthorityError::Failed) => {
            IdentityAdministrationError::Failed
        }
    }
}

const fn map_file_authentication_error(
    error: FileApiAuthenticationError,
) -> IdentityAdministrationError {
    match error {
        FileApiAuthenticationError::Rejected => IdentityAdministrationError::Unauthenticated,
        FileApiAuthenticationError::InvalidGateway
        | FileApiAuthenticationError::AuthorityFailed => IdentityAdministrationError::Failed,
        FileApiAuthenticationError::AuthorityUnavailable => {
            IdentityAdministrationError::Unavailable
        }
    }
}
