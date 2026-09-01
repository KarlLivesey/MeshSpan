// SPDX-License-Identifier: GPL-2.0-only

//! Manager-authorised topology administration application service.

use axum::http::HeaderMap;
use axum::http::header::{AUTHORIZATION, COOKIE};
use meshspan_api_contract::{
    CreateFaultGroupRequest, CreateFaultGroupResponse, ListFaultGroupMembershipsResponse,
    ListFaultGroupsResponse, ListTopologyNodesResponse, ListTopologyQuery,
    ListTopologyTargetsResponse, SetFaultGroupMembershipRequest, SetFaultGroupMembershipResponse,
    validate_list_topology_query,
};
use meshspan_domain::{AssuranceLevel, UnixMicros};
use meshspan_metadata::{EntityKind, PageLimit};

use super::model::{
    command_context, create_command, decode_group_cursor, decode_membership_cursor,
    decode_node_cursor, decode_target_cursor, group_response, group_summary, membership_command,
    membership_response, node_response, target_response,
};
use super::{
    TopologyAdministrationAuthority, TopologyAdministrationAuthorityError,
    TopologyAdministrationController, TopologyAdministrationError,
};
use crate::{
    BrowserAuthenticationError, BrowserRequestProtection, BrowserSessionAuthenticator,
    FileApiAuthenticationError, GatewaySessionIdentity, IdentityAdministrationAuthorityError,
    IdentityAdministrator, NativeApiKeyAuthenticator,
};

const DEFAULT_PAGE_LIMIT: u16 = 100;

/// Complete topology administration over one replaceable replicated authority.
pub struct TopologyAdministrationService<A> {
    authority: A,
    gateway: GatewaySessionIdentity,
}

impl<A> TopologyAdministrationService<A> {
    /// Binds manager authentication and topology operations to one authority view.
    #[must_use]
    pub const fn new(authority: A, gateway: GatewaySessionIdentity) -> Self {
        Self { authority, gateway }
    }
}

impl<A> TopologyAdministrationController for TopologyAdministrationService<A>
where
    A: TopologyAdministrationAuthority + Send + 'static,
{
    fn authenticate(
        &self,
        headers: &HeaderMap,
        protection: BrowserRequestProtection,
        now: UnixMicros,
    ) -> Result<IdentityAdministrator, TopologyAdministrationError> {
        let has_authorization = headers.contains_key(AUTHORIZATION);
        if has_authorization && headers.contains_key(COOKIE) {
            return Err(TopologyAdministrationError::Unauthenticated);
        }
        if has_authorization {
            let principal_id = NativeApiKeyAuthenticator::new(&self.authority, self.gateway)
                .authenticate_principal(headers, now)
                .map_err(map_file_authentication_error)?;
            return self
                .authority
                .is_system_manager(principal_id, now)
                .map_err(map_identity_authority_error)?
                .then_some(IdentityAdministrator { principal_id, now })
                .ok_or(TopologyAdministrationError::Forbidden);
        }
        let capability = BrowserSessionAuthenticator::new(&self.authority, self.gateway)
            .authenticate(headers, protection, AssuranceLevel::SingleFactor, now)
            .map_err(map_browser_authentication_error)?;
        if !capability.is_system_manager() {
            return Err(TopologyAdministrationError::Forbidden);
        }
        Ok(IdentityAdministrator {
            principal_id: capability.principal_id,
            now,
        })
    }

    fn list_nodes(
        &self,
        _administrator: IdentityAdministrator,
        query: ListTopologyQuery,
    ) -> Result<ListTopologyNodesResponse, TopologyAdministrationError> {
        validate_list_topology_query(&query)
            .map_err(|_| TopologyAdministrationError::InvalidInput)?;
        let cursor = query.cursor.as_ref().map(decode_node_cursor).transpose()?;
        let page = self
            .authority
            .topology_nodes(cursor.as_ref(), page_limit(&query)?)
            .map_err(map_authority_error)?;
        node_response(&query, page)
    }

    fn list_targets(
        &self,
        _administrator: IdentityAdministrator,
        query: ListTopologyQuery,
    ) -> Result<ListTopologyTargetsResponse, TopologyAdministrationError> {
        validate_list_topology_query(&query)
            .map_err(|_| TopologyAdministrationError::InvalidInput)?;
        let cursor = query
            .cursor
            .as_ref()
            .map(decode_target_cursor)
            .transpose()?;
        let page = self
            .authority
            .topology_targets(cursor.as_ref(), page_limit(&query)?)
            .map_err(map_authority_error)?;
        target_response(&query, page)
    }

    fn list_fault_groups(
        &self,
        _administrator: IdentityAdministrator,
        query: ListTopologyQuery,
    ) -> Result<ListFaultGroupsResponse, TopologyAdministrationError> {
        validate_list_topology_query(&query)
            .map_err(|_| TopologyAdministrationError::InvalidInput)?;
        let cursor = query.cursor.as_ref().map(decode_group_cursor).transpose()?;
        let page = self
            .authority
            .fault_groups(cursor.as_ref(), page_limit(&query)?)
            .map_err(map_authority_error)?;
        group_response(&query, page)
    }

    fn list_fault_group_memberships(
        &self,
        _administrator: IdentityAdministrator,
        query: ListTopologyQuery,
    ) -> Result<ListFaultGroupMembershipsResponse, TopologyAdministrationError> {
        validate_list_topology_query(&query)
            .map_err(|_| TopologyAdministrationError::InvalidInput)?;
        let cursor = query
            .cursor
            .as_ref()
            .map(decode_membership_cursor)
            .transpose()?;
        let page = self
            .authority
            .fault_group_memberships(cursor, page_limit(&query)?)
            .map_err(map_authority_error)?;
        membership_response(&query, page)
    }

    fn create_fault_group(
        &mut self,
        administrator: IdentityAdministrator,
        request: CreateFaultGroupRequest,
    ) -> Result<CreateFaultGroupResponse, TopologyAdministrationError> {
        let operation = request.operation_id.clone();
        let (operation_id, group_id, command) = create_command(&request)?;
        let expected_digest = command.request_digest(command_context(administrator, operation_id)?);
        let receipt = self
            .authority
            .commit_topology_operation(command_context(administrator, operation_id)?, &command)
            .map_err(map_authority_error)?;
        if receipt.request_digest != expected_digest
            || receipt.entity.kind != EntityKind::FaultGroup
            || receipt.entity.id != group_id.as_bytes()
        {
            return Err(TopologyAdministrationError::Conflict);
        }
        let record = self
            .authority
            .fault_group(group_id)
            .map_err(map_authority_error)?
            .ok_or(TopologyAdministrationError::Failed)?;
        Ok(CreateFaultGroupResponse {
            operation_id: operation,
            group: group_summary(record),
        })
    }

    fn set_fault_group_membership(
        &mut self,
        administrator: IdentityAdministrator,
        group_id: &str,
        host_id: &str,
        request: SetFaultGroupMembershipRequest,
    ) -> Result<SetFaultGroupMembershipResponse, TopologyAdministrationError> {
        let operation = request.operation_id.clone();
        let present = request.present;
        let (operation_id, group_id, host_id, command) =
            membership_command(group_id, host_id, &request)?;
        let context = command_context(administrator, operation_id)?;
        let expected_digest = command.request_digest(context);
        let receipt = self
            .authority
            .commit_topology_operation(context, &command)
            .map_err(map_authority_error)?;
        if receipt.request_digest != expected_digest
            || receipt.entity.kind != EntityKind::FaultGroupMembership
            || receipt.entity.id != group_id.as_bytes()
        {
            return Err(TopologyAdministrationError::Conflict);
        }
        Ok(SetFaultGroupMembershipResponse {
            operation_id: operation,
            host_id: crate::create_mesh_setup::format_uuid(host_id.as_bytes()),
            group_id: crate::create_mesh_setup::format_uuid(group_id.as_bytes()),
            present,
            revision: receipt.committed_revision.get(),
        })
    }
}

fn page_limit(query: &ListTopologyQuery) -> Result<PageLimit, TopologyAdministrationError> {
    PageLimit::new(usize::from(query.limit.unwrap_or(DEFAULT_PAGE_LIMIT)))
        .map_err(|_| TopologyAdministrationError::InvalidInput)
}

const fn map_identity_authority_error(
    error: IdentityAdministrationAuthorityError,
) -> TopologyAdministrationError {
    match error {
        IdentityAdministrationAuthorityError::Unavailable => {
            TopologyAdministrationError::Unavailable
        }
        IdentityAdministrationAuthorityError::Conflict
        | IdentityAdministrationAuthorityError::Failed => TopologyAdministrationError::Failed,
    }
}

const fn map_authority_error(
    error: TopologyAdministrationAuthorityError,
) -> TopologyAdministrationError {
    match error {
        TopologyAdministrationAuthorityError::Unavailable => {
            TopologyAdministrationError::Unavailable
        }
        TopologyAdministrationAuthorityError::Conflict => TopologyAdministrationError::Conflict,
        TopologyAdministrationAuthorityError::Failed => TopologyAdministrationError::Failed,
    }
}

const fn map_file_authentication_error(
    error: FileApiAuthenticationError,
) -> TopologyAdministrationError {
    match error {
        FileApiAuthenticationError::Rejected => TopologyAdministrationError::Unauthenticated,
        FileApiAuthenticationError::AuthorityUnavailable => {
            TopologyAdministrationError::Unavailable
        }
        FileApiAuthenticationError::InvalidGateway
        | FileApiAuthenticationError::AuthorityFailed => TopologyAdministrationError::Failed,
    }
}

const fn map_browser_authentication_error(
    error: BrowserAuthenticationError,
) -> TopologyAdministrationError {
    match error {
        BrowserAuthenticationError::Rejected => TopologyAdministrationError::Unauthenticated,
        BrowserAuthenticationError::Authority(crate::BrowserSessionAuthorityError::Unavailable) => {
            TopologyAdministrationError::Unavailable
        }
        BrowserAuthenticationError::InvalidGateway
        | BrowserAuthenticationError::Authority(crate::BrowserSessionAuthorityError::Failed) => {
            TopologyAdministrationError::Failed
        }
    }
}
