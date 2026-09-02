// SPDX-License-Identifier: GPL-2.0-only

//! Manager-only mesh node, target and shared-failure topology administration.

mod api;
mod contract;
mod model;
mod service;

use axum::http::HeaderMap;
use meshspan_api_contract::{
    AssignVolumeProtectionPolicyRequest, AssignVolumeProtectionPolicyResponse,
    CreateFaultGroupRequest, CreateFaultGroupResponse, CreateProtectionPolicyRequest,
    CreateProtectionPolicyResponse, ListFaultGroupMembershipsResponse, ListFaultGroupsResponse,
    ListProtectionPoliciesResponse, ListTopologyNodesResponse, ListTopologyQuery,
    ListTopologyTargetsResponse, SetFaultGroupMembershipRequest, SetFaultGroupMembershipResponse,
};
use meshspan_domain::UnixMicros;
use thiserror::Error;

use crate::{BrowserRequestProtection, IdentityAdministrator};

pub use api::{TopologyAdministrationApiError, topology_administration_api_router};
pub use contract::{TopologyAdministrationAuthority, TopologyAdministrationAuthorityError};
pub use service::TopologyAdministrationService;

/// Synchronous topology controller executed on Tokio's bounded blocking pool.
pub trait TopologyAdministrationController: Send + 'static {
    /// Authenticates current manager authority before parsing or state access.
    ///
    /// # Errors
    ///
    /// Rejects missing, ambiguous, expired or insufficient manager authority.
    fn authenticate(
        &self,
        headers: &HeaderMap,
        protection: BrowserRequestProtection,
        now: UnixMicros,
    ) -> Result<IdentityAdministrator, TopologyAdministrationError>;

    /// Returns one bounded daemon-node page.
    ///
    /// # Errors
    ///
    /// Rejects invalid input or unavailable/corrupt committed topology.
    fn list_nodes(
        &self,
        administrator: IdentityAdministrator,
        query: ListTopologyQuery,
    ) -> Result<ListTopologyNodesResponse, TopologyAdministrationError>;

    /// Returns one bounded mesh-wide storage-target page.
    ///
    /// # Errors
    ///
    /// Rejects invalid input or unavailable/corrupt committed topology.
    fn list_targets(
        &self,
        administrator: IdentityAdministrator,
        query: ListTopologyQuery,
    ) -> Result<ListTopologyTargetsResponse, TopologyAdministrationError>;

    /// Returns one bounded shared-failure-group page.
    ///
    /// # Errors
    ///
    /// Rejects invalid input or unavailable/corrupt committed topology.
    fn list_fault_groups(
        &self,
        administrator: IdentityAdministrator,
        query: ListTopologyQuery,
    ) -> Result<ListFaultGroupsResponse, TopologyAdministrationError>;

    /// Returns one bounded overlapping machine/group-membership page.
    ///
    /// # Errors
    ///
    /// Rejects invalid input or unavailable/corrupt committed topology.
    fn list_fault_group_memberships(
        &self,
        administrator: IdentityAdministrator,
        query: ListTopologyQuery,
    ) -> Result<ListFaultGroupMembershipsResponse, TopologyAdministrationError>;

    /// Returns one bounded immutable survival-policy page.
    ///
    /// # Errors
    ///
    /// Rejects invalid input or unavailable/corrupt committed policy state.
    fn list_protection_policies(
        &self,
        administrator: IdentityAdministrator,
        query: ListTopologyQuery,
    ) -> Result<ListProtectionPoliciesResponse, TopologyAdministrationError>;

    /// Creates or exactly resolves one named shared-failure group.
    ///
    /// # Errors
    ///
    /// Rejects invalid, conflicting, unauthorised or uncommitted mutations.
    fn create_fault_group(
        &mut self,
        administrator: IdentityAdministrator,
        request: CreateFaultGroupRequest,
    ) -> Result<CreateFaultGroupResponse, TopologyAdministrationError>;

    /// Sets or exactly resolves one desired machine/group membership.
    ///
    /// # Errors
    ///
    /// Rejects invalid, missing, conflicting, unauthorised or uncommitted mutations.
    fn set_fault_group_membership(
        &mut self,
        administrator: IdentityAdministrator,
        group_id: &str,
        host_id: &str,
        request: SetFaultGroupMembershipRequest,
    ) -> Result<SetFaultGroupMembershipResponse, TopologyAdministrationError>;

    /// Creates or exactly resolves one immutable data-survival policy.
    ///
    /// # Errors
    ///
    /// Rejects invalid, conflicting, unauthorised or uncommitted mutations.
    fn create_protection_policy(
        &mut self,
        administrator: IdentityAdministrator,
        request: CreateProtectionPolicyRequest,
    ) -> Result<CreateProtectionPolicyResponse, TopologyAdministrationError>;

    /// Selects or exactly resolves one immutable policy for a volume.
    ///
    /// # Errors
    ///
    /// Rejects invalid, missing, conflicting, unauthorised or uncommitted mutations.
    fn assign_volume_protection_policy(
        &mut self,
        administrator: IdentityAdministrator,
        volume_id: &str,
        policy_id: &str,
        request: AssignVolumeProtectionPolicyRequest,
    ) -> Result<AssignVolumeProtectionPolicyResponse, TopologyAdministrationError>;
}

/// Closed non-secret topology-administration failure categories.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TopologyAdministrationError {
    /// An identifier, name, bound or continuation is invalid.
    #[error("topology-administration input is invalid")]
    InvalidInput,
    /// Authentication was rejected.
    #[error("topology-administration authentication was rejected")]
    Unauthenticated,
    /// Current principal lacks system-management authority.
    #[error("topology-administration authority was denied")]
    Forbidden,
    /// Name or exact operation reuse conflicts with committed state.
    #[error("topology-administration operation conflicts with committed state")]
    Conflict,
    /// Requested machine or shared-failure group does not exist.
    #[error("topology-administration resource was not found")]
    NotFound,
    /// Required metadata authority is temporarily unavailable.
    #[error("topology-administration authority is unavailable")]
    Unavailable,
    /// Persisted evidence, outgoing response or an invariant failed closed.
    #[error("topology-administration failed closed")]
    Failed,
}
