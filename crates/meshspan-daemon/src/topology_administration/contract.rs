// SPDX-License-Identifier: GPL-2.0-only

//! Replaceable replicated-authority boundary for topology administration.

use meshspan_domain::{FaultGroupId, OperationId};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, CommandReceipt, FaultGroupCursor,
    FaultGroupMembershipCursor, FaultGroupMembershipRecord, FaultGroupRecord, Page, PageLimit,
    TopologyNodeCursor, TopologyNodeRecord, TopologyTargetCursor, TopologyTargetRecord,
};
use thiserror::Error;

use crate::IdentityAdministrationAuthority;

/// Replicated reads and consensus mutations required by topology administration.
pub trait TopologyAdministrationAuthority: IdentityAdministrationAuthority {
    /// Returns one bounded daemon-node page.
    fn topology_nodes(
        &self,
        after: Option<&TopologyNodeCursor>,
        limit: PageLimit,
    ) -> Result<Page<TopologyNodeRecord, TopologyNodeCursor>, TopologyAdministrationAuthorityError>;

    /// Returns one bounded mesh-wide target page.
    fn topology_targets(
        &self,
        after: Option<&TopologyTargetCursor>,
        limit: PageLimit,
    ) -> Result<
        Page<TopologyTargetRecord, TopologyTargetCursor>,
        TopologyAdministrationAuthorityError,
    >;

    /// Returns one bounded shared-failure-group page.
    fn fault_groups(
        &self,
        after: Option<&FaultGroupCursor>,
        limit: PageLimit,
    ) -> Result<Page<FaultGroupRecord, FaultGroupCursor>, TopologyAdministrationAuthorityError>;

    /// Returns one current shared-failure group.
    fn fault_group(
        &self,
        group_id: FaultGroupId,
    ) -> Result<Option<FaultGroupRecord>, TopologyAdministrationAuthorityError>;

    /// Returns one bounded overlapping membership page.
    fn fault_group_memberships(
        &self,
        after: Option<FaultGroupMembershipCursor>,
        limit: PageLimit,
    ) -> Result<
        Page<FaultGroupMembershipRecord, FaultGroupMembershipCursor>,
        TopologyAdministrationAuthorityError,
    >;

    /// Resolves an already committed topology operation.
    fn resolve_topology_operation(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<CommandReceipt>, TopologyAdministrationAuthorityError>;

    /// Commits or exactly resolves one topology mutation through consensus.
    fn commit_topology_operation(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, TopologyAdministrationAuthorityError>;
}

/// Closed replicated-authority failures safe for service classification.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TopologyAdministrationAuthorityError {
    /// Current replicated authority cannot be reached.
    #[error("topology authority is unavailable")]
    Unavailable,
    /// Operation, name or desired-state mutation conflicts with committed state.
    #[error("topology authority reports a conflict")]
    Conflict,
    /// Persisted topology or receipt evidence failed validation.
    #[error("topology authority failed closed")]
    Failed,
}
