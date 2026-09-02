// SPDX-License-Identifier: GPL-2.0-only

//! Replaceable replicated-authority boundary for topology administration.

use meshspan_domain::{
    AcknowledgementPolicyId, AvailabilityCellId, FaultGroupId, LocalityPolicyId, OperationId,
    ProtectionPolicyId,
};
use meshspan_metadata::{
    AcknowledgementPolicyCursor, AcknowledgementPolicyRecord, AuthoritativeCommand,
    AvailabilityCellCursor, AvailabilityCellRecord, CommandContext, CommandReceipt,
    FaultGroupCursor, FaultGroupMembershipCursor, FaultGroupMembershipRecord, FaultGroupRecord,
    LocalityPolicyCursor, LocalityPolicyRecord, Page, PageLimit, ProtectionPolicyCursor,
    ProtectionPolicyRecord, TopologyNodeCursor, TopologyNodeRecord, TopologyTargetCursor,
    TopologyTargetRecord,
};
use thiserror::Error;

use crate::IdentityAdministrationAuthority;

/// Replicated reads and consensus mutations required by topology administration.
pub trait TopologyAdministrationAuthority: IdentityAdministrationAuthority {
    /// Returns one bounded daemon-node page.
    ///
    /// # Errors
    ///
    /// Returns a closed authority error when committed topology cannot be read safely.
    fn topology_nodes(
        &self,
        after: Option<&TopologyNodeCursor>,
        limit: PageLimit,
    ) -> Result<Page<TopologyNodeRecord, TopologyNodeCursor>, TopologyAdministrationAuthorityError>;

    /// Returns one bounded mesh-wide target page.
    ///
    /// # Errors
    ///
    /// Returns a closed authority error when committed topology cannot be read safely.
    fn topology_targets(
        &self,
        after: Option<&TopologyTargetCursor>,
        limit: PageLimit,
    ) -> Result<
        Page<TopologyTargetRecord, TopologyTargetCursor>,
        TopologyAdministrationAuthorityError,
    >;

    /// Returns one bounded shared-failure-group page.
    ///
    /// # Errors
    ///
    /// Returns a closed authority error when committed topology cannot be read safely.
    fn fault_groups(
        &self,
        after: Option<&FaultGroupCursor>,
        limit: PageLimit,
    ) -> Result<Page<FaultGroupRecord, FaultGroupCursor>, TopologyAdministrationAuthorityError>;

    /// Returns one current shared-failure group.
    ///
    /// # Errors
    ///
    /// Returns a closed authority error when committed topology cannot be read safely.
    fn fault_group(
        &self,
        group_id: FaultGroupId,
    ) -> Result<Option<FaultGroupRecord>, TopologyAdministrationAuthorityError>;

    /// Returns one bounded overlapping membership page.
    ///
    /// # Errors
    ///
    /// Returns a closed authority error when committed topology cannot be read safely.
    fn fault_group_memberships(
        &self,
        after: Option<FaultGroupMembershipCursor>,
        limit: PageLimit,
    ) -> Result<
        Page<FaultGroupMembershipRecord, FaultGroupMembershipCursor>,
        TopologyAdministrationAuthorityError,
    >;

    /// Returns one bounded immutable survival-policy page.
    ///
    /// # Errors
    ///
    /// Returns a closed authority error when committed policy state cannot be read safely.
    fn protection_policies(
        &self,
        after: Option<&ProtectionPolicyCursor>,
        limit: PageLimit,
    ) -> Result<
        Page<ProtectionPolicyRecord, ProtectionPolicyCursor>,
        TopologyAdministrationAuthorityError,
    >;

    /// Returns one exact immutable survival policy.
    ///
    /// # Errors
    ///
    /// Returns a closed authority error when committed policy state cannot be read safely.
    fn protection_policy(
        &self,
        policy_id: ProtectionPolicyId,
    ) -> Result<Option<ProtectionPolicyRecord>, TopologyAdministrationAuthorityError>;

    /// Returns one bounded availability-cell page.
    ///
    /// # Errors
    ///
    /// Returns a closed authority error when committed cell state cannot be read safely.
    fn availability_cells(
        &self,
        after: Option<&AvailabilityCellCursor>,
        limit: PageLimit,
    ) -> Result<
        Page<AvailabilityCellRecord, AvailabilityCellCursor>,
        TopologyAdministrationAuthorityError,
    >;

    /// Returns one exact active availability cell.
    ///
    /// # Errors
    ///
    /// Returns a closed authority error when committed cell state cannot be read safely.
    fn availability_cell(
        &self,
        cell_id: AvailabilityCellId,
    ) -> Result<Option<AvailabilityCellRecord>, TopologyAdministrationAuthorityError>;

    /// Returns one bounded immutable desired-locality policy page.
    ///
    /// # Errors
    ///
    /// Returns a closed authority error when committed policy state cannot be read safely.
    fn locality_policies(
        &self,
        after: Option<&LocalityPolicyCursor>,
        limit: PageLimit,
    ) -> Result<
        Page<LocalityPolicyRecord, LocalityPolicyCursor>,
        TopologyAdministrationAuthorityError,
    >;

    /// Returns one exact immutable desired-locality policy.
    ///
    /// # Errors
    ///
    /// Returns a closed authority error when committed policy state cannot be read safely.
    fn locality_policy(
        &self,
        policy_id: LocalityPolicyId,
    ) -> Result<Option<LocalityPolicyRecord>, TopologyAdministrationAuthorityError>;

    /// Returns one bounded immutable write-acknowledgement policy page.
    ///
    /// # Errors
    ///
    /// Returns a closed authority error when committed policy state cannot be read safely.
    fn acknowledgement_policies(
        &self,
        after: Option<&AcknowledgementPolicyCursor>,
        limit: PageLimit,
    ) -> Result<
        Page<AcknowledgementPolicyRecord, AcknowledgementPolicyCursor>,
        TopologyAdministrationAuthorityError,
    >;

    /// Returns one exact immutable write-acknowledgement policy.
    ///
    /// # Errors
    ///
    /// Returns a closed authority error when committed policy state cannot be read safely.
    fn acknowledgement_policy(
        &self,
        policy_id: AcknowledgementPolicyId,
    ) -> Result<Option<AcknowledgementPolicyRecord>, TopologyAdministrationAuthorityError>;

    /// Resolves an already committed topology operation.
    ///
    /// # Errors
    ///
    /// Returns a closed authority error when the operation receipt cannot be trusted.
    fn resolve_topology_operation(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<CommandReceipt>, TopologyAdministrationAuthorityError>;

    /// Commits or exactly resolves one topology mutation through consensus.
    ///
    /// # Errors
    ///
    /// Returns a closed authority error when consensus cannot commit or resolve safely.
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
