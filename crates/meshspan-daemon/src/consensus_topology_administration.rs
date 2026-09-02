// SPDX-License-Identifier: GPL-2.0-only

//! Consensus-owned adapter for mesh topology administration.

use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_domain::{
    AcknowledgementPolicyId, AvailabilityCellId, FaultGroupId, LocalityPolicyId, OperationId,
    ProtectionPolicyId,
};
use meshspan_metadata::{
    AcknowledgementPolicyCursor, AcknowledgementPolicyRecord, AuthoritativeCommand,
    AvailabilityCellCursor, AvailabilityCellRecord, CommandContext, CommandReceipt,
    FaultGroupCursor, FaultGroupMembershipCursor, FaultGroupMembershipRecord, FaultGroupRecord,
    LocalityPolicyCursor, LocalityPolicyRecord, Page, PageLimit, ProtectionPolicyCursor,
    ProtectionPolicyRecord, RepositoryError, TopologyNodeCursor, TopologyNodeRecord,
    TopologyTargetCursor, TopologyTargetRecord,
};

use crate::{
    ConsensusAuthenticationAuthority, TopologyAdministrationAuthority,
    TopologyAdministrationAuthorityError,
};

impl TopologyAdministrationAuthority for ConsensusAuthenticationAuthority {
    fn topology_nodes(
        &self,
        after: Option<&TopologyNodeCursor>,
        limit: PageLimit,
    ) -> Result<Page<TopologyNodeRecord, TopologyNodeCursor>, TopologyAdministrationAuthorityError>
    {
        self.reader()
            .topology_nodes(after, limit)
            .map_err(|error| map_repository_error(&error))
    }

    fn topology_targets(
        &self,
        after: Option<&TopologyTargetCursor>,
        limit: PageLimit,
    ) -> Result<
        Page<TopologyTargetRecord, TopologyTargetCursor>,
        TopologyAdministrationAuthorityError,
    > {
        self.reader()
            .topology_targets(after, limit)
            .map_err(|error| map_repository_error(&error))
    }

    fn fault_groups(
        &self,
        after: Option<&FaultGroupCursor>,
        limit: PageLimit,
    ) -> Result<Page<FaultGroupRecord, FaultGroupCursor>, TopologyAdministrationAuthorityError>
    {
        self.reader()
            .fault_groups(after, limit)
            .map_err(|error| map_repository_error(&error))
    }

    fn fault_group(
        &self,
        group_id: FaultGroupId,
    ) -> Result<Option<FaultGroupRecord>, TopologyAdministrationAuthorityError> {
        self.reader()
            .fault_group(group_id)
            .map_err(|error| map_repository_error(&error))
    }

    fn fault_group_memberships(
        &self,
        after: Option<FaultGroupMembershipCursor>,
        limit: PageLimit,
    ) -> Result<
        Page<FaultGroupMembershipRecord, FaultGroupMembershipCursor>,
        TopologyAdministrationAuthorityError,
    > {
        self.reader()
            .fault_group_memberships(after, limit)
            .map_err(|error| map_repository_error(&error))
    }

    fn protection_policies(
        &self,
        after: Option<&ProtectionPolicyCursor>,
        limit: PageLimit,
    ) -> Result<
        Page<ProtectionPolicyRecord, ProtectionPolicyCursor>,
        TopologyAdministrationAuthorityError,
    > {
        self.reader()
            .protection_policies(after, limit)
            .map_err(|error| map_repository_error(&error))
    }

    fn protection_policy(
        &self,
        policy_id: ProtectionPolicyId,
    ) -> Result<Option<ProtectionPolicyRecord>, TopologyAdministrationAuthorityError> {
        self.reader()
            .protection_policy(policy_id)
            .map_err(|error| map_repository_error(&error))
    }

    fn availability_cells(
        &self,
        after: Option<&AvailabilityCellCursor>,
        limit: PageLimit,
    ) -> Result<
        Page<AvailabilityCellRecord, AvailabilityCellCursor>,
        TopologyAdministrationAuthorityError,
    > {
        self.reader()
            .availability_cells(after, limit)
            .map_err(|error| map_repository_error(&error))
    }

    fn availability_cell(
        &self,
        cell_id: AvailabilityCellId,
    ) -> Result<Option<AvailabilityCellRecord>, TopologyAdministrationAuthorityError> {
        self.reader()
            .availability_cell(cell_id)
            .map_err(|error| map_repository_error(&error))
    }

    fn locality_policies(
        &self,
        after: Option<&LocalityPolicyCursor>,
        limit: PageLimit,
    ) -> Result<
        Page<LocalityPolicyRecord, LocalityPolicyCursor>,
        TopologyAdministrationAuthorityError,
    > {
        self.reader()
            .locality_policies(after, limit)
            .map_err(|error| map_repository_error(&error))
    }

    fn locality_policy(
        &self,
        policy_id: LocalityPolicyId,
    ) -> Result<Option<LocalityPolicyRecord>, TopologyAdministrationAuthorityError> {
        self.reader()
            .locality_policy(policy_id)
            .map_err(|error| map_repository_error(&error))
    }

    fn acknowledgement_policies(
        &self,
        after: Option<&AcknowledgementPolicyCursor>,
        limit: PageLimit,
    ) -> Result<
        Page<AcknowledgementPolicyRecord, AcknowledgementPolicyCursor>,
        TopologyAdministrationAuthorityError,
    > {
        self.reader()
            .acknowledgement_policies(after, limit)
            .map_err(|error| map_repository_error(&error))
    }

    fn acknowledgement_policy(
        &self,
        policy_id: AcknowledgementPolicyId,
    ) -> Result<Option<AcknowledgementPolicyRecord>, TopologyAdministrationAuthorityError> {
        self.reader()
            .acknowledgement_policy(policy_id)
            .map_err(|error| map_repository_error(&error))
    }

    fn resolve_topology_operation(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<CommandReceipt>, TopologyAdministrationAuthorityError> {
        self.reader()
            .resolve_operation(operation_id)
            .map_err(|error| map_repository_error(&error))
    }

    fn commit_topology_operation(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, TopologyAdministrationAuthorityError> {
        self.commit_authoritative(context, command)
            .map_err(map_authority_error)
    }
}

fn map_authority_error(
    error: MetadataAuthorityRequestError,
) -> TopologyAdministrationAuthorityError {
    match error {
        MetadataAuthorityRequestError::NotLeader { .. }
        | MetadataAuthorityRequestError::Unavailable => {
            TopologyAdministrationAuthorityError::Unavailable
        }
        MetadataAuthorityRequestError::Conflict | MetadataAuthorityRequestError::Rejected => {
            TopologyAdministrationAuthorityError::Conflict
        }
        MetadataAuthorityRequestError::Unsupported | MetadataAuthorityRequestError::Failed => {
            TopologyAdministrationAuthorityError::Failed
        }
    }
}

fn map_repository_error(error: &RepositoryError) -> TopologyAdministrationAuthorityError {
    match error {
        RepositoryError::OperationConflict
        | RepositoryError::StaleRevision
        | RepositoryError::InvalidCommand => TopologyAdministrationAuthorityError::Conflict,
        RepositoryError::Store(_) | RepositoryError::Sqlite(_) | RepositoryError::Io(_) => {
            TopologyAdministrationAuthorityError::Unavailable
        }
        _ => TopologyAdministrationAuthorityError::Failed,
    }
}
