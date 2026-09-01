// SPDX-License-Identifier: GPL-2.0-only

//! Consensus-owned adapter for mesh topology administration.

use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_domain::{FaultGroupId, OperationId};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, CommandReceipt, FaultGroupCursor,
    FaultGroupMembershipCursor, FaultGroupMembershipRecord, FaultGroupRecord, Page, PageLimit,
    RepositoryError, TopologyNodeCursor, TopologyNodeRecord, TopologyTargetCursor,
    TopologyTargetRecord,
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
            .map_err(map_repository_error)
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
            .map_err(map_repository_error)
    }

    fn fault_groups(
        &self,
        after: Option<&FaultGroupCursor>,
        limit: PageLimit,
    ) -> Result<Page<FaultGroupRecord, FaultGroupCursor>, TopologyAdministrationAuthorityError>
    {
        self.reader()
            .fault_groups(after, limit)
            .map_err(map_repository_error)
    }

    fn fault_group(
        &self,
        group_id: FaultGroupId,
    ) -> Result<Option<FaultGroupRecord>, TopologyAdministrationAuthorityError> {
        self.reader()
            .fault_group(group_id)
            .map_err(map_repository_error)
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
            .map_err(map_repository_error)
    }

    fn resolve_topology_operation(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<CommandReceipt>, TopologyAdministrationAuthorityError> {
        self.reader()
            .resolve_operation(operation_id)
            .map_err(map_repository_error)
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

fn map_repository_error(error: RepositoryError) -> TopologyAdministrationAuthorityError {
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
