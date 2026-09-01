// SPDX-License-Identifier: GPL-2.0-only

//! Consensus-backed node join-grant and enrolment authority adapters.

use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_domain::{JoinGrantId, MeshId, NodeId, OperationId, PrincipalId, UnixMicros};
use meshspan_metadata::{AuthoritativeCommand, CommandContext, EntityKind, RepositoryError};

use crate::{
    ConsensusAuthenticationAuthority, NodeEnrolmentAuthority, NodeEnrolmentAuthorityError,
    NodeEnrolmentCommit, NodeJoinGrantIssuanceAuthority, NodeJoinGrantIssuanceAuthorityError,
    NodeJoinGrantIssuanceCommit,
};

impl NodeJoinGrantIssuanceAuthority for ConsensusAuthenticationAuthority {
    fn is_system_manager(
        &self,
        principal_id: PrincipalId,
        now: UnixMicros,
    ) -> Result<bool, NodeJoinGrantIssuanceAuthorityError> {
        self.reader()
            .principal_is_system_manager(principal_id, now)
            .map_err(|error| repository_error(&error))
    }

    fn local_mesh_id(&self) -> Result<Option<MeshId>, NodeJoinGrantIssuanceAuthorityError> {
        self.reader()
            .local_mesh_id()
            .map_err(|error| repository_error(&error))
    }

    fn resolve_join_grant_issuance(
        &self,
        operation_id: OperationId,
        join_grant_id: JoinGrantId,
    ) -> Result<Option<NodeJoinGrantIssuanceCommit>, NodeJoinGrantIssuanceAuthorityError> {
        self.reader()
            .resolve_operation(operation_id)
            .map_err(|error| repository_error(&error))?
            .map(|receipt| issuance_commit(self, receipt, join_grant_id))
            .transpose()
    }

    fn commit_or_resolve_join_grant_issuance(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<NodeJoinGrantIssuanceCommit, NodeJoinGrantIssuanceAuthorityError> {
        let receipt = self
            .commit_authoritative(context, command)
            .map_err(authority_error)?;
        let AuthoritativeCommand::IssueJoinGrant(issued) = command else {
            return Err(NodeJoinGrantIssuanceAuthorityError::Failed);
        };
        issuance_commit(self, receipt, issued.join_grant_id)
    }
}

impl NodeEnrolmentAuthority for ConsensusAuthenticationAuthority {
    fn join_grant(
        &self,
        join_grant_id: JoinGrantId,
    ) -> Result<Option<meshspan_metadata::JoinGrantRecord>, NodeEnrolmentAuthorityError> {
        self.reader()
            .join_grant(join_grant_id)
            .map_err(|error| node_repository_error(&error))
    }

    fn mesh_recovery_authority(
        &self,
        mesh_id: MeshId,
    ) -> Result<Option<meshspan_metadata::MeshRecoveryAuthority>, NodeEnrolmentAuthorityError> {
        self.reader()
            .mesh_recovery_authority(mesh_id)
            .map_err(|error| node_repository_error(&error))
    }

    fn resolve_node_enrolment(
        &self,
        operation_id: OperationId,
        node_id: NodeId,
    ) -> Result<Option<NodeEnrolmentCommit>, NodeEnrolmentAuthorityError> {
        self.reader()
            .resolve_operation(operation_id)
            .map_err(|error| node_repository_error(&error))?
            .map(|receipt| node_enrolment_commit(self, receipt, node_id))
            .transpose()
    }

    fn commit_or_resolve_node_enrolment(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<NodeEnrolmentCommit, NodeEnrolmentAuthorityError> {
        let receipt = self
            .commit_authoritative(context, command)
            .map_err(node_authority_error)?;
        let AuthoritativeCommand::ConsumeJoinGrant(consumed) = command else {
            return Err(NodeEnrolmentAuthorityError::Failed);
        };
        node_enrolment_commit(self, receipt, consumed.node_id)
    }
}

fn node_enrolment_commit(
    authority: &ConsensusAuthenticationAuthority,
    receipt: meshspan_metadata::CommandReceipt,
    node_id: NodeId,
) -> Result<NodeEnrolmentCommit, NodeEnrolmentAuthorityError> {
    if receipt.entity.kind != EntityKind::Node
        || receipt.entity.id != node_id.as_bytes()
        || receipt.result_digest == [0; 32]
    {
        return Err(NodeEnrolmentAuthorityError::Failed);
    }
    let record = authority
        .reader()
        .node_enrolment(node_id)
        .map_err(|error| node_repository_error(&error))?
        .ok_or(NodeEnrolmentAuthorityError::Failed)?;
    if record.revision != receipt.committed_revision {
        return Err(NodeEnrolmentAuthorityError::Failed);
    }
    Ok(NodeEnrolmentCommit {
        request_digest: receipt.request_digest,
        result_digest: receipt.result_digest,
        record,
    })
}

fn issuance_commit(
    authority: &ConsensusAuthenticationAuthority,
    receipt: meshspan_metadata::CommandReceipt,
    join_grant_id: JoinGrantId,
) -> Result<NodeJoinGrantIssuanceCommit, NodeJoinGrantIssuanceAuthorityError> {
    if receipt.entity.kind != EntityKind::JoinGrant
        || receipt.entity.id != join_grant_id.as_bytes()
        || receipt.result_digest == [0; 32]
    {
        return Err(NodeJoinGrantIssuanceAuthorityError::Failed);
    }
    let record = authority
        .reader()
        .join_grant(join_grant_id)
        .map_err(|error| repository_error(&error))?
        .ok_or(NodeJoinGrantIssuanceAuthorityError::Failed)?;
    if record.revision != receipt.committed_revision {
        return Err(NodeJoinGrantIssuanceAuthorityError::Failed);
    }
    Ok(NodeJoinGrantIssuanceCommit {
        request_digest: receipt.request_digest,
        result_digest: receipt.result_digest,
        record,
    })
}

fn repository_error(error: &RepositoryError) -> NodeJoinGrantIssuanceAuthorityError {
    match error {
        RepositoryError::Store(_) | RepositoryError::Sqlite(_) | RepositoryError::Io(_) => {
            NodeJoinGrantIssuanceAuthorityError::Unavailable
        }
        RepositoryError::OperationConflict => NodeJoinGrantIssuanceAuthorityError::Conflict,
        _ => NodeJoinGrantIssuanceAuthorityError::Failed,
    }
}

const fn authority_error(
    error: MetadataAuthorityRequestError,
) -> NodeJoinGrantIssuanceAuthorityError {
    match error {
        MetadataAuthorityRequestError::NotLeader { .. }
        | MetadataAuthorityRequestError::Unavailable => {
            NodeJoinGrantIssuanceAuthorityError::Unavailable
        }
        MetadataAuthorityRequestError::Conflict | MetadataAuthorityRequestError::Rejected => {
            NodeJoinGrantIssuanceAuthorityError::Conflict
        }
        MetadataAuthorityRequestError::Unsupported | MetadataAuthorityRequestError::Failed => {
            NodeJoinGrantIssuanceAuthorityError::Failed
        }
    }
}

fn node_repository_error(error: &RepositoryError) -> NodeEnrolmentAuthorityError {
    match error {
        RepositoryError::Store(_) | RepositoryError::Sqlite(_) | RepositoryError::Io(_) => {
            NodeEnrolmentAuthorityError::Unavailable
        }
        RepositoryError::OperationConflict => NodeEnrolmentAuthorityError::Conflict,
        RepositoryError::InvalidCommand => NodeEnrolmentAuthorityError::Rejected,
        _ => NodeEnrolmentAuthorityError::Failed,
    }
}

const fn node_authority_error(error: MetadataAuthorityRequestError) -> NodeEnrolmentAuthorityError {
    match error {
        MetadataAuthorityRequestError::NotLeader { .. }
        | MetadataAuthorityRequestError::Unavailable => NodeEnrolmentAuthorityError::Unavailable,
        MetadataAuthorityRequestError::Conflict => NodeEnrolmentAuthorityError::Conflict,
        MetadataAuthorityRequestError::Rejected => NodeEnrolmentAuthorityError::Rejected,
        MetadataAuthorityRequestError::Unsupported | MetadataAuthorityRequestError::Failed => {
            NodeEnrolmentAuthorityError::Failed
        }
    }
}
