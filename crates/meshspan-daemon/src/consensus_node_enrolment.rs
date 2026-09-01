// SPDX-License-Identifier: GPL-2.0-only

//! Consensus-backed node join-grant and enrolment authority adapters.

use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_domain::{JoinGrantId, MeshId, OperationId, PrincipalId, UnixMicros};
use meshspan_metadata::{AuthoritativeCommand, CommandContext, EntityKind, RepositoryError};

use crate::{
    ConsensusAuthenticationAuthority, NodeJoinGrantIssuanceAuthority,
    NodeJoinGrantIssuanceAuthorityError, NodeJoinGrantIssuanceCommit,
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
