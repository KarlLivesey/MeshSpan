// SPDX-License-Identifier: GPL-2.0-only

//! Consensus-owned adapter for user, group and direct-membership administration.

use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_domain::{GroupId, OperationId, PrincipalId, UnixMicros};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, CommandReceipt, EntityKind, GroupMemberCursor,
    GroupMembershipRecord, Page, PageLimit, PrincipalCursor, PrincipalKind, PrincipalRecord,
    RepositoryError,
};

use crate::{
    ConsensusAuthenticationAuthority, GroupMembershipAdministrationCommit,
    IdentityAdministrationAuthority, IdentityAdministrationAuthorityError,
    IdentityAdministrationCommit,
};

impl IdentityAdministrationAuthority for ConsensusAuthenticationAuthority {
    fn is_system_manager(
        &self,
        principal_id: PrincipalId,
        now: UnixMicros,
    ) -> Result<bool, IdentityAdministrationAuthorityError> {
        self.reader()
            .principal_is_system_manager(principal_id, now)
            .map_err(|error| map_repository_error(&error))
    }

    fn principals(
        &self,
        kind: PrincipalKind,
        after: Option<&PrincipalCursor>,
        limit: PageLimit,
    ) -> Result<Page<PrincipalRecord, PrincipalCursor>, IdentityAdministrationAuthorityError> {
        self.reader()
            .principals(kind, after, limit)
            .map_err(|error| map_repository_error(&error))
    }

    fn principal(
        &self,
        principal_id: PrincipalId,
    ) -> Result<Option<PrincipalRecord>, IdentityAdministrationAuthorityError> {
        self.reader()
            .principal(principal_id)
            .map_err(|error| map_repository_error(&error))
    }

    fn resolve_principal_creation(
        &self,
        operation_id: OperationId,
        kind: PrincipalKind,
    ) -> Result<Option<IdentityAdministrationCommit>, IdentityAdministrationAuthorityError> {
        self.reader()
            .resolve_operation(operation_id)
            .map_err(|error| map_repository_error(&error))?
            .map(|receipt| principal_commit(self.reader(), receipt, kind))
            .transpose()
    }

    fn commit_or_resolve_principal_creation(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
        kind: PrincipalKind,
    ) -> Result<IdentityAdministrationCommit, IdentityAdministrationAuthorityError> {
        let expected_digest = command.request_digest(context);
        let receipt = self
            .commit_authoritative(context, command)
            .map_err(map_authority_error)?;
        if receipt.request_digest != expected_digest {
            return Err(IdentityAdministrationAuthorityError::Conflict);
        }
        principal_commit(self.reader(), receipt, kind)
    }

    fn group_memberships(
        &self,
        group_id: GroupId,
        after: Option<GroupMemberCursor>,
        limit: PageLimit,
    ) -> Result<Page<GroupMembershipRecord, GroupMemberCursor>, IdentityAdministrationAuthorityError>
    {
        self.reader()
            .direct_group_memberships(group_id, after, limit)
            .map_err(|error| map_repository_error(&error))
    }

    fn group_membership(
        &self,
        group_id: GroupId,
        member_principal_id: PrincipalId,
    ) -> Result<Option<GroupMembershipRecord>, IdentityAdministrationAuthorityError> {
        self.reader()
            .direct_group_membership(group_id, member_principal_id)
            .map_err(|error| map_repository_error(&error))
    }

    fn resolve_group_membership_mutation(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<GroupMembershipAdministrationCommit>, IdentityAdministrationAuthorityError>
    {
        self.reader()
            .resolve_operation(operation_id)
            .map_err(|error| map_repository_error(&error))?
            .map(|receipt| membership_commit(self.reader(), receipt))
            .transpose()
    }

    fn commit_or_resolve_group_membership_mutation(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<GroupMembershipAdministrationCommit, IdentityAdministrationAuthorityError> {
        let expected_digest = command.request_digest(context);
        let receipt = self
            .commit_authoritative(context, command)
            .map_err(map_authority_error)?;
        if receipt.request_digest != expected_digest {
            return Err(IdentityAdministrationAuthorityError::Conflict);
        }
        membership_commit(self.reader(), receipt)
    }
}

fn principal_commit(
    repository: &meshspan_metadata::AuthoritativeRepository,
    receipt: CommandReceipt,
    kind: PrincipalKind,
) -> Result<IdentityAdministrationCommit, IdentityAdministrationAuthorityError> {
    let expected = match kind {
        PrincipalKind::User => EntityKind::User,
        PrincipalKind::Group => EntityKind::Group,
        PrincipalKind::Service => return Err(IdentityAdministrationAuthorityError::Failed),
    };
    if receipt.entity.kind != expected {
        return Err(IdentityAdministrationAuthorityError::Failed);
    }
    let principal_id = PrincipalId::from_bytes(receipt.entity.id)
        .map_err(|_| IdentityAdministrationAuthorityError::Failed)?;
    let record = repository
        .principal(principal_id)
        .map_err(|error| map_repository_error(&error))?
        .ok_or(IdentityAdministrationAuthorityError::Failed)?;
    if record.kind != kind {
        return Err(IdentityAdministrationAuthorityError::Failed);
    }
    Ok(IdentityAdministrationCommit {
        request_digest: receipt.request_digest,
        result_digest: receipt.result_digest,
        principal_id,
        committed_revision: receipt.committed_revision.get(),
        occurred_at: record.created_at,
    })
}

fn membership_commit(
    repository: &meshspan_metadata::AuthoritativeRepository,
    receipt: CommandReceipt,
) -> Result<GroupMembershipAdministrationCommit, IdentityAdministrationAuthorityError> {
    if receipt.entity.kind != EntityKind::GroupMembership {
        return Err(IdentityAdministrationAuthorityError::Failed);
    }
    let group_id = GroupId::from_bytes(receipt.entity.id)
        .map_err(|_| IdentityAdministrationAuthorityError::Failed)?;
    let event = repository
        .group_membership_event(group_id, receipt.committed_revision)
        .map_err(|error| map_repository_error(&error))?
        .ok_or(IdentityAdministrationAuthorityError::Failed)?;
    Ok(GroupMembershipAdministrationCommit {
        request_digest: receipt.request_digest,
        result_digest: receipt.result_digest,
        group_id,
        member_principal_id: event.member_principal_id,
        mutation_kind: event.kind,
        actor_principal_id: event.actor_principal_id,
        committed_revision: receipt.committed_revision.get(),
        occurred_at: event.occurred_at,
    })
}

fn map_authority_error(
    error: MetadataAuthorityRequestError,
) -> IdentityAdministrationAuthorityError {
    match error {
        MetadataAuthorityRequestError::NotLeader { .. }
        | MetadataAuthorityRequestError::Unavailable => {
            IdentityAdministrationAuthorityError::Unavailable
        }
        MetadataAuthorityRequestError::Conflict | MetadataAuthorityRequestError::Rejected => {
            IdentityAdministrationAuthorityError::Conflict
        }
        MetadataAuthorityRequestError::Unsupported | MetadataAuthorityRequestError::Failed => {
            IdentityAdministrationAuthorityError::Failed
        }
    }
}

fn map_repository_error(error: &RepositoryError) -> IdentityAdministrationAuthorityError {
    match error {
        RepositoryError::OperationConflict
        | RepositoryError::StaleRevision
        | RepositoryError::InvalidCommand => IdentityAdministrationAuthorityError::Conflict,
        RepositoryError::Store(_) | RepositoryError::Sqlite(_) | RepositoryError::Io(_) => {
            IdentityAdministrationAuthorityError::Unavailable
        }
        _ => IdentityAdministrationAuthorityError::Failed,
    }
}
