// SPDX-License-Identifier: GPL-2.0-only

//! Replaceable replicated-authority boundary for identity administration.

use meshspan_domain::{GroupId, OperationId, PrincipalId, UnixMicros};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, GroupMemberCursor, GroupMembershipEventKind,
    GroupMembershipRecord, Page, PageLimit, PrincipalCursor, PrincipalKind, PrincipalRecord,
};
use thiserror::Error;

use crate::{BrowserSessionAuthority, NativeApiKeyAuthority};

/// Exact durable evidence returned after one user/group creation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdentityAdministrationCommit {
    /// Original semantic request digest.
    pub request_digest: [u8; 32],
    /// Durable result digest.
    pub result_digest: [u8; 32],
    /// Created local principal.
    pub principal_id: PrincipalId,
    /// Authoritative revision created by the original operation.
    pub committed_revision: u64,
    /// Original authoritative creation instant used by exact retries.
    pub occurred_at: UnixMicros,
}

/// Exact durable evidence returned after one direct-membership mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroupMembershipAdministrationCommit {
    /// Original semantic request digest.
    pub request_digest: [u8; 32],
    /// Durable result digest.
    pub result_digest: [u8; 32],
    /// Containing group identified by the durable receipt.
    pub group_id: GroupId,
    /// Direct member identified by immutable mutation history.
    pub member_principal_id: PrincipalId,
    /// Original mutation family identified by immutable history.
    pub mutation_kind: GroupMembershipEventKind,
    /// Principal that authorised the original mutation.
    pub actor_principal_id: PrincipalId,
    /// Authoritative revision created by the original operation.
    pub committed_revision: u64,
    /// Original authoritative mutation instant used by exact retries.
    pub occurred_at: UnixMicros,
}

/// Replicated reads and consensus commits required by user/group administration.
pub trait IdentityAdministrationAuthority: BrowserSessionAuthority + NativeApiKeyAuthority {
    /// Reports whether one active principal currently carries system-management authority.
    ///
    /// # Errors
    ///
    /// Fails closed for unavailable or corrupt committed role state.
    fn is_system_manager(
        &self,
        principal_id: PrincipalId,
        now: UnixMicros,
    ) -> Result<bool, IdentityAdministrationAuthorityError>;

    /// Returns one bounded current principal page.
    ///
    /// # Errors
    ///
    /// Rejects cursor substitution and unavailable or corrupt committed state.
    fn principals(
        &self,
        kind: PrincipalKind,
        after: Option<&PrincipalCursor>,
        limit: PageLimit,
    ) -> Result<Page<PrincipalRecord, PrincipalCursor>, IdentityAdministrationAuthorityError>;

    /// Reads one exact current principal.
    ///
    /// # Errors
    ///
    /// Fails closed for unavailable or corrupt committed state.
    fn principal(
        &self,
        principal_id: PrincipalId,
    ) -> Result<Option<PrincipalRecord>, IdentityAdministrationAuthorityError>;

    /// Resolves an already committed creation operation, if present.
    ///
    /// # Errors
    ///
    /// Rejects another command family or malformed durable evidence.
    fn resolve_principal_creation(
        &self,
        operation_id: OperationId,
        kind: PrincipalKind,
    ) -> Result<Option<IdentityAdministrationCommit>, IdentityAdministrationAuthorityError>;

    /// Commits or exactly resolves one user/group creation through consensus.
    ///
    /// # Errors
    ///
    /// Rejects changed operation reuse and never reports success without durable evidence.
    fn commit_or_resolve_principal_creation(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
        kind: PrincipalKind,
    ) -> Result<IdentityAdministrationCommit, IdentityAdministrationAuthorityError>;

    /// Returns one bounded page of current direct-membership records.
    ///
    /// # Errors
    ///
    /// Rejects stale cursors and unavailable or corrupt committed state.
    fn group_memberships(
        &self,
        group_id: GroupId,
        after: Option<GroupMemberCursor>,
        limit: PageLimit,
    ) -> Result<Page<GroupMembershipRecord, GroupMemberCursor>, IdentityAdministrationAuthorityError>;

    /// Reads one exact current direct-membership edge.
    ///
    /// # Errors
    ///
    /// Fails closed for unavailable or corrupt committed state.
    fn group_membership(
        &self,
        group_id: GroupId,
        member_principal_id: PrincipalId,
    ) -> Result<Option<GroupMembershipRecord>, IdentityAdministrationAuthorityError>;

    /// Resolves an already committed direct-membership mutation, if present.
    ///
    /// # Errors
    ///
    /// Rejects another command family or malformed durable evidence.
    fn resolve_group_membership_mutation(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<GroupMembershipAdministrationCommit>, IdentityAdministrationAuthorityError>;

    /// Commits or exactly resolves one direct-membership mutation through consensus.
    ///
    /// # Errors
    ///
    /// Rejects changed operation reuse and never reports success without durable evidence.
    fn commit_or_resolve_group_membership_mutation(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<GroupMembershipAdministrationCommit, IdentityAdministrationAuthorityError>;
}

/// Closed replicated-authority failures safe for service classification.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum IdentityAdministrationAuthorityError {
    /// Current replicated authority cannot be reached.
    #[error("identity authority is unavailable")]
    Unavailable,
    /// Operation or name uniqueness conflicts with committed state.
    #[error("identity authority reports a conflict")]
    Conflict,
    /// Persisted authority or its receipt failed validation.
    #[error("identity authority failed closed")]
    Failed,
}
