// SPDX-License-Identifier: GPL-2.0-only

//! Replaceable replicated-authority boundary for permission administration.

use meshspan_domain::{GrantId, OperationId, PrincipalId, UnixMicros, VolumeId};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, CommandReceipt, Page, PageLimit, PermissionGrantRecord,
    PermissionGrantRevocationRecord, ScopedGrantCursor, VolumeInventoryRecord,
};
use thiserror::Error;

use crate::{BrowserSessionAuthority, NativeApiKeyAuthority};

/// Replicated reads and consensus mutations required by permission administration.
pub trait PermissionAdministrationAuthority:
    BrowserSessionAuthority + NativeApiKeyAuthority
{
    /// Reports current system-manager authority.
    fn is_system_manager(
        &self,
        principal_id: PrincipalId,
        now: UnixMicros,
    ) -> Result<bool, PermissionAdministrationAuthorityError>;

    /// Returns one exact current principal when it exists.
    fn principal_exists(
        &self,
        principal_id: PrincipalId,
    ) -> Result<bool, PermissionAdministrationAuthorityError>;

    /// Returns one exact current volume.
    fn volume(
        &self,
        volume_id: VolumeId,
    ) -> Result<Option<VolumeInventoryRecord>, PermissionAdministrationAuthorityError>;

    /// Returns one bounded active grant page for an exact volume scope.
    fn volume_grants(
        &self,
        volume_id: VolumeId,
        after: Option<ScopedGrantCursor>,
        limit: PageLimit,
    ) -> Result<
        Page<PermissionGrantRecord, ScopedGrantCursor>,
        PermissionAdministrationAuthorityError,
    >;

    /// Returns one exact active grant.
    fn grant(
        &self,
        grant_id: GrantId,
    ) -> Result<Option<PermissionGrantRecord>, PermissionAdministrationAuthorityError>;

    /// Returns durable evidence for one exact revoked grant.
    fn grant_revocation(
        &self,
        grant_id: GrantId,
    ) -> Result<Option<PermissionGrantRevocationRecord>, PermissionAdministrationAuthorityError>;

    /// Resolves a prior authoritative operation, if any.
    fn resolve_operation(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<CommandReceipt>, PermissionAdministrationAuthorityError>;

    /// Commits or exactly resolves one permission mutation through consensus.
    fn commit_permission(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, PermissionAdministrationAuthorityError>;
}

/// Closed replicated-authority failures safe for public mapping.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PermissionAdministrationAuthorityError {
    /// Required committed authority cannot currently be reached.
    #[error("permission authority is unavailable")]
    Unavailable,
    /// The operation conflicts with existing committed state.
    #[error("permission authority operation conflicts")]
    Conflict,
    /// Persisted or returned authority failed validation.
    #[error("permission authority failed closed")]
    Failed,
}
