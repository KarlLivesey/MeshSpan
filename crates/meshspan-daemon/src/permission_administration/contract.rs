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
    ///
    /// # Errors
    ///
    /// Returns a closed authority error when current authority cannot be established.
    fn is_system_manager(
        &self,
        principal_id: PrincipalId,
        now: UnixMicros,
    ) -> Result<bool, PermissionAdministrationAuthorityError>;

    /// Returns one exact current principal when it exists.
    ///
    /// # Errors
    ///
    /// Returns a closed authority error when principal state cannot be trusted.
    fn principal_exists(
        &self,
        principal_id: PrincipalId,
    ) -> Result<bool, PermissionAdministrationAuthorityError>;

    /// Returns one exact current volume.
    ///
    /// # Errors
    ///
    /// Returns a closed authority error when volume state cannot be trusted.
    fn volume(
        &self,
        volume_id: VolumeId,
    ) -> Result<Option<VolumeInventoryRecord>, PermissionAdministrationAuthorityError>;

    /// Returns one bounded active grant page for an exact volume scope.
    ///
    /// # Errors
    ///
    /// Returns a closed authority error when grant state cannot be read safely.
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
    ///
    /// # Errors
    ///
    /// Returns a closed authority error when grant state cannot be read safely.
    fn grant(
        &self,
        grant_id: GrantId,
    ) -> Result<Option<PermissionGrantRecord>, PermissionAdministrationAuthorityError>;

    /// Returns durable evidence for one exact revoked grant.
    ///
    /// # Errors
    ///
    /// Returns a closed authority error when revocation evidence cannot be read safely.
    fn grant_revocation(
        &self,
        grant_id: GrantId,
    ) -> Result<Option<PermissionGrantRevocationRecord>, PermissionAdministrationAuthorityError>;

    /// Resolves a prior authoritative operation, if any.
    ///
    /// # Errors
    ///
    /// Returns a closed authority error when the operation receipt cannot be trusted.
    fn resolve_operation(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<CommandReceipt>, PermissionAdministrationAuthorityError>;

    /// Commits or exactly resolves one permission mutation through consensus.
    ///
    /// # Errors
    ///
    /// Returns a closed authority error when consensus cannot commit or resolve safely.
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
