// SPDX-License-Identifier: GPL-2.0-only

//! Consensus-owned adapter for permission administration.

use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_domain::{GrantId, OperationId, PrincipalId, UnixMicros, VolumeId};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, CommandReceipt, Page, PageLimit, PermissionGrantRecord,
    PermissionGrantRevocationRecord, PermissionScope, RepositoryError, ScopedGrantCursor,
    VolumeInventoryRecord,
};

use crate::{
    ConsensusAuthenticationAuthority, PermissionAdministrationAuthority,
    PermissionAdministrationAuthorityError,
};

impl PermissionAdministrationAuthority for ConsensusAuthenticationAuthority {
    fn is_system_manager(
        &self,
        principal_id: PrincipalId,
        now: UnixMicros,
    ) -> Result<bool, PermissionAdministrationAuthorityError> {
        self.reader()
            .principal_is_system_manager(principal_id, now)
            .map_err(|error| map_repository_error(&error))
    }

    fn principal_exists(
        &self,
        principal_id: PrincipalId,
    ) -> Result<bool, PermissionAdministrationAuthorityError> {
        self.reader()
            .principal(principal_id)
            .map(|record| record.is_some())
            .map_err(|error| map_repository_error(&error))
    }

    fn volume(
        &self,
        volume_id: VolumeId,
    ) -> Result<Option<VolumeInventoryRecord>, PermissionAdministrationAuthorityError> {
        self.reader()
            .volume_inventory_record(volume_id)
            .map_err(|error| map_repository_error(&error))
    }

    fn volume_grants(
        &self,
        volume_id: VolumeId,
        after: Option<ScopedGrantCursor>,
        limit: PageLimit,
    ) -> Result<
        Page<PermissionGrantRecord, ScopedGrantCursor>,
        PermissionAdministrationAuthorityError,
    > {
        self.reader()
            .permission_grants_for_scope(PermissionScope::Volume(volume_id), after, limit)
            .map_err(|error| map_repository_error(&error))
    }

    fn grant(
        &self,
        grant_id: GrantId,
    ) -> Result<Option<PermissionGrantRecord>, PermissionAdministrationAuthorityError> {
        self.reader()
            .permission_grant(grant_id)
            .map_err(|error| map_repository_error(&error))
    }

    fn grant_revocation(
        &self,
        grant_id: GrantId,
    ) -> Result<Option<PermissionGrantRevocationRecord>, PermissionAdministrationAuthorityError>
    {
        self.reader()
            .permission_grant_revocation(grant_id)
            .map_err(|error| map_repository_error(&error))
    }

    fn resolve_operation(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<CommandReceipt>, PermissionAdministrationAuthorityError> {
        self.reader()
            .resolve_operation(operation_id)
            .map_err(|error| map_repository_error(&error))
    }

    fn commit_permission(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, PermissionAdministrationAuthorityError> {
        let expected_digest = command.request_digest(context);
        let receipt = self
            .commit_authoritative(context, command)
            .map_err(map_authority_error)?;
        if receipt.request_digest != expected_digest {
            return Err(PermissionAdministrationAuthorityError::Conflict);
        }
        Ok(receipt)
    }
}

fn map_authority_error(
    error: MetadataAuthorityRequestError,
) -> PermissionAdministrationAuthorityError {
    match error {
        MetadataAuthorityRequestError::NotLeader { .. }
        | MetadataAuthorityRequestError::Unavailable => {
            PermissionAdministrationAuthorityError::Unavailable
        }
        MetadataAuthorityRequestError::Conflict | MetadataAuthorityRequestError::Rejected => {
            PermissionAdministrationAuthorityError::Conflict
        }
        MetadataAuthorityRequestError::Unsupported | MetadataAuthorityRequestError::Failed => {
            PermissionAdministrationAuthorityError::Failed
        }
    }
}

fn map_repository_error(error: &RepositoryError) -> PermissionAdministrationAuthorityError {
    match error {
        RepositoryError::OperationConflict
        | RepositoryError::StaleRevision
        | RepositoryError::InvalidCommand => PermissionAdministrationAuthorityError::Conflict,
        RepositoryError::Store(_) | RepositoryError::Sqlite(_) | RepositoryError::Io(_) => {
            PermissionAdministrationAuthorityError::Unavailable
        }
        _ => PermissionAdministrationAuthorityError::Failed,
    }
}
