// SPDX-License-Identifier: GPL-2.0-only

//! Consensus-owned adapter for explicit SMB-export administration.

use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_metadata::{AuthoritativeCommand, CommandContext, CommandReceipt, RepositoryError};

use crate::{
    ConsensusAuthenticationAuthority, SmbExportAdministrationAuthority,
    SmbExportAdministrationAuthorityError,
};

impl SmbExportAdministrationAuthority for ConsensusAuthenticationAuthority {
    fn is_system_manager(
        &self,
        principal_id: meshspan_domain::PrincipalId,
        now: meshspan_domain::UnixMicros,
    ) -> Result<bool, SmbExportAdministrationAuthorityError> {
        self.reader()
            .principal_is_system_manager(principal_id, now)
            .map_err(|error| map_repository_error(&error))
    }

    fn resolve_smb_export_operation(
        &self,
        operation_id: meshspan_domain::OperationId,
    ) -> Result<Option<CommandReceipt>, SmbExportAdministrationAuthorityError> {
        self.reader()
            .resolve_operation(operation_id)
            .map_err(|error| map_repository_error(&error))
    }

    fn commit_smb_export_operation(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, SmbExportAdministrationAuthorityError> {
        self.commit_authoritative(context, command)
            .map_err(map_authority_error)
    }
}

fn map_authority_error(
    error: MetadataAuthorityRequestError,
) -> SmbExportAdministrationAuthorityError {
    match error {
        MetadataAuthorityRequestError::NotLeader { .. }
        | MetadataAuthorityRequestError::Unavailable => {
            SmbExportAdministrationAuthorityError::Unavailable
        }
        MetadataAuthorityRequestError::Conflict | MetadataAuthorityRequestError::Rejected => {
            SmbExportAdministrationAuthorityError::Conflict
        }
        MetadataAuthorityRequestError::Unsupported | MetadataAuthorityRequestError::Failed => {
            SmbExportAdministrationAuthorityError::Failed
        }
    }
}

fn map_repository_error(error: &RepositoryError) -> SmbExportAdministrationAuthorityError {
    match error {
        RepositoryError::OperationConflict
        | RepositoryError::StaleRevision
        | RepositoryError::InvalidCommand => SmbExportAdministrationAuthorityError::Conflict,
        RepositoryError::Store(_) | RepositoryError::Sqlite(_) | RepositoryError::Io(_) => {
            SmbExportAdministrationAuthorityError::Unavailable
        }
        _ => SmbExportAdministrationAuthorityError::Failed,
    }
}
