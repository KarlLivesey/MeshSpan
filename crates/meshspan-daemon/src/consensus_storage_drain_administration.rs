// SPDX-License-Identifier: GPL-2.0-only

//! Consensus-owned adapter for storage-drain administration.

use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_domain::WorkId;
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, CommandReceipt, PageLimit, RepositoryError,
    StorageDrainCursor, StorageDrainRecord, StorageDrainStatusPage,
};

use crate::{
    ConsensusAuthenticationAuthority, StorageDrainAdministrationAuthority,
    StorageDrainAdministrationAuthorityError,
};

impl StorageDrainAdministrationAuthority for ConsensusAuthenticationAuthority {
    fn storage_drain(
        &self,
        drain_id: WorkId,
    ) -> Result<Option<StorageDrainRecord>, StorageDrainAdministrationAuthorityError> {
        self.reader()
            .storage_drain(drain_id)
            .map_err(|error| map_repository_error(&error))
    }

    fn storage_drains(
        &self,
        after: Option<StorageDrainCursor>,
        limit: PageLimit,
    ) -> Result<StorageDrainStatusPage, StorageDrainAdministrationAuthorityError> {
        self.reader()
            .storage_drains(after, limit)
            .map_err(|error| map_repository_error(&error))
    }

    fn commit_storage_drain_operation(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, StorageDrainAdministrationAuthorityError> {
        self.commit_authoritative(context, command)
            .map_err(map_authority_error)
    }
}

fn map_authority_error(
    error: MetadataAuthorityRequestError,
) -> StorageDrainAdministrationAuthorityError {
    match error {
        MetadataAuthorityRequestError::NotLeader { .. }
        | MetadataAuthorityRequestError::Unavailable => {
            StorageDrainAdministrationAuthorityError::Unavailable
        }
        MetadataAuthorityRequestError::Conflict | MetadataAuthorityRequestError::Rejected => {
            StorageDrainAdministrationAuthorityError::Conflict
        }
        MetadataAuthorityRequestError::Unsupported | MetadataAuthorityRequestError::Failed => {
            StorageDrainAdministrationAuthorityError::Failed
        }
    }
}

fn map_repository_error(error: &RepositoryError) -> StorageDrainAdministrationAuthorityError {
    match error {
        RepositoryError::OperationConflict
        | RepositoryError::StaleRevision
        | RepositoryError::InvalidCommand => StorageDrainAdministrationAuthorityError::Conflict,
        RepositoryError::Store(_) | RepositoryError::Sqlite(_) | RepositoryError::Io(_) => {
            StorageDrainAdministrationAuthorityError::Unavailable
        }
        _ => StorageDrainAdministrationAuthorityError::Failed,
    }
}
