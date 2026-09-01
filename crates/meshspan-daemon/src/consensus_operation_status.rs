// SPDX-License-Identifier: GPL-2.0-only

//! Consensus-owned adapter for durable operation status.

use meshspan_domain::{OperationId, PrincipalId, UnixMicros};
use meshspan_metadata::{AuthoritativeOperationStatus, RepositoryError};

use crate::{
    ConsensusAuthenticationAuthority, OperationStatusAuthority, OperationStatusAuthorityError,
};

impl OperationStatusAuthority for ConsensusAuthenticationAuthority {
    fn operation_status(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<AuthoritativeOperationStatus>, OperationStatusAuthorityError> {
        self.reader()
            .operation_status(operation_id)
            .map_err(|error| map_repository_error(&error))
    }

    fn is_system_manager(
        &self,
        principal_id: PrincipalId,
        now: UnixMicros,
    ) -> Result<bool, OperationStatusAuthorityError> {
        self.reader()
            .principal_is_system_manager(principal_id, now)
            .map_err(|error| map_repository_error(&error))
    }
}

fn map_repository_error(error: &RepositoryError) -> OperationStatusAuthorityError {
    match error {
        RepositoryError::Store(_) | RepositoryError::Sqlite(_) | RepositoryError::Io(_) => {
            OperationStatusAuthorityError::Unavailable
        }
        _ => OperationStatusAuthorityError::Failed,
    }
}
