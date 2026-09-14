// SPDX-License-Identifier: GPL-2.0-only

//! Consensus composition for typed first-credential consent.

use super::{UserEnrollmentAuthority, UserEnrollmentError};
use crate::ConsensusAuthenticationAuthority;
use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_domain::{OperationId, PrincipalId, UnixMicros};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, CommandReceipt, PrincipalRecord, UserEnrollmentRecord,
};

impl UserEnrollmentAuthority for ConsensusAuthenticationAuthority {
    fn refresh_enrollment_authority(
        &self,
        requested_at: UnixMicros,
    ) -> Result<UnixMicros, UserEnrollmentError> {
        self.refresh_enrollment_read()
            .map(|now| now.max(requested_at))
    }
    fn enrollment(
        &self,
        operation: OperationId,
    ) -> Result<Option<UserEnrollmentRecord>, UserEnrollmentError> {
        self.reader()
            .user_enrollment(operation)
            .map_err(|_| UserEnrollmentError::Failed)
    }
    fn enrollment_principal(
        &self,
        principal: PrincipalId,
    ) -> Result<Option<PrincipalRecord>, UserEnrollmentError> {
        self.reader()
            .principal(principal)
            .map_err(|_| UserEnrollmentError::Failed)
    }
    fn enrollment_manager(
        &self,
        principal: PrincipalId,
        now: UnixMicros,
    ) -> Result<bool, UserEnrollmentError> {
        self.reader()
            .principal_is_system_manager(principal, now)
            .map_err(|_| UserEnrollmentError::Failed)
    }
    fn enrollment_operation_time(
        &self,
        operation: OperationId,
    ) -> Result<Option<UnixMicros>, UserEnrollmentError> {
        self.reader()
            .operation_status(operation)
            .map(|status| status.map(|value| value.started_at))
            .map_err(|_| UserEnrollmentError::Failed)
    }
    fn commit_enrollment(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, UserEnrollmentError> {
        self.commit_authoritative(context, command)
            .map_err(|error| match error {
                MetadataAuthorityRequestError::NotLeader { .. }
                | MetadataAuthorityRequestError::Unavailable => UserEnrollmentError::Unavailable,
                MetadataAuthorityRequestError::Conflict => UserEnrollmentError::Conflict,
                MetadataAuthorityRequestError::Rejected => UserEnrollmentError::Rejected,
                MetadataAuthorityRequestError::Unsupported
                | MetadataAuthorityRequestError::Failed => UserEnrollmentError::Failed,
            })
    }
}
