// SPDX-License-Identifier: GPL-2.0-only

//! Current-consent checks and exact durable invitation issuance/cancellation.

use super::{UserEnrollmentAuthority, UserEnrollmentError};
use crate::{
    BrowserAuthenticationError, BrowserRequestProtection, BrowserSessionAuthenticator,
    BrowserSessionAuthorityError, GatewaySessionIdentity, IdentityAdministrator,
};
use axum::http::HeaderMap;
use meshspan_api_contract::{
    IssueUserEnrollmentRequest, IssueUserEnrollmentResponse, OperationId as PublicOperationId,
    PrincipalId as PublicPrincipalId, RevokeUserEnrollmentRequest, RevokeUserEnrollmentResponse,
};
use meshspan_domain::{
    ApiKeyIssuanceKey, AssuranceLevel, AuditEventId, OperationId, PrincipalId, Revision,
    UnixMicros, UserEnrollmentBundle,
};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, CommandReceipt, EntityKind, IssueUserEnrollment,
    PrincipalKind, RevokeUserEnrollment, UserEnrollmentRecord, UserEnrollmentState,
};
use sha2::{Digest, Sha256};

/// Enrollment service using current authority and request-scoped issuance key material.
pub struct UserEnrollmentService<A> {
    pub(super) authority: A,
    gateway: GatewaySessionIdentity,
}

impl<A: UserEnrollmentAuthority> UserEnrollmentService<A> {
    /// Binds operations and browser authentication to the current gateway.
    #[must_use]
    pub const fn new(authority: A, gateway: GatewaySessionIdentity) -> Self {
        Self { authority, gateway }
    }

    /// Returns the owned authority for shutdown and subsequent service composition.
    #[must_use]
    pub fn into_authority(self) -> A {
        self.authority
    }

    /// Authenticates a current manager with recent step-up and mutation CSRF proof.
    /// # Errors
    /// Rejects insufficient, unavailable or malformed authentication.
    pub fn authenticate(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<IdentityAdministrator, UserEnrollmentError> {
        let now = self.authority.refresh_enrollment_authority(now)?;
        let capability = BrowserSessionAuthenticator::new(&self.authority, self.gateway)
            .authenticate(
                headers,
                BrowserRequestProtection::Mutation,
                AssuranceLevel::RecentStepUp,
                now,
            )
            .map_err(authentication_error)?;
        if !capability.is_system_manager() {
            return Err(UserEnrollmentError::Rejected);
        }
        Ok(IdentityAdministrator {
            principal_id: capability.principal_id,
            now,
        })
    }

    /// Issues or exactly retrieves live manager consent for a user's first credential.
    /// # Errors
    /// Rejects stale consent, expired/revoked invitations and substituted durable receipts.
    pub fn issue(
        &mut self,
        administrator: IdentityAdministrator,
        target: &PublicPrincipalId,
        request: &IssueUserEnrollmentRequest,
        key: &ApiKeyIssuanceKey,
    ) -> Result<IssueUserEnrollmentResponse, UserEnrollmentError> {
        let administrator = IdentityAdministrator {
            now: self
                .authority
                .refresh_enrollment_authority(administrator.now)?,
            ..administrator
        };
        let operation = domain_operation(&request.operation_id)?;
        let principal = PrincipalId::from_bytes(
            crate::create_mesh_setup::parse_uuid(target.as_str())
                .map_err(|_| UserEnrollmentError::InvalidRequest)?,
        )
        .map_err(|_| UserEnrollmentError::InvalidRequest)?;
        self.require_manager(administrator)?;
        if let Some(existing) = self.authority.enrollment(operation)? {
            self.require_live(existing, administrator.now)?;
        }
        let bundle = UserEnrollmentBundle::derive_issued(key, principal, operation)
            .map_err(|_| UserEnrollmentError::Failed)?;
        let command = AuthoritativeCommand::IssueUserEnrollment(IssueUserEnrollment {
            principal_id: principal,
            expected_principal_revision: Revision::new(request.expected_principal_revision),
            token_digest: bundle.secret_digest(),
            expires_at: UnixMicros::new(request.expires_at_epoch_micros),
        });
        let context = self.context(operation, administrator)?;
        let receipt = self.authority.commit_enrollment(context, &command)?;
        require_receipt(
            receipt,
            context,
            &command,
            EntityKind::UserEnrollment,
            operation.as_bytes(),
        )?;
        let now = self
            .authority
            .refresh_enrollment_authority(administrator.now)?;
        let current = self
            .authority
            .enrollment(operation)?
            .ok_or(UserEnrollmentError::Failed)?;
        self.require_live(current, now)?;
        if current.issued_by != administrator.principal_id
            || current.principal_id != principal
            || current.token_digest != bundle.secret_digest()
            || current.issuance_request_digest != receipt.request_digest
        {
            return Err(UserEnrollmentError::Failed);
        }
        Ok(IssueUserEnrollmentResponse {
            operation_id: request.operation_id.clone(),
            principal_id: target.clone(),
            token: bundle.expose_encoded().to_string(),
            expires_at_epoch_micros: current.expires_at.get(),
            committed_revision: receipt.committed_revision.get(),
        })
    }

    /// Cancels invitation redemption and secret recovery, leaving an existing method intact.
    /// # Errors
    /// Rejects nonmanagers, stale revisions and changed operation reuse.
    pub fn revoke(
        &mut self,
        administrator: IdentityAdministrator,
        invitation: &PublicOperationId,
        request: &RevokeUserEnrollmentRequest,
    ) -> Result<RevokeUserEnrollmentResponse, UserEnrollmentError> {
        let administrator = IdentityAdministrator {
            now: self
                .authority
                .refresh_enrollment_authority(administrator.now)?,
            ..administrator
        };
        self.require_manager(administrator)?;
        let operation = domain_operation(&request.operation_id)?;
        let invitation_id = domain_operation(invitation)?;
        let command = AuthoritativeCommand::RevokeUserEnrollment(RevokeUserEnrollment {
            enrollment_operation_id: invitation_id,
            expected_revision: Revision::new(request.expected_revision),
        });
        let context = self.context(operation, administrator)?;
        let receipt = self.authority.commit_enrollment(context, &command)?;
        require_receipt(
            receipt,
            context,
            &command,
            EntityKind::UserEnrollment,
            invitation_id.as_bytes(),
        )?;
        Ok(RevokeUserEnrollmentResponse {
            operation_id: request.operation_id.clone(),
            enrollment_operation_id: invitation.clone(),
            committed_revision: receipt.committed_revision.get(),
        })
    }

    pub(super) fn require_live(
        &self,
        invitation: UserEnrollmentRecord,
        now: UnixMicros,
    ) -> Result<(), UserEnrollmentError> {
        if now < invitation.issued_at
            || now >= invitation.expires_at
            || invitation.state == UserEnrollmentState::Revoked
        {
            return Err(UserEnrollmentError::Rejected);
        }
        let principal = self
            .authority
            .enrollment_principal(invitation.principal_id)?
            .ok_or(UserEnrollmentError::Rejected)?;
        if principal.kind != PrincipalKind::User
            || principal.state != 1
            || principal.revision != invitation.principal_revision
            || !self
                .authority
                .enrollment_manager(invitation.issued_by, now)?
        {
            return Err(UserEnrollmentError::Rejected);
        }
        Ok(())
    }

    fn require_manager(
        &self,
        administrator: IdentityAdministrator,
    ) -> Result<(), UserEnrollmentError> {
        if self
            .authority
            .enrollment_manager(administrator.principal_id, administrator.now)?
        {
            Ok(())
        } else {
            Err(UserEnrollmentError::Rejected)
        }
    }

    fn context(
        &self,
        operation_id: OperationId,
        administrator: IdentityAdministrator,
    ) -> Result<CommandContext, UserEnrollmentError> {
        let occurred_at = self
            .authority
            .enrollment_operation_time(operation_id)?
            .unwrap_or(administrator.now);
        let mut digest = Sha256::new();
        digest.update(b"meshspan.user-enrollment.audit.v1\0");
        digest.update(operation_id.as_bytes());
        digest.update(administrator.principal_id.as_bytes());
        let bytes: [u8; 16] = digest.finalize()[..16]
            .try_into()
            .map_err(|_| UserEnrollmentError::Failed)?;
        let audit_event_id = AuditEventId::from_bytes(meshspan_domain::uuid_v8(bytes))
            .map_err(|_| UserEnrollmentError::Failed)?;
        Ok(CommandContext {
            operation_id,
            actor_principal_id: administrator.principal_id,
            audit_event_id,
            occurred_at,
            expected_revision: None,
        })
    }
}

pub(super) fn domain_operation(
    value: &PublicOperationId,
) -> Result<OperationId, UserEnrollmentError> {
    OperationId::from_bytes(
        crate::create_mesh_setup::parse_uuid(value.as_str())
            .map_err(|_| UserEnrollmentError::InvalidRequest)?,
    )
    .map_err(|_| UserEnrollmentError::InvalidRequest)
}

pub(super) fn require_receipt(
    receipt: CommandReceipt,
    context: CommandContext,
    command: &AuthoritativeCommand,
    kind: EntityKind,
    id: [u8; 16],
) -> Result<(), UserEnrollmentError> {
    if receipt.operation_id != context.operation_id
        || receipt.request_digest != command.request_digest(context)
        || receipt.entity.kind != kind
        || receipt.entity.id != id
        || receipt.result_digest == [0; 32]
        || receipt.committed_revision.get() == 0
    {
        Err(UserEnrollmentError::Conflict)
    } else {
        Ok(())
    }
}

fn authentication_error(error: BrowserAuthenticationError) -> UserEnrollmentError {
    match error {
        BrowserAuthenticationError::Rejected => UserEnrollmentError::Rejected,
        BrowserAuthenticationError::Authority(BrowserSessionAuthorityError::Unavailable) => {
            UserEnrollmentError::Unavailable
        }
        BrowserAuthenticationError::InvalidGateway
        | BrowserAuthenticationError::Authority(BrowserSessionAuthorityError::Failed) => {
            UserEnrollmentError::Failed
        }
    }
}
