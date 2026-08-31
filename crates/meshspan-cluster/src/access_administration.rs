// SPDX-License-Identifier: GPL-2.0-only

//! Authorised administration reads over committed access-control projections.

use meshspan_domain::{ObjectId, PrincipalId, Rights, VolumeId};
use meshspan_filesystem::FilesystemAccessContext;
use meshspan_metadata::{
    AccessActivationCursor, AccessActivationRecord, AccessCapability, AccessDecision, AccessDenial,
    AccessRequest, AuthoritativeRepository, ObjectOwnerCursor, ObjectOwnerRecord, Page, PageLimit,
    PermissionGrantRecord, PermissionScope, RepositoryError, ScopedGrantCursor,
    SessionAccessCapability, SessionAccessDecision, SessionAccessDenial, SessionAccessRequest,
    SubjectGrantCursor,
};
use thiserror::Error;

/// Exact current authority evidence attached to an administration page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessAdministrationAuthority {
    /// Object permission evidence used for owner and exact-scope views.
    Object(AccessCapability),
    /// Session, gateway and system-role evidence used for self/system views.
    Session(SessionAccessCapability),
}

/// One bounded administration page plus the authority projection used to disclose it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorisedAccessPage<T, C> {
    /// Stable ordered records.
    pub items: Vec<T>,
    /// Opaque continuation, absent at the end.
    pub next: Option<C>,
    /// Current authority evidence for response validation and audit binding.
    pub authority: AccessAdministrationAuthority,
}

/// Committed metadata administration adapter shared by HTTPS and future connectors.
pub struct MetadataAccessAdministration<'a> {
    repository: &'a AuthoritativeRepository,
}

impl<'a> MetadataAccessAdministration<'a> {
    /// Binds administration reads to one committed metadata repository.
    #[must_use]
    pub const fn new(repository: &'a AuthoritativeRepository) -> Self {
        Self { repository }
    }

    /// Returns one exact object's current owner set after proving `READ_PERMISSIONS`.
    ///
    /// # Errors
    ///
    /// Rejects unauthenticated, unauthorised, substituted-cursor or corrupt requests before
    /// disclosing owner records. Existing sessions are re-evaluated against current authority.
    pub fn object_owners(
        &self,
        context: FilesystemAccessContext,
        volume_id: VolumeId,
        object_id: ObjectId,
        after: Option<ObjectOwnerCursor>,
        limit: PageLimit,
    ) -> Result<AuthorisedAccessPage<ObjectOwnerRecord, ObjectOwnerCursor>, AccessAdministrationError>
    {
        let authority = self.authorise_object(context, volume_id, object_id)?;
        let page = self
            .repository
            .object_owners(object_id, after, limit)?
            .ok_or(AccessAdministrationError::ProjectionUnavailable)?;
        Ok(authorised_page(
            page,
            AccessAdministrationAuthority::Object(authority),
        ))
    }

    /// Returns current grants for one exact applicable scope after proving `READ_PERMISSIONS`.
    ///
    /// # Errors
    ///
    /// Rejects scope substitution, missing current permission, stale cursors and corrupt state.
    pub fn permission_grants_for_scope(
        &self,
        context: FilesystemAccessContext,
        authority_volume_id: VolumeId,
        authority_object_id: ObjectId,
        scope: PermissionScope,
        after: Option<ScopedGrantCursor>,
        limit: PageLimit,
    ) -> Result<
        AuthorisedAccessPage<PermissionGrantRecord, ScopedGrantCursor>,
        AccessAdministrationError,
    > {
        let authority = self.authorise_object(context, authority_volume_id, authority_object_id)?;
        if !scope_applies_to_authority(scope, authority_volume_id, authority_object_id) {
            return Err(AccessAdministrationError::ScopeMismatch);
        }
        let page = self
            .repository
            .permission_grants_for_scope(scope, after, limit)?;
        Ok(authorised_page(
            page,
            AccessAdministrationAuthority::Object(authority),
        ))
    }

    /// Returns current grants for the authenticated user or, for system managers, another subject.
    ///
    /// # Errors
    ///
    /// Rejects missing sessions, inactive gateways, cross-user disclosure by ordinary users,
    /// cursor substitution and corrupt state. Existing sessions use current committed roles.
    pub fn permission_grants_for_subject(
        &self,
        context: FilesystemAccessContext,
        subject_principal_id: PrincipalId,
        after: Option<SubjectGrantCursor>,
        limit: PageLimit,
    ) -> Result<
        AuthorisedAccessPage<PermissionGrantRecord, SubjectGrantCursor>,
        AccessAdministrationError,
    > {
        let authority = self.authorise_session(context)?;
        require_self_or_manager(authority, subject_principal_id)?;
        let page =
            self.repository
                .permission_grants_for_subject(subject_principal_id, after, limit)?;
        Ok(authorised_page(
            page,
            AccessAdministrationAuthority::Session(authority),
        ))
    }

    /// Returns nominally live activations for the authenticated user or a manager-selected user.
    ///
    /// # Errors
    ///
    /// Rejects missing sessions, inactive gateways, cross-user disclosure by ordinary users,
    /// cursor substitution and corrupt state. Existing sessions use current committed roles.
    pub fn access_activations(
        &self,
        context: FilesystemAccessContext,
        principal_id: PrincipalId,
        after: Option<AccessActivationCursor>,
        limit: PageLimit,
    ) -> Result<
        AuthorisedAccessPage<AccessActivationRecord, AccessActivationCursor>,
        AccessAdministrationError,
    > {
        let authority = self.authorise_session(context)?;
        require_self_or_manager(authority, principal_id)?;
        let page = self.repository.unrevoked_access_activations(
            principal_id,
            context.now,
            after,
            limit,
        )?;
        Ok(authorised_page(
            page,
            AccessAdministrationAuthority::Session(authority),
        ))
    }

    fn authorise_object(
        &self,
        context: FilesystemAccessContext,
        volume_id: VolumeId,
        object_id: ObjectId,
    ) -> Result<AccessCapability, AccessAdministrationError> {
        match self.repository.evaluate_access(AccessRequest {
            authentication_service: context.authentication_service,
            credential_digest: context.credential_digest,
            required_assurance: context.required_assurance,
            gateway_node_id: context.gateway_node_id,
            gateway_incarnation: context.gateway_incarnation,
            volume_id,
            object_id,
            requested_rights: Rights::READ_PERMISSIONS,
            now: context.now,
        })? {
            AccessDecision::Granted(capability) => Ok(capability),
            AccessDecision::Denied(denial) => Err(AccessAdministrationError::ObjectDenied(denial)),
        }
    }

    fn authorise_session(
        &self,
        context: FilesystemAccessContext,
    ) -> Result<SessionAccessCapability, AccessAdministrationError> {
        match self
            .repository
            .evaluate_session_access(SessionAccessRequest {
                token_digest: context.credential_digest,
                required_assurance: context.required_assurance,
                gateway_node_id: context.gateway_node_id,
                gateway_incarnation: context.gateway_incarnation,
                now: context.now,
            })? {
            SessionAccessDecision::Granted(capability) => Ok(capability),
            SessionAccessDecision::Denied(denial) => {
                Err(AccessAdministrationError::SessionDenied(denial))
            }
        }
    }
}

/// Stable rejection classes for the connector-neutral administration boundary.
#[derive(Debug, Error)]
pub enum AccessAdministrationError {
    /// Current object permissions deny disclosure.
    #[error("committed metadata denied access-administration object disclosure: {0:?}")]
    ObjectDenied(AccessDenial),
    /// Current session or gateway authority is unavailable.
    #[error("committed metadata denied access-administration session disclosure: {0:?}")]
    SessionDenied(SessionAccessDenial),
    /// An ordinary user attempted to inspect another principal.
    #[error("access-administration subject is outside the current session scope")]
    SubjectForbidden,
    /// The requested grant scope does not apply to the authority object.
    #[error("access-administration scope does not match its authority target")]
    ScopeMismatch,
    /// An authorised target had no corresponding administration projection.
    #[error("access-administration projection is unavailable")]
    ProjectionUnavailable,
    /// The committed metadata projection failed verification.
    #[error("committed access-administration projection failed")]
    Repository(#[from] RepositoryError),
}

fn require_self_or_manager(
    authority: SessionAccessCapability,
    subject_principal_id: PrincipalId,
) -> Result<(), AccessAdministrationError> {
    if authority.principal_id == subject_principal_id || authority.is_system_manager() {
        Ok(())
    } else {
        Err(AccessAdministrationError::SubjectForbidden)
    }
}

fn scope_applies_to_authority(
    scope: PermissionScope,
    volume_id: VolumeId,
    object_id: ObjectId,
) -> bool {
    match scope {
        PermissionScope::Global => true,
        PermissionScope::Volume(scope_volume) => scope_volume == volume_id,
        PermissionScope::Object {
            volume_id: scope_volume,
            object_id: scope_object,
        } => scope_volume == volume_id && scope_object == object_id,
    }
}

fn authorised_page<T, C>(
    page: Page<T, C>,
    authority: AccessAdministrationAuthority,
) -> AuthorisedAccessPage<T, C> {
    AuthorisedAccessPage {
        items: page.items,
        next: page.next,
        authority,
    }
}
