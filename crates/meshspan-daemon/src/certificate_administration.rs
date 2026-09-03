// SPDX-License-Identifier: GPL-2.0-only

//! Manager-authorised atomic public-certificate provisioning.

use axum::http::HeaderMap;
use axum::http::header::{AUTHORIZATION, COOKIE};
use meshspan_api_contract::{ProvisionCertificateRequest, ProvisionCertificateResponse};
use meshspan_domain::{OperationId, PrincipalId, RandomSource, UnixMicros};
use meshspan_metadata::{
    AcmeConfigurationRecord, AuthoritativeCommand, CertificateOrderRecord, CommandContext,
};
use meshspan_secret_envelope::WrappingPublicKey;
use thiserror::Error;

use crate::{
    BrowserRequestProtection, BrowserSessionAuthenticator, BrowserSessionAuthority,
    FileApiAuthenticationError, GatewaySessionIdentity, IdentityAdministrator,
    NativeApiKeyAuthenticator, NativeApiKeyAuthority,
};

mod provisioning_evidence;
mod provisioning_request;

use provisioning_evidence::{provisioning_response, validate_commit};
use provisioning_request::{ProvisioningIdentity, prepare_command};

/// Exact durable evidence returned for one certificate-provisioning operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateProvisioningCommit {
    /// Canonical encrypted command digest accepted by consensus.
    pub request_digest: [u8; 32],
    /// Non-zero durable result digest.
    pub result_digest: [u8; 32],
    /// Original authoritative revision created by the provisioning transaction.
    pub committed_revision: meshspan_domain::Revision,
    /// Immutable committed configuration.
    pub configuration: AcmeConfigurationRecord,
    /// Initial durable order.
    pub order: CertificateOrderRecord,
}

/// Replicated reads and consensus mutation needed by certificate provisioning.
pub trait CertificateProvisioningAuthority:
    BrowserSessionAuthority + NativeApiKeyAuthority
{
    /// Reports current system-manager authority.
    ///
    /// # Errors
    ///
    /// Fails closed when the current role projection is unavailable or malformed.
    fn is_system_manager(
        &self,
        principal_id: PrincipalId,
        now: UnixMicros,
    ) -> Result<bool, CertificateProvisioningAuthorityError>;

    /// Resolves one prior provisioning operation.
    ///
    /// # Errors
    ///
    /// Rejects another command family or untrustworthy retained evidence.
    fn resolve_certificate_provisioning(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<CertificateProvisioningCommit>, CertificateProvisioningAuthorityError>;

    /// Returns every current gateway wrapping key plus verified offline recovery.
    ///
    /// # Errors
    ///
    /// Fails closed unless the complete current recipient set can be established.
    fn certificate_secret_recipients(
        &self,
    ) -> Result<Vec<WrappingPublicKey>, CertificateProvisioningAuthorityError>;

    /// Commits or exactly resolves one provisioning transaction through consensus.
    ///
    /// # Errors
    ///
    /// Rejects changed operation reuse and never invents success from transport outcome.
    fn commit_or_resolve_certificate_provisioning(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CertificateProvisioningCommit, CertificateProvisioningAuthorityError>;
}

/// Synchronous certificate controller kept behind the bounded HTTP blocking pool.
pub trait CertificateProvisioningController: Send + 'static {
    /// Authenticates before the HTTP boundary consumes a request body.
    ///
    /// # Errors
    ///
    /// Rejects missing, ambiguous, stale or insufficient credentials and unavailable authority.
    fn authenticate(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<IdentityAdministrator, CertificateProvisioningError>;

    /// Encrypts and atomically commits public-certificate configuration and its first order.
    ///
    /// # Errors
    ///
    /// Rejects invalid input, conflicting retries and unavailable or corrupt authority.
    fn provision(
        &mut self,
        administrator: IdentityAdministrator,
        request: ProvisionCertificateRequest,
    ) -> Result<ProvisionCertificateResponse, CertificateProvisioningError>;
}

/// Complete certificate-provisioning application service.
pub struct CertificateProvisioningService<A, R> {
    authority: A,
    gateway: GatewaySessionIdentity,
    random: R,
}

impl<A, R> CertificateProvisioningService<A, R> {
    /// Binds manager authentication, consensus authority and cryptographic entropy.
    #[must_use]
    pub const fn new(authority: A, gateway: GatewaySessionIdentity, random: R) -> Self {
        Self {
            authority,
            gateway,
            random,
        }
    }
}

impl<A, R> CertificateProvisioningController for CertificateProvisioningService<A, R>
where
    A: CertificateProvisioningAuthority + Send + 'static,
    R: RandomSource + Send + 'static,
{
    fn authenticate(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<IdentityAdministrator, CertificateProvisioningError> {
        let has_authorization = headers.contains_key(AUTHORIZATION);
        if has_authorization && headers.contains_key(COOKIE) {
            return Err(CertificateProvisioningError::Unauthenticated);
        }
        if has_authorization {
            let principal_id = NativeApiKeyAuthenticator::new(&self.authority, self.gateway)
                .authenticate_principal(headers, now)
                .map_err(map_file_authentication_error)?;
            return self
                .authority
                .is_system_manager(principal_id, now)
                .map_err(map_authority_error)?
                .then_some(IdentityAdministrator { principal_id, now })
                .ok_or(CertificateProvisioningError::Forbidden);
        }
        let capability = BrowserSessionAuthenticator::new(&self.authority, self.gateway)
            .authenticate(
                headers,
                BrowserRequestProtection::Mutation,
                meshspan_domain::AssuranceLevel::SingleFactor,
                now,
            )
            .map_err(|error| match error {
                crate::BrowserAuthenticationError::Rejected => {
                    CertificateProvisioningError::Unauthenticated
                }
                crate::BrowserAuthenticationError::Authority(
                    crate::BrowserSessionAuthorityError::Unavailable,
                ) => CertificateProvisioningError::Unavailable,
                crate::BrowserAuthenticationError::InvalidGateway
                | crate::BrowserAuthenticationError::Authority(
                    crate::BrowserSessionAuthorityError::Failed,
                ) => CertificateProvisioningError::Failed,
            })?;
        if !capability.is_system_manager() {
            return Err(CertificateProvisioningError::Forbidden);
        }
        Ok(IdentityAdministrator {
            principal_id: capability.principal_id,
            now,
        })
    }

    fn provision(
        &mut self,
        administrator: IdentityAdministrator,
        request: ProvisionCertificateRequest,
    ) -> Result<ProvisionCertificateResponse, CertificateProvisioningError> {
        let identity = ProvisioningIdentity::from_request(&request)?;
        if let Some(commit) = self
            .authority
            .resolve_certificate_provisioning(identity.operation_id)
            .map_err(map_authority_error)?
        {
            validate_commit(&commit, identity, None)?;
            return provisioning_response(request.operation_id, commit);
        }
        let recipients = self
            .authority
            .certificate_secret_recipients()
            .map_err(map_authority_error)?;
        let (context, command) = prepare_command(
            request,
            identity,
            administrator,
            &recipients,
            &mut self.random,
        )?;
        let expected_digest = command.request_digest(context);
        let (commit, exact_digest) = match self
            .authority
            .commit_or_resolve_certificate_provisioning(context, &command)
        {
            Ok(commit) => (commit, Some(expected_digest)),
            Err(commit_error) => match self
                .authority
                .resolve_certificate_provisioning(identity.operation_id)
                .map_err(map_authority_error)?
            {
                Some(commit) => (commit, None),
                None => return Err(map_authority_error(commit_error)),
            },
        };
        validate_commit(&commit, identity, exact_digest)?;
        provisioning_response(
            meshspan_api_contract::OperationId::from_uuid_bytes(identity.operation_id.as_bytes())
                .ok_or(CertificateProvisioningError::Failed)?,
            commit,
        )
    }
}

fn map_file_authentication_error(
    error: FileApiAuthenticationError,
) -> CertificateProvisioningError {
    match error {
        FileApiAuthenticationError::Rejected => CertificateProvisioningError::Unauthenticated,
        FileApiAuthenticationError::AuthorityUnavailable => {
            CertificateProvisioningError::Unavailable
        }
        FileApiAuthenticationError::InvalidGateway
        | FileApiAuthenticationError::AuthorityFailed => CertificateProvisioningError::Failed,
    }
}

fn map_authority_error(
    error: CertificateProvisioningAuthorityError,
) -> CertificateProvisioningError {
    match error {
        CertificateProvisioningAuthorityError::Unavailable => {
            CertificateProvisioningError::Unavailable
        }
        CertificateProvisioningAuthorityError::Conflict => CertificateProvisioningError::Conflict,
        CertificateProvisioningAuthorityError::Failed => CertificateProvisioningError::Failed,
    }
}

/// Closed replicated-authority failure safe for public classification.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CertificateProvisioningAuthorityError {
    /// Current consensus projection or leader is unavailable.
    #[error("certificate provisioning authority is unavailable")]
    Unavailable,
    /// Operation or retained configuration conflicts with the request.
    #[error("certificate provisioning operation conflicts")]
    Conflict,
    /// Persisted evidence or an invariant failed closed.
    #[error("certificate provisioning authority failed closed")]
    Failed,
}

/// Closed manager-only certificate-provisioning outcome.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CertificateProvisioningError {
    /// Public names, endpoints or provider settings are invalid.
    #[error("certificate provisioning input is invalid")]
    InvalidInput,
    /// No current credential was accepted.
    #[error("certificate provisioning authentication was rejected")]
    Unauthenticated,
    /// The current principal lacks system-manager authority.
    #[error("certificate provisioning authority was denied")]
    Forbidden,
    /// Operation reuse conflicts with committed intent.
    #[error("certificate provisioning operation conflicts")]
    Conflict,
    /// Current consensus authority or entropy is temporarily unavailable.
    #[error("certificate provisioning authority is unavailable")]
    Unavailable,
    /// Persisted evidence or response construction failed closed.
    #[error("certificate provisioning failed closed")]
    Failed,
}
