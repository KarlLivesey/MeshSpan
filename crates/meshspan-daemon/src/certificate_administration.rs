// SPDX-License-Identifier: GPL-2.0-only

//! Manager-authorised atomic public-certificate provisioning.

use axum::http::HeaderMap;
use meshspan_api_contract::{
    CertificateGeneration, CertificateOperationalState, CertificateStatusResponse,
    CertificateStatusSource, CurrentCertificateStatus, ProvisionCertificateRequest,
    ProvisionCertificateResponse,
};
use meshspan_domain::{OperationId, RandomSource, UnixMicros};
use meshspan_metadata::{
    AcmeConfigurationRecord, AuthoritativeCommand, CertificateOrderRecord, CommandContext,
    PublicCertificateSource, PublicCertificateStatusRecord,
};
use meshspan_secret_envelope::WrappingPublicKey;
use thiserror::Error;

use crate::{
    GatewaySessionIdentity, IdentityAdministrator, SystemManagerAuthenticationError,
    SystemManagerAuthority, authenticate_system_manager, authenticate_system_manager_read,
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
pub trait CertificateProvisioningAuthority: SystemManagerAuthority {
    /// Returns the current secret-free certificate and delivery projection.
    ///
    /// # Errors
    ///
    /// Fails closed when persisted certificate or acknowledgement evidence is malformed.
    fn public_certificate_status(
        &self,
    ) -> Result<Option<PublicCertificateStatusRecord>, CertificateProvisioningAuthorityError>;

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

    /// Authenticates a read before returning current secret-free certificate health.
    ///
    /// # Errors
    ///
    /// Rejects missing authority or malformed persisted status.
    fn status(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<CertificateStatusResponse, CertificateProvisioningError>;

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
        authenticate_system_manager(&self.authority, self.gateway, headers, now)
            .map_err(map_authentication_error)
    }

    fn status(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<CertificateStatusResponse, CertificateProvisioningError> {
        let administrator =
            authenticate_system_manager_read(&self.authority, self.gateway, headers, now)
                .map_err(map_authentication_error)?;
        let status = self
            .authority
            .public_certificate_status()
            .map_err(map_authority_error)?;
        certificate_status_response(administrator.now, status)
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

fn certificate_status_response(
    observed_at: UnixMicros,
    status: Option<PublicCertificateStatusRecord>,
) -> Result<CertificateStatusResponse, CertificateProvisioningError> {
    let observed_at_epoch_micros = safe_micros(observed_at)?;
    let certificate = status
        .map(|status| current_certificate_status(observed_at, status))
        .transpose()?;
    Ok(CertificateStatusResponse {
        observed_at_epoch_micros,
        certificate,
    })
}

fn current_certificate_status(
    observed_at: UnixMicros,
    status: PublicCertificateStatusRecord,
) -> Result<CurrentCertificateStatus, CertificateProvisioningError> {
    let (source, source_id) = match status.selection.source {
        PublicCertificateSource::AcmeOrder(id) => (
            CertificateStatusSource::Acme,
            crate::create_mesh_setup::format_uuid(id.as_bytes()),
        ),
        PublicCertificateSource::ExternalPublication(id) => (
            CertificateStatusSource::External,
            crate::create_mesh_setup::format_uuid(id.as_bytes()),
        ),
        PublicCertificateSource::MeshLocalIssuance(id) => (
            CertificateStatusSource::MeshLocal,
            crate::create_mesh_setup::format_uuid(id.as_bytes()),
        ),
    };
    let state = if observed_at < status.not_before {
        CertificateOperationalState::NotYetValid
    } else if observed_at >= status.not_after {
        CertificateOperationalState::Expired
    } else if status.rollout_complete() {
        CertificateOperationalState::Active
    } else {
        CertificateOperationalState::Distributing
    };
    Ok(CurrentCertificateStatus {
        source,
        source_id,
        delivery_generation: CertificateGeneration::from_value(
            status.selection.certificate.generation,
        )
        .ok_or(CertificateProvisioningError::Failed)?,
        not_before_epoch_micros: safe_micros(status.not_before)?,
        not_after_epoch_micros: safe_micros(status.not_after)?,
        required_gateway_count: status.required_gateway_count,
        installed_gateway_count: status.installed_gateway_count,
        state,
        source_revision: CertificateGeneration::from_value(status.selection.source_revision.get())
            .ok_or(CertificateProvisioningError::Failed)?,
    })
}

fn safe_micros(value: UnixMicros) -> Result<u64, CertificateProvisioningError> {
    u64::try_from(value.get())
        .ok()
        .filter(|value| *value <= 9_007_199_254_740_991)
        .ok_or(CertificateProvisioningError::Failed)
}

const fn map_authentication_error(
    error: SystemManagerAuthenticationError,
) -> CertificateProvisioningError {
    match error {
        SystemManagerAuthenticationError::Rejected => CertificateProvisioningError::Unauthenticated,
        SystemManagerAuthenticationError::Forbidden => CertificateProvisioningError::Forbidden,
        SystemManagerAuthenticationError::Unavailable => CertificateProvisioningError::Unavailable,
        SystemManagerAuthenticationError::Failed => CertificateProvisioningError::Failed,
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

#[cfg(test)]
mod status_tests {
    use meshspan_api_contract::{CertificateOperationalState, CertificateStatusSource};
    use meshspan_domain::{CertificateOrderId, PrincipalId, Revision, UnixMicros, uuid_v8};
    use meshspan_metadata::{
        PublicCertificateSelection, PublicCertificateSource, PublicCertificateStatusRecord,
        SecretGenerationReference,
    };

    use super::certificate_status_response;

    #[test]
    fn status_classifies_validity_and_delivery_without_exposing_secret_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let order_id = CertificateOrderId::from_bytes(uuid_v8([41; 16]))?;
        let principal_id = PrincipalId::from_bytes(uuid_v8([42; 16]))?;
        let status = PublicCertificateStatusRecord {
            selection: PublicCertificateSelection {
                source: PublicCertificateSource::AcmeOrder(order_id),
                certificate: SecretGenerationReference {
                    secret_id: order_id.as_bytes(),
                    generation: 2,
                },
                bundle_digest: [43; 32],
                configured_by: principal_id,
                completed_at: UnixMicros::new(20),
                source_revision: Revision::new(7),
            },
            not_before: UnixMicros::new(10),
            not_after: UnixMicros::new(100),
            required_gateway_count: 3,
            installed_gateway_count: 2,
        };
        let response = certificate_status_response(UnixMicros::new(50), Some(status))?;
        let certificate = response.certificate.ok_or("certificate")?;
        assert_eq!(certificate.source, CertificateStatusSource::Acme);
        assert_eq!(certificate.delivery_generation.value(), Some(2));
        assert_eq!(certificate.state, CertificateOperationalState::Distributing);

        let response = certificate_status_response(
            UnixMicros::new(50),
            Some(PublicCertificateStatusRecord {
                installed_gateway_count: 3,
                ..status
            }),
        )?;
        assert_eq!(
            response.certificate.ok_or("certificate")?.state,
            CertificateOperationalState::Active
        );
        assert_eq!(
            certificate_status_response(UnixMicros::new(100), Some(status))?
                .certificate
                .ok_or("certificate")?
                .state,
            CertificateOperationalState::Expired
        );
        Ok(())
    }
}
