// SPDX-License-Identifier: GPL-2.0-only

//! Manager-authorised atomic public-certificate provisioning.

use std::net::SocketAddr;

use axum::http::HeaderMap;
use axum::http::header::{AUTHORIZATION, COOKIE};
use meshspan_acme::{
    AcmeAccountKey, CloudflareDnsSettings, DnsProviderSettings, Rfc2136DnsSettings,
    Rfc2136TsigAlgorithm as DomainTsigAlgorithm, WebhookDnsSettings,
};
use meshspan_api_contract::{
    CertificateChallenge, ProvisionCertificateRequest, ProvisionCertificateResponse,
    Rfc2136TsigAlgorithm as ApiTsigAlgorithm,
};
use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    AcmeConfigurationId, AuditEventId, CertificateOrderId, OperationId, PrincipalId, RandomSource,
    UnixMicros, uuid_v8,
};
use meshspan_metadata::{
    ACME_ACCOUNT_KEY_SECRET_KIND, ACME_CHALLENGE_SETTINGS_SECRET_KIND, AcmeChallengeKind,
    AcmeConfigurationRecord, AuthoritativeCommand, CertificateOrderRecord, CommandContext,
    CommitSecretGeneration, ConfigureAcme, ProvisionAcme, QueueCertificateOrder,
    SecretGenerationReference,
};
use meshspan_secret_envelope::{SecretContext, WrappingPublicKey, encrypt_secret};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::create_mesh_setup::parse_uuid;
use crate::{
    BrowserRequestProtection, BrowserSessionAuthenticator, BrowserSessionAuthority,
    FileApiAuthenticationError, GatewaySessionIdentity, IdentityAdministrator,
    NativeApiKeyAuthenticator, NativeApiKeyAuthority,
};

const CONFIGURATION_ID_DOMAIN: &[u8] = b"meshspan.certificate.configuration-id.v1\0";
const ORDER_ID_DOMAIN: &[u8] = b"meshspan.certificate.order-id.v1\0";
const ACCOUNT_SECRET_ID_DOMAIN: &[u8] = b"meshspan.certificate.account-secret-id.v1\0";
const SETTINGS_SECRET_ID_DOMAIN: &[u8] = b"meshspan.certificate.settings-secret-id.v1\0";
const AUDIT_ID_DOMAIN: &[u8] = b"meshspan.certificate.audit-id.v1\0";
const INTENT_DIGEST_DOMAIN: &[u8] = b"meshspan.certificate.provisioning-intent.v1\0";
const INITIAL_SECRET_GENERATION: u64 = 1;
const ACCOUNT_KEY_BYTES: usize = 32;
const MAXIMUM_ACCOUNT_KEY_ATTEMPTS: usize = 8;

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
        let operation_id = domain_operation(&request.operation_id)?;
        let configuration_id =
            derived_id::<AcmeConfigurationId>(CONFIGURATION_ID_DOMAIN, operation_id)?;
        let order_id = derived_id::<CertificateOrderId>(ORDER_ID_DOMAIN, operation_id)?;
        let intent_digest = intent_digest(&request);
        if let Some(commit) = self
            .authority
            .resolve_certificate_provisioning(operation_id)
            .map_err(map_authority_error)?
        {
            validate_commit(&commit, configuration_id, order_id, intent_digest, None)?;
            return provisioning_response(request.operation_id, commit);
        }
        let recipients = self
            .authority
            .certificate_secret_recipients()
            .map_err(map_authority_error)?;
        let challenge = challenge_settings(request.challenge)?;
        let account_reference = secret_reference(ACCOUNT_SECRET_ID_DOMAIN, operation_id);
        let settings_reference = challenge
            .settings
            .as_ref()
            .map(|_| secret_reference(SETTINGS_SECRET_ID_DOMAIN, operation_id));
        let account_key_generation =
            account_key_generation(account_reference, &recipients, &mut self.random)?;
        let challenge_settings_generation = challenge
            .settings
            .as_deref()
            .zip(settings_reference)
            .map(|(plaintext, reference)| {
                encrypted_generation(
                    ACME_CHALLENGE_SETTINGS_SECRET_KIND,
                    reference,
                    plaintext,
                    &recipients,
                    &mut self.random,
                )
                .map(Box::new)
            })
            .transpose()?;
        let configuration = ConfigureAcme {
            config_id: configuration_id,
            directory_url: request.directory_url,
            account_key: account_reference,
            challenge_kind: challenge.kind,
            challenge_settings: settings_reference,
            certificate_names: BoundedItems::new(request.certificate_names, 256)
                .map_err(|_| CertificateProvisioningError::InvalidInput)?,
        };
        let command = AuthoritativeCommand::ProvisionAcme(Box::new(ProvisionAcme {
            intent_digest,
            configuration,
            account_key_generation,
            challenge_settings_generation,
            initial_order: QueueCertificateOrder {
                order_id,
                config_id: configuration_id,
                next_attempt_at: administrator.now,
            },
        }));
        let context = command_context(operation_id, administrator)?;
        let expected_digest = command.request_digest(context);
        let (commit, exact_digest) = match self
            .authority
            .commit_or_resolve_certificate_provisioning(context, &command)
        {
            Ok(commit) => (commit, Some(expected_digest)),
            Err(commit_error) => match self
                .authority
                .resolve_certificate_provisioning(operation_id)
                .map_err(map_authority_error)?
            {
                Some(commit) => (commit, None),
                None => return Err(map_authority_error(commit_error)),
            },
        };
        validate_commit(
            &commit,
            configuration_id,
            order_id,
            intent_digest,
            exact_digest,
        )?;
        provisioning_response(request.operation_id, commit)
    }
}

struct ChallengeMaterial {
    kind: AcmeChallengeKind,
    settings: Option<Zeroizing<Vec<u8>>>,
}

fn challenge_settings(
    challenge: CertificateChallenge,
) -> Result<ChallengeMaterial, CertificateProvisioningError> {
    let settings = match challenge {
        CertificateChallenge::Http01 => {
            return Ok(ChallengeMaterial {
                kind: AcmeChallengeKind::Http01,
                settings: None,
            });
        }
        CertificateChallenge::Dns01Manual => None,
        CertificateChallenge::Dns01Rfc2136 {
            server,
            zone,
            key_name,
            algorithm,
            secret,
        } => Some(DnsProviderSettings::Rfc2136(
            Rfc2136DnsSettings::new(
                server
                    .parse::<SocketAddr>()
                    .map_err(|_| CertificateProvisioningError::InvalidInput)?,
                zone,
                key_name,
                match algorithm {
                    ApiTsigAlgorithm::HmacSha256 => DomainTsigAlgorithm::HmacSha256,
                    ApiTsigAlgorithm::HmacSha512 => DomainTsigAlgorithm::HmacSha512,
                },
                secret.into_bytes(),
            )
            .map_err(|_| CertificateProvisioningError::InvalidInput)?,
        )),
        CertificateChallenge::Dns01Cloudflare { zone_id, api_token } => {
            Some(DnsProviderSettings::Cloudflare(
                CloudflareDnsSettings::new(zone_id, api_token.into_bytes())
                    .map_err(|_| CertificateProvisioningError::InvalidInput)?,
            ))
        }
        CertificateChallenge::Dns01Webhook {
            endpoint,
            bearer_token,
        } => Some(DnsProviderSettings::Webhook(
            WebhookDnsSettings::new(endpoint, bearer_token.into_bytes())
                .map_err(|_| CertificateProvisioningError::InvalidInput)?,
        )),
    };
    let encoded = settings
        .map(|value| value.encode())
        .transpose()
        .map_err(|_| CertificateProvisioningError::InvalidInput)?;
    Ok(ChallengeMaterial {
        kind: AcmeChallengeKind::Dns01,
        settings: encoded,
    })
}

fn account_key_generation(
    reference: SecretGenerationReference,
    recipients: &[WrappingPublicKey],
    random: &mut impl RandomSource,
) -> Result<Box<CommitSecretGeneration>, CertificateProvisioningError> {
    let mut plaintext = Zeroizing::new([0_u8; ACCOUNT_KEY_BYTES]);
    for _ in 0..MAXIMUM_ACCOUNT_KEY_ATTEMPTS {
        random
            .fill_bytes(plaintext.as_mut())
            .map_err(|_| CertificateProvisioningError::Unavailable)?;
        if AcmeAccountKey::from_secret_bytes(plaintext.as_ref()).is_ok() {
            return encrypted_generation(
                ACME_ACCOUNT_KEY_SECRET_KIND,
                reference,
                plaintext.as_ref(),
                recipients,
                random,
            )
            .map(Box::new);
        }
    }
    Err(CertificateProvisioningError::Unavailable)
}

fn encrypted_generation(
    kind: u16,
    reference: SecretGenerationReference,
    plaintext: &[u8],
    recipients: &[WrappingPublicKey],
    random: &mut impl RandomSource,
) -> Result<CommitSecretGeneration, CertificateProvisioningError> {
    let context = SecretContext::new(kind, reference.secret_id, reference.generation)
        .map_err(|_| CertificateProvisioningError::Failed)?;
    let (secret, envelopes) = encrypt_secret(context, plaintext, recipients, random)
        .map_err(|_| CertificateProvisioningError::Unavailable)?;
    Ok(CommitSecretGeneration {
        secret: secret.parts(),
        recipients: envelopes.into_iter().map(|value| value.parts()).collect(),
    })
}

fn intent_digest(request: &ProvisionCertificateRequest) -> [u8; 32] {
    let mut digest = Sha256::new();
    field(&mut digest, INTENT_DIGEST_DOMAIN);
    field(&mut digest, request.operation_id.as_str().as_bytes());
    field(&mut digest, request.directory_url.as_bytes());
    for name in &request.certificate_names {
        field(&mut digest, name.as_bytes());
    }
    match &request.challenge {
        CertificateChallenge::Http01 => field(&mut digest, b"http-01"),
        CertificateChallenge::Dns01Manual => field(&mut digest, b"dns-01-manual"),
        CertificateChallenge::Dns01Rfc2136 {
            server,
            zone,
            key_name,
            algorithm,
            secret,
        } => {
            field(&mut digest, b"dns-01-rfc2136");
            field(&mut digest, server.as_bytes());
            field(&mut digest, zone.as_bytes());
            field(&mut digest, key_name.as_bytes());
            field(
                &mut digest,
                match algorithm {
                    ApiTsigAlgorithm::HmacSha256 => b"hmac-sha256",
                    ApiTsigAlgorithm::HmacSha512 => b"hmac-sha512",
                },
            );
            field(&mut digest, secret.as_bytes());
        }
        CertificateChallenge::Dns01Cloudflare { zone_id, api_token } => {
            field(&mut digest, b"dns-01-cloudflare");
            field(&mut digest, zone_id.as_bytes());
            field(&mut digest, api_token.as_bytes());
        }
        CertificateChallenge::Dns01Webhook {
            endpoint,
            bearer_token,
        } => {
            field(&mut digest, b"dns-01-webhook");
            field(&mut digest, endpoint.as_bytes());
            field(&mut digest, bearer_token.as_bytes());
        }
    }
    digest.finalize().into()
}

fn field(digest: &mut Sha256, value: &[u8]) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
}

fn validate_commit(
    commit: &CertificateProvisioningCommit,
    configuration_id: AcmeConfigurationId,
    order_id: CertificateOrderId,
    intent_digest: [u8; 32],
    expected_request_digest: Option<[u8; 32]>,
) -> Result<(), CertificateProvisioningError> {
    if expected_request_digest.is_some_and(|digest| commit.request_digest != digest)
        || commit.request_digest == [0; 32]
        || commit.result_digest == [0; 32]
        || commit.configuration.config_id != configuration_id
        || commit.configuration.provisioning_intent_digest != Some(intent_digest)
        || commit.order.order_id != order_id
        || commit.order.config_id != configuration_id
        || commit.configuration.revision != commit.committed_revision
        || commit.order.revision < commit.committed_revision
    {
        Err(CertificateProvisioningError::Conflict)
    } else {
        Ok(())
    }
}

fn provisioning_response(
    operation_id: meshspan_api_contract::OperationId,
    commit: CertificateProvisioningCommit,
) -> Result<ProvisionCertificateResponse, CertificateProvisioningError> {
    Ok(ProvisionCertificateResponse {
        operation_id,
        configuration_id: meshspan_api_contract::AcmeConfigurationId::from_uuid_bytes(
            commit.configuration.config_id.as_bytes(),
        )
        .ok_or(CertificateProvisioningError::Failed)?,
        order_id: meshspan_api_contract::CertificateOrderId::from_uuid_bytes(
            commit.order.order_id.as_bytes(),
        )
        .ok_or(CertificateProvisioningError::Failed)?,
        certificate_names: commit.configuration.certificate_names,
        revision: commit.committed_revision.get(),
    })
}

fn secret_reference(domain: &[u8], operation_id: OperationId) -> SecretGenerationReference {
    SecretGenerationReference {
        secret_id: derived_bytes(domain, operation_id),
        generation: INITIAL_SECRET_GENERATION,
    }
}

trait DerivedIdentifier: Sized {
    fn from_derived_bytes(bytes: [u8; 16]) -> Result<Self, meshspan_domain::IdentifierError>;
}

impl DerivedIdentifier for AcmeConfigurationId {
    fn from_derived_bytes(bytes: [u8; 16]) -> Result<Self, meshspan_domain::IdentifierError> {
        Self::from_bytes(bytes)
    }
}

impl DerivedIdentifier for CertificateOrderId {
    fn from_derived_bytes(bytes: [u8; 16]) -> Result<Self, meshspan_domain::IdentifierError> {
        Self::from_bytes(bytes)
    }
}

fn derived_id<T: DerivedIdentifier>(
    domain: &[u8],
    operation_id: OperationId,
) -> Result<T, CertificateProvisioningError> {
    T::from_derived_bytes(derived_bytes(domain, operation_id))
        .map_err(|_| CertificateProvisioningError::Failed)
}

fn derived_bytes(domain: &[u8], operation_id: OperationId) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(operation_id.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.finalize()[..16]);
    uuid_v8(bytes)
}

fn domain_operation(
    value: &meshspan_api_contract::OperationId,
) -> Result<OperationId, CertificateProvisioningError> {
    OperationId::from_bytes(
        parse_uuid(value.as_str()).map_err(|_| CertificateProvisioningError::InvalidInput)?,
    )
    .map_err(|_| CertificateProvisioningError::InvalidInput)
}

fn command_context(
    operation_id: OperationId,
    administrator: IdentityAdministrator,
) -> Result<CommandContext, CertificateProvisioningError> {
    let mut digest = Sha256::new();
    digest.update(AUDIT_ID_DOMAIN);
    digest.update(operation_id.as_bytes());
    digest.update(administrator.principal_id.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.finalize()[..16]);
    Ok(CommandContext {
        operation_id,
        actor_principal_id: administrator.principal_id,
        audit_event_id: AuditEventId::from_bytes(uuid_v8(bytes))
            .map_err(|_| CertificateProvisioningError::Failed)?,
        occurred_at: administrator.now,
        expected_revision: None,
    })
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
