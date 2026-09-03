// SPDX-License-Identifier: GPL-2.0-only

//! API-key-only publication of externally issued public certificates.

use std::sync::Arc;
use std::time::Duration;

use axum::http::HeaderMap;
use axum::http::header::{AUTHORIZATION, COOKIE};
use meshspan_api_contract::{
    CertificateGeneration, PublishExternalCertificateRequest, PublishExternalCertificateResponse,
};
use meshspan_certificates::{
    ExternalCertificateRequestKey, PublicCertificateBundle, validate_external_certificate_response,
};
use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    AuditEventId, ExternalCertificatePublicationId, OperationId, PrincipalId, PublicCertificateId,
    RandomSource, UnixMicros, uuid_v8,
};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, CommitSecretGeneration,
    ExternalCertificatePublicationRecord, PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND,
    PublishExternalCertificate,
};
use meshspan_secret_envelope::{SecretContext, WrappingPublicKey, encrypt_secret};
use rustls::RootCertStore;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::ServerCertVerifier as _;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::sign::CertifiedKey;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    FileApiAuthenticationError, GatewaySessionIdentity, IdentityAdministrator,
    NativeApiKeyAuthenticator, NativeApiKeyAuthority,
};

const PUBLICATION_ID_DOMAIN: &[u8] = b"meshspan.external-certificate.publication-id.v1\0";
const CERTIFICATE_ID_DOMAIN: &[u8] = b"meshspan.external-certificate.certificate-id.v1\0";
const AUDIT_ID_DOMAIN: &[u8] = b"meshspan.external-certificate.audit-id.v1\0";
const CHAIN_DIGEST_DOMAIN: &[u8] = b"meshspan.external-certificate.chain.v1\0";
const MICROS_PER_SECOND: u64 = 1_000_000;
const WILDCARD_VALIDATION_LABEL: &str = "meshspan-validation";

/// Exact durable evidence returned for one external certificate publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalCertificatePublisherCommit {
    /// Canonical encrypted command digest accepted by consensus.
    pub request_digest: [u8; 32],
    /// Non-zero durable result digest.
    pub result_digest: [u8; 32],
    /// Original authoritative revision created by the publication.
    pub committed_revision: meshspan_domain::Revision,
    /// Immutable committed publication.
    pub publication: ExternalCertificatePublicationRecord,
}

/// Replicated reads and consensus mutation needed by an external certificate publisher.
pub trait ExternalCertificatePublisherAuthority: NativeApiKeyAuthority {
    /// Reports current system-manager authority.
    ///
    /// # Errors
    ///
    /// Fails closed when current role evidence is unavailable or malformed.
    fn is_system_manager(
        &self,
        principal_id: PrincipalId,
        now: UnixMicros,
    ) -> Result<bool, ExternalCertificatePublisherAuthorityError>;

    /// Resolves one prior publication operation.
    ///
    /// # Errors
    ///
    /// Fails closed when retained operation or publication evidence cannot be trusted.
    fn resolve_external_certificate_publication(
        &self,
        operation_id: OperationId,
    ) -> Result<
        Option<ExternalCertificatePublisherCommit>,
        ExternalCertificatePublisherAuthorityError,
    >;

    /// Returns every current gateway wrapping key plus verified offline recovery.
    ///
    /// # Errors
    ///
    /// Fails closed unless the complete current recipient set is available.
    fn certificate_secret_recipients(
        &self,
    ) -> Result<Vec<WrappingPublicKey>, ExternalCertificatePublisherAuthorityError>;

    /// Commits or exactly resolves one external certificate publication through consensus.
    ///
    /// # Errors
    ///
    /// Never reports success without exact durable publication evidence.
    fn commit_or_resolve_external_certificate_publication(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<ExternalCertificatePublisherCommit, ExternalCertificatePublisherAuthorityError>;
}

/// Synchronous controller retained behind the bounded HTTP blocking pool.
pub trait ExternalCertificatePublisherController: Send + 'static {
    /// Authenticates an API key before the HTTP boundary consumes a request body.
    ///
    /// # Errors
    ///
    /// Rejects missing, ambiguous, stale or insufficient credentials and unavailable authority.
    fn authenticate(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<IdentityAdministrator, ExternalCertificatePublisherError>;

    /// Validates, encrypts and atomically publishes one external certificate generation.
    ///
    /// # Errors
    ///
    /// Rejects malformed certificates, changed retries and unavailable or corrupt authority.
    fn publish(
        &mut self,
        administrator: IdentityAdministrator,
        request: PublishExternalCertificateRequest,
    ) -> Result<PublishExternalCertificateResponse, ExternalCertificatePublisherError>;
}

/// Complete external certificate publisher application service.
pub struct ExternalCertificatePublisherService<A, R> {
    authority: A,
    gateway: GatewaySessionIdentity,
    random: R,
}

impl<A, R> ExternalCertificatePublisherService<A, R> {
    /// Binds API-key authentication, consensus authority and cryptographic entropy.
    #[must_use]
    pub const fn new(authority: A, gateway: GatewaySessionIdentity, random: R) -> Self {
        Self {
            authority,
            gateway,
            random,
        }
    }
}

impl<A, R> ExternalCertificatePublisherController for ExternalCertificatePublisherService<A, R>
where
    A: ExternalCertificatePublisherAuthority + Send + 'static,
    R: RandomSource + Send + 'static,
{
    fn authenticate(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<IdentityAdministrator, ExternalCertificatePublisherError> {
        if !headers.contains_key(AUTHORIZATION) || headers.contains_key(COOKIE) {
            return Err(ExternalCertificatePublisherError::Unauthenticated);
        }
        let principal_id = NativeApiKeyAuthenticator::new(&self.authority, self.gateway)
            .authenticate_principal(headers, now)
            .map_err(map_authentication_error)?;
        self.authority
            .is_system_manager(principal_id, now)?
            .then_some(IdentityAdministrator { principal_id, now })
            .ok_or(ExternalCertificatePublisherError::Forbidden)
    }

    fn publish(
        &mut self,
        administrator: IdentityAdministrator,
        request: PublishExternalCertificateRequest,
    ) -> Result<PublishExternalCertificateResponse, ExternalCertificatePublisherError> {
        let prepared = PreparedPublication::from_request(request, administrator.now)?;
        if let Some(commit) = self
            .authority
            .resolve_external_certificate_publication(prepared.operation_id)?
        {
            return prepared.response(&commit);
        }
        let recipients = self.authority.certificate_secret_recipients()?;
        let (context, command) = prepared.command(administrator, &recipients, &mut self.random)?;
        let expected_digest = command.request_digest(context);
        let commit = match self
            .authority
            .commit_or_resolve_external_certificate_publication(context, &command)
        {
            Ok(commit) => {
                if commit.request_digest != expected_digest {
                    return Err(ExternalCertificatePublisherError::Conflict);
                }
                commit
            }
            Err(error) => match self
                .authority
                .resolve_external_certificate_publication(prepared.operation_id)?
            {
                Some(commit) => commit,
                None => return Err(error.into()),
            },
        };
        prepared.response(&commit)
    }
}

struct PreparedPublication {
    operation_id: OperationId,
    publication_id: ExternalCertificatePublicationId,
    certificate_id: PublicCertificateId,
    generation: u64,
    certificate_names: Vec<String>,
    bundle: PublicCertificateBundle,
    bundle_digest: [u8; 32],
    chain_digest: [u8; 32],
    public_key_fingerprint: [u8; 32],
    not_before: UnixMicros,
    not_after: UnixMicros,
}

impl PreparedPublication {
    fn from_request(
        request: PublishExternalCertificateRequest,
        now: UnixMicros,
    ) -> Result<Self, ExternalCertificatePublisherError> {
        let operation_bytes = crate::create_mesh_setup::parse_uuid(request.operation_id.as_str())
            .map_err(|_| ExternalCertificatePublisherError::InvalidInput)?;
        let operation_id = OperationId::from_bytes(operation_bytes)?;
        let generation = request
            .generation
            .value()
            .ok_or(ExternalCertificatePublisherError::InvalidInput)?;
        let key_pem = request.private_key_pkcs8_pem.into_zeroizing();
        let key = ExternalCertificateRequestKey::from_pkcs8_pem(&key_pem)
            .map_err(|_| ExternalCertificatePublisherError::InvalidInput)?;
        let now_seconds = unix_seconds(now)?;
        let validated = validate_external_certificate_response(
            request.certificate_chain_pem.as_bytes(),
            &request.certificate_names,
            &key,
            now_seconds,
        )
        .map_err(|_| ExternalCertificatePublisherError::InvalidInput)?;
        verify_submitted_chain(validated.bundle(), &request.certificate_names, now_seconds)?;
        let bundle_digest = validated.bundle().digest();
        let chain_digest = certificate_chain_digest(validated.bundle().certificate_chain());
        let public_key_fingerprint = key.public_key_fingerprint();
        let not_before = unix_micros(validated.not_before_unix_seconds())?;
        let not_after = unix_micros(validated.not_after_unix_seconds())?;
        Ok(Self {
            operation_id,
            publication_id: derived_id(PUBLICATION_ID_DOMAIN, operation_id, generation)?,
            certificate_id: derived_id(CERTIFICATE_ID_DOMAIN, operation_id, generation)?,
            generation,
            certificate_names: request.certificate_names,
            bundle: validated.into_bundle(),
            bundle_digest,
            chain_digest,
            public_key_fingerprint,
            not_before,
            not_after,
        })
    }

    fn command(
        &self,
        administrator: IdentityAdministrator,
        recipients: &[WrappingPublicKey],
        random: &mut impl RandomSource,
    ) -> Result<(CommandContext, AuthoritativeCommand), ExternalCertificatePublisherError> {
        let plaintext = self
            .bundle
            .encode()
            .map_err(|_| ExternalCertificatePublisherError::Failed)?;
        let context = SecretContext::new(
            PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND,
            self.certificate_id.as_bytes(),
            self.generation,
        )
        .map_err(|_| ExternalCertificatePublisherError::Failed)?;
        let (secret, envelopes) = encrypt_secret(context, &plaintext, recipients, random)
            .map_err(|_| ExternalCertificatePublisherError::Unavailable)?;
        let command = AuthoritativeCommand::PublishExternalCertificate(Box::new(
            PublishExternalCertificate {
                publication_id: self.publication_id,
                certificate_id: self.certificate_id,
                generation: self.generation,
                certificate_names: BoundedItems::new(self.certificate_names.clone(), 256)
                    .map_err(|_| ExternalCertificatePublisherError::InvalidInput)?,
                certificate: Box::new(CommitSecretGeneration {
                    secret: secret.parts(),
                    recipients: envelopes.into_iter().map(|value| value.parts()).collect(),
                }),
                bundle_digest: self.bundle_digest,
                chain_digest: self.chain_digest,
                public_key_fingerprint: self.public_key_fingerprint,
                not_before: self.not_before,
                not_after: self.not_after,
            },
        ));
        let command_context = CommandContext {
            operation_id: self.operation_id,
            actor_principal_id: administrator.principal_id,
            audit_event_id: AuditEventId::from_bytes(derived_bytes(
                AUDIT_ID_DOMAIN,
                self.operation_id,
                self.generation,
            ))?,
            occurred_at: administrator.now,
            expected_revision: None,
        };
        Ok((command_context, command))
    }

    fn response(
        &self,
        commit: &ExternalCertificatePublisherCommit,
    ) -> Result<PublishExternalCertificateResponse, ExternalCertificatePublisherError> {
        validate_commit(self, commit)?;
        Ok(PublishExternalCertificateResponse {
            operation_id: meshspan_api_contract::OperationId::from_uuid_bytes(
                self.operation_id.as_bytes(),
            )
            .ok_or(ExternalCertificatePublisherError::Failed)?,
            publication_id:
                meshspan_api_contract::ExternalCertificatePublicationId::from_uuid_bytes(
                    self.publication_id.as_bytes(),
                )
                .ok_or(ExternalCertificatePublisherError::Failed)?,
            certificate_id: meshspan_api_contract::PublicCertificateId::from_uuid_bytes(
                self.certificate_id.as_bytes(),
            )
            .ok_or(ExternalCertificatePublisherError::Failed)?,
            generation: CertificateGeneration::from_value(self.generation)
                .ok_or(ExternalCertificatePublisherError::Failed)?,
            certificate_names: self.certificate_names.clone(),
            public_key_fingerprint: hex_digest(self.public_key_fingerprint),
            not_before_epoch_micros: u64::try_from(self.not_before.get())
                .map_err(|_| ExternalCertificatePublisherError::Failed)?,
            not_after_epoch_micros: u64::try_from(self.not_after.get())
                .map_err(|_| ExternalCertificatePublisherError::Failed)?,
            revision: commit.committed_revision.get(),
        })
    }
}

fn validate_commit(
    prepared: &PreparedPublication,
    commit: &ExternalCertificatePublisherCommit,
) -> Result<(), ExternalCertificatePublisherError> {
    let record = &commit.publication;
    if commit.request_digest == [0; 32]
        || commit.result_digest == [0; 32]
        || commit.committed_revision != record.revision
        || record.publication_id != prepared.publication_id
        || record.certificate_id != prepared.certificate_id
        || record.generation != prepared.generation
        || record.certificate_names != prepared.certificate_names
        || record.bundle_digest != prepared.bundle_digest
        || record.chain_digest != prepared.chain_digest
        || record.public_key_fingerprint != prepared.public_key_fingerprint
        || record.not_before != prepared.not_before
        || record.not_after != prepared.not_after
    {
        Err(ExternalCertificatePublisherError::Conflict)
    } else {
        Ok(())
    }
}

fn verify_submitted_chain(
    bundle: &PublicCertificateBundle,
    names: &[String],
    now_seconds: u64,
) -> Result<(), ExternalCertificatePublisherError> {
    CertifiedKey::from_der(
        bundle
            .certificate_chain()
            .iter()
            .cloned()
            .map(CertificateDer::from)
            .collect(),
        PrivatePkcs8KeyDer::from(bundle.private_key_pkcs8().to_vec()).into(),
        &meshspan_rustls_provider::provider(),
    )
    .map_err(|_| ExternalCertificatePublisherError::InvalidInput)?;
    let (leaf, remaining) = bundle
        .certificate_chain()
        .split_first()
        .ok_or(ExternalCertificatePublisherError::InvalidInput)?;
    let (root, intermediates) = remaining
        .split_last()
        .ok_or(ExternalCertificatePublisherError::InvalidInput)?;
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(root.clone()))
        .map_err(|_| ExternalCertificatePublisherError::InvalidInput)?;
    let verifier = WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(meshspan_rustls_provider::provider()),
    )
    .build()
    .map_err(|_| ExternalCertificatePublisherError::InvalidInput)?;
    let intermediates = intermediates
        .iter()
        .cloned()
        .map(CertificateDer::from)
        .collect::<Vec<_>>();
    let now = UnixTime::since_unix_epoch(Duration::from_secs(now_seconds));
    for name in names {
        let validation_name = name.strip_prefix("*.").map_or_else(
            || name.clone(),
            |suffix| format!("{WILDCARD_VALIDATION_LABEL}.{suffix}"),
        );
        let server_name = ServerName::try_from(validation_name)
            .map_err(|_| ExternalCertificatePublisherError::InvalidInput)?;
        verifier
            .verify_server_cert(
                &CertificateDer::from(leaf.as_slice()),
                &intermediates,
                &server_name,
                &[],
                now,
            )
            .map_err(|_| ExternalCertificatePublisherError::InvalidInput)?;
    }
    Ok(())
}

fn certificate_chain_digest(chain: &[Vec<u8>]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(CHAIN_DIGEST_DOMAIN);
    digest.update(chain.len().to_be_bytes());
    for certificate in chain {
        digest.update(certificate.len().to_be_bytes());
        digest.update(certificate);
    }
    digest.finalize().into()
}

fn derived_id<T>(
    domain: &[u8],
    operation_id: OperationId,
    generation: u64,
) -> Result<T, meshspan_domain::IdentifierError>
where
    T: FromDerivedIdentifier,
{
    T::from_derived(derived_bytes(domain, operation_id, generation))
}

trait FromDerivedIdentifier: Sized {
    fn from_derived(bytes: [u8; 16]) -> Result<Self, meshspan_domain::IdentifierError>;
}

impl FromDerivedIdentifier for ExternalCertificatePublicationId {
    fn from_derived(bytes: [u8; 16]) -> Result<Self, meshspan_domain::IdentifierError> {
        Self::from_bytes(bytes)
    }
}

impl FromDerivedIdentifier for PublicCertificateId {
    fn from_derived(bytes: [u8; 16]) -> Result<Self, meshspan_domain::IdentifierError> {
        Self::from_bytes(bytes)
    }
}

fn derived_bytes(domain: &[u8], operation_id: OperationId, generation: u64) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(operation_id.as_bytes());
    digest.update(generation.to_be_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.finalize()[..16]);
    uuid_v8(bytes)
}

fn unix_seconds(now: UnixMicros) -> Result<u64, ExternalCertificatePublisherError> {
    let micros =
        u64::try_from(now.get()).map_err(|_| ExternalCertificatePublisherError::InvalidInput)?;
    Ok(micros / MICROS_PER_SECOND)
}

fn unix_micros(seconds: u64) -> Result<UnixMicros, ExternalCertificatePublisherError> {
    seconds
        .checked_mul(MICROS_PER_SECOND)
        .and_then(|value| i64::try_from(value).ok())
        .map(UnixMicros::new)
        .ok_or(ExternalCertificatePublisherError::InvalidInput)
}

fn hex_digest(digest: [u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut value = String::with_capacity(64);
    for byte in digest {
        let _ = write!(value, "{byte:02x}");
    }
    value
}

fn map_authentication_error(
    error: FileApiAuthenticationError,
) -> ExternalCertificatePublisherError {
    match error {
        FileApiAuthenticationError::Rejected => ExternalCertificatePublisherError::Unauthenticated,
        FileApiAuthenticationError::AuthorityUnavailable => {
            ExternalCertificatePublisherError::Unavailable
        }
        FileApiAuthenticationError::InvalidGateway
        | FileApiAuthenticationError::AuthorityFailed => ExternalCertificatePublisherError::Failed,
    }
}

/// Closed external certificate publisher authority failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ExternalCertificatePublisherAuthorityError {
    /// Current consensus authority cannot safely answer or commit.
    #[error("external certificate publisher authority is unavailable")]
    Unavailable,
    /// Existing durable operation state contradicts this request.
    #[error("external certificate publisher authority conflicts with the request")]
    Conflict,
    /// Authority evidence was malformed or violated the contract.
    #[error("external certificate publisher authority failed closed")]
    Failed,
}

/// Closed external certificate publication failure without certificate or key detail.
#[derive(Debug, Error)]
pub enum ExternalCertificatePublisherError {
    /// Request identity, generation, names, key, chain or lifetime is invalid.
    #[error("external certificate publication input is invalid")]
    InvalidInput,
    /// API-key authentication was rejected.
    #[error("external certificate publisher authentication was rejected")]
    Unauthenticated,
    /// Current principal lacks system-manager authority.
    #[error("external certificate publisher requires system-manager authority")]
    Forbidden,
    /// Current authority is temporarily unavailable.
    #[error("external certificate publisher is unavailable")]
    Unavailable,
    /// Durable operation state conflicts with this request.
    #[error("external certificate publication conflicts with current state")]
    Conflict,
    /// Cryptographic or durable evidence failed closed.
    #[error("external certificate publication failed closed")]
    Failed,
    /// Derived durable identity was invalid.
    #[error("external certificate publication identity failed")]
    Identifier(#[from] meshspan_domain::IdentifierError),
}

impl From<ExternalCertificatePublisherAuthorityError> for ExternalCertificatePublisherError {
    fn from(error: ExternalCertificatePublisherAuthorityError) -> Self {
        match error {
            ExternalCertificatePublisherAuthorityError::Unavailable => Self::Unavailable,
            ExternalCertificatePublisherAuthorityError::Conflict => Self::Conflict,
            ExternalCertificatePublisherAuthorityError::Failed => Self::Failed,
        }
    }
}
