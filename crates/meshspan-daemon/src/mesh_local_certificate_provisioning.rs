// SPDX-License-Identifier: GPL-2.0-only

//! Self-contained mesh-local HTTPS authority creation and endpoint issuance.

use axum::http::HeaderMap;
use meshspan_api_contract::{
    CertificateGeneration, ProvisionMeshLocalCertificateRequest,
    ProvisionMeshLocalCertificateResponse,
};
use meshspan_certificates::{
    ExternalCertificateRequestKey, MeshLocalCertificateAuthority, PublicCertificateBundle,
};
use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    AuditEventId, MeshLocalCertificateAuthorityId, MeshLocalCertificateIssuanceId, OperationId,
    PublicCertificateId, RandomSource, Revision, UnixMicros, uuid_v8,
};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, CommitSecretGeneration,
    CreateMeshLocalCertificateAuthority, IssueMeshLocalCertificate,
    MESH_LOCAL_CERTIFICATE_AUTHORITY_KEY_SECRET_KIND, MeshLocalCertificateAuthorityRecord,
    MeshLocalCertificateIssuanceRecord, PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND,
};
use meshspan_secret_envelope::{SecretContext, WrappingPublicKey, encrypt_secret};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::volume_key_loading::load_secret_generation;
use crate::{
    GatewaySessionIdentity, IdentityAdministrator, SecretGenerationAuthority,
    SecretGenerationDecryptor, SecretGenerationLoadingError, SystemManagerAuthenticationError,
    SystemManagerAuthority, authenticate_system_manager,
};

const CA_GENERATION: u64 = 1;
const MICROS_PER_SECOND: i64 = 1_000_000;
const BACKDATE_SECONDS: i64 = 5 * 60;
const CA_LIFETIME_SECONDS: i64 = 10 * 365 * 24 * 60 * 60;
const ENDPOINT_LIFETIME_SECONDS: i64 = 90 * 24 * 60 * 60;
const CA_OPERATION_DOMAIN: &[u8] = b"meshspan.local-ca.operation.v1\0";
const CA_ID_DOMAIN: &[u8] = b"meshspan.local-ca.id.v1\0";
const CA_AUDIT_DOMAIN: &[u8] = b"meshspan.local-ca.audit.v1\0";
const ISSUANCE_ID_DOMAIN: &[u8] = b"meshspan.local-certificate.issuance.v1\0";
const CERTIFICATE_ID_DOMAIN: &[u8] = b"meshspan.local-certificate.id.v1\0";
const ISSUANCE_AUDIT_DOMAIN: &[u8] = b"meshspan.local-certificate.audit.v1\0";

/// Complete durable result of one authority-creation attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeshLocalAuthorityCommit {
    /// Canonical command digest accepted by consensus.
    pub request_digest: [u8; 32],
    /// Non-zero durable result digest.
    pub result_digest: [u8; 32],
    /// Original authoritative revision.
    pub committed_revision: Revision,
    /// Immutable authority record.
    pub authority: MeshLocalCertificateAuthorityRecord,
}

/// Complete durable result of one local certificate issuance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeshLocalCertificateCommit {
    /// Canonical command digest accepted by consensus.
    pub request_digest: [u8; 32],
    /// Non-zero durable result digest.
    pub result_digest: [u8; 32],
    /// Original authoritative revision.
    pub committed_revision: Revision,
    /// Immutable issuance record.
    pub issuance: MeshLocalCertificateIssuanceRecord,
}

/// Replicated reads and mutations needed by mesh-local certificate provisioning.
pub trait MeshLocalCertificateProvisioningAuthority:
    SystemManagerAuthority + SecretGenerationAuthority
{
    /// Returns the one current mesh-local signing authority, if created.
    ///
    /// # Errors
    ///
    /// Fails closed when replicated authority state is unavailable or malformed.
    fn mesh_local_authority(
        &self,
    ) -> Result<Option<MeshLocalCertificateAuthorityRecord>, MeshLocalCertificateAuthorityError>;

    /// Returns the next strictly increasing local endpoint generation.
    ///
    /// # Errors
    ///
    /// Fails closed when the current sequence cannot be read or incremented.
    fn next_mesh_local_generation(&self) -> Result<u64, MeshLocalCertificateAuthorityError>;

    /// Resolves one prior endpoint issuance operation.
    ///
    /// # Errors
    ///
    /// Fails closed when retained operation or issuance evidence is untrustworthy.
    fn resolve_mesh_local_certificate(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<MeshLocalCertificateCommit>, MeshLocalCertificateAuthorityError>;

    /// Returns every current gateway wrapping key plus verified offline recovery.
    ///
    /// # Errors
    ///
    /// Fails closed unless the complete recipient set can be proven.
    fn mesh_local_secret_recipients(
        &self,
    ) -> Result<Vec<WrappingPublicKey>, MeshLocalCertificateAuthorityError>;

    /// Commits or exactly resolves this initial authority creation operation.
    ///
    /// # Errors
    ///
    /// Rejects changed retries and never invents success after an ambiguous result.
    fn commit_or_resolve_mesh_local_authority(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<MeshLocalAuthorityCommit, MeshLocalCertificateAuthorityError>;

    /// Commits or exactly resolves one endpoint issuance through consensus.
    ///
    /// # Errors
    ///
    /// Rejects changed retries and never invents success after an ambiguous result.
    fn commit_or_resolve_mesh_local_certificate(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<MeshLocalCertificateCommit, MeshLocalCertificateAuthorityError>;
}

/// Synchronous controller retained behind the HTTP blocking pool.
pub trait MeshLocalCertificateProvisioningController: Send + 'static {
    /// Authenticates a system manager before request-body consumption.
    ///
    /// # Errors
    ///
    /// Rejects invalid, ambiguous, stale or insufficient credentials.
    fn authenticate(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<IdentityAdministrator, MeshLocalCertificateProvisioningError>;

    /// Creates or reuses the local authority, then issues one encrypted endpoint generation.
    ///
    /// # Errors
    ///
    /// Rejects invalid names, conflicting retries, unavailable authority and malformed evidence.
    fn provision(
        &mut self,
        administrator: IdentityAdministrator,
        request: ProvisionMeshLocalCertificateRequest,
    ) -> Result<ProvisionMeshLocalCertificateResponse, MeshLocalCertificateProvisioningError>;
}

/// In-process local certificate provisioning service.
pub struct MeshLocalCertificateProvisioningService<A, D, R> {
    authority: A,
    decryptor: D,
    gateway: GatewaySessionIdentity,
    random: R,
}

impl<A, D, R> MeshLocalCertificateProvisioningService<A, D, R> {
    /// Binds consensus authority, the node-local key operation and envelope entropy.
    #[must_use]
    pub const fn new(
        authority: A,
        decryptor: D,
        gateway: GatewaySessionIdentity,
        random: R,
    ) -> Self {
        Self {
            authority,
            decryptor,
            gateway,
            random,
        }
    }
}

impl<A, D, R> MeshLocalCertificateProvisioningController
    for MeshLocalCertificateProvisioningService<A, D, R>
where
    A: MeshLocalCertificateProvisioningAuthority + Send + 'static,
    D: SecretGenerationDecryptor + Send + 'static,
    R: RandomSource + Send + 'static,
{
    fn authenticate(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<IdentityAdministrator, MeshLocalCertificateProvisioningError> {
        authenticate_system_manager(&self.authority, self.gateway, headers, now)
            .map_err(map_authentication_error)
    }

    fn provision(
        &mut self,
        administrator: IdentityAdministrator,
        request: ProvisionMeshLocalCertificateRequest,
    ) -> Result<ProvisionMeshLocalCertificateResponse, MeshLocalCertificateProvisioningError> {
        let operation_id = parse_operation_id(&request)?;
        if let Some(commit) = self
            .authority
            .resolve_mesh_local_certificate(operation_id)?
        {
            let authority = self.current_authority()?;
            return response(request, &authority, commit);
        }
        let recipients = self.authority.mesh_local_secret_recipients()?;
        let (authority_record, signer) =
            self.ensure_authority(administrator, operation_id, &recipients)?;
        let generation = self.authority.next_mesh_local_generation()?;
        let prepared = PreparedEndpoint::new(
            request,
            operation_id,
            generation,
            administrator.now,
            &authority_record,
            &signer,
        )?;
        let (context, command) = prepared.command(administrator, &recipients, &mut self.random)?;
        let expected_digest = command.request_digest(context);
        let commit = match self
            .authority
            .commit_or_resolve_mesh_local_certificate(context, &command)
        {
            Ok(commit) if commit.request_digest == expected_digest => commit,
            Ok(_) => return Err(MeshLocalCertificateProvisioningError::Conflict),
            Err(error) => self
                .authority
                .resolve_mesh_local_certificate(operation_id)?
                .ok_or(error)?,
        };
        prepared.response(&authority_record, commit)
    }
}

impl<A, D, R> MeshLocalCertificateProvisioningService<A, D, R>
where
    A: MeshLocalCertificateProvisioningAuthority,
    D: SecretGenerationDecryptor,
    R: RandomSource,
{
    fn current_authority(
        &self,
    ) -> Result<MeshLocalCertificateAuthorityRecord, MeshLocalCertificateProvisioningError> {
        self.authority
            .mesh_local_authority()?
            .ok_or(MeshLocalCertificateProvisioningError::Failed)
    }

    fn ensure_authority(
        &mut self,
        administrator: IdentityAdministrator,
        operation_id: OperationId,
        recipients: &[WrappingPublicKey],
    ) -> Result<
        (
            MeshLocalCertificateAuthorityRecord,
            MeshLocalCertificateAuthority,
        ),
        MeshLocalCertificateProvisioningError,
    > {
        if let Some(record) = self.authority.mesh_local_authority()? {
            let signer = self.load_authority(&record, administrator.now)?;
            return Ok((record, signer));
        }
        let lifetime = Lifetime::at(administrator.now)?;
        let signer = MeshLocalCertificateAuthority::generate(lifetime.start, lifetime.ca_end)
            .map_err(|_| MeshLocalCertificateProvisioningError::Failed)?;
        let authority_id = MeshLocalCertificateAuthorityId::from_bytes(derived_bytes(
            CA_ID_DOMAIN,
            operation_id,
            0,
        ))?;
        let secret_context = SecretContext::new(
            MESH_LOCAL_CERTIFICATE_AUTHORITY_KEY_SECRET_KIND,
            authority_id.as_bytes(),
            CA_GENERATION,
        )
        .map_err(|_| MeshLocalCertificateProvisioningError::Failed)?;
        let (secret, envelopes) = encrypt_secret(
            secret_context,
            signer.private_key_pkcs8(),
            recipients,
            &mut self.random,
        )
        .map_err(|_| MeshLocalCertificateProvisioningError::Unavailable)?;
        let command = AuthoritativeCommand::CreateMeshLocalCertificateAuthority(Box::new(
            CreateMeshLocalCertificateAuthority {
                authority_id,
                generation: CA_GENERATION,
                certificate_der: signer.certificate_der().to_vec(),
                certificate_digest: Sha256::digest(signer.certificate_der()).into(),
                authority_key: Box::new(CommitSecretGeneration {
                    secret: secret.parts(),
                    recipients: envelopes.into_iter().map(|value| value.parts()).collect(),
                }),
                not_before: seconds_to_micros(lifetime.start)?,
                not_after: seconds_to_micros(lifetime.ca_end)?,
            },
        ));
        let context = CommandContext {
            operation_id: OperationId::from_bytes(derived_bytes(
                CA_OPERATION_DOMAIN,
                operation_id,
                0,
            ))?,
            actor_principal_id: administrator.principal_id,
            audit_event_id: AuditEventId::from_bytes(derived_bytes(
                CA_AUDIT_DOMAIN,
                operation_id,
                0,
            ))?,
            occurred_at: administrator.now,
            expected_revision: None,
        };
        let expected_digest = command.request_digest(context);
        let commit = match self
            .authority
            .commit_or_resolve_mesh_local_authority(context, &command)
        {
            Ok(commit) => commit,
            Err(MeshLocalCertificateAuthorityError::Conflict) => {
                let record = self.current_authority()?;
                let winning_signer = self.load_authority(&record, administrator.now)?;
                return Ok((record, winning_signer));
            }
            Err(error) => return Err(error.into()),
        };
        if commit.request_digest == expected_digest
            && commit.authority.authority_id == authority_id
            && commit.authority.certificate_der == signer.certificate_der()
        {
            return Ok((commit.authority, signer));
        }
        let record = commit.authority;
        let winning_signer = self.load_authority(&record, administrator.now)?;
        Ok((record, winning_signer))
    }

    fn load_authority(
        &self,
        record: &MeshLocalCertificateAuthorityRecord,
        now: UnixMicros,
    ) -> Result<MeshLocalCertificateAuthority, MeshLocalCertificateProvisioningError> {
        let context = SecretContext::new(
            MESH_LOCAL_CERTIFICATE_AUTHORITY_KEY_SECRET_KIND,
            record.authority_key.secret_id,
            record.authority_key.generation,
        )
        .map_err(|_| MeshLocalCertificateProvisioningError::Failed)?;
        let key = load_secret_generation(&self.authority, &self.decryptor, context)?;
        MeshLocalCertificateAuthority::from_parts(
            &record.certificate_der,
            key.expose(),
            unix_seconds(now)?,
        )
        .map_err(|_| MeshLocalCertificateProvisioningError::Failed)
    }
}

struct PreparedEndpoint {
    request: ProvisionMeshLocalCertificateRequest,
    operation_id: OperationId,
    issuance_id: MeshLocalCertificateIssuanceId,
    certificate_id: PublicCertificateId,
    generation: u64,
    authority: MeshLocalCertificateAuthorityRecord,
    bundle: PublicCertificateBundle,
    bundle_digest: [u8; 32],
    public_key_fingerprint: [u8; 32],
    not_before: UnixMicros,
    not_after: UnixMicros,
}

impl PreparedEndpoint {
    fn new(
        request: ProvisionMeshLocalCertificateRequest,
        operation_id: OperationId,
        generation: u64,
        now: UnixMicros,
        authority: &MeshLocalCertificateAuthorityRecord,
        signer: &MeshLocalCertificateAuthority,
    ) -> Result<Self, MeshLocalCertificateProvisioningError> {
        let lifetime = Lifetime::at(now)?;
        let key = ExternalCertificateRequestKey::generate()
            .map_err(|_| MeshLocalCertificateProvisioningError::Failed)?;
        let leaf = signer
            .issue_endpoint(
                &request.certificate_names,
                &key,
                lifetime.start,
                lifetime.endpoint_end,
            )
            .map_err(|_| MeshLocalCertificateProvisioningError::InvalidInput)?;
        let public_key_fingerprint = key.public_key_fingerprint();
        let bundle = PublicCertificateBundle::new(
            vec![leaf, authority.certificate_der.clone()],
            key.private_key_pkcs8().to_vec(),
        )
        .map_err(|_| MeshLocalCertificateProvisioningError::Failed)?;
        let bundle_digest = bundle.digest();
        Ok(Self {
            request,
            operation_id,
            issuance_id: MeshLocalCertificateIssuanceId::from_bytes(derived_bytes(
                ISSUANCE_ID_DOMAIN,
                operation_id,
                generation,
            ))?,
            certificate_id: PublicCertificateId::from_bytes(derived_bytes(
                CERTIFICATE_ID_DOMAIN,
                operation_id,
                generation,
            ))?,
            generation,
            authority: authority.clone(),
            bundle,
            bundle_digest,
            public_key_fingerprint,
            not_before: seconds_to_micros(lifetime.start)?,
            not_after: seconds_to_micros(lifetime.endpoint_end)?,
        })
    }

    fn command(
        &self,
        administrator: IdentityAdministrator,
        recipients: &[WrappingPublicKey],
        random: &mut impl RandomSource,
    ) -> Result<(CommandContext, AuthoritativeCommand), MeshLocalCertificateProvisioningError> {
        let secret_context = SecretContext::new(
            PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND,
            self.certificate_id.as_bytes(),
            self.generation,
        )
        .map_err(|_| MeshLocalCertificateProvisioningError::Failed)?;
        let encoded = self
            .bundle
            .encode()
            .map_err(|_| MeshLocalCertificateProvisioningError::Failed)?;
        let (secret, envelopes) = encrypt_secret(secret_context, &encoded, recipients, random)
            .map_err(|_| MeshLocalCertificateProvisioningError::Unavailable)?;
        let command =
            AuthoritativeCommand::IssueMeshLocalCertificate(Box::new(IssueMeshLocalCertificate {
                issuance_id: self.issuance_id,
                authority_id: self.authority.authority_id,
                authority_generation: self.authority.generation,
                authority_certificate_digest: self.authority.certificate_digest,
                certificate_id: self.certificate_id,
                generation: self.generation,
                certificate_names: BoundedItems::new(self.request.certificate_names.clone(), 256)
                    .map_err(|_| {
                    MeshLocalCertificateProvisioningError::InvalidInput
                })?,
                certificate: Box::new(CommitSecretGeneration {
                    secret: secret.parts(),
                    recipients: envelopes.into_iter().map(|value| value.parts()).collect(),
                }),
                bundle_digest: self.bundle_digest,
                public_key_fingerprint: self.public_key_fingerprint,
                not_before: self.not_before,
                not_after: self.not_after,
            }));
        Ok((
            CommandContext {
                operation_id: self.operation_id,
                actor_principal_id: administrator.principal_id,
                audit_event_id: AuditEventId::from_bytes(derived_bytes(
                    ISSUANCE_AUDIT_DOMAIN,
                    self.operation_id,
                    self.generation,
                ))?,
                occurred_at: administrator.now,
                expected_revision: None,
            },
            command,
        ))
    }

    fn response(
        self,
        authority: &MeshLocalCertificateAuthorityRecord,
        commit: MeshLocalCertificateCommit,
    ) -> Result<ProvisionMeshLocalCertificateResponse, MeshLocalCertificateProvisioningError> {
        validate_commit(&self.request, authority, &commit)?;
        response(self.request, authority, commit)
    }
}

#[derive(Clone, Copy)]
struct Lifetime {
    start: u64,
    ca_end: u64,
    endpoint_end: u64,
}

impl Lifetime {
    fn at(now: UnixMicros) -> Result<Self, MeshLocalCertificateProvisioningError> {
        let now_seconds = i64::try_from(unix_seconds(now)?)
            .map_err(|_| MeshLocalCertificateProvisioningError::InvalidInput)?;
        let start = now_seconds
            .checked_sub(BACKDATE_SECONDS)
            .and_then(|value| u64::try_from(value).ok())
            .ok_or(MeshLocalCertificateProvisioningError::InvalidInput)?;
        let ca_end = now_seconds
            .checked_add(CA_LIFETIME_SECONDS)
            .and_then(|value| u64::try_from(value).ok())
            .ok_or(MeshLocalCertificateProvisioningError::InvalidInput)?;
        let endpoint_end = now_seconds
            .checked_add(ENDPOINT_LIFETIME_SECONDS)
            .and_then(|value| u64::try_from(value).ok())
            .ok_or(MeshLocalCertificateProvisioningError::InvalidInput)?;
        Ok(Self {
            start,
            ca_end,
            endpoint_end,
        })
    }
}

fn response(
    request: ProvisionMeshLocalCertificateRequest,
    authority: &MeshLocalCertificateAuthorityRecord,
    commit: MeshLocalCertificateCommit,
) -> Result<ProvisionMeshLocalCertificateResponse, MeshLocalCertificateProvisioningError> {
    validate_commit(&request, authority, &commit)?;
    let issuance = commit.issuance;
    Ok(ProvisionMeshLocalCertificateResponse {
        operation_id: request.operation_id,
        authority_id: meshspan_api_contract::MeshLocalCertificateAuthorityId::from_uuid_bytes(
            authority.authority_id.as_bytes(),
        )
        .ok_or(MeshLocalCertificateProvisioningError::Failed)?,
        issuance_id: meshspan_api_contract::MeshLocalCertificateIssuanceId::from_uuid_bytes(
            issuance.issuance_id.as_bytes(),
        )
        .ok_or(MeshLocalCertificateProvisioningError::Failed)?,
        certificate_id: meshspan_api_contract::PublicCertificateId::from_uuid_bytes(
            issuance.certificate_id.as_bytes(),
        )
        .ok_or(MeshLocalCertificateProvisioningError::Failed)?,
        generation: CertificateGeneration::from_value(issuance.generation)
            .ok_or(MeshLocalCertificateProvisioningError::Failed)?,
        certificate_names: issuance.certificate_names,
        trust_anchor_pem: certificate_pem(&authority.certificate_der),
        public_key_fingerprint: hex_digest(issuance.public_key_fingerprint),
        not_before_epoch_micros: u64::try_from(issuance.not_before.get())
            .map_err(|_| MeshLocalCertificateProvisioningError::Failed)?,
        not_after_epoch_micros: u64::try_from(issuance.not_after.get())
            .map_err(|_| MeshLocalCertificateProvisioningError::Failed)?,
        revision: commit.committed_revision.get(),
    })
}

fn validate_commit(
    request: &ProvisionMeshLocalCertificateRequest,
    authority: &MeshLocalCertificateAuthorityRecord,
    commit: &MeshLocalCertificateCommit,
) -> Result<(), MeshLocalCertificateProvisioningError> {
    let issuance = &commit.issuance;
    if commit.request_digest == [0; 32]
        || commit.result_digest == [0; 32]
        || commit.committed_revision != issuance.revision
        || issuance.authority_id != authority.authority_id
        || issuance.authority_generation != authority.generation
        || issuance.authority_certificate_digest != authority.certificate_digest
        || issuance.certificate_names != request.certificate_names
    {
        Err(MeshLocalCertificateProvisioningError::Conflict)
    } else {
        Ok(())
    }
}

fn parse_operation_id(
    request: &ProvisionMeshLocalCertificateRequest,
) -> Result<OperationId, MeshLocalCertificateProvisioningError> {
    let bytes = crate::create_mesh_setup::parse_uuid(request.operation_id.as_str())
        .map_err(|_| MeshLocalCertificateProvisioningError::InvalidInput)?;
    OperationId::from_bytes(bytes).map_err(Into::into)
}

fn unix_seconds(now: UnixMicros) -> Result<u64, MeshLocalCertificateProvisioningError> {
    u64::try_from(now.get())
        .map(|value| value / u64::try_from(MICROS_PER_SECOND).unwrap_or(1))
        .map_err(|_| MeshLocalCertificateProvisioningError::InvalidInput)
}

fn seconds_to_micros(seconds: u64) -> Result<UnixMicros, MeshLocalCertificateProvisioningError> {
    seconds
        .checked_mul(u64::try_from(MICROS_PER_SECOND).unwrap_or(1))
        .and_then(|value| i64::try_from(value).ok())
        .map(UnixMicros::new)
        .ok_or(MeshLocalCertificateProvisioningError::InvalidInput)
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

fn certificate_pem(der: &[u8]) -> String {
    let encoded = base64(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = Vec::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let value = u32::from(chunk[0]) << 16
            | u32::from(*chunk.get(1).unwrap_or(&0)) << 8
            | u32::from(*chunk.get(2).unwrap_or(&0));
        encoded.push(ALPHABET[((value >> 18) & 63) as usize]);
        encoded.push(ALPHABET[((value >> 12) & 63) as usize]);
        encoded.push(if chunk.len() > 1 {
            ALPHABET[((value >> 6) & 63) as usize]
        } else {
            b'='
        });
        encoded.push(if chunk.len() > 2 {
            ALPHABET[(value & 63) as usize]
        } else {
            b'='
        });
    }
    String::from_utf8(encoded).unwrap_or_default()
}

fn hex_digest(digest: [u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut value = String::with_capacity(64);
    for byte in digest {
        let _ = write!(value, "{byte:02x}");
    }
    value
}

const fn map_authentication_error(
    error: SystemManagerAuthenticationError,
) -> MeshLocalCertificateProvisioningError {
    match error {
        SystemManagerAuthenticationError::Rejected => {
            MeshLocalCertificateProvisioningError::Unauthenticated
        }
        SystemManagerAuthenticationError::Forbidden => {
            MeshLocalCertificateProvisioningError::Forbidden
        }
        SystemManagerAuthenticationError::Unavailable => {
            MeshLocalCertificateProvisioningError::Unavailable
        }
        SystemManagerAuthenticationError::Failed => MeshLocalCertificateProvisioningError::Failed,
    }
}

/// Closed replicated-authority failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MeshLocalCertificateAuthorityError {
    /// Current authority cannot safely answer or commit.
    #[error("mesh-local certificate authority is unavailable")]
    Unavailable,
    /// Existing durable operation state contradicts this request.
    #[error("mesh-local certificate authority conflicts with the request")]
    Conflict,
    /// Authority evidence failed closed.
    #[error("mesh-local certificate authority failed closed")]
    Failed,
}

/// Closed public provisioning failure without private material detail.
#[derive(Debug, Error, PartialEq)]
pub enum MeshLocalCertificateProvisioningError {
    /// Request identity, names or time is invalid.
    #[error("mesh-local certificate request is invalid")]
    InvalidInput,
    /// Authentication was rejected.
    #[error("mesh-local certificate authentication was rejected")]
    Unauthenticated,
    /// Current principal lacks system-manager authority.
    #[error("mesh-local certificate provisioning requires system-manager authority")]
    Forbidden,
    /// Authority or protected secret access is temporarily unavailable.
    #[error("mesh-local certificate provisioning is unavailable")]
    Unavailable,
    /// Durable state conflicts with this exact request.
    #[error("mesh-local certificate provisioning conflicts with current state")]
    Conflict,
    /// Cryptographic or durable evidence failed closed.
    #[error("mesh-local certificate provisioning failed closed")]
    Failed,
    /// Derived durable identity was invalid.
    #[error("mesh-local certificate identity failed")]
    Identifier(#[from] meshspan_domain::IdentifierError),
}

impl From<MeshLocalCertificateAuthorityError> for MeshLocalCertificateProvisioningError {
    fn from(error: MeshLocalCertificateAuthorityError) -> Self {
        match error {
            MeshLocalCertificateAuthorityError::Unavailable => Self::Unavailable,
            MeshLocalCertificateAuthorityError::Conflict => Self::Conflict,
            MeshLocalCertificateAuthorityError::Failed => Self::Failed,
        }
    }
}

impl From<SecretGenerationLoadingError> for MeshLocalCertificateProvisioningError {
    fn from(error: SecretGenerationLoadingError) -> Self {
        match error {
            SecretGenerationLoadingError::Unavailable => Self::Unavailable,
            SecretGenerationLoadingError::NotFound
            | SecretGenerationLoadingError::NotRecipient
            | SecretGenerationLoadingError::Failed => Self::Failed,
        }
    }
}
