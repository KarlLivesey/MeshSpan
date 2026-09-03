// SPDX-License-Identifier: GPL-2.0-only

//! Protected key loading and restart-safe state-machine preparation for one claimed ACME order.

use meshspan_acme::{AcmeAccountKey, AcmeChallengePreference, AcmeOrderMachine, AcmeOrderRequest};
use meshspan_certificates::ExternalCertificateRequestKey;
use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_domain::{
    AuditEventId, EntropyError, OperationId, PrincipalId, RandomSource, Revision, UnixMicros,
    uuid_v8,
};
use meshspan_metadata::{
    ACME_ACCOUNT_KEY_SECRET_KIND, ACME_CHALLENGE_SETTINGS_SECRET_KIND, AuthoritativeCommand,
    CommandContext, CommandReceipt, CommitSecretGeneration, EntityKind,
    PUBLIC_CERTIFICATE_REQUEST_KEY_SECRET_KIND, RepositoryError, SecretGenerationReference,
};
use meshspan_secret_envelope::{SecretContext, SecretPlaintext, WrappingPublicKey, encrypt_secret};
use thiserror::Error;

use crate::volume_key_loading::load_secret_generation;
use crate::{
    CertificateOrderAssignment, ConsensusAuthenticationAuthority, SecretGenerationAuthority,
    SecretGenerationDecryptor, SecretGenerationLoadingError,
};

const LEAF_KEY_GENERATION: u64 = 1;

/// Secret reads and mutations required before an ACME machine can run.
pub trait CertificateOrderPreparationAuthority: SecretGenerationAuthority {
    /// Returns every active gateway wrapping key plus verified offline recovery.
    ///
    /// # Errors
    ///
    /// Fails closed unless the complete current recipient set can be proven.
    fn certificate_key_recipients(
        &self,
    ) -> Result<Vec<WrappingPublicKey>, CertificateOrderPreparationAuthorityError>;

    /// Resolves a previous encrypted leaf-key generation submission.
    ///
    /// # Errors
    ///
    /// Fails closed when retained operation evidence cannot be trusted.
    fn resolve_certificate_key_commit(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<CommandReceipt>, CertificateOrderPreparationAuthorityError>;

    /// Commits or exactly resolves one encrypted leaf-key generation.
    ///
    /// # Errors
    ///
    /// Never reports success without an exact durable receipt.
    fn commit_certificate_key(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, CertificateOrderPreparationAuthorityError>;
}

impl CertificateOrderPreparationAuthority for ConsensusAuthenticationAuthority {
    fn certificate_key_recipients(
        &self,
    ) -> Result<Vec<WrappingPublicKey>, CertificateOrderPreparationAuthorityError> {
        self.reader()
            .volume_key_recipients()
            .map_err(|error| map_repository_error(&error))
    }

    fn resolve_certificate_key_commit(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<CommandReceipt>, CertificateOrderPreparationAuthorityError> {
        self.reader()
            .resolve_operation(operation_id)
            .map_err(|error| map_repository_error(&error))
    }

    fn commit_certificate_key(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, CertificateOrderPreparationAuthorityError> {
        self.commit_authoritative(context, command)
            .map_err(map_authority_error)
    }
}

/// Protected executable inputs for one claimed order.
pub struct PreparedCertificateOrder {
    /// Exact durable assignment and any prior checkpoint evidence.
    pub assignment: CertificateOrderAssignment,
    /// Fresh or resumed pure order state machine.
    pub machine: AcmeOrderMachine,
    /// Decrypted account signing capability, never printable or exportable.
    pub account_key: AcmeAccountKey,
    /// Decrypted automatic DNS provider settings, absent for HTTP-01 and manual DNS-01.
    pub challenge_settings: Option<SecretPlaintext>,
    /// Order-bound leaf key retained for CSR and final bundle construction.
    pub certificate_key: ExternalCertificateRequestKey,
    /// Exact DER PKCS#10 request bound to the immutable configured names.
    pub csr_der: Vec<u8>,
    /// Deterministic encrypted-secret reference shared by replacement workers.
    pub certificate_key_reference: SecretGenerationReference,
}

/// Composes authoritative encrypted secrets with one node-local wrapping key.
pub struct CertificateOrderPreparationService<A, D, R> {
    authority: A,
    decryptor: D,
    random: R,
}

impl<A, D, R> CertificateOrderPreparationService<A, D, R> {
    /// Binds preparation to replicated authority, local key operations and entropy.
    #[must_use]
    pub const fn new(authority: A, decryptor: D, random: R) -> Self {
        Self {
            authority,
            decryptor,
            random,
        }
    }
}

impl<A, D, R> CertificateOrderPreparationService<A, D, R>
where
    A: CertificateOrderPreparationAuthority,
    D: SecretGenerationDecryptor,
    R: RandomSource,
{
    /// Loads shared keys and creates or resumes the exact machine under the current fence.
    ///
    /// # Errors
    ///
    /// Rejects expired or contradictory assignments, unavailable secret access, malformed keys,
    /// substituted checkpoints, entropy failure, unavailable consensus and invalid receipts.
    pub fn prepare(
        &mut self,
        now: UnixMicros,
        assignment: CertificateOrderAssignment,
    ) -> Result<PreparedCertificateOrder, CertificateOrderPreparationError> {
        let claim = validate_assignment(now, &assignment)?;
        let account_key = self.load_account_key(&assignment)?;
        let challenge_settings = self.load_challenge_settings(&assignment)?;
        let certificate_key_reference = SecretGenerationReference {
            secret_id: assignment.order.order_id.as_bytes(),
            generation: LEAF_KEY_GENERATION,
        };
        let certificate_key = self.load_or_create_certificate_key(
            assignment.configuration.configured_by,
            now,
            certificate_key_reference,
        )?;
        let machine = prepare_machine(&assignment, claim.fence, certificate_key_reference)?;
        let csr_der = certificate_key
            .certificate_signing_request(&assignment.configuration.certificate_names)?;
        Ok(PreparedCertificateOrder {
            assignment,
            machine,
            account_key,
            challenge_settings,
            certificate_key,
            csr_der,
            certificate_key_reference,
        })
    }

    fn load_account_key(
        &self,
        assignment: &CertificateOrderAssignment,
    ) -> Result<AcmeAccountKey, CertificateOrderPreparationError> {
        let reference = assignment.configuration.account_key;
        let context = SecretContext::new(
            ACME_ACCOUNT_KEY_SECRET_KIND,
            reference.secret_id,
            reference.generation,
        )
        .map_err(|_| CertificateOrderPreparationError::InvalidInput)?;
        let plaintext = load_secret_generation(&self.authority, &self.decryptor, context)?;
        AcmeAccountKey::from_secret_bytes(plaintext.expose()).map_err(Into::into)
    }

    fn load_challenge_settings(
        &self,
        assignment: &CertificateOrderAssignment,
    ) -> Result<Option<SecretPlaintext>, CertificateOrderPreparationError> {
        let Some(reference) = assignment.configuration.challenge_settings else {
            return Ok(None);
        };
        let context = SecretContext::new(
            ACME_CHALLENGE_SETTINGS_SECRET_KIND,
            reference.secret_id,
            reference.generation,
        )
        .map_err(|_| CertificateOrderPreparationError::InvalidInput)?;
        load_secret_generation(&self.authority, &self.decryptor, context)
            .map(Some)
            .map_err(Into::into)
    }

    fn load_or_create_certificate_key(
        &mut self,
        actor_principal_id: PrincipalId,
        now: UnixMicros,
        reference: SecretGenerationReference,
    ) -> Result<ExternalCertificateRequestKey, CertificateOrderPreparationError> {
        let context = SecretContext::new(
            PUBLIC_CERTIFICATE_REQUEST_KEY_SECRET_KIND,
            reference.secret_id,
            reference.generation,
        )
        .map_err(|_| CertificateOrderPreparationError::InvalidInput)?;
        match load_secret_generation(&self.authority, &self.decryptor, context) {
            Ok(plaintext) => {
                ExternalCertificateRequestKey::from_pkcs8(plaintext.expose()).map_err(Into::into)
            }
            Err(SecretGenerationLoadingError::NotFound) => {
                self.create_certificate_key(actor_principal_id, now, context)
            }
            Err(error) => Err(error.into()),
        }
    }

    fn create_certificate_key(
        &mut self,
        actor_principal_id: PrincipalId,
        now: UnixMicros,
        context: SecretContext,
    ) -> Result<ExternalCertificateRequestKey, CertificateOrderPreparationError> {
        let key = ExternalCertificateRequestKey::generate()?;
        let recipients = self.authority.certificate_key_recipients()?;
        let (secret, envelopes) = encrypt_secret(
            context,
            key.private_key_pkcs8(),
            &recipients,
            &mut self.random,
        )?;
        let command = AuthoritativeCommand::CommitSecretGeneration(CommitSecretGeneration {
            secret: secret.parts(),
            recipients: envelopes
                .iter()
                .map(meshspan_secret_envelope::RecipientKeyEnvelope::parts)
                .collect(),
        });
        let (operation_id, audit_event_id) = random_command_identities(&mut self.random)?;
        let command_context = CommandContext {
            operation_id,
            actor_principal_id,
            audit_event_id,
            occurred_at: now,
            expected_revision: None,
        };
        let expected_digest = command.request_digest(command_context);
        let receipt = match self
            .authority
            .commit_certificate_key(command_context, &command)
        {
            Ok(receipt) => receipt,
            Err(commit_error) => self
                .authority
                .resolve_certificate_key_commit(operation_id)?
                .ok_or(commit_error)?,
        };
        validate_secret_receipt(receipt, operation_id, expected_digest, context.id())?;
        Ok(key)
    }
}

fn validate_assignment(
    now: UnixMicros,
    assignment: &CertificateOrderAssignment,
) -> Result<meshspan_metadata::CertificateOrderClaim, CertificateOrderPreparationError> {
    let claim = assignment
        .order
        .claim
        .ok_or(CertificateOrderPreparationError::InvalidInput)?;
    if assignment.order.state != meshspan_metadata::CertificateOrderState::Claimed
        || assignment.order.config_id != assignment.configuration.config_id
        || claim.generation == 0
        || claim.worker_incarnation == 0
        || claim.fence == 0
        || claim.lease_expires_at <= now
    {
        Err(CertificateOrderPreparationError::InvalidInput)
    } else {
        Ok(claim)
    }
}

fn prepare_machine(
    assignment: &CertificateOrderAssignment,
    fence: u64,
    certificate_key: SecretGenerationReference,
) -> Result<AcmeOrderMachine, CertificateOrderPreparationError> {
    if let Some(checkpoint) = &assignment.checkpoint {
        if checkpoint.order_id != assignment.order.order_id
            || checkpoint.certificate_key != certificate_key
        {
            return Err(CertificateOrderPreparationError::InvalidInput);
        }
        let mut machine = AcmeOrderMachine::decode_checkpoint(&checkpoint.checkpoint)?;
        machine.resume_under_fence(fence)?;
        return Ok(machine);
    }
    let preference = match assignment.configuration.challenge_kind {
        meshspan_metadata::AcmeChallengeKind::Http01 => AcmeChallengePreference::Http01,
        meshspan_metadata::AcmeChallengeKind::Dns01 => AcmeChallengePreference::Dns01,
    };
    Ok(AcmeOrderMachine::new(
        assignment.configuration.directory_url.clone(),
        AcmeOrderRequest::new(assignment.configuration.certificate_names.clone())?,
        preference,
        fence,
    )?)
}

fn random_command_identities(
    random: &mut impl RandomSource,
) -> Result<(OperationId, AuditEventId), CertificateOrderPreparationError> {
    let mut bytes = [0_u8; 32];
    random.fill_bytes(&mut bytes)?;
    let operation = uuid_v8(
        bytes[..16]
            .try_into()
            .map_err(|_| CertificateOrderPreparationError::InvalidInput)?,
    );
    let audit = uuid_v8(
        bytes[16..]
            .try_into()
            .map_err(|_| CertificateOrderPreparationError::InvalidInput)?,
    );
    if operation == audit {
        return Err(CertificateOrderPreparationError::InvalidInput);
    }
    Ok((
        OperationId::from_bytes(operation)
            .map_err(|_| CertificateOrderPreparationError::InvalidInput)?,
        AuditEventId::from_bytes(audit)
            .map_err(|_| CertificateOrderPreparationError::InvalidInput)?,
    ))
}

fn validate_secret_receipt(
    receipt: CommandReceipt,
    operation_id: OperationId,
    expected_request_digest: [u8; 32],
    secret_id: [u8; 16],
) -> Result<(), CertificateOrderPreparationError> {
    if receipt.operation_id != operation_id
        || receipt.request_digest != expected_request_digest
        || receipt.result_digest == [0; 32]
        || receipt.committed_revision == Revision::ZERO
        || receipt.entity.kind != EntityKind::SecretGeneration
        || receipt.entity.id != secret_id
    {
        Err(CertificateOrderPreparationError::Conflict)
    } else {
        Ok(())
    }
}

fn map_repository_error(error: &RepositoryError) -> CertificateOrderPreparationAuthorityError {
    match error {
        RepositoryError::Store(_) | RepositoryError::Sqlite(_) | RepositoryError::Io(_) => {
            CertificateOrderPreparationAuthorityError::Unavailable
        }
        _ => CertificateOrderPreparationAuthorityError::Failed,
    }
}

const fn map_authority_error(
    error: MetadataAuthorityRequestError,
) -> CertificateOrderPreparationAuthorityError {
    match error {
        MetadataAuthorityRequestError::NotLeader { .. }
        | MetadataAuthorityRequestError::Unavailable => {
            CertificateOrderPreparationAuthorityError::Unavailable
        }
        MetadataAuthorityRequestError::Conflict | MetadataAuthorityRequestError::Rejected => {
            CertificateOrderPreparationAuthorityError::Conflict
        }
        MetadataAuthorityRequestError::Unsupported | MetadataAuthorityRequestError::Failed => {
            CertificateOrderPreparationAuthorityError::Failed
        }
    }
}

/// Closed preparation-authority failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CertificateOrderPreparationAuthorityError {
    /// Current authority cannot safely read recipients, resolve or commit.
    #[error("certificate order preparation authority is unavailable")]
    Unavailable,
    /// Durable operation state conflicts with the leaf-key generation.
    #[error("certificate order preparation authority conflicts with the request")]
    Conflict,
    /// Authority evidence is malformed or violated the contract.
    #[error("certificate order preparation authority failed closed")]
    Failed,
}

/// Closed protected ACME preparation failure.
#[derive(Debug, Error)]
pub enum CertificateOrderPreparationError {
    /// Assignment identity, claim, configuration or checkpoint is contradictory.
    #[error("certificate order preparation input is invalid")]
    InvalidInput,
    /// Durable receipt evidence conflicts with the attempted leaf-key generation.
    #[error("certificate order preparation conflicts with durable state")]
    Conflict,
    /// Encrypted secret loading or local recipient decryption failed.
    #[error("certificate order preparation secret loading failed")]
    SecretLoading(#[from] SecretGenerationLoadingError),
    /// ACME account key material is invalid.
    #[error("certificate order preparation account key is invalid")]
    AccountKey(#[from] meshspan_acme::AcmeAccountKeyError),
    /// Leaf-key generation, decoding or CSR construction failed.
    #[error("certificate order preparation leaf key is invalid")]
    Certificate(#[from] meshspan_certificates::CertificateError),
    /// State-machine construction or checkpoint recovery failed.
    #[error("certificate order preparation machine is invalid")]
    Machine(#[from] meshspan_acme::AcmeMachineError),
    /// ACME order request construction failed.
    #[error("certificate order preparation request is invalid")]
    Protocol(#[from] meshspan_acme::AcmeProtocolError),
    /// Per-recipient envelope encryption failed.
    #[error("certificate order preparation envelope failed")]
    Envelope(#[from] meshspan_secret_envelope::SecretEnvelopeError),
    /// Cryptographic command identities could not be generated.
    #[error("certificate order preparation entropy failed")]
    Entropy(#[from] EntropyError),
    /// Consensus-backed secret authority rejected or could not commit.
    #[error("certificate order preparation authority failed")]
    Authority(#[from] CertificateOrderPreparationAuthorityError),
}
