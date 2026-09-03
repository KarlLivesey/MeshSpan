// SPDX-License-Identifier: GPL-2.0-only

//! Atomic fenced publication of one validated public certificate to every gateway recipient.

use meshspan_certificates::PublicCertificateBundle;
use meshspan_domain::{
    AuditEventId, CertificateOrderId, OperationId, PrincipalId, RandomSource, Revision, UnixMicros,
    uuid_v8,
};
use meshspan_metadata::{
    AuthoritativeCommand, CertificateOrderClaim, CertificateOrderCompletion, CommandContext,
    CommandReceipt, CommitSecretGeneration, CompleteCertificateOrder, EntityKind,
    PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND, SecretGenerationReference,
};
use meshspan_secret_envelope::{SecretContext, WrappingPublicKey, encrypt_secret};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

const OPERATION_ID_DOMAIN: &[u8] = b"meshspan.certificate-order-completion.operation.v1\0";
const AUDIT_ID_DOMAIN: &[u8] = b"meshspan.certificate-order-completion.audit.v1\0";
const INITIAL_CERTIFICATE_GENERATION: u64 = 1;

/// Validated issuance inputs retained outside replicated metadata until one atomic completion.
pub struct CertificateOrderIssuance {
    /// Claimed durable order.
    pub order_id: CertificateOrderId,
    /// Exact still-live claim.
    pub claim: CertificateOrderClaim,
    /// Gateway HTTPS certificate chain and matching private key.
    pub bundle: PublicCertificateBundle,
    /// Validated lower certificate validity bound.
    pub not_before: UnixMicros,
    /// Validated upper certificate validity bound.
    pub not_after: UnixMicros,
}

/// Exact committed outcome safe to pass to local installation workers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertificateOrderCompletionCommit {
    /// Immutable encrypted generation stored atomically with order completion.
    pub certificate: SecretGenerationReference,
    /// Digest of the canonical decrypted bundle.
    pub bundle_digest: [u8; 32],
    /// Consensus state revision containing both secret and completion.
    pub revision: Revision,
}

/// Recipient discovery and consensus mutation needed by the fenced order worker.
pub trait CertificateOrderCompletionAuthority {
    /// Resolves a prior completion before generating new encrypted bytes.
    ///
    /// # Errors
    ///
    /// Fails closed when retained operation evidence cannot be trusted.
    fn resolve_certificate_order_completion(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<CommandReceipt>, CertificateOrderCompletionAuthorityError>;

    /// Returns every active gateway wrapping key plus verified offline recovery.
    ///
    /// # Errors
    ///
    /// Fails closed unless the complete current recipient set can be proven.
    fn certificate_recipients(
        &self,
    ) -> Result<Vec<WrappingPublicKey>, CertificateOrderCompletionAuthorityError>;

    /// Commits or exactly resolves the single atomic secret/order command.
    ///
    /// # Errors
    ///
    /// Never reports success without an exact durable receipt.
    fn complete_certificate_order(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, CertificateOrderCompletionAuthorityError>;
}

/// Atomic certificate-order completion application service.
pub struct CertificateOrderCompletionService<A, R> {
    authority: A,
    random: R,
}

impl<A, R> CertificateOrderCompletionService<A, R> {
    /// Binds one authority and cryptographic entropy source.
    #[must_use]
    pub const fn new(authority: A, random: R) -> Self {
        Self { authority, random }
    }
}

impl<A, R> CertificateOrderCompletionService<A, R>
where
    A: CertificateOrderCompletionAuthority,
    R: RandomSource,
{
    /// Encrypts one validated bundle to every gateway and atomically completes its fenced order.
    ///
    /// # Errors
    ///
    /// Rejects invalid claims or validity, missing recipients, entropy failure, conflicting
    /// authority results and any durable receipt that does not exactly describe this command.
    pub fn complete(
        &mut self,
        actor_principal_id: PrincipalId,
        now: UnixMicros,
        issuance: &CertificateOrderIssuance,
    ) -> Result<CertificateOrderCompletionCommit, CertificateOrderCompletionError> {
        validate_issuance(now, issuance)?;
        let bundle_digest = issuance.bundle.digest();
        let reference = SecretGenerationReference {
            secret_id: issuance.order_id.as_bytes(),
            generation: INITIAL_CERTIFICATE_GENERATION,
        };
        let operation_id = derived_id(OPERATION_ID_DOMAIN, issuance, bundle_digest)?;
        if let Some(receipt) = self
            .authority
            .resolve_certificate_order_completion(operation_id)?
        {
            validate_receipt(receipt, operation_id, None, issuance.order_id)?;
            return Ok(CertificateOrderCompletionCommit {
                certificate: reference,
                bundle_digest,
                revision: receipt.committed_revision,
            });
        }
        let recipients = self.authority.certificate_recipients()?;
        let context = SecretContext::new(
            PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND,
            reference.secret_id,
            reference.generation,
        )
        .map_err(|_| CertificateOrderCompletionError::Failed)?;
        let plaintext = issuance.bundle.encode()?;
        let (secret, envelopes) =
            encrypt_secret(context, &plaintext, &recipients, &mut self.random)?;
        let command = AuthoritativeCommand::CompleteCertificateOrder(CompleteCertificateOrder {
            order_id: issuance.order_id,
            claim_generation: issuance.claim.generation,
            worker_node_id: issuance.claim.worker_node_id,
            worker_incarnation: issuance.claim.worker_incarnation,
            fence: issuance.claim.fence,
            outcome: CertificateOrderCompletion::Issued {
                certificate: Box::new(CommitSecretGeneration {
                    secret: secret.parts(),
                    recipients: envelopes
                        .iter()
                        .map(meshspan_secret_envelope::RecipientKeyEnvelope::parts)
                        .collect(),
                }),
                not_before: issuance.not_before,
                not_after: issuance.not_after,
                result_digest: bundle_digest,
            },
        });
        let command_context = CommandContext {
            operation_id,
            actor_principal_id,
            audit_event_id: AuditEventId::from_bytes(derived_id_bytes(
                AUDIT_ID_DOMAIN,
                issuance,
                bundle_digest,
            )?)?,
            occurred_at: now,
            expected_revision: None,
        };
        let expected_digest = command.request_digest(command_context);
        let receipt = self
            .authority
            .complete_certificate_order(command_context, &command)?;
        validate_receipt(
            receipt,
            operation_id,
            Some(expected_digest),
            issuance.order_id,
        )?;
        Ok(CertificateOrderCompletionCommit {
            certificate: reference,
            bundle_digest,
            revision: receipt.committed_revision,
        })
    }
}

fn validate_issuance(
    now: UnixMicros,
    issuance: &CertificateOrderIssuance,
) -> Result<(), CertificateOrderCompletionError> {
    if issuance.claim.generation == 0
        || issuance.claim.worker_incarnation == 0
        || issuance.claim.fence == 0
        || issuance.claim.lease_expires_at <= now
        || issuance.not_after <= issuance.not_before
        || issuance.not_after <= now
    {
        Err(CertificateOrderCompletionError::InvalidInput)
    } else {
        Ok(())
    }
}

fn validate_receipt(
    receipt: CommandReceipt,
    operation_id: OperationId,
    expected_request_digest: Option<[u8; 32]>,
    order_id: CertificateOrderId,
) -> Result<(), CertificateOrderCompletionError> {
    if receipt.operation_id != operation_id
        || expected_request_digest.is_some_and(|digest| receipt.request_digest != digest)
        || receipt.request_digest == [0; 32]
        || receipt.result_digest == [0; 32]
        || receipt.committed_revision == Revision::ZERO
        || receipt.entity.kind != EntityKind::CertificateOrder
        || receipt.entity.id != order_id.as_bytes()
    {
        Err(CertificateOrderCompletionError::Conflict)
    } else {
        Ok(())
    }
}

fn derived_id(
    domain: &[u8],
    issuance: &CertificateOrderIssuance,
    bundle_digest: [u8; 32],
) -> Result<OperationId, CertificateOrderCompletionError> {
    OperationId::from_bytes(derived_id_bytes(domain, issuance, bundle_digest)?)
        .map_err(CertificateOrderCompletionError::from)
}

fn derived_id_bytes(
    domain: &[u8],
    issuance: &CertificateOrderIssuance,
    bundle_digest: [u8; 32],
) -> Result<[u8; 16], CertificateOrderCompletionError> {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(issuance.order_id.as_bytes());
    digest.update(issuance.claim.generation.to_be_bytes());
    digest.update(issuance.claim.worker_node_id.as_bytes());
    digest.update(issuance.claim.worker_incarnation.to_be_bytes());
    digest.update(issuance.claim.fence.to_be_bytes());
    digest.update(issuance.not_before.get().to_be_bytes());
    digest.update(issuance.not_after.get().to_be_bytes());
    digest.update(bundle_digest);
    let bytes: [u8; 16] = digest.finalize()[..16]
        .try_into()
        .map_err(|_| CertificateOrderCompletionError::Failed)?;
    Ok(uuid_v8(bytes))
}

/// Closed certificate-order authority failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CertificateOrderCompletionAuthorityError {
    /// Current authority cannot safely answer or commit.
    #[error("certificate order authority is unavailable")]
    Unavailable,
    /// Operation identity was reused for another command or result.
    #[error("certificate order authority conflicts with the request")]
    Conflict,
    /// Authority evidence was malformed or violated the contract.
    #[error("certificate order authority failed closed")]
    Failed,
}

/// Closed certificate-order completion failure without certificate or secret detail.
#[derive(Debug, Error)]
pub enum CertificateOrderCompletionError {
    /// Claim or validity inputs are invalid or already stale.
    #[error("certificate order completion input is invalid")]
    InvalidInput,
    /// Required authority or entropy is temporarily unavailable.
    #[error("certificate order completion is unavailable")]
    Unavailable,
    /// An existing durable operation contradicts this completion.
    #[error("certificate order completion conflicts with durable state")]
    Conflict,
    /// Local validation or durable evidence failed closed.
    #[error("certificate order completion failed closed")]
    Failed,
    /// Public certificate bundle framing failed.
    #[error("certificate order bundle is invalid")]
    Bundle(#[from] meshspan_certificates::PublicCertificateBundleError),
    /// Per-recipient authenticated encryption failed.
    #[error("certificate order envelope failed")]
    Envelope(#[from] meshspan_secret_envelope::SecretEnvelopeError),
    /// Derived durable identity was invalid.
    #[error("certificate order identity failed")]
    Identifier(#[from] meshspan_domain::IdentifierError),
    /// Consensus-backed authority rejected or could not commit.
    #[error("certificate order authority failed")]
    Authority(#[from] CertificateOrderCompletionAuthorityError),
}
