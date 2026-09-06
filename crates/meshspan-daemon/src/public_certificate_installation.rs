// SPDX-License-Identifier: GPL-2.0-only

//! Live HTTPS rotation followed by a durable, exact gateway installation acknowledgement.

use meshspan_domain::{
    AuditEventId, NodeId, OperationId, PrincipalId, Revision, UnixMicros, uuid_v8,
};
use meshspan_metadata::{
    AcknowledgeExternalCertificateInstallation, AcknowledgeMeshLocalCertificateInstallation,
    AcknowledgePublicCertificateInstallation, AuthoritativeCommand, CommandContext, CommandReceipt,
    EntityKind, PublicCertificateSource, SecretGenerationReference,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{LoadedPublicCertificate, PublicCertificateRotationError, RotatingHttpsIdentity};

const OPERATION_ID_DOMAIN: &[u8] = b"meshspan.public-certificate-installation.operation.v1\0";
const AUDIT_ID_DOMAIN: &[u8] = b"meshspan.public-certificate-installation.audit.v1\0";

/// Authoritative identity and timing for one gateway's live certificate installation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicCertificateInstallationRequest {
    /// Durable issuance source being installed.
    pub source: PublicCertificateSource,
    /// Exact source revision observed before loading its encrypted generation.
    pub source_revision: Revision,
    /// Local gateway node.
    pub gateway_node_id: NodeId,
    /// Current local gateway process incarnation.
    pub gateway_incarnation: u64,
    /// Principal attributed to the replicated acknowledgement.
    pub actor_principal_id: PrincipalId,
    /// Authority-agreed acknowledgement instant.
    pub now: UnixMicros,
}

/// Durable result of selecting and acknowledging one certificate generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicCertificateInstallationCommit {
    /// Exact encrypted generation installed by the live resolver.
    pub certificate: SecretGenerationReference,
    /// Digest of the decrypted canonical bundle.
    pub bundle_digest: [u8; 32],
    /// Consensus revision containing the gateway acknowledgement.
    pub acknowledgement_revision: Revision,
}

/// Original durable receipt and timestamp needed to validate an installation retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicCertificateInstallationReceipt {
    /// Exact committed operation receipt, including its canonical request digest.
    pub receipt: CommandReceipt,
    /// Original operation time; a later retry must not substitute its current clock.
    pub occurred_at: UnixMicros,
}

/// Consensus operations required after the node-local live resolver has switched.
pub trait PublicCertificateInstallationAuthority {
    /// Resolves an exact prior acknowledgement after an ambiguous response or process restart.
    ///
    /// # Errors
    ///
    /// Fails closed when current operation evidence cannot be read safely.
    fn resolve_public_certificate_installation(
        &self,
        operation_id: OperationId,
    ) -> Result<
        Option<PublicCertificateInstallationReceipt>,
        PublicCertificateInstallationAuthorityError,
    >;

    /// Commits or exactly resolves one gateway installation acknowledgement.
    ///
    /// # Errors
    ///
    /// Never reports success without an exact durable receipt.
    fn acknowledge_public_certificate_installation(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, PublicCertificateInstallationAuthorityError>;
}

/// Installs a validated identity locally before claiming it is live in replicated metadata.
pub struct PublicCertificateInstallationService<A> {
    authority: A,
}

impl<A> PublicCertificateInstallationService<A> {
    /// Binds one consensus-backed acknowledgement authority.
    #[must_use]
    pub const fn new(authority: A) -> Self {
        Self { authority }
    }
}

impl<A> PublicCertificateInstallationService<A>
where
    A: PublicCertificateInstallationAuthority,
{
    /// Selects the identity for new handshakes, then durably acknowledges that exact selection.
    ///
    /// A lost acknowledgement response is safe: retry observes the same live identity and resolves
    /// the deterministic operation. No acknowledgement is submitted before the resolver switch.
    ///
    /// # Errors
    ///
    /// Rejects inconsistent order/generation identity, stale local rotation, authority conflict or
    /// malformed durable evidence.
    pub fn install_and_acknowledge(
        &self,
        identity: &RotatingHttpsIdentity,
        certificate: &LoadedPublicCertificate,
        request: PublicCertificateInstallationRequest,
    ) -> Result<PublicCertificateInstallationCommit, PublicCertificateInstallationError> {
        validate_request(certificate, request)?;
        identity
            .install(request.source_revision, certificate)
            .map_err(map_rotation_error)?;
        let command = match request.source {
            PublicCertificateSource::AcmeOrder(order_id) => {
                AuthoritativeCommand::AcknowledgePublicCertificateInstallation(
                    AcknowledgePublicCertificateInstallation {
                        order_id,
                        gateway_node_id: request.gateway_node_id,
                        gateway_incarnation: request.gateway_incarnation,
                        certificate: certificate.generation(),
                        bundle_digest: certificate.bundle_digest(),
                        observed_order_revision: request.source_revision,
                    },
                )
            }
            PublicCertificateSource::ExternalPublication(publication_id) => {
                AuthoritativeCommand::AcknowledgeExternalCertificateInstallation(
                    AcknowledgeExternalCertificateInstallation {
                        publication_id,
                        gateway_node_id: request.gateway_node_id,
                        gateway_incarnation: request.gateway_incarnation,
                        certificate: certificate.generation(),
                        bundle_digest: certificate.bundle_digest(),
                        observed_publication_revision: request.source_revision,
                    },
                )
            }
            PublicCertificateSource::MeshLocalIssuance(issuance_id) => {
                AuthoritativeCommand::AcknowledgeMeshLocalCertificateInstallation(
                    AcknowledgeMeshLocalCertificateInstallation {
                        issuance_id,
                        gateway_node_id: request.gateway_node_id,
                        gateway_incarnation: request.gateway_incarnation,
                        certificate: certificate.generation(),
                        bundle_digest: certificate.bundle_digest(),
                        observed_issuance_revision: request.source_revision,
                    },
                )
            }
        };
        let operation_id = derived_id(OPERATION_ID_DOMAIN, certificate, request)?;
        let mut context = CommandContext {
            operation_id,
            actor_principal_id: request.actor_principal_id,
            audit_event_id: AuditEventId::from_bytes(derived_bytes(
                AUDIT_ID_DOMAIN,
                certificate,
                request,
            )?)?,
            occurred_at: request.now,
            expected_revision: None,
        };
        let receipt = match self
            .authority
            .resolve_public_certificate_installation(operation_id)?
        {
            Some(stored) => {
                context.occurred_at = stored.occurred_at;
                stored.receipt
            }
            None => self
                .authority
                .acknowledge_public_certificate_installation(context, &command)?,
        };
        let expected_digest = command.request_digest(context);
        validate_receipt(receipt, operation_id, expected_digest, request.source)?;
        Ok(PublicCertificateInstallationCommit {
            certificate: certificate.generation(),
            bundle_digest: certificate.bundle_digest(),
            acknowledgement_revision: receipt.committed_revision,
        })
    }
}

fn validate_request(
    certificate: &LoadedPublicCertificate,
    request: PublicCertificateInstallationRequest,
) -> Result<(), PublicCertificateInstallationError> {
    if request.source_revision == Revision::ZERO
        || request.gateway_incarnation == 0
        || matches!(request.source, PublicCertificateSource::AcmeOrder(order_id)
            if certificate.generation().secret_id != order_id.as_bytes())
        || certificate.generation().generation == 0
        || certificate.bundle_digest() == [0; 32]
    {
        Err(PublicCertificateInstallationError::InvalidInput)
    } else {
        Ok(())
    }
}

fn derived_id(
    domain: &[u8],
    certificate: &LoadedPublicCertificate,
    request: PublicCertificateInstallationRequest,
) -> Result<OperationId, PublicCertificateInstallationError> {
    OperationId::from_bytes(derived_bytes(domain, certificate, request)?)
        .map_err(PublicCertificateInstallationError::from)
}

fn derived_bytes(
    domain: &[u8],
    certificate: &LoadedPublicCertificate,
    request: PublicCertificateInstallationRequest,
) -> Result<[u8; 16], PublicCertificateInstallationError> {
    let mut digest = Sha256::new();
    digest.update(domain);
    let (source_kind, source_id) = source_identity(request.source);
    digest.update([source_kind]);
    digest.update(source_id);
    digest.update(request.source_revision.get().to_be_bytes());
    digest.update(request.gateway_node_id.as_bytes());
    digest.update(request.gateway_incarnation.to_be_bytes());
    digest.update(certificate.generation().secret_id);
    digest.update(certificate.generation().generation.to_be_bytes());
    digest.update(certificate.bundle_digest());
    let bytes: [u8; 16] = digest.finalize()[..16]
        .try_into()
        .map_err(|_| PublicCertificateInstallationError::Failed)?;
    Ok(uuid_v8(bytes))
}

fn validate_receipt(
    receipt: CommandReceipt,
    operation_id: OperationId,
    expected_digest: [u8; 32],
    source: PublicCertificateSource,
) -> Result<(), PublicCertificateInstallationError> {
    let (expected_kind, expected_id) = source_entity(source);
    if receipt.operation_id != operation_id
        || receipt.request_digest != expected_digest
        || receipt.result_digest == [0; 32]
        || receipt.committed_revision == Revision::ZERO
        || receipt.entity.kind != expected_kind
        || receipt.entity.id != expected_id
    {
        Err(PublicCertificateInstallationError::Conflict)
    } else {
        Ok(())
    }
}

const fn source_identity(source: PublicCertificateSource) -> (u8, [u8; 16]) {
    match source {
        PublicCertificateSource::AcmeOrder(order_id) => (1, order_id.as_bytes()),
        PublicCertificateSource::ExternalPublication(publication_id) => {
            (2, publication_id.as_bytes())
        }
        PublicCertificateSource::MeshLocalIssuance(issuance_id) => (3, issuance_id.as_bytes()),
    }
}

const fn source_entity(source: PublicCertificateSource) -> (EntityKind, [u8; 16]) {
    match source {
        PublicCertificateSource::AcmeOrder(order_id) => {
            (EntityKind::CertificateOrder, order_id.as_bytes())
        }
        PublicCertificateSource::ExternalPublication(publication_id) => (
            EntityKind::ExternalCertificatePublication,
            publication_id.as_bytes(),
        ),
        PublicCertificateSource::MeshLocalIssuance(issuance_id) => (
            EntityKind::MeshLocalCertificateIssuance,
            issuance_id.as_bytes(),
        ),
    }
}

fn map_rotation_error(error: PublicCertificateRotationError) -> PublicCertificateInstallationError {
    match error {
        PublicCertificateRotationError::StaleRevision
        | PublicCertificateRotationError::ConflictingRevision => {
            PublicCertificateInstallationError::Conflict
        }
        PublicCertificateRotationError::Configuration
        | PublicCertificateRotationError::Unavailable => PublicCertificateInstallationError::Failed,
    }
}

/// Closed acknowledgement-authority failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PublicCertificateInstallationAuthorityError {
    /// Current consensus authority cannot safely answer or commit.
    #[error("public certificate installation authority is unavailable")]
    Unavailable,
    /// Existing durable operation state contradicts this request.
    #[error("public certificate installation authority conflicts with the request")]
    Conflict,
    /// Authority evidence was malformed or violated the contract.
    #[error("public certificate installation authority failed closed")]
    Failed,
}

/// Closed live-installation failure without certificate or key detail.
#[derive(Debug, Error)]
pub enum PublicCertificateInstallationError {
    /// Order, node incarnation, revision or generation identity is invalid.
    #[error("public certificate installation input is invalid")]
    InvalidInput,
    /// Current authority is temporarily unavailable.
    #[error("public certificate installation is unavailable")]
    Unavailable,
    /// Durable or local authoritative state conflicts with this installation.
    #[error("public certificate installation conflicts with current state")]
    Conflict,
    /// Local rotation or durable evidence failed closed.
    #[error("public certificate installation failed closed")]
    Failed,
    /// Derived durable identity was invalid.
    #[error("public certificate installation identity failed")]
    Identifier(#[from] meshspan_domain::IdentifierError),
}

impl From<PublicCertificateInstallationAuthorityError> for PublicCertificateInstallationError {
    fn from(error: PublicCertificateInstallationAuthorityError) -> Self {
        match error {
            PublicCertificateInstallationAuthorityError::Unavailable => Self::Unavailable,
            PublicCertificateInstallationAuthorityError::Conflict => Self::Conflict,
            PublicCertificateInstallationAuthorityError::Failed => Self::Failed,
        }
    }
}
