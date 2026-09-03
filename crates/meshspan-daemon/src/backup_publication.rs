// SPDX-License-Identifier: GPL-2.0-only

//! Retry-safe publication of one encrypted metadata backup to one exact destination.

mod authority;
mod evidence;

use std::fs::File;
use std::path::Path;

use evidence::{
    PublicationStep, command_context, object_identity, provider_context, record_backup,
    validate_backup, validate_copy, validate_receipt,
};
use meshspan_backup::{BackupError, BackupFileEvidence};
use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_contracts::{
    BackupObjectIdentity, BackupObjectReference, BackupProvider, BackupStoreRequest,
    BackupVerifyRequest, ContractError,
};
use meshspan_domain::{BackupDestinationId, PrincipalId, Revision, UnixMicros};
use meshspan_metadata::{
    AuthoritativeCommand, BackupCopyRecord, BackupCopyState, BackupDestinationRecord,
    BackupDestinationState, EntityKind, MetadataBackupRecord, MetadataBackupRunClaim,
    RepositoryError, VerifyBackupCopy,
};
use thiserror::Error;

pub use authority::BackupPublicationAuthority;

/// Stable inputs for one bounded publication attempt.
#[derive(Clone, Copy, Debug)]
pub struct BackupPublicationRequest<'a> {
    /// Closed encrypted container produced from one exact committed state.
    pub encrypted_source: &'a Path,
    /// Exact source and encrypted-container evidence.
    pub evidence: BackupFileEvidence,
    /// Configured destination selected for this copy.
    pub destination_id: BackupDestinationId,
    /// Exact live schedule-run claim which produced this first recoverable copy.
    pub claim: MetadataBackupRunClaim,
    /// Authoritative principal responsible for this automatic policy operation.
    pub actor_principal_id: PrincipalId,
    /// Authority time shared by this bounded attempt's durable transitions.
    pub now: UnixMicros,
    /// Strict provider IO deadline.
    pub deadline: UnixMicros,
}

/// Exact verified state returned only after provider and replicated catalogue confirmation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupPublicationOutcome {
    /// Admitted exact backup generation.
    pub backup: MetadataBackupRecord,
    /// Read-after-write-verified destination copy.
    pub copy: BackupCopyRecord,
}

/// Stateless coordinator for a single bounded publication attempt.
pub struct MetadataBackupPublisher<'a, Authority> {
    authority: &'a Authority,
}

impl<'a, Authority> MetadataBackupPublisher<'a, Authority> {
    /// Binds publication to the current replicated backup catalogue.
    #[must_use]
    pub const fn new(authority: &'a Authority) -> Self {
        Self { authority }
    }
}

impl<Authority> MetadataBackupPublisher<'_, Authority>
where
    Authority: BackupPublicationAuthority,
{
    /// Publishes and verifies one already-created encrypted backup container.
    ///
    /// Existing exact catalogue stages are resumed. Contradictory rows, provider generations,
    /// receipts, bytes or references fail closed. No copy is marked verified before the provider
    /// has independently reread and digested the complete encrypted object.
    ///
    /// # Errors
    ///
    /// Rejects elapsed bounds, inactive/substituted destinations, changed retry state, provider
    /// failures, unavailable consensus, malformed receipts and local source-file errors.
    pub fn publish<P: BackupProvider>(
        &self,
        provider: &mut P,
        request: &BackupPublicationRequest<'_>,
    ) -> Result<BackupPublicationOutcome, BackupPublicationError> {
        validate_request(request)?;
        let destination = self.load_active_destination(request.destination_id)?;
        let object = object_identity(
            request.evidence,
            request.destination_id,
            destination.binding.provider_generation(),
        );
        let copy = match self.authority.metadata_backup(object.backup_id)? {
            Some(backup) => {
                validate_backup(backup, request.evidence)?;
                self.load_copy(object)?
            }
            None => self.store_and_admit(provider, request, object, destination.revision)?,
        };
        let copy_revision = copy.revision;
        let verified = self.verify_and_record(provider, request, object, copy, copy_revision)?;
        let backup = self.load_backup(request.evidence)?;
        Ok(BackupPublicationOutcome {
            backup,
            copy: verified,
        })
    }

    fn load_active_destination(
        &self,
        destination_id: BackupDestinationId,
    ) -> Result<BackupDestinationRecord, BackupPublicationError> {
        let destination = self
            .authority
            .backup_destination(destination_id)?
            .ok_or(BackupPublicationError::InvalidProjection)?;
        if destination.destination_id != destination_id
            || destination.state != BackupDestinationState::Active
            || destination.binding.provider_generation() == 0
        {
            return Err(BackupPublicationError::InvalidProjection);
        }
        Ok(destination)
    }

    fn load_backup(
        &self,
        evidence: BackupFileEvidence,
    ) -> Result<MetadataBackupRecord, BackupPublicationError> {
        validate_backup(
            self.authority
                .metadata_backup(evidence.source.backup_id)?
                .ok_or(BackupPublicationError::InvalidProjection)?,
            evidence,
        )
    }

    fn store_and_admit<P: BackupProvider>(
        &self,
        provider: &mut P,
        request: &BackupPublicationRequest<'_>,
        object: BackupObjectIdentity,
        destination_revision: Revision,
    ) -> Result<BackupCopyRecord, BackupPublicationError> {
        let mut source = File::open(request.encrypted_source)?;
        let store_context = provider_context(
            PublicationStep::StoreProvider,
            request.evidence,
            object.destination_id,
            request.now,
            request.deadline,
            destination_revision,
        )?;
        let receipt = provider.store_exact(
            BackupStoreRequest {
                context: store_context,
                object,
            },
            &mut source,
            request.now,
        )?;
        if receipt.operation_id != store_context.operation_id || receipt.object != object {
            return Err(BackupPublicationError::InvalidReceipt);
        }
        let context = command_context(
            PublicationStep::RecordBackup,
            request.evidence,
            object.destination_id,
            request.actor_principal_id,
            request.now,
        )?;
        let command = AuthoritativeCommand::RecordMetadataBackup(record_backup(
            request.evidence,
            &receipt,
            request.claim,
        ));
        let committed = self.authority.commit_backup_publication(context, &command);
        if let Ok(receipt) = committed {
            validate_receipt(
                receipt,
                context,
                &command,
                EntityKind::MetadataBackup,
                object.backup_id.as_bytes(),
            )?;
        }
        self.authority
            .metadata_backup(object.backup_id)?
            .ok_or_else(|| publication_failure(committed))
            .and_then(|backup| validate_backup(backup, request.evidence))?;
        self.load_copy(object)
    }

    fn load_copy(
        &self,
        object: BackupObjectIdentity,
    ) -> Result<BackupCopyRecord, BackupPublicationError> {
        let copy = self
            .authority
            .backup_copy(object.backup_id, object.destination_id)?
            .ok_or(BackupPublicationError::InvalidProjection)?;
        validate_copy(copy, object)
    }

    fn verify_and_record<P: BackupProvider>(
        &self,
        provider: &P,
        request: &BackupPublicationRequest<'_>,
        object: BackupObjectIdentity,
        copy: BackupCopyRecord,
        copy_revision: Revision,
    ) -> Result<BackupCopyRecord, BackupPublicationError> {
        let object_reference = BackupObjectReference::new(copy.object_reference.clone())?;
        let verify_context = provider_context(
            PublicationStep::VerifyProvider,
            request.evidence,
            object.destination_id,
            request.now,
            request.deadline,
            copy_revision,
        )?;
        let verification = provider.verify_exact(
            &BackupVerifyRequest {
                context: verify_context,
                object,
                object_reference: object_reference.clone(),
            },
            request.now,
        )?;
        if verification.operation_id != verify_context.operation_id
            || verification.object != object
            || verification.object_reference != object_reference
        {
            return Err(BackupPublicationError::InvalidReceipt);
        }
        if copy.state == BackupCopyState::Verified {
            return Ok(copy);
        }
        self.record_verified_copy(request, object)
    }

    fn record_verified_copy(
        &self,
        request: &BackupPublicationRequest<'_>,
        object: BackupObjectIdentity,
    ) -> Result<BackupCopyRecord, BackupPublicationError> {
        let context = command_context(
            PublicationStep::VerifyCopy,
            request.evidence,
            object.destination_id,
            request.actor_principal_id,
            request.now,
        )?;
        let command = AuthoritativeCommand::VerifyBackupCopy(VerifyBackupCopy {
            backup_id: object.backup_id,
            destination_id: object.destination_id,
            provider_generation: object.provider_generation,
            copy_digest: object.digest,
        });
        let committed = self.authority.commit_backup_publication(context, &command);
        if let Ok(receipt) = committed {
            validate_receipt(
                receipt,
                context,
                &command,
                EntityKind::BackupCopy,
                object.backup_id.as_bytes(),
            )?;
        }
        let verified = self
            .authority
            .backup_copy(object.backup_id, object.destination_id)?
            .ok_or_else(|| publication_failure(committed))?;
        let verified = validate_copy(verified, object)?;
        if verified.state != BackupCopyState::Verified {
            return Err(BackupPublicationError::InvalidProjection);
        }
        Ok(verified)
    }
}

fn validate_request(request: &BackupPublicationRequest<'_>) -> Result<(), BackupPublicationError> {
    if request.now.get() < 0 || request.deadline <= request.now {
        return Err(BackupPublicationError::InvalidInput);
    }
    request.evidence.source.validate()?;
    if request.evidence.byte_length == 0 || request.evidence.digest == [0; 32] {
        return Err(BackupPublicationError::InvalidInput);
    }
    Ok(())
}

fn publication_failure(
    result: Result<meshspan_metadata::CommandReceipt, MetadataAuthorityRequestError>,
) -> BackupPublicationError {
    result.err().map_or(
        BackupPublicationError::InvalidProjection,
        BackupPublicationError::Authority,
    )
}

/// Failure to publish and verify one encrypted metadata-backup copy.
#[derive(Debug, Error)]
pub enum BackupPublicationError {
    /// Caller-provided time or evidence is invalid.
    #[error("backup publication input is invalid")]
    InvalidInput,
    /// Replicated state contradicts the exact backup or provider object.
    #[error("backup publication conflicts with durable state")]
    Conflict,
    /// Required destination, backup, copy or transition state is absent or invalid.
    #[error("backup publication projection is invalid")]
    InvalidProjection,
    /// A returned authority or provider receipt contradicts its request.
    #[error("backup publication receipt is invalid")]
    InvalidReceipt,
    /// Replicated catalogue query failed closed.
    #[error("backup catalogue query failed")]
    Repository(#[from] RepositoryError),
    /// Consensus could not durably resolve a catalogue mutation.
    #[error("backup catalogue authority failed")]
    Authority(#[from] MetadataAuthorityRequestError),
    /// Backup provider rejected or failed the exact request.
    #[error("backup provider failed")]
    Provider(#[from] ContractError),
    /// Encrypted backup evidence is structurally invalid.
    #[error("encrypted backup evidence is invalid")]
    Backup(#[from] BackupError),
    /// Encrypted source bytes could not be opened.
    #[error("encrypted backup source failed")]
    Io(#[from] std::io::Error),
    /// A derived identifier was invalid.
    #[error("backup publication identifier is invalid")]
    Identifier(#[from] meshspan_domain::IdentifierError),
}
