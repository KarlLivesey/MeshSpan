// SPDX-License-Identifier: GPL-2.0-only

//! Replacement workers recover admitted ciphertext; they never take a fresh snapshot under its ID.

use super::{
    MetadataBackupPreparationError, MetadataBackupPreparationService, PreparedMetadataBackup,
    encrypted_file_name, hash_regular_file, remove_orphan, sync_directory, validate_run,
    validate_staging,
};
use crate::ConsensusAuthenticationAuthority;
use crate::{BackupPublicationAuthority, MetadataBackupProviderResolver};
use meshspan_backup::{BackupFileEvidence, VerifiedBackupExport};
use meshspan_contracts::{
    BackupObjectIdentity, BackupObjectReference, BackupReadRequest, ContractVersion, RequestContext,
};
use meshspan_domain::{BackupId, OperationId, Revision, UnixMicros, uuid_v8};
use meshspan_metadata::{
    BackupCopyRecord, BackupCopyState, BackupDestinationCursor, BackupDestinationState,
    LocalMetadataBackupStaging, MetadataBackupRun, MetadataBackupRunState, Page, PageLimit,
    RepositoryError,
};
use sha2::{Digest, Sha256};
use std::fs::{self, File};

/// Read-only recorded-copy inventory for replacement backup workers.
pub trait MetadataBackupRecoveryAuthority: BackupPublicationAuthority {
    /// Lists a bounded page, including paused destinations; reads remain possible there.
    ///
    /// # Errors
    /// Rejects unavailable authority, malformed rows and invalid bounds.
    fn recovery_copies(
        &self,
        backup_id: BackupId,
        after: Option<BackupDestinationCursor>,
        limit: PageLimit,
    ) -> Result<Page<BackupCopyRecord, BackupDestinationCursor>, RepositoryError>;
}

impl MetadataBackupRecoveryAuthority for ConsensusAuthenticationAuthority {
    fn recovery_copies(
        &self,
        backup_id: BackupId,
        after: Option<BackupDestinationCursor>,
        limit: PageLimit,
    ) -> Result<Page<BackupCopyRecord, BackupDestinationCursor>, RepositoryError> {
        self.reader().backup_copies(backup_id, after, limit)
    }
}

/// One finite recovery pass; the enclosing worker retains only a fairness cursor.
#[derive(Clone, Copy)]
pub struct MetadataBackupRecoveryInput {
    /// Currently claimed recorded generation.
    pub run: MetadataBackupRun,
    /// Last destination considered, not an authority token.
    pub after: Option<BackupDestinationCursor>,
    /// Authority time at admission.
    pub now: UnixMicros,
    /// Shared provider deadline for this pass.
    pub deadline: UnixMicros,
    /// Maximum recorded copies considered.
    pub page_items: usize,
}

/// Recovery never reports a staged source until bytes and its journal are durable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MetadataBackupRecoveryOutcome {
    /// The original admitted encrypted container is locally available again.
    Recovered(Box<PreparedMetadataBackup>),
    /// No usable source on this page; wrap to the beginning after the last page.
    Pending {
        /// Bounded seek continuation, if more copies remain.
        next: Option<BackupDestinationCursor>,
    },
}

impl<Authority: MetadataBackupRecoveryAuthority, Random>
    MetadataBackupPreparationService<'_, Authority, Random>
{
    /// Recovers one admitted generation from existing local bytes or one bounded source page.
    ///
    /// All provider implementations use the same verified stream. A partial or lying provider
    /// never installs a complete staging file; retired authority is rechecked before installation.
    /// Recovery needs no keys, captures no new backup and deletes no provider object.
    ///
    /// # Errors
    /// Rejects inconsistent authority, unsafe local paths, malformed pages and local IO failure.
    /// Unavailable or invalid remote copies leave a normal pending outcome for another pass.
    pub fn recover(
        &mut self,
        resolver: &mut impl MetadataBackupProviderResolver,
        input: MetadataBackupRecoveryInput,
    ) -> Result<MetadataBackupRecoveryOutcome, MetadataBackupPreparationError> {
        validate_run(input.run, input.now)?;
        let limit = PageLimit::new(input.page_items)?;
        if input.run.state != MetadataBackupRunState::Recorded || input.deadline <= input.now {
            return Err(MetadataBackupPreparationError::InvalidInput);
        }
        let evidence = self.admitted_evidence(input.run)?;
        if let Some(prepared) = self.recover_local(input, evidence)? {
            return Ok(MetadataBackupRecoveryOutcome::Recovered(Box::new(prepared)));
        }
        let page = self
            .authority
            .recovery_copies(input.run.backup_id, input.after, limit)?;
        validate_page(&page, input)?;
        for copy in page.items {
            if let Some(prepared) = self.recover_copy(resolver, input, evidence, &copy)? {
                return Ok(MetadataBackupRecoveryOutcome::Recovered(Box::new(prepared)));
            }
        }
        Ok(MetadataBackupRecoveryOutcome::Pending { next: page.next })
    }

    fn admitted_evidence(
        &self,
        run: MetadataBackupRun,
    ) -> Result<BackupFileEvidence, MetadataBackupPreparationError> {
        let backup = self
            .authority
            .metadata_backup(run.backup_id)?
            .ok_or(MetadataBackupPreparationError::InvalidProjection)?;
        let evidence = crate::backup_restore_readiness::catalogue_evidence(backup)
            .map_err(|_| MetadataBackupPreparationError::InvalidProjection)?;
        if evidence.source.backup_id != run.backup_id
            || evidence.source.partition_id != run.partition_id
        {
            return Err(MetadataBackupPreparationError::InvalidProjection);
        }
        Ok(evidence)
    }

    fn recover_local(
        &mut self,
        input: MetadataBackupRecoveryInput,
        evidence: BackupFileEvidence,
    ) -> Result<Option<PreparedMetadataBackup>, MetadataBackupPreparationError> {
        let file_path = self
            .directory
            .join(encrypted_file_name(input.run.backup_id));
        match hash_regular_file(&file_path) {
            Ok(measured) if measured == (evidence.byte_length, evidence.digest) => {
                File::open(&file_path)?.sync_all()?;
                sync_directory(&self.directory)?;
                self.record_recovered(input, evidence).map(Some)
            }
            Ok(_) => Ok(None),
            Err(MetadataBackupPreparationError::Io(error))
                if error.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    fn recover_copy(
        &mut self,
        resolver: &mut impl MetadataBackupProviderResolver,
        input: MetadataBackupRecoveryInput,
        evidence: BackupFileEvidence,
        copy: &BackupCopyRecord,
    ) -> Result<Option<PreparedMetadataBackup>, MetadataBackupPreparationError> {
        if !matches!(
            copy.state,
            BackupCopyState::Stored | BackupCopyState::Verified
        ) {
            return Ok(None);
        }
        let Some(destination) = self.authority.backup_destination(copy.destination_id)? else {
            return Ok(None);
        };
        if destination.destination_id != copy.destination_id
            || destination.state == BackupDestinationState::Retired
            || destination.binding.provider_generation() != copy.provider_generation
        {
            return Ok(None);
        }
        let request = recovery_request(input, evidence, copy)?;
        let Ok(provider) = resolver.resolve(&destination) else {
            return Ok(None);
        };
        let temporary = self.directory.join(format!(
            "{}.recovery.tmp",
            encrypted_file_name(input.run.backup_id)
        ));
        remove_orphan(&temporary)?;
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        let mut sink = VerifiedBackupExport::new(&mut output, &request, input.now)?;
        let Ok(receipt) = provider.read_exact(&request, &mut sink, input.now) else {
            // Private partial bytes are replaced on the next source attempt.
            return Ok(None);
        };
        match sink.finish(receipt) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::InvalidData => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        output.sync_all()?;
        drop(output);
        if self.admitted_evidence(input.run)? != evidence
            || self
                .authority
                .backup_copy(input.run.backup_id, copy.destination_id)?
                .as_ref()
                != Some(copy)
        {
            return Err(MetadataBackupPreparationError::InvalidProjection);
        }
        let destination = self
            .authority
            .backup_destination(copy.destination_id)?
            .ok_or(MetadataBackupPreparationError::InvalidProjection)?;
        if destination.destination_id != copy.destination_id
            || destination.state == BackupDestinationState::Retired
            || destination.binding.provider_generation() != copy.provider_generation
        {
            return Err(MetadataBackupPreparationError::InvalidProjection);
        }
        fs::rename(
            &temporary,
            self.directory
                .join(encrypted_file_name(input.run.backup_id)),
        )?;
        sync_directory(&self.directory)?;
        self.record_recovered(input, evidence).map(Some)
    }

    fn record_recovered(
        &mut self,
        input: MetadataBackupRecoveryInput,
        evidence: BackupFileEvidence,
    ) -> Result<PreparedMetadataBackup, MetadataBackupPreparationError> {
        if self.admitted_evidence(input.run)? != evidence {
            return Err(MetadataBackupPreparationError::InvalidProjection);
        }
        let staging = match self.local.metadata_backup_staging(input.run.backup_id)? {
            Some(existing) if existing.evidence == evidence => existing,
            Some(_) => return Err(MetadataBackupPreparationError::InvalidProjection),
            None => LocalMetadataBackupStaging {
                evidence,
                relative_file_name: encrypted_file_name(input.run.backup_id),
                prepared_at: input.now,
                revision: 1,
            },
        };
        let encrypted_path = self
            .directory
            .join(encrypted_file_name(input.run.backup_id));
        validate_staging(
            input.run,
            &encrypted_file_name(input.run.backup_id),
            &staging,
            &encrypted_path,
        )?;
        self.local.record_metadata_backup_staging(&staging)?;
        Ok(PreparedMetadataBackup {
            encrypted_path,
            staging,
        })
    }
}

fn recovery_request(
    input: MetadataBackupRecoveryInput,
    evidence: BackupFileEvidence,
    copy: &BackupCopyRecord,
) -> Result<BackupReadRequest, MetadataBackupPreparationError> {
    if copy.backup_id != input.run.backup_id
        || copy.revision == Revision::ZERO
        || copy.byte_length != evidence.byte_length
        || copy.copy_digest != evidence.digest
    {
        return Err(MetadataBackupPreparationError::InvalidProjection);
    }
    let mut digest = Sha256::new();
    digest.update(b"meshspan.backup-source-recovery.v1\0");
    digest.update(copy.backup_id.as_bytes());
    digest.update(copy.destination_id.as_bytes());
    digest.update(input.now.get().to_be_bytes());
    let digest = digest.finalize();
    let mut prefix = [0; 16];
    prefix.copy_from_slice(&digest[..16]);
    let operation_id = OperationId::from_bytes(uuid_v8(prefix))
        .map_err(|_| MetadataBackupPreparationError::InvalidInput)?;
    Ok(BackupReadRequest {
        context: RequestContext {
            contract_version: ContractVersion::V1_0,
            operation_id,
            deadline: input.deadline,
            expected_revision: Some(copy.revision),
        },
        object: BackupObjectIdentity {
            backup_id: copy.backup_id,
            destination_id: copy.destination_id,
            provider_generation: copy.provider_generation,
            byte_length: evidence.byte_length,
            digest: evidence.digest,
        },
        object_reference: BackupObjectReference::new(copy.object_reference.clone())?,
    })
}

fn validate_page(
    page: &Page<BackupCopyRecord, BackupDestinationCursor>,
    input: MetadataBackupRecoveryInput,
) -> Result<(), MetadataBackupPreparationError> {
    let mut after = input.after.map(|cursor| cursor.destination_id);
    if page.items.len() > input.page_items {
        return Err(MetadataBackupPreparationError::InvalidProjection);
    }
    for copy in &page.items {
        if copy.backup_id != input.run.backup_id
            || after.is_some_and(|previous| copy.destination_id <= previous)
        {
            return Err(MetadataBackupPreparationError::InvalidProjection);
        }
        after = Some(copy.destination_id);
    }
    if page
        .next
        .is_some_and(|next| page.items.is_empty() || Some(next.destination_id) != after)
    {
        return Err(MetadataBackupPreparationError::InvalidProjection);
    }
    Ok(())
}
