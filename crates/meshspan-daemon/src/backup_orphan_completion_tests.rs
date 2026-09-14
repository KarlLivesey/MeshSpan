// SPDX-License-Identifier: GPL-2.0-only

//! Actual provider deletion followed by an unavailable consensus completion boundary.

use super::*;
use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_metadata::{
    BackupDestinationRecord, BackupReclamationCandidate, BackupReclamationCursor, CommandContext,
    CommandReceipt, Page, PageLimit, RepositoryError, RetireMetadataBackup,
};

pub(super) fn recover_lost_completion(
    fixture: &RunningAuthority,
    authority: &ConsensusAuthenticationAuthority,
    provider: DirectoryBackupProvider,
    receipt: &BackupObjectReceipt,
) -> TestResult {
    prove_absence_stays_pending(fixture, authority, receipt.object.destination_id)?;
    let shared = SharedBackupProvider::new(provider);
    let mut first_resolver = resolver(receipt.object.destination_id, shared.clone())?;
    let first = MetadataBackupRetentionWorker::default().run_once(
        &UnavailableCompletion(authority),
        &mut first_resolver,
        &mut crate::OperatingSystemRandom,
        input(fixture, 202),
    )?;
    assert_eq!((first.reclaimed, first.failed), (0, 1));
    let retired = authority
        .reader()
        .abandoned_backup_retirement(receipt.object.backup_id, receipt.object.destination_id)?
        .ok_or("automatic retirement missing")?;
    assert!(first.retired);
    assert_eq!(retired.command.receipt.object, receipt.object);
    assert_eq!(
        retired.command.receipt.object_reference,
        receipt.object_reference
    );
    let verify = BackupVerifyRequest {
        context: RequestContext {
            contract_version: ContractVersion::V1_0,
            operation_id: OperationId::from_bytes([177; 16])?,
            deadline: UnixMicros::new(300),
            expected_revision: Some(retired.retirement_revision),
        },
        object: receipt.object,
        object_reference: receipt.object_reference.clone(),
    };
    assert_eq!(
        shared.verify_exact(&verify, UnixMicros::new(202)),
        Err(ContractError::NotFound)
    );
    assert_eq!(
        authority
            .reader()
            .pending_backup_reclamations(None, PageLimit::new(10)?)?
            .items
            .len(),
        1
    );
    drop(first_resolver);
    drop(shared);

    // Reopen the real provider and replace the worker: neither carries an in-memory receipt.
    let provider = DirectoryBackupProvider::open(
        &fixture.directory.path().join("unadmitted-provider"),
        receipt.object.destination_id,
        1,
        16 * 1024 * 1024,
        UnixMicros::new(203),
    )?;
    let mut resumed = resolver(
        receipt.object.destination_id,
        SharedBackupProvider::new(provider),
    )?;
    let outcome = MetadataBackupRetentionWorker::default().run_once(
        authority,
        &mut resumed,
        &mut crate::OperatingSystemRandom,
        input(fixture, 203),
    )?;
    assert_eq!((outcome.reclaimed, outcome.failed), (1, 0));
    assert!(
        authority
            .reader()
            .pending_backup_reclamations(None, PageLimit::new(10)?)?
            .items
            .is_empty()
    );
    let idle = MetadataBackupRetentionWorker::default().run_once(
        authority,
        &mut resumed,
        &mut crate::OperatingSystemRandom,
        input(fixture, 204),
    )?;
    assert_eq!((idle.reclaimed, idle.failed), (0, 0));
    assert!(
        authority
            .reader()
            .backup_copy(receipt.object.backup_id, receipt.object.destination_id)?
            .is_none()
    );
    Ok(())
}

fn prove_absence_stays_pending(
    fixture: &RunningAuthority,
    authority: &ConsensusAuthenticationAuthority,
    destination_id: BackupDestinationId,
) -> TestResult {
    // Inject a real provider with no object: a missing lookup is not terminal evidence.
    let directory = tempfile::tempdir()?;
    let empty = DirectoryBackupProvider::open(
        directory.path(),
        destination_id,
        1,
        16 * 1024 * 1024,
        UnixMicros::new(201),
    )?;
    let mut unresolved = resolver(destination_id, SharedBackupProvider::new(empty))?;
    let before = authority.reader().current_revision()?;
    let outcome = MetadataBackupRetentionWorker::default().run_once(
        authority,
        &mut unresolved,
        &mut crate::OperatingSystemRandom,
        input(fixture, 201),
    )?;
    assert_eq!(
        (outcome.reclaimed, outcome.failed, outcome.retired),
        (0, 1, false)
    );
    assert_eq!(authority.reader().current_revision()?, before);
    assert_eq!(
        authority
            .reader()
            .abandoned_backup_publications(None, PageLimit::new(10)?)?
            .items
            .len(),
        1
    );
    assert!(
        authority
            .reader()
            .pending_backup_reclamations(None, PageLimit::new(10)?)?
            .items
            .is_empty()
    );
    Ok(())
}

fn resolver(
    destination_id: BackupDestinationId,
    provider: SharedBackupProvider<DirectoryBackupProvider>,
) -> TestResult<RegisteredTargetBackupProviderResolver> {
    Ok(RegisteredTargetBackupProviderResolver::new([
        RegisteredBackupTarget {
            destination_id,
            target_id: TargetId::from_bytes(uuid_v8([32; 16]))?,
            target_generation: 1,
            provider,
        },
    ])?)
}

fn input(fixture: &RunningAuthority, now: i64) -> BackupRetentionInput {
    BackupRetentionInput {
        actor: fixture.administrator_id,
        now: UnixMicros::new(now),
        limits: MetadataBackupWorkerLimits {
            lease_duration: DurationMicros::new(100),
            provider_timeout: DurationMicros::new(50),
            destination_page_items: 10,
        },
    }
}

struct UnavailableCompletion<'a>(&'a ConsensusAuthenticationAuthority);

impl BackupRetentionAuthority for UnavailableCompletion<'_> {
    fn unadmitted(
        &self,
        after: Option<BackupReclamationCursor>,
        limit: PageLimit,
    ) -> Result<
        Page<meshspan_metadata::AbandonedBackupPublication, BackupReclamationCursor>,
        RepositoryError,
    > {
        self.0.unadmitted(after, limit)
    }
    fn candidate(&self) -> Result<Option<RetireMetadataBackup>, RepositoryError> {
        self.0.candidate()
    }
    fn pending(
        &self,
        after: Option<BackupReclamationCursor>,
        limit: PageLimit,
    ) -> Result<Page<BackupReclamationCandidate, BackupReclamationCursor>, RepositoryError> {
        self.0.pending(after, limit)
    }
    fn destination(
        &self,
        destination: BackupDestinationId,
    ) -> Result<Option<BackupDestinationRecord>, RepositoryError> {
        self.0.destination(destination)
    }
    fn commit(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, MetadataAuthorityRequestError> {
        if matches!(command, AuthoritativeCommand::RecordBackupReclamation(_)) {
            Err(MetadataAuthorityRequestError::Unavailable)
        } else {
            self.0.commit(context, command)
        }
    }
}
