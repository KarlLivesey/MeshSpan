// SPDX-License-Identifier: GPL-2.0-only

use meshspan_backup::{DirectoryBackupProvider, SharedBackupProvider};
use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_contracts::{
    BackupObjectIdentity, BackupProvider, BackupStoreRequest, ContractVersion, RequestContext,
};
use meshspan_domain::{
    BackupDestinationId, BackupId, ComponentInstanceId, DurationMicros, OperationId, PrincipalId,
    Revision, UnixMicros,
};
use meshspan_metadata::{
    ApplyDisposition, AuthoritativeCommand, BackupCopyRecord, BackupCopyState,
    BackupDestinationBinding, BackupDestinationRecord, BackupDestinationState,
    BackupFailureRelationship, BackupReclamationCursor, CommandContext, CommandReceipt, EntityKind,
    EntityReference, LogPosition, Page, PageLimit, RepositoryError, RetireMetadataBackup,
};
use sha2::{Digest, Sha256};
use std::cell::{Cell, RefCell};
use std::io::Cursor;
use tempfile::tempdir;

use crate::metadata_backup_retention::{
    BackupRetentionAuthority, BackupRetentionInput, MetadataBackupRetentionWorker,
};
use crate::{
    MetadataBackupProviderResolutionError, MetadataBackupProviderResolver,
    MetadataBackupWorkerLimits,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn retention_worker_recovers_deletion_before_receipt_commit_with_a_fresh_deadline() -> TestResult {
    let directory = tempdir()?;
    let destination = destination(2)?;
    let (provider, copy) = stored_copy(directory.path(), &destination)?;
    let authority = MemoryAuthority {
        copies: RefCell::new(vec![copy.clone()]),
        destination,
        reject_commit: Cell::new(true),
        receipts: Cell::new(0),
    };
    let mut resolver = Resolver {
        provider,
        unavailable: None,
    };
    let mut random = crate::OperatingSystemRandom;
    let first = MetadataBackupRetentionWorker::default().run_once(
        &authority,
        &mut resolver,
        &mut random,
        input(20)?,
    )?;
    assert_eq!((first.reclaimed, first.failed), (0, 1));
    assert_eq!(authority.copies.borrow().as_slice(), &[copy]);
    // New worker and later time simulate losing volatile state after physical deletion.
    authority.reject_commit.set(false);
    let second = MetadataBackupRetentionWorker::default().run_once(
        &authority,
        &mut resolver,
        &mut random,
        input(200)?,
    )?;
    assert_eq!((second.reclaimed, second.failed), (1, 0));
    assert_eq!(authority.receipts.get(), 1);
    assert!(authority.copies.borrow().is_empty());
    Ok(())
}

#[test]
fn unreachable_destination_does_not_starve_later_cleanup_pages() -> TestResult {
    let directory = tempdir()?;
    let destination = destination(2)?;
    let (provider, copy) = stored_copy(directory.path(), &destination)?;
    let mut unavailable = copy.clone();
    unavailable.backup_id = BackupId::from_bytes([1; 16])?;
    unavailable.destination_id = BackupDestinationId::from_bytes([1; 16])?;
    let authority = MemoryAuthority {
        copies: RefCell::new(vec![unavailable.clone(), copy]),
        destination,
        reject_commit: Cell::new(false),
        receipts: Cell::new(0),
    };
    let mut resolver = Resolver {
        provider,
        unavailable: Some(unavailable.destination_id),
    };
    let mut random = crate::OperatingSystemRandom;
    let mut worker = MetadataBackupRetentionWorker::default();
    assert_eq!(
        worker
            .run_once(&authority, &mut resolver, &mut random, input(20)?)?
            .failed,
        1
    );
    assert_eq!(
        worker
            .run_once(&authority, &mut resolver, &mut random, input(21)?)?
            .reclaimed,
        1
    );
    assert_eq!(authority.copies.borrow().as_slice(), &[unavailable]);
    assert_eq!(
        worker
            .run_once(&authority, &mut resolver, &mut random, input(22)?)?
            .failed,
        1
    );
    Ok(())
}

struct Resolver {
    provider: SharedBackupProvider<DirectoryBackupProvider>,
    unavailable: Option<BackupDestinationId>,
}

impl MetadataBackupProviderResolver for Resolver {
    fn resolve(
        &mut self,
        destination: &BackupDestinationRecord,
    ) -> Result<Box<dyn BackupProvider>, MetadataBackupProviderResolutionError> {
        if self.unavailable == Some(destination.destination_id) {
            Err(MetadataBackupProviderResolutionError::Unavailable)
        } else {
            Ok(Box::new(self.provider.clone()))
        }
    }
}

struct MemoryAuthority {
    copies: RefCell<Vec<BackupCopyRecord>>,
    destination: BackupDestinationRecord,
    reject_commit: Cell<bool>,
    receipts: Cell<usize>,
}

impl BackupRetentionAuthority for MemoryAuthority {
    fn candidate(&self) -> Result<Option<RetireMetadataBackup>, RepositoryError> {
        Ok(None)
    }
    fn pending(
        &self,
        after: Option<BackupReclamationCursor>,
        limit: PageLimit,
    ) -> Result<Page<BackupCopyRecord, BackupReclamationCursor>, RepositoryError> {
        assert_eq!(limit, PageLimit::new(1)?);
        let mut items = self
            .copies
            .borrow()
            .iter()
            .filter(|copy| {
                after.is_none_or(|cursor| {
                    (copy.backup_id, copy.destination_id)
                        > (cursor.backup_id, cursor.destination_id)
                })
            })
            .take(2)
            .cloned()
            .collect::<Vec<_>>();
        let more = items.len() > 1;
        if more {
            items.pop();
        }
        let next = if more {
            items.last().map(|copy| BackupReclamationCursor {
                backup_id: copy.backup_id,
                destination_id: copy.destination_id,
            })
        } else {
            None
        };
        Ok(Page { items, next })
    }
    fn destination(
        &self,
        destination_id: BackupDestinationId,
    ) -> Result<Option<BackupDestinationRecord>, RepositoryError> {
        Ok(Some(BackupDestinationRecord {
            destination_id,
            ..self.destination.clone()
        }))
    }
    fn commit(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, MetadataAuthorityRequestError> {
        if self.reject_commit.get() {
            return Err(MetadataAuthorityRequestError::Unavailable);
        }
        let AuthoritativeCommand::RecordBackupReclamation(value) = command else {
            return Err(MetadataAuthorityRequestError::Rejected);
        };
        let mut copies = self.copies.borrow_mut();
        let copy = copies
            .iter()
            .find(|copy| {
                copy.backup_id == value.receipt.object.backup_id
                    && copy.destination_id == value.receipt.object.destination_id
            })
            .ok_or(MetadataAuthorityRequestError::Rejected)?;
        if value.receipt.retirement_revision != copy.revision
            || value.receipt.object.digest != copy.copy_digest
        {
            return Err(MetadataAuthorityRequestError::Rejected);
        }
        copies.retain(|copy| {
            copy.backup_id != value.receipt.object.backup_id
                || copy.destination_id != value.receipt.object.destination_id
        });
        self.receipts.set(self.receipts.get() + 1);
        Ok(CommandReceipt {
            operation_id: context.operation_id,
            request_digest: command.request_digest(context),
            result_digest: [1; 32],
            entity: EntityReference {
                kind: EntityKind::MetadataBackup,
                id: value.receipt.object.backup_id.as_bytes(),
            },
            committed_revision: Revision::new(12),
            committed_position: LogPosition { index: 12, term: 1 },
            applied_position: LogPosition { index: 12, term: 1 },
            disposition: ApplyDisposition::Applied,
        })
    }
}

fn stored_copy(
    directory: &std::path::Path,
    destination: &BackupDestinationRecord,
) -> TestResult<(
    SharedBackupProvider<DirectoryBackupProvider>,
    BackupCopyRecord,
)> {
    let bytes = b"encrypted backup test bytes";
    let object = BackupObjectIdentity {
        backup_id: BackupId::from_bytes([3; 16])?,
        destination_id: destination.destination_id,
        provider_generation: 1,
        byte_length: bytes.len() as u64,
        digest: Sha256::digest(bytes).into(),
    };
    let mut provider = DirectoryBackupProvider::open(
        directory,
        destination.destination_id,
        1,
        1024,
        UnixMicros::new(1),
    )?;
    let receipt = provider.store_exact(
        BackupStoreRequest {
            context: RequestContext {
                contract_version: ContractVersion::V1_0,
                operation_id: OperationId::from_bytes([4; 16])?,
                deadline: UnixMicros::new(100),
                expected_revision: Some(Revision::new(10)),
            },
            object,
        },
        &mut Cursor::new(bytes),
        UnixMicros::new(2),
    )?;
    let copy = BackupCopyRecord {
        backup_id: object.backup_id,
        destination_id: object.destination_id,
        provider_generation: 1,
        object_reference: receipt.object_reference.as_str().to_owned(),
        byte_length: object.byte_length,
        copy_digest: object.digest,
        state: BackupCopyState::Retired,
        stored_at: UnixMicros::new(2),
        verified_at: None,
        revision: Revision::new(11),
    };
    Ok((SharedBackupProvider::new(provider), copy))
}

fn destination(value: u8) -> TestResult<BackupDestinationRecord> {
    Ok(BackupDestinationRecord {
        destination_id: BackupDestinationId::from_bytes([value; 16])?,
        display_name: "backup".to_owned(),
        canonical_name: "backup".to_owned(),
        binding: BackupDestinationBinding::ComponentProvider {
            instance_id: ComponentInstanceId::from_bytes([6; 16])?,
            provider_generation: 1,
        },
        failure_relationship: BackupFailureRelationship::Unknown,
        failure_evidence_digest: [7; 32],
        state: BackupDestinationState::Paused,
        created_at: UnixMicros::new(1),
        revision: Revision::new(6),
    })
}

fn input(now: i64) -> TestResult<BackupRetentionInput> {
    Ok(BackupRetentionInput {
        actor: PrincipalId::from_bytes([8; 16])?,
        now: UnixMicros::new(now),
        limits: MetadataBackupWorkerLimits {
            lease_duration: DurationMicros::new(10),
            provider_timeout: DurationMicros::new(10),
            destination_page_items: 1,
        },
    })
}
