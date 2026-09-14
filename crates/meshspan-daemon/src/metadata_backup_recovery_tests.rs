// SPDX-License-Identifier: GPL-2.0-only

//! Real encrypted providers, local-journal restart and exact original-generation recovery.

use crate::*;
use meshspan_backup::{
    BackupFileEvidence, BackupSourceManifest, DirectoryBackupProvider, SharedBackupProvider,
};
use meshspan_contracts::{
    BackupObjectIdentity, BackupProvider, BackupStoreRequest, ContractVersion, RequestContext,
};
use meshspan_domain::{
    BackupDestinationId, BackupId, MeshId, NodeId, OperationId, PartitionId, Revision, TargetId,
    UnixMicros,
};
use meshspan_metadata::{
    AuthoritativeCommand, BackupCopyRecord, BackupCopyState, BackupDestinationBinding,
    BackupDestinationCursor, BackupDestinationRecord, BackupDestinationState,
    BackupFailureRelationship, CommandContext, CommandReceipt, LocalDatabase, MetadataBackupRecord,
    MetadataBackupRun, MetadataBackupRunState, MetadataBackupState, Page, PageLimit,
    RepositoryError,
};
use meshspan_secret_envelope::WrappingPrivateKey;
use sha2::{Digest, Sha256};
use std::{cell::Cell, fs, io::Cursor, path::PathBuf};

#[test]
fn backup_recovery_pages_sources_and_restores_exact_generation_after_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    fixture.corrupt(0)?;
    let mut local = fixture.local()?;
    let mut random = OperatingSystemRandom;
    let first = fixture.recover(&mut local, &mut random, None, 1)?;
    let MetadataBackupRecoveryOutcome::Pending { next: Some(next) } = first else {
        return Err("corrupt first source must yield a continuation".into());
    };
    assert_eq!(
        next.destination_id,
        fixture.authority.copies[0].destination_id
    );
    assert!(
        local
            .metadata_backup_staging(fixture.run.backup_id)?
            .is_none()
    );
    let MetadataBackupRecoveryOutcome::Recovered(prepared) =
        fixture.recover(&mut local, &mut random, Some(next), 1)?
    else {
        return Err("second source was not recovered".into());
    };
    assert_eq!(prepared.staging.evidence, fixture.authority.evidence);
    assert_eq!(fs::read(&prepared.encrypted_path)?, fixture.encrypted);
    drop(local);
    let mut local = fixture.local()?;
    let resumed = MetadataBackupPreparationService::open(
        &fixture.authority,
        &mut local,
        &mut random,
        fixture.directory.path(),
    )?
    .prepare(fixture.run, UnixMicros::new(30))?;
    assert_eq!(resumed, *prepared);
    let restored = fixture.directory.path().join("restored-source");
    meshspan_backup::restore_backup(
        &resumed.encrypted_path,
        &restored,
        fixture.authority.evidence,
        &fixture.recipient,
    )?;
    assert_eq!(fs::read(restored)?, fixture.plaintext);

    // Lost local journal evidence can be reconstructed without any reachable provider.
    local.remove_metadata_backup_staging(&prepared.staging)?;
    fixture.resolver = RegisteredTargetBackupProviderResolver::new([])?;
    let MetadataBackupRecoveryOutcome::Recovered(recovered) =
        fixture.recover(&mut local, &mut random, None, 1)?
    else {
        return Err("valid local bytes required an external source".into());
    };
    assert_eq!(recovered.staging.evidence, prepared.staging.evidence);
    assert_eq!(recovered.encrypted_path, prepared.encrypted_path);
    assert_eq!(fixture.authority.new_snapshots.get(), 0);
    Ok(())
}

#[test]
fn backup_recovery_keeps_failed_copies_pending_and_retries_without_new_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    fixture.corrupt(0)?;
    fixture.corrupt(1)?;
    let mut local = fixture.local()?;
    let mut random = OperatingSystemRandom;
    assert_eq!(
        fixture.recover(&mut local, &mut random, None, 2)?,
        MetadataBackupRecoveryOutcome::Pending { next: None }
    );
    assert!(
        local
            .metadata_backup_staging(fixture.run.backup_id)?
            .is_none()
    );
    drop(local);
    fs::write(&fixture.objects[1], &fixture.encrypted)?;
    let mut local = fixture.local()?;
    let MetadataBackupRecoveryOutcome::Recovered(prepared) =
        fixture.recover(&mut local, &mut random, None, 2)?
    else {
        return Err("returning exact source was not recovered".into());
    };
    assert_eq!(fs::read(prepared.encrypted_path)?, fixture.encrypted);
    assert_eq!(
        prepared.staging.evidence.source.backup_id,
        fixture.run.backup_id
    );
    assert_eq!(fixture.authority.new_snapshots.get(), 0);
    Ok(())
}

#[test]
fn backup_recovery_does_not_revive_retired_authority_or_overwrite_changed_journal()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    let mut local = fixture.local()?;
    let mut random = OperatingSystemRandom;
    let MetadataBackupRecoveryOutcome::Recovered(prepared) =
        fixture.recover(&mut local, &mut random, None, 2)?
    else {
        return Err("initial recovery failed".into());
    };
    fixture.authority.retired.set(true);
    assert!(matches!(
        fixture.recover(&mut local, &mut random, None, 2),
        Err(MetadataBackupPreparationError::InvalidProjection)
    ));
    assert_eq!(
        local.metadata_backup_staging(fixture.run.backup_id)?,
        Some(prepared.staging.clone())
    );
    assert_eq!(fs::read(&prepared.encrypted_path)?, fixture.encrypted);
    fixture.authority.retired.set(false);
    local.remove_metadata_backup_staging(&prepared.staging)?;
    let mut changed = prepared.staging;
    changed.evidence.digest = [99; 32];
    local.record_metadata_backup_staging(&changed)?;
    assert!(matches!(
        fixture.recover(&mut local, &mut random, None, 2),
        Err(MetadataBackupPreparationError::InvalidProjection)
    ));
    assert_eq!(
        local.metadata_backup_staging(fixture.run.backup_id)?,
        Some(changed)
    );
    Ok(())
}

struct Fixture {
    directory: tempfile::TempDir,
    authority: Authority,
    resolver: RegisteredTargetBackupProviderResolver,
    objects: Vec<PathBuf>,
    run: MetadataBackupRun,
    plaintext: Vec<u8>,
    encrypted: Vec<u8>,
    recipient: WrappingPrivateKey,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let plaintext = vec![0x5a; 160_000];
        let source = directory.path().join("source");
        let encrypted_path = directory.path().join("original-encrypted");
        fs::write(&source, &plaintext)?;
        let recipient = WrappingPrivateKey::from_bytes([19; 32])?;
        let source_manifest = BackupSourceManifest {
            backup_id: BackupId::from_bytes([2; 16])?,
            partition_id: PartitionId::from_bytes([3; 16])?,
            mesh_id: MeshId::from_bytes([4; 16])?,
            last_log_index: 23,
            last_log_term: 4,
            state_revision: 24,
            schema_version: 1,
            byte_length: plaintext.len() as u64,
            digest: Sha256::digest(&plaintext).into(),
            created_at: UnixMicros::new(10),
        };
        let evidence = meshspan_backup::encrypt_backup(
            &source,
            &encrypted_path,
            source_manifest,
            &[recipient.public_key()],
            &mut OperatingSystemRandom,
        )?;
        let encrypted = fs::read(&encrypted_path)?;
        let mut targets = Vec::new();
        let mut authority = Authority {
            evidence,
            destinations: Vec::new(),
            copies: Vec::new(),
            retired: Cell::new(false),
            new_snapshots: Cell::new(0),
        };
        let mut objects = Vec::new();
        for id in [11, 12] {
            let (target, object) = authority.add_provider(directory.path(), id, &encrypted)?;
            targets.push(target);
            objects.push(object);
        }
        let run = MetadataBackupRun {
            backup_id: source_manifest.backup_id,
            partition_id: source_manifest.partition_id,
            schedule_sequence: 1,
            run_sequence: 1,
            scheduled_for: UnixMicros::new(10),
            minimum_verified_copies: 2,
            minimum_independent_copies: 0,
            state: MetadataBackupRunState::Recorded,
            completed_at: None,
            result_digest: None,
            revision: Revision::new(3),
        };
        Ok(Self {
            directory,
            authority,
            resolver: RegisteredTargetBackupProviderResolver::new(targets)?,
            objects,
            run,
            plaintext,
            encrypted,
            recipient,
        })
    }

    fn local(&self) -> Result<LocalDatabase, RepositoryError> {
        Ok(LocalDatabase::open(
            &self.directory.path().join("local.sqlite3"),
            NodeId::from_bytes([1; 16]).map_err(|_| RepositoryError::BackupMismatch)?,
            UnixMicros::new(1),
        )?)
    }

    fn recover(
        &mut self,
        local: &mut LocalDatabase,
        random: &mut OperatingSystemRandom,
        after: Option<BackupDestinationCursor>,
        page_items: usize,
    ) -> Result<MetadataBackupRecoveryOutcome, MetadataBackupPreparationError> {
        MetadataBackupPreparationService::open(
            &self.authority,
            local,
            random,
            self.directory.path(),
        )?
        .recover(
            &mut self.resolver,
            MetadataBackupRecoveryInput {
                run: self.run,
                after,
                now: UnixMicros::new(20),
                deadline: UnixMicros::new(100),
                page_items,
            },
        )
    }

    fn corrupt(&self, index: usize) -> Result<(), Box<dyn std::error::Error>> {
        let mut changed = self.encrypted.clone();
        changed[70_000] ^= 1;
        fs::write(&self.objects[index], changed)?;
        Ok(())
    }
}

struct Authority {
    evidence: BackupFileEvidence,
    destinations: Vec<BackupDestinationRecord>,
    copies: Vec<BackupCopyRecord>,
    retired: Cell<bool>,
    new_snapshots: Cell<usize>,
}

impl Authority {
    /// Publishes one actual copy and retains its independent expected catalogue evidence.
    fn add_provider(
        &mut self,
        root: &std::path::Path,
        id: u8,
        encrypted: &[u8],
    ) -> Result<(RegisteredBackupTarget, PathBuf), Box<dyn std::error::Error>> {
        let evidence = self.evidence;
        let folder = root.join(format!("provider-{id}"));
        fs::create_dir(&folder)?;
        let destination = destination(id)?;
        let mut provider = DirectoryBackupProvider::open(
            &folder,
            destination.destination_id,
            1,
            1_000_000,
            UnixMicros::new(1),
        )?;
        let receipt = provider.store_exact(
            BackupStoreRequest {
                context: RequestContext {
                    contract_version: ContractVersion::V1_0,
                    operation_id: OperationId::from_bytes([id; 16])?,
                    deadline: UnixMicros::new(100),
                    expected_revision: Some(Revision::new(1)),
                },
                object: BackupObjectIdentity {
                    backup_id: evidence.source.backup_id,
                    destination_id: destination.destination_id,
                    provider_generation: 1,
                    byte_length: evidence.byte_length,
                    digest: evidence.digest,
                },
            },
            &mut Cursor::new(encrypted),
            UnixMicros::new(12),
        )?;
        let object = folder
            .join(".meshspan-backups")
            .join(destination.destination_id.to_string().replace('-', ""))
            .join("objects")
            .join(receipt.object_reference.as_str());
        let target = RegisteredBackupTarget {
            destination_id: destination.destination_id,
            target_id: TargetId::from_bytes([id; 16])?,
            target_generation: 1,
            provider: SharedBackupProvider::new(provider),
        };
        self.copies.push(BackupCopyRecord {
            backup_id: evidence.source.backup_id,
            destination_id: destination.destination_id,
            provider_generation: 1,
            object_reference: receipt.object_reference.as_str().to_owned(),
            byte_length: evidence.byte_length,
            copy_digest: evidence.digest,
            state: BackupCopyState::Stored,
            stored_at: UnixMicros::new(12),
            verified_at: None,
            revision: Revision::new(2),
        });
        self.destinations.push(destination);
        Ok((target, object))
    }
}

impl BackupPublicationAuthority for Authority {
    fn metadata_backup(
        &self,
        backup_id: BackupId,
    ) -> Result<Option<MetadataBackupRecord>, RepositoryError> {
        let evidence = self.evidence;
        let source = evidence.source;
        assert_eq!(backup_id, source.backup_id);
        Ok(Some(MetadataBackupRecord {
            backup_id,
            partition_id: source.partition_id,
            mesh_id: source.mesh_id,
            last_log_index: source.last_log_index,
            last_log_term: source.last_log_term,
            state_revision: Revision::new(source.state_revision),
            schema_version: source.schema_version,
            source_byte_length: source.byte_length,
            source_digest: source.digest,
            manifest_digest: source.catalogue_digest(),
            encrypted_byte_length: evidence.byte_length,
            encrypted_digest: evidence.digest,
            state: if self.retired.get() {
                MetadataBackupState::Retired
            } else {
                MetadataBackupState::Recorded
            },
            created_at: source.created_at,
            verified_at: None,
            revision: Revision::new(3),
        }))
    }
    fn backup_destination(
        &self,
        id: BackupDestinationId,
    ) -> Result<Option<BackupDestinationRecord>, RepositoryError> {
        Ok(self
            .destinations
            .iter()
            .find(|destination| destination.destination_id == id)
            .cloned())
    }
    fn backup_copy(
        &self,
        id: BackupId,
        destination: BackupDestinationId,
    ) -> Result<Option<BackupCopyRecord>, RepositoryError> {
        Ok(self
            .copies
            .iter()
            .find(|copy| copy.backup_id == id && copy.destination_id == destination)
            .cloned())
    }
    fn commit_backup_publication(
        &self,
        _context: CommandContext,
        _command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, meshspan_cluster::MetadataAuthorityRequestError> {
        Err(meshspan_cluster::MetadataAuthorityRequestError::Unavailable)
    }
}

impl MetadataBackupRecoveryAuthority for Authority {
    fn recovery_copies(
        &self,
        id: BackupId,
        after: Option<BackupDestinationCursor>,
        limit: PageLimit,
    ) -> Result<Page<BackupCopyRecord, BackupDestinationCursor>, RepositoryError> {
        let page_items = if limit == PageLimit::new(1)? {
            1
        } else if limit == PageLimit::new(2)? {
            2
        } else {
            return Err(RepositoryError::InvalidPageLimit);
        };
        let mut items: Vec<_> = self
            .copies
            .iter()
            .filter(|copy| {
                copy.backup_id == id
                    && after.is_none_or(|cursor| copy.destination_id > cursor.destination_id)
            })
            .take(page_items + 1)
            .cloned()
            .collect();
        let next = if items.len() > page_items {
            items.truncate(page_items);
            items.last().map(|copy| BackupDestinationCursor {
                destination_id: copy.destination_id,
            })
        } else {
            None
        };
        Ok(Page { items, next })
    }
}

impl MetadataBackupPreparationAuthority for Authority {
    fn create_encrypted_metadata_backup<Random: meshspan_domain::RandomSource>(
        &self,
        _paths: crate::MetadataBackupCapturePaths<'_>,
        _id: BackupId,
        _at: UnixMicros,
        _random: &mut Random,
    ) -> Result<meshspan_metadata::EncryptedPartitionBackupManifest, RepositoryError> {
        self.new_snapshots.set(self.new_snapshots.get() + 1);
        Err(RepositoryError::BackupMismatch)
    }
}

fn destination(id: u8) -> Result<BackupDestinationRecord, Box<dyn std::error::Error>> {
    Ok(BackupDestinationRecord {
        destination_id: BackupDestinationId::from_bytes([id; 16])?,
        display_name: format!("provider {id}"),
        canonical_name: format!("provider {id}"),
        binding: BackupDestinationBinding::RegisteredTarget {
            target_id: TargetId::from_bytes([id; 16])?,
            target_generation: 1,
        },
        failure_relationship: BackupFailureRelationship::Unknown,
        failure_evidence_digest: [1; 32],
        state: BackupDestinationState::Paused,
        created_at: UnixMicros::new(1),
        revision: Revision::new(1),
    })
}
