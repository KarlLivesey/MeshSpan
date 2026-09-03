// SPDX-License-Identifier: GPL-2.0-only

use std::cell::{Cell, RefCell};
use std::io::{Read, Write};

use meshspan_backup::{BackupFileEvidence, BackupSourceManifest, DirectoryBackupProvider};
use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_contracts::{
    BackupObjectReceipt, BackupProvider, BackupReadReceipt, BackupReadRequest, BackupStoreRequest,
    BackupVerifyRequest, ContractError, ContractKind, ContractLimits, ContractVersion,
    ImplementationDescriptor,
};
use meshspan_domain::{
    BackupDestinationId, BackupId, ComponentInstanceId, MeshId, PartitionId, PrincipalId, Revision,
    UnixMicros,
};
use meshspan_metadata::{
    ApplyDisposition, AuthoritativeCommand, BackupCopyRecord, BackupCopyState,
    BackupDestinationBinding, BackupDestinationRecord, BackupDestinationState,
    BackupFailureRelationship, CommandContext, CommandReceipt, EntityKind, EntityReference,
    LogPosition, MetadataBackupRecord, MetadataBackupState, RepositoryError,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

use crate::{BackupPublicationAuthority, BackupPublicationRequest, MetadataBackupPublisher};

#[test]
fn publication_records_stores_verifies_and_replays_exact_copy()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let directory = tempdir()?;
    let encrypted = directory.path().join("backup.msb");
    std::fs::write(&encrypted, fixture.bytes)?;
    let destination_id = fixture.destination.destination_id;
    let authority = MemoryAuthority::new(fixture.destination);
    let mut provider = MemoryProvider::default();
    let publisher = MetadataBackupPublisher::new(&authority);

    let first = publisher.publish(
        &mut provider,
        BackupPublicationRequest {
            encrypted_source: &encrypted,
            evidence: fixture.evidence,
            destination_id,
            actor_principal_id: fixture.actor,
            now: UnixMicros::new(20),
            deadline: UnixMicros::new(100),
        },
    )?;
    assert_eq!(first.backup.state, MetadataBackupState::Verified);
    assert_eq!(first.copy.state, BackupCopyState::Verified);
    assert_eq!(provider.stores, 1);
    assert_eq!(provider.verifications.get(), 1);

    let replay = publisher.publish(
        &mut provider,
        BackupPublicationRequest {
            encrypted_source: &encrypted,
            evidence: fixture.evidence,
            destination_id,
            actor_principal_id: fixture.actor,
            now: UnixMicros::new(21),
            deadline: UnixMicros::new(101),
        },
    )?;
    assert_eq!(replay, first);
    assert_eq!(provider.stores, 1);
    assert_eq!(provider.verifications.get(), 2);
    assert_eq!(authority.commit_count(), 3);
    Ok(())
}

#[test]
fn publication_uses_real_restartable_directory_provider() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = Fixture::new()?;
    let directory = tempdir()?;
    let encrypted = directory.path().join("backup.msb");
    std::fs::write(&encrypted, fixture.bytes)?;
    let destination_id = fixture.destination.destination_id;
    let authority = MemoryAuthority::new(fixture.destination);
    let publisher = MetadataBackupPublisher::new(&authority);
    let mut provider = DirectoryBackupProvider::open(
        directory.path(),
        destination_id,
        1,
        1_024,
        UnixMicros::new(1),
    )?;
    let request = BackupPublicationRequest {
        encrypted_source: &encrypted,
        evidence: fixture.evidence,
        destination_id,
        actor_principal_id: fixture.actor,
        now: UnixMicros::new(20),
        deadline: UnixMicros::new(100),
    };
    let first = publisher.publish(&mut provider, request)?;
    assert_eq!(first.copy.state, BackupCopyState::Verified);
    drop(provider);

    let mut reopened = DirectoryBackupProvider::open(
        directory.path(),
        destination_id,
        1,
        1_024,
        UnixMicros::new(21),
    )?;
    let replay = publisher.publish(
        &mut reopened,
        BackupPublicationRequest {
            now: UnixMicros::new(21),
            deadline: UnixMicros::new(101),
            ..request
        },
    )?;
    assert_eq!(replay, first);
    assert_eq!(authority.commit_count(), 3);
    Ok(())
}

#[test]
fn corrupt_encrypted_source_never_records_a_copy() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let directory = tempdir()?;
    let encrypted = directory.path().join("backup.msb");
    std::fs::write(&encrypted, b"substituted")?;
    let destination_id = fixture.destination.destination_id;
    let authority = MemoryAuthority::new(fixture.destination);
    let publisher = MetadataBackupPublisher::new(&authority);
    let mut provider = DirectoryBackupProvider::open(
        directory.path(),
        destination_id,
        1,
        1_024,
        UnixMicros::new(1),
    )?;
    let result = publisher.publish(
        &mut provider,
        BackupPublicationRequest {
            encrypted_source: &encrypted,
            evidence: fixture.evidence,
            destination_id,
            actor_principal_id: fixture.actor,
            now: UnixMicros::new(20),
            deadline: UnixMicros::new(100),
        },
    );
    assert!(matches!(
        result,
        Err(crate::BackupPublicationError::Provider(
            ContractError::Corrupt
        ))
    ));
    assert!(authority.copy.borrow().is_none());
    assert_eq!(authority.commit_count(), 1);
    Ok(())
}

struct Fixture {
    bytes: &'static [u8],
    evidence: BackupFileEvidence,
    destination: BackupDestinationRecord,
    actor: PrincipalId,
}

impl Fixture {
    fn new() -> Result<Self, meshspan_domain::IdentifierError> {
        let bytes = b"authenticated encrypted backup".as_slice();
        let backup_id = BackupId::from_bytes([1; 16])?;
        let destination_id = BackupDestinationId::from_bytes([2; 16])?;
        let source = BackupSourceManifest {
            backup_id,
            partition_id: PartitionId::from_bytes([3; 16])?,
            mesh_id: MeshId::from_bytes([4; 16])?,
            last_log_index: 8,
            last_log_term: 2,
            state_revision: 7,
            schema_version: 81,
            byte_length: 1_024,
            digest: [5; 32],
            created_at: UnixMicros::new(10),
        };
        Ok(Self {
            bytes,
            evidence: BackupFileEvidence {
                source,
                byte_length: bytes.len() as u64,
                digest: Sha256::digest(bytes).into(),
            },
            destination: BackupDestinationRecord {
                destination_id,
                display_name: "local backup".to_owned(),
                canonical_name: "local backup".to_owned(),
                binding: BackupDestinationBinding::ComponentProvider {
                    instance_id: ComponentInstanceId::from_bytes([6; 16])?,
                    provider_generation: 1,
                },
                failure_relationship: BackupFailureRelationship::Unknown,
                failure_evidence_digest: [7; 32],
                state: BackupDestinationState::Active,
                created_at: UnixMicros::new(9),
                revision: Revision::new(6),
            },
            actor: PrincipalId::from_bytes([8; 16])?,
        })
    }
}

struct MemoryAuthority {
    destination: BackupDestinationRecord,
    backup: RefCell<Option<MetadataBackupRecord>>,
    copy: RefCell<Option<BackupCopyRecord>>,
    commits: RefCell<usize>,
}

impl MemoryAuthority {
    fn new(destination: BackupDestinationRecord) -> Self {
        Self {
            destination,
            backup: RefCell::new(None),
            copy: RefCell::new(None),
            commits: RefCell::new(0),
        }
    }

    fn commit_count(&self) -> usize {
        *self.commits.borrow()
    }
}

impl BackupPublicationAuthority for MemoryAuthority {
    fn metadata_backup(
        &self,
        backup_id: BackupId,
    ) -> Result<Option<MetadataBackupRecord>, RepositoryError> {
        Ok(self
            .backup
            .borrow()
            .filter(|record| record.backup_id == backup_id))
    }

    fn backup_destination(
        &self,
        destination_id: BackupDestinationId,
    ) -> Result<Option<BackupDestinationRecord>, RepositoryError> {
        Ok((destination_id == self.destination.destination_id).then(|| self.destination.clone()))
    }

    fn backup_copy(
        &self,
        backup_id: BackupId,
        destination_id: BackupDestinationId,
    ) -> Result<Option<BackupCopyRecord>, RepositoryError> {
        Ok(self.copy.borrow().clone().filter(|record| {
            record.backup_id == backup_id && record.destination_id == destination_id
        }))
    }

    fn commit_backup_publication(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, MetadataAuthorityRequestError> {
        *self.commits.borrow_mut() += 1;
        let (kind, id, revision) = match command {
            AuthoritativeCommand::RecordMetadataBackup(value) => {
                *self.backup.borrow_mut() = Some(MetadataBackupRecord {
                    backup_id: value.backup_id,
                    partition_id: value.partition_id,
                    mesh_id: value.mesh_id,
                    last_log_index: value.last_log_index,
                    last_log_term: value.last_log_term,
                    state_revision: value.state_revision,
                    schema_version: value.schema_version,
                    source_byte_length: value.source_byte_length,
                    source_digest: value.source_digest,
                    manifest_digest: value.manifest_digest,
                    encrypted_byte_length: value.encrypted_byte_length,
                    encrypted_digest: value.encrypted_digest,
                    state: MetadataBackupState::Recorded,
                    created_at: context.occurred_at,
                    verified_at: None,
                    revision: Revision::new(10),
                });
                (EntityKind::MetadataBackup, value.backup_id.as_bytes(), 10)
            }
            AuthoritativeCommand::RecordBackupCopy(value) => {
                *self.copy.borrow_mut() = Some(BackupCopyRecord {
                    backup_id: value.backup_id,
                    destination_id: value.destination_id,
                    provider_generation: value.provider_generation,
                    object_reference: value.object_reference.clone(),
                    byte_length: value.byte_length,
                    copy_digest: value.copy_digest,
                    state: BackupCopyState::Stored,
                    stored_at: context.occurred_at,
                    verified_at: None,
                    revision: Revision::new(11),
                });
                (EntityKind::BackupCopy, value.backup_id.as_bytes(), 11)
            }
            AuthoritativeCommand::VerifyBackupCopy(value) => {
                let mut copy = self.copy.borrow_mut();
                let record = copy.as_mut().ok_or(MetadataAuthorityRequestError::Failed)?;
                record.state = BackupCopyState::Verified;
                record.verified_at = Some(context.occurred_at);
                record.revision = Revision::new(12);
                let mut backup = self.backup.borrow_mut();
                let backup = backup
                    .as_mut()
                    .ok_or(MetadataAuthorityRequestError::Failed)?;
                backup.state = MetadataBackupState::Verified;
                backup.verified_at = Some(context.occurred_at);
                backup.revision = Revision::new(12);
                (EntityKind::BackupCopy, value.backup_id.as_bytes(), 12)
            }
            _ => return Err(MetadataAuthorityRequestError::Unsupported),
        };
        Ok(CommandReceipt {
            disposition: ApplyDisposition::Applied,
            operation_id: context.operation_id,
            request_digest: command.request_digest(context),
            result_digest: [9; 32],
            committed_revision: Revision::new(revision),
            committed_position: LogPosition {
                term: 1,
                index: revision,
            },
            applied_position: LogPosition {
                term: 1,
                index: revision,
            },
            entity: EntityReference { kind, id },
        })
    }
}

#[derive(Default)]
struct MemoryProvider {
    bytes: Vec<u8>,
    stores: usize,
    verifications: Cell<usize>,
}

impl BackupProvider for MemoryProvider {
    fn describe(&self) -> ImplementationDescriptor {
        ImplementationDescriptor {
            implementation_id: "memory-backup-test",
            contract: ContractKind::BackupProvider,
            versions: &[ContractVersion::V1_0],
            limits: ContractLimits {
                maximum_control_bytes: 1_024,
                maximum_items: 1,
                maximum_concurrency: 1,
            },
        }
    }

    fn store_exact(
        &mut self,
        request: BackupStoreRequest,
        source: &mut dyn Read,
        _observed_at: UnixMicros,
    ) -> Result<BackupObjectReceipt, ContractError> {
        source
            .read_to_end(&mut self.bytes)
            .map_err(|_| ContractError::Unavailable)?;
        if self.bytes.len() as u64 != request.object.byte_length
            || <[u8; 32]>::from(Sha256::digest(&self.bytes)) != request.object.digest
        {
            return Err(ContractError::Corrupt);
        }
        self.stores += 1;
        Ok(BackupObjectReceipt {
            operation_id: request.context.operation_id,
            object: request.object,
            object_reference: meshspan_contracts::BackupObjectReference::new(
                "memory-object".to_owned(),
            )?,
        })
    }

    fn read_exact(
        &self,
        _request: &BackupReadRequest,
        destination: &mut dyn Write,
        _observed_at: UnixMicros,
    ) -> Result<BackupReadReceipt, ContractError> {
        destination
            .write_all(&self.bytes)
            .map_err(|_| ContractError::Unavailable)?;
        Err(ContractError::InternalContract)
    }

    fn verify_exact(
        &self,
        request: &BackupVerifyRequest,
        _observed_at: UnixMicros,
    ) -> Result<BackupObjectReceipt, ContractError> {
        self.verifications.set(self.verifications.get() + 1);
        if self.bytes.len() as u64 != request.object.byte_length
            || <[u8; 32]>::from(Sha256::digest(&self.bytes)) != request.object.digest
        {
            return Err(ContractError::Corrupt);
        }
        // The counter is checked through interior publication behaviour in the fixture.
        Ok(BackupObjectReceipt {
            operation_id: request.context.operation_id,
            object: request.object,
            object_reference: request.object_reference.clone(),
        })
    }

    fn delete_exact(
        &mut self,
        _request: &meshspan_contracts::BackupDeleteRequest,
        _observed_at: UnixMicros,
    ) -> Result<meshspan_contracts::BackupDeleteReceipt, ContractError> {
        Err(ContractError::InternalContract)
    }
}
