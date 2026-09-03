// SPDX-License-Identifier: GPL-2.0-only

use std::cell::Cell;
use std::fs;

use meshspan_backup::{BackupFileEvidence, BackupSourceManifest};
use meshspan_domain::{
    BackupId, EntropyError, MeshId, NodeId, PartitionId, RandomSource, Revision, UnixMicros,
};
use meshspan_metadata::{
    EncryptedBackupPaths, EncryptedPartitionBackupManifest, LocalDatabase, MetadataBackupRun,
    MetadataBackupRunState, PartitionBackupManifest, RepositoryError,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

use crate::{
    MetadataBackupPreparationAuthority, MetadataBackupPreparationError,
    MetadataBackupPreparationService,
};

const ENCRYPTED_BYTES: &[u8] = b"authenticated encrypted metadata backup";

#[test]
fn preparation_reuses_exact_journalled_bytes_and_detects_change()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let state_directory = directory.path().join("state");
    fs::create_dir(&state_directory)?;
    set_private_permissions(&state_directory)?;
    let node_id = NodeId::from_bytes([1; 16])?;
    let mut local = LocalDatabase::open(
        &state_directory.join("local.sqlite3"),
        node_id,
        UnixMicros::new(1),
    )?;
    let authority = MemoryAuthority::new();
    let run = run(MetadataBackupRunState::Claimed)?;
    let mut random = FixedRandom;

    let first = MetadataBackupPreparationService::open(
        &authority,
        &mut local,
        &mut random,
        &state_directory,
    )?
    .prepare(run, UnixMicros::new(20))?;
    assert_eq!(authority.calls.get(), 1);
    assert_eq!(fs::read(&first.encrypted_path)?, ENCRYPTED_BYTES);

    let resumed = MetadataBackupPreparationService::open(
        &authority,
        &mut local,
        &mut random,
        &state_directory,
    )?
    .prepare(run, UnixMicros::new(30))?;
    assert_eq!(resumed, first);
    assert_eq!(authority.calls.get(), 1);

    fs::write(&first.encrypted_path, b"substituted")?;
    assert!(matches!(
        MetadataBackupPreparationService::open(
            &authority,
            &mut local,
            &mut random,
            &state_directory,
        )?
        .prepare(run, UnixMicros::new(31)),
        Err(MetadataBackupPreparationError::ChangedStagingFile)
    ));
    Ok(())
}

#[test]
fn recorded_run_without_exact_local_staging_requires_recovery()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let state_directory = directory.path().join("state");
    fs::create_dir(&state_directory)?;
    set_private_permissions(&state_directory)?;
    let mut local = LocalDatabase::open(
        &state_directory.join("local.sqlite3"),
        NodeId::from_bytes([1; 16])?,
        UnixMicros::new(1),
    )?;
    let authority = MemoryAuthority::new();
    let mut random = FixedRandom;
    assert!(matches!(
        MetadataBackupPreparationService::open(
            &authority,
            &mut local,
            &mut random,
            &state_directory,
        )?
        .prepare(run(MetadataBackupRunState::Recorded)?, UnixMicros::new(20)),
        Err(MetadataBackupPreparationError::MissingRecordedStaging)
    ));
    assert_eq!(authority.calls.get(), 0);
    Ok(())
}

struct MemoryAuthority {
    calls: Cell<usize>,
}

impl MemoryAuthority {
    const fn new() -> Self {
        Self {
            calls: Cell::new(0),
        }
    }
}

impl MetadataBackupPreparationAuthority for MemoryAuthority {
    fn create_encrypted_metadata_backup<Random: RandomSource>(
        &self,
        paths: EncryptedBackupPaths<'_>,
        backup_id: BackupId,
        created_at: UnixMicros,
        _random: &mut Random,
    ) -> Result<EncryptedPartitionBackupManifest, RepositoryError> {
        self.calls.set(self.calls.get() + 1);
        fs::write(paths.encrypted_destination, ENCRYPTED_BYTES)
            .map_err(|_| RepositoryError::BackupMismatch)?;
        let encrypted_digest: [u8; 32] = Sha256::digest(ENCRYPTED_BYTES).into();
        let partition = PartitionBackupManifest {
            backup_id,
            partition_id: PartitionId::from_bytes([3; 16])
                .map_err(|_| RepositoryError::BackupMismatch)?,
            mesh_id: MeshId::from_bytes([4; 16]).map_err(|_| RepositoryError::BackupMismatch)?,
            applied_position: meshspan_metadata::LogPosition { index: 8, term: 2 },
            state_revision: Revision::new(9),
            schema_version: 13,
            byte_length: 1_024,
            digest: [5; 32],
            created_at,
        };
        Ok(EncryptedPartitionBackupManifest {
            partition,
            encrypted: BackupFileEvidence {
                source: BackupSourceManifest {
                    backup_id,
                    partition_id: partition.partition_id,
                    mesh_id: partition.mesh_id,
                    last_log_index: partition.applied_position.index,
                    last_log_term: partition.applied_position.term,
                    state_revision: partition.state_revision.get(),
                    schema_version: partition.schema_version,
                    byte_length: partition.byte_length,
                    digest: partition.digest,
                    created_at,
                },
                byte_length: u64::try_from(ENCRYPTED_BYTES.len())
                    .map_err(|_| RepositoryError::BackupMismatch)?,
                digest: encrypted_digest,
            },
        })
    }
}

fn run(
    state: MetadataBackupRunState,
) -> Result<MetadataBackupRun, meshspan_domain::IdentifierError> {
    Ok(MetadataBackupRun {
        backup_id: BackupId::from_bytes([2; 16])?,
        partition_id: PartitionId::from_bytes([3; 16])?,
        schedule_sequence: 1,
        run_sequence: 1,
        scheduled_for: UnixMicros::new(10),
        minimum_verified_copies: 1,
        minimum_independent_copies: 0,
        state,
        completed_at: None,
        result_digest: None,
        revision: Revision::new(1),
    })
}

struct FixedRandom;

impl RandomSource for FixedRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        destination.fill(42);
        Ok(())
    }
}

#[cfg(unix)]
fn set_private_permissions(path: &std::path::Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &std::path::Path) -> Result<(), std::io::Error> {
    Ok(())
}
