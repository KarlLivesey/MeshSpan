// SPDX-License-Identifier: GPL-2.0-only

use std::fs;

use meshspan_domain::{BackupId, EntropyError, PartitionId, RandomSource, UnixMicros, uuid_v8};
use meshspan_secret_envelope::WrappingPrivateKey;
use sha2::{Digest, Sha256};

use crate::{
    BackupError, BackupFileEvidence, BackupSourceManifest, encrypt_backup, restore_backup,
};

#[test]
fn two_recovery_recipients_restore_exact_streamed_bytes() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempfile::tempdir()?;
    let source = directory.path().join("partition.sqlite3");
    let encrypted = directory.path().join("partition.msbackup");
    let restored = directory.path().join("restored.sqlite3");
    let bytes = source_bytes();
    fs::write(&source, &bytes)?;
    let first = WrappingPrivateKey::from_bytes([21; 32])?;
    let second = WrappingPrivateKey::from_bytes([22; 32])?;
    let evidence = encrypt_backup(
        &source,
        &encrypted,
        manifest(&bytes)?,
        &[first.public_key(), second.public_key()],
        &mut DeterministicRandom::new(31),
    )?;

    restore_backup(&encrypted, &restored, evidence, &second)?;
    assert_eq!(fs::read(restored)?, bytes);
    assert!(evidence.byte_length > evidence.source.byte_length);
    Ok(())
}

#[test]
fn wrong_recipient_cannot_create_plaintext_destination() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let source = directory.path().join("partition.sqlite3");
    let encrypted = directory.path().join("partition.msbackup");
    let restored = directory.path().join("restored.sqlite3");
    let bytes = source_bytes();
    fs::write(&source, &bytes)?;
    let recipient = WrappingPrivateKey::from_bytes([23; 32])?;
    let evidence = encrypt_backup(
        &source,
        &encrypted,
        manifest(&bytes)?,
        &[recipient.public_key()],
        &mut DeterministicRandom::new(41),
    )?;

    assert!(matches!(
        restore_backup(
            &encrypted,
            &restored,
            evidence,
            &WrappingPrivateKey::from_bytes([24; 32])?
        ),
        Err(BackupError::RecipientUnavailable)
    ));
    assert!(!restored.exists());
    Ok(())
}

#[test]
fn changed_ciphertext_fails_authentication_even_with_updated_file_digest()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let source = directory.path().join("partition.sqlite3");
    let encrypted = directory.path().join("partition.msbackup");
    let restored = directory.path().join("restored.sqlite3");
    let bytes = source_bytes();
    fs::write(&source, &bytes)?;
    let recipient = WrappingPrivateKey::from_bytes([25; 32])?;
    let evidence = encrypt_backup(
        &source,
        &encrypted,
        manifest(&bytes)?,
        &[recipient.public_key()],
        &mut DeterministicRandom::new(51),
    )?;
    let mut changed = fs::read(&encrypted)?;
    let last = changed.last_mut().ok_or("empty backup")?;
    *last ^= 0x40;
    fs::write(&encrypted, &changed)?;
    let changed_evidence = BackupFileEvidence {
        byte_length: u64::try_from(changed.len())?,
        digest: Sha256::digest(&changed).into(),
        ..evidence
    };

    assert!(matches!(
        restore_backup(&encrypted, &restored, changed_evidence, &recipient),
        Err(BackupError::Corrupt)
    ));
    Ok(())
}

#[test]
fn exact_source_manifest_and_new_destination_are_mandatory()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let source = directory.path().join("partition.sqlite3");
    let encrypted = directory.path().join("partition.msbackup");
    let restored = directory.path().join("restored.sqlite3");
    let bytes = source_bytes();
    fs::write(&source, &bytes)?;
    let recipient = WrappingPrivateKey::from_bytes([26; 32])?;
    let evidence = encrypt_backup(
        &source,
        &encrypted,
        manifest(&bytes)?,
        &[recipient.public_key()],
        &mut DeterministicRandom::new(61),
    )?;
    let changed_evidence = BackupFileEvidence {
        source: BackupSourceManifest {
            state_revision: evidence.source.state_revision + 1,
            ..evidence.source
        },
        ..evidence
    };
    assert!(matches!(
        restore_backup(&encrypted, &restored, changed_evidence, &recipient),
        Err(BackupError::Corrupt)
    ));

    fs::write(&restored, b"existing")?;
    assert!(matches!(
        restore_backup(&encrypted, &restored, evidence, &recipient),
        Err(BackupError::DestinationExists)
    ));
    assert_eq!(fs::read(restored)?, b"existing");
    Ok(())
}

fn source_bytes() -> Vec<u8> {
    (0_u8..=250).cycle().take(2 * 1_048_576 + 73).collect()
}

fn manifest(bytes: &[u8]) -> Result<BackupSourceManifest, Box<dyn std::error::Error>> {
    Ok(BackupSourceManifest {
        backup_id: BackupId::from_bytes(uuid_v8([1; 16]))?,
        partition_id: PartitionId::from_bytes(uuid_v8([2; 16]))?,
        last_log_index: 41,
        last_log_term: 7,
        state_revision: 89,
        schema_version: 3,
        byte_length: u64::try_from(bytes.len())?,
        digest: Sha256::digest(bytes).into(),
        created_at: UnixMicros::new(1_700_000_000_000_000),
    })
}

struct DeterministicRandom {
    next: u8,
}

impl DeterministicRandom {
    const fn new(next: u8) -> Self {
        Self { next }
    }
}

impl RandomSource for DeterministicRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        for byte in destination {
            *byte = self.next;
            self.next = self.next.wrapping_add(1);
            if self.next == 0 {
                self.next = 1;
            }
        }
        Ok(())
    }
}
