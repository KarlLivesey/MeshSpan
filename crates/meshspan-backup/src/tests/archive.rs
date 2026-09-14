// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::{BackupFiles, BackupHistoryFiles, encrypt_backup_files, restore_backup_files};

#[test]
fn archive_restores_all_members_after_originals_are_removed()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Archive::new()?;
    for name in ["metadata", "namespace", "content"] {
        fs::remove_file(fixture.directory.path().join(name))?;
    }
    let restored = fixture.outputs();
    let history =
        restore_backup_files(&fixture.archive(), restored, fixture.evidence, &fixture.key)?
            .ok_or("archive history missing")?;
    assert_eq!(fs::read(restored.metadata)?, [11; 32]);
    assert_eq!(
        fs::read(fixture.directory.path().join("restored-namespace"))?,
        [12; 32]
    );
    assert_eq!(
        fs::read(fixture.directory.path().join("restored-content"))?,
        [13; 32]
    );
    assert_eq!(history.namespace.byte_length, 32);
    assert_eq!(
        history.namespace.digest,
        <[u8; 32]>::from(Sha256::digest([12; 32]))
    );
    assert_eq!(
        history.content.digest,
        <[u8; 32]>::from(Sha256::digest([13; 32]))
    );
    assert!(matches!(
        restore_backup_files(&fixture.archive(), restored, fixture.evidence, &fixture.key),
        Err(BackupError::DestinationExists)
    ));
    assert_eq!(fs::read(restored.metadata)?, [11; 32]);
    Ok(())
}

#[test]
fn discarded_history_is_authenticated_and_member_reordering_is_rejected()
-> Result<(), Box<dyn std::error::Error>> {
    for reorder in [false, true] {
        let fixture = Archive::new()?;
        let mut bytes = fs::read(fixture.archive())?;
        if reorder {
            // Header framing: 8 magic bytes, 2 version bytes, then a big-endian u32 length.
            let offset = 14 + usize::try_from(u32::from_be_bytes(bytes[10..14].try_into()?))?;
            let first = bytes[offset..offset + 48].to_vec();
            let second = bytes[offset + 48..offset + 96].to_vec();
            bytes[offset..offset + 48].copy_from_slice(&second);
            bytes[offset + 48..offset + 96].copy_from_slice(&first);
        } else {
            *bytes.last_mut().ok_or("empty archive")? ^= 1;
        }
        fs::write(fixture.archive(), &bytes)?;
        let evidence = BackupFileEvidence {
            digest: Sha256::digest(&bytes).into(),
            ..fixture.evidence
        };
        assert!(matches!(
            restore_backup(
                &fixture.archive(),
                fixture.outputs().metadata,
                evidence,
                &fixture.key
            ),
            Err(BackupError::Corrupt)
        ));
    }
    Ok(())
}

#[test]
fn metadata_only_backup_cannot_claim_requested_history() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Archive::new()?;
    let metadata_only = fixture.directory.path().join("metadata-only");
    let evidence = encrypt_backup(
        &fixture.directory.path().join("metadata"),
        &metadata_only,
        manifest(&[11; 32])?,
        &[fixture.key.public_key()],
        &mut DeterministicRandom::new(67),
    )?;
    assert!(matches!(
        restore_backup_files(&metadata_only, fixture.outputs(), evidence, &fixture.key),
        Err(BackupError::InvalidInput)
    ));
    assert!(!fixture.outputs().metadata.exists());
    Ok(())
}

struct Archive {
    directory: tempfile::TempDir,
    metadata: std::path::PathBuf,
    namespace: std::path::PathBuf,
    content: std::path::PathBuf,
    key: WrappingPrivateKey,
    evidence: BackupFileEvidence,
}

impl Archive {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let key = WrappingPrivateKey::from_bytes([28; 32])?;
        for (name, byte) in [("metadata", 11), ("namespace", 12), ("content", 13)] {
            fs::write(directory.path().join(name), [byte; 32])?;
        }
        let evidence = encrypt_backup_files(
            BackupFiles {
                metadata: &directory.path().join("metadata"),
                history: Some(BackupHistoryFiles {
                    namespace: &directory.path().join("namespace"),
                    content: &directory.path().join("content"),
                }),
            },
            &directory.path().join("archive"),
            manifest(&[11; 32])?,
            &[key.public_key()],
            &mut DeterministicRandom::new(66),
        )?;
        Ok(Self {
            metadata: directory.path().join("restored-metadata"),
            namespace: directory.path().join("restored-namespace"),
            content: directory.path().join("restored-content"),
            directory,
            key,
            evidence,
        })
    }

    fn archive(&self) -> std::path::PathBuf {
        self.directory.path().join("archive")
    }

    fn outputs(&self) -> BackupFiles<'_> {
        BackupFiles {
            metadata: &self.metadata,
            history: Some(BackupHistoryFiles {
                namespace: &self.namespace,
                content: &self.content,
            }),
        }
    }
}
