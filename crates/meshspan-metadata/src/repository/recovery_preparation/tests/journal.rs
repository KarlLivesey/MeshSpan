// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{Revision, UnixMicros};
use meshspan_secret_envelope::WrappingPrivateKey;

use super::{Fixture, TestResult};
use crate::{AuthoritativeRepository, ConsensusStoreError, PartitionDatabase, RepositoryError};

#[test]
fn recovery_control_journal_reopens_exact_keys_and_conflicts_on_regeneration() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.prepare(&fixture.authorization, &fixture.authority)?;
    let dest = fixture.directory.path().join("prepared.sqlite3");
    let mut repo = AuthoritativeRepository::new(PartitionDatabase::open_existing(
        &dest,
        UnixMicros::new(30),
    )?);
    assert_eq!(repo.staged_recovery_control_keys(&fixture.authority)?, None);
    let gateway = WrappingPrivateKey::from_bytes([61; 32])?;
    let mut random = crate::test_support::SequentialRandom(121);
    let material = repo.prepare_recovery_control_keys(
        &fixture.authority,
        &[gateway.public_key()],
        &[],
        &mut random,
    )?;
    let digest =
        repo.stage_recovery_control_keys(&fixture.authority, &material, UnixMicros::new(31))?;
    drop(repo);
    let mut repo = AuthoritativeRepository::new(PartitionDatabase::open_existing(
        &dest,
        UnixMicros::new(32),
    )?);
    assert_eq!(
        repo.staged_recovery_control_keys(&fixture.authority)?,
        Some(material.clone())
    );
    assert_eq!(
        repo.stage_recovery_control_keys(&fixture.authority, &material, UnixMicros::new(33))?,
        digest
    );
    let replacement = repo.prepare_recovery_control_keys(
        &fixture.authority,
        &[gateway.public_key()],
        &[],
        &mut random,
    )?;
    assert!(matches!(
        repo.stage_recovery_control_keys(&fixture.authority, &replacement, UnixMicros::new(34)),
        Err(RepositoryError::OperationConflict)
    ));
    assert_eq!(
        repo.staged_recovery_control_keys(&fixture.authority)?,
        Some(material)
    );
    assert_eq!(repo.current_revision()?, Revision::new(1));
    assert_eq!(
        repo.latest_online_authority_generation(fixture.authority.mesh_id())?,
        Some(1)
    );
    assert_eq!(
        repo.latest_storage_permit_generation(fixture.authority.mesh_id())?,
        Some(1)
    );
    assert!(matches!(
        repo.load_consensus_state(1),
        Err(ConsensusStoreError::RecoveryAdmissionRequired)
    ));
    let db = repo.into_database();
    db.check_integrity()?;
    assert!(
        db.connection()
            .execute("DELETE FROM partition_recovery_control_material", [])
            .is_err()
    );
    assert!(
        db.connection()
            .execute(
                "UPDATE partition_recovery_control_material SET staged_at = 99",
                []
            )
            .is_err()
    );
    let staged: i64 = db.connection().query_row(
        "SELECT staged_at FROM partition_recovery_control_material",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(staged, 31);
    Ok(())
}

#[test]
fn recovery_control_journal_rejects_unprepared_and_mismatched_material_without_writes() -> TestResult
{
    let fixture = Fixture::new()?;
    let mut live = AuthoritativeRepository::new(PartitionDatabase::open_existing(
        &fixture.directory.path().join("live.sqlite3"),
        UnixMicros::new(30),
    )?);
    let gateway = WrappingPrivateKey::from_bytes([62; 32])?;
    let mut random = crate::test_support::SequentialRandom(101);
    let material = live.prepare_recovery_control_keys(
        &fixture.authority,
        &[gateway.public_key()],
        &[],
        &mut random,
    )?;
    assert!(matches!(
        live.stage_recovery_control_keys(&fixture.authority, &material, UnixMicros::new(31)),
        Err(RepositoryError::InvalidCommand)
    ));
    fixture.prepare(&fixture.authorization, &fixture.authority)?;
    let mut repo = AuthoritativeRepository::new(PartitionDatabase::open_existing(
        &fixture.directory.path().join("prepared.sqlite3"),
        UnixMicros::new(32),
    )?);
    let other = repo.prepare_recovery_control_keys(
        &fixture.authority,
        &[gateway.public_key()],
        &[],
        &mut random,
    )?;
    let mut bad_certificate = material.clone();
    bad_certificate.online_certificate_der = other.online_certificate_der;
    let mut bad_generation = material.clone();
    bad_generation.storage_permit_key.secret.context =
        meshspan_secret_envelope::SecretContext::new(
            crate::STORAGE_PERMIT_KEY_SECRET_KIND,
            fixture.authority.mesh_id().as_bytes(),
            99,
        )?;
    let mut missing_recipient = material.clone();
    missing_recipient.storage_permit_key.recipients.pop();
    for invalid in [bad_certificate, bad_generation, missing_recipient] {
        assert!(matches!(
            repo.stage_recovery_control_keys(&fixture.authority, &invalid, UnixMicros::new(33)),
            Err(RepositoryError::InvalidCommand)
        ));
        assert_eq!(repo.staged_recovery_control_keys(&fixture.authority)?, None);
    }
    repo.stage_recovery_control_keys(&fixture.authority, &material, UnixMicros::new(34))?;
    assert_eq!(
        repo.staged_recovery_control_keys(&fixture.authority)?,
        Some(material)
    );
    Ok(())
}

#[test]
fn recovery_control_journal_rolls_back_failed_insert_before_retry() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.prepare(&fixture.authorization, &fixture.authority)?;
    let dest = fixture.directory.path().join("prepared.sqlite3");
    let db = PartitionDatabase::open_existing(&dest, UnixMicros::new(30))?;
    // Fail after SQLite has performed the insert, before its transaction can commit.
    db.connection().execute_batch(
        "CREATE TRIGGER test_recovery_io_failure AFTER INSERT ON partition_recovery_control_material
         BEGIN SELECT RAISE(ABORT, 'injected persistence failure'); END;",
    )?;
    let mut repo = AuthoritativeRepository::new(db);
    let gateway = WrappingPrivateKey::from_bytes([63; 32])?;
    let material = repo.prepare_recovery_control_keys(
        &fixture.authority,
        &[gateway.public_key()],
        &[],
        &mut crate::test_support::SequentialRandom(101),
    )?;
    assert!(
        repo.stage_recovery_control_keys(&fixture.authority, &material, UnixMicros::new(31))
            .is_err()
    );
    drop(repo);
    let db = PartitionDatabase::open_existing(&dest, UnixMicros::new(32))?;
    db.connection()
        .execute_batch("DROP TRIGGER test_recovery_io_failure;")?;
    let mut repo = AuthoritativeRepository::new(db);
    assert_eq!(repo.staged_recovery_control_keys(&fixture.authority)?, None);
    repo.stage_recovery_control_keys(&fixture.authority, &material, UnixMicros::new(33))?;
    assert_eq!(
        repo.staged_recovery_control_keys(&fixture.authority)?,
        Some(material)
    );
    Ok(())
}

#[test]
fn recovery_material_codec_rejects_truncation_trailing_bytes_and_corruption() -> TestResult {
    let fixture = Fixture::new()?;
    let source = AuthoritativeRepository::new(PartitionDatabase::open_existing(
        &fixture.directory.path().join("live.sqlite3"),
        UnixMicros::new(30),
    )?);
    let gateway = WrappingPrivateKey::from_bytes([64; 32])?;
    let material = source.prepare_recovery_control_keys(
        &fixture.authority,
        &[gateway.public_key()],
        &[],
        &mut crate::test_support::SequentialRandom(121),
    )?;
    let encoded = crate::command_codec::recovery_material::encode(&material)?;
    assert_eq!(&encoded[..7], b"MSRKEY\x01");
    assert_eq!(
        crate::command_codec::recovery_material::decode(&encoded)?,
        material
    );
    for end in 0..encoded.len() {
        assert!(crate::command_codec::recovery_material::decode(&encoded[..end]).is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(crate::command_codec::recovery_material::decode(&trailing).is_err());
    let mut corrupt = encoded;
    let last = corrupt.last_mut().ok_or("empty encoding")?;
    *last ^= 1;
    assert!(crate::command_codec::recovery_material::decode(&corrupt).is_err());
    assert!(crate::command_codec::recovery_material::decode(&vec![0; 1024 * 1024 + 1]).is_err());
    Ok(())
}
