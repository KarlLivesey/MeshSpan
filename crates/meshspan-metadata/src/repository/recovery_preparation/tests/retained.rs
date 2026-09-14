// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{Revision, UnixMicros};
use meshspan_secret_envelope::{EncryptedSecret, RecipientKeyEnvelope, WrappingPrivateKey};

use super::{Fixture, TestResult};
use crate::{
    AuthoritativeRepository, CommitSecretGeneration, ConsensusStoreError, PageLimit,
    PartitionDatabase, RepositoryError,
};

#[test]
fn retained_recovery_resumes_and_seals_only_the_complete_exact_inventory() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.prepare(&fixture.authorization, &fixture.authority)?;
    let gateway = WrappingPrivateKey::from_bytes([81; 32])?;
    let mut repo = prepared_repository(&fixture)?;
    stage_control(&mut repo, &fixture, &gateway)?;
    let contexts = repo.secret_generation_contexts(None, PageLimit::new(128)?)?;
    assert_eq!(contexts.items.len(), 3);
    assert_eq!(contexts.next, None);
    let first = *contexts.items.first().ok_or("no source generations")?;
    let mut random = crate::test_support::SequentialRandom(101);
    let retained = repo.prepare_recovery_secret(
        &fixture.authority,
        first,
        &[gateway.public_key()],
        &mut random,
    )?;
    let digest = repo.stage_recovery_secret(&fixture.authority, &retained, UnixMicros::new(32))?;
    assert!(matches!(
        repo.seal_recovery_secret_inventory(&fixture.authority, UnixMicros::new(33)),
        Err(RepositoryError::InvalidCommand)
    ));
    drop(repo);
    let mut repo = prepared_repository(&fixture)?;
    assert_eq!(
        repo.staged_recovery_secret(&fixture.authority, first)?,
        Some(retained.clone())
    );
    assert_eq!(
        repo.stage_recovery_secret(&fixture.authority, &retained, UnixMicros::new(34))?,
        digest
    );
    for context in contexts.items.iter().skip(1) {
        let material = repo.prepare_recovery_secret(
            &fixture.authority,
            *context,
            &[gateway.public_key()],
            &mut random,
        )?;
        repo.stage_recovery_secret(&fixture.authority, &material, UnixMicros::new(35))?;
    }
    let seal = repo.seal_recovery_secret_inventory(&fixture.authority, UnixMicros::new(36))?;
    assert_eq!(seal.generation_count, 3);
    assert_ne!(seal.digest, [0; 32]);
    drop(repo);
    let mut repo = prepared_repository(&fixture)?;
    assert_eq!(
        repo.seal_recovery_secret_inventory(&fixture.authority, UnixMicros::new(37))?,
        seal
    );
    assert_eq!(
        repo.stage_recovery_secret(&fixture.authority, &retained, UnixMicros::new(38))?,
        digest
    );
    assert_eq!(repo.current_revision()?, Revision::new(1));
    assert!(matches!(
        repo.load_consensus_state(1),
        Err(ConsensusStoreError::RecoveryAdmissionRequired)
    ));
    for context in contexts.items {
        verify_replacement_decryption(&repo, &fixture, &gateway, context)?;
    }
    let db = repo.into_database();
    db.check_integrity()?;
    let sealed_at: i64 = db.connection().query_row(
        "SELECT sealed_at FROM partition_recovery_secret_inventory",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(sealed_at, 36);
    Ok(())
}

#[test]
fn retained_recovery_rejects_changed_ciphertext_recipients_and_conflicting_retry() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.prepare(&fixture.authorization, &fixture.authority)?;
    let gateway = WrappingPrivateKey::from_bytes([82; 32])?;
    let other = WrappingPrivateKey::from_bytes([83; 32])?;
    let mut repo = prepared_repository(&fixture)?;
    let context = meshspan_secret_envelope::SecretContext::new(
        crate::AUTHENTICATION_ROOT_KEY_SECRET_KIND,
        fixture.authority.mesh_id().as_bytes(),
        1,
    )?;
    let mut random = crate::test_support::SequentialRandom(111);
    let material = repo.prepare_recovery_secret(
        &fixture.authority,
        context,
        &[gateway.public_key()],
        &mut random,
    )?;
    assert!(matches!(
        repo.stage_recovery_secret(&fixture.authority, &material, UnixMicros::new(31)),
        Err(RepositoryError::InvalidCommand)
    ));
    stage_control(&mut repo, &fixture, &gateway)?;
    let wrong_recipients = repo.prepare_recovery_secret(
        &fixture.authority,
        context,
        &[other.public_key()],
        &mut random,
    )?;
    assert!(matches!(
        repo.stage_recovery_secret(&fixture.authority, &wrong_recipients, UnixMicros::new(32)),
        Err(RepositoryError::InvalidCommand)
    ));
    let (secret, recipients) = meshspan_secret_envelope::encrypt_secret(
        context,
        &[99; 32],
        &[
            gateway.public_key(),
            fixture.authority.public_wrapping_key(),
        ],
        &mut random,
    )?;
    let changed = CommitSecretGeneration {
        secret: secret.parts(),
        recipients: recipients.into_iter().map(|r| r.parts()).collect(),
    };
    assert!(matches!(
        repo.stage_recovery_secret(&fixture.authority, &changed, UnixMicros::new(33)),
        Err(RepositoryError::InvalidCommand)
    ));
    assert_eq!(
        repo.staged_recovery_secret(&fixture.authority, context)?,
        None
    );
    repo.stage_recovery_secret(&fixture.authority, &material, UnixMicros::new(34))?;
    let retry = repo.prepare_recovery_secret(
        &fixture.authority,
        context,
        &[gateway.public_key()],
        &mut random,
    )?;
    assert!(matches!(
        repo.stage_recovery_secret(&fixture.authority, &retry, UnixMicros::new(35)),
        Err(RepositoryError::OperationConflict)
    ));
    assert_eq!(
        repo.staged_recovery_secret(&fixture.authority, context)?,
        Some(material)
    );
    Ok(())
}

fn prepared_repository(
    fixture: &Fixture,
) -> Result<AuthoritativeRepository, Box<dyn std::error::Error>> {
    Ok(AuthoritativeRepository::new(
        PartitionDatabase::open_existing(
            &fixture.directory.path().join("prepared.sqlite3"),
            UnixMicros::new(30),
        )?,
    ))
}

fn verify_replacement_decryption(
    repo: &AuthoritativeRepository,
    fixture: &Fixture,
    gateway: &WrappingPrivateKey,
    context: meshspan_secret_envelope::SecretContext,
) -> TestResult {
    let material = repo
        .staged_recovery_secret(&fixture.authority, context)?
        .ok_or("missing prepared generation")?;
    let original = repo
        .secret_generation(context)?
        .ok_or("source generation removed")?;
    assert_eq!(material.secret, original.secret.parts());
    let envelope = material
        .recipients
        .iter()
        .find(|r| r.recipient_public_key == gateway.public_key().as_bytes())
        .ok_or("gateway envelope missing")?;
    let key = RecipientKeyEnvelope::from_parts(envelope.clone())?.open(gateway)?;
    assert_eq!(
        EncryptedSecret::from_parts(material.secret)?
            .decrypt(&key)?
            .expose(),
        fixture
            .authority
            .open_secret(&original.secret, &original.recipients)?
            .expose()
    );
    Ok(())
}

#[test]
fn recovery_inventory_seal_rolls_back_and_rejects_corruption_after_reopen() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.prepare(&fixture.authorization, &fixture.authority)?;
    let gateway = WrappingPrivateKey::from_bytes([84; 32])?;
    let mut repo = prepared_repository(&fixture)?;
    stage_control(&mut repo, &fixture, &gateway)?;
    let mut random = crate::test_support::SequentialRandom(101);
    for context in repo
        .secret_generation_contexts(None, PageLimit::new(128)?)?
        .items
    {
        let material = repo.prepare_recovery_secret(
            &fixture.authority,
            context,
            &[gateway.public_key()],
            &mut random,
        )?;
        repo.stage_recovery_secret(&fixture.authority, &material, UnixMicros::new(32))?;
    }
    let db = repo.into_database();
    db.connection().execute_batch(
        "CREATE TRIGGER test_seal_failure AFTER INSERT ON partition_recovery_secret_inventory
         BEGIN SELECT RAISE(ABORT, 'injected persistence failure'); END;",
    )?;
    let mut repo = AuthoritativeRepository::new(db);
    assert!(
        repo.seal_recovery_secret_inventory(&fixture.authority, UnixMicros::new(33))
            .is_err()
    );
    drop(repo);
    let db = prepared_repository(&fixture)?.into_database();
    let count: i64 = db.connection().query_row(
        "SELECT COUNT(*) FROM partition_recovery_secret_inventory",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    db.connection()
        .execute_batch("DROP TRIGGER test_seal_failure;")?;
    let mut repo = AuthoritativeRepository::new(db);
    let seal = repo.seal_recovery_secret_inventory(&fixture.authority, UnixMicros::new(34))?;
    assert_eq!(seal.generation_count, 3);
    let db = repo.into_database();
    assert!(
        db.connection()
            .execute("DELETE FROM partition_recovery_secret_material", [])
            .is_err()
    );
    assert!(
        db.connection()
            .execute("DELETE FROM partition_recovery_secret_inventory", [])
            .is_err()
    );
    assert!(
        db.connection()
            .execute(
                "UPDATE partition_recovery_secret_inventory SET inventory_digest = zeroblob(32)",
                []
            )
            .is_err()
    );
    // Simulate damaged persisted bytes in this test-owned copy, bypassing normal SQL guards.
    db.connection().execute_batch(
        "DROP TRIGGER partition_recovery_secret_inventory_immutable;
         UPDATE partition_recovery_secret_inventory SET inventory_digest = zeroblob(32);",
    )?;
    drop(db);
    assert!(matches!(
        prepared_repository(&fixture)?
            .seal_recovery_secret_inventory(&fixture.authority, UnixMicros::new(35)),
        Err(RepositoryError::CorruptState)
    ));
    Ok(())
}

fn stage_control(
    repo: &mut AuthoritativeRepository,
    fixture: &Fixture,
    gateway: &WrappingPrivateKey,
) -> TestResult {
    let material = repo.prepare_recovery_control_keys(
        &fixture.authority,
        &[gateway.public_key()],
        &[],
        &mut crate::test_support::SequentialRandom(121),
    )?;
    repo.stage_recovery_control_keys(&fixture.authority, &material, UnixMicros::new(31))?;
    Ok(())
}
