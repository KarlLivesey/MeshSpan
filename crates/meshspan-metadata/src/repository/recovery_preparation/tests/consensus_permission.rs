// SPDX-License-Identifier: GPL-2.0-only

use super::{
    TestResult,
    key_transfer::{Transfer, recovery_time},
};
use crate::{AuthoritativeRepository, ConsensusStoreError, RepositoryError};
use meshspan_domain::Revision;
use meshspan_recovery_bundle::{RecoveryStateTransfer, RecoveryStateTransferClaims};

#[test]
fn consensus_permission_requires_installed_state_and_retains_one_decision() -> TestResult {
    let fixture = Transfer::new()?;
    let authority = &fixture.candidate.fixture.authority;
    let expected = transfer(&fixture, 41)?;
    let mut repository = fixture.candidate.reopen()?;
    assert!(
        repository
            .authorize_recovery_consensus(
                authority,
                std::slice::from_ref(&expected),
                recovery_time(60)
            )
            .is_err()
    );
    record(&fixture, &mut repository, &expected)?;
    let permission = repository.authorize_recovery_consensus(
        authority,
        std::slice::from_ref(&expected),
        recovery_time(70),
    )?;
    drop(repository);
    let mut repository = fixture.candidate.reopen()?;
    assert_eq!(
        repository
            .authorize_recovery_consensus(
                authority,
                std::slice::from_ref(&expected),
                recovery_time(80)
            )?
            .encode()?,
        permission.encode()?
    );
    assert_eq!(permission.claims().state_digest, [41; 32]);
    let later = transfer(&fixture, 42)?;
    record(&fixture, &mut repository, &later)?;
    assert!(matches!(
        repository.authorize_recovery_consensus(authority, &[later], recovery_time(90)),
        Err(RepositoryError::OperationConflict)
    ));
    assert_eq!(repository.current_revision()?, Revision::new(1));
    assert!(matches!(
        repository.load_consensus_state(2),
        Err(ConsensusStoreError::RecoveryAdmissionRequired)
    ));
    let sql = repository.database.connection();
    assert_eq!(
        sql.query_row(
            "SELECT recorded_at FROM partition_recovery_consensus_permission",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        recovery_time(70).get()
    );
    assert!(
        sql.execute("DELETE FROM partition_recovery_consensus_permission", [])
            .is_err()
    );
    assert!(
        sql.execute(
            "UPDATE partition_recovery_consensus_permission SET recorded_at = 0",
            []
        )
        .is_err()
    );
    repository.into_database().check_integrity()?;
    Ok(())
}

#[test]
fn consensus_permission_failed_commit_does_not_leave_a_decision() -> TestResult {
    let fixture = Transfer::new()?;
    let authority = &fixture.candidate.fixture.authority;
    let mut repository = fixture.candidate.reopen()?;
    let expected = transfer(&fixture, 43)?;
    record(&fixture, &mut repository, &expected)?;
    assert!(
        repository
            .authorize_recovery_consensus(
                authority,
                std::slice::from_ref(&expected),
                recovery_time(59)
            )
            .is_err()
    );
    repository.database.connection().execute_batch("CREATE TRIGGER fail_permission BEFORE INSERT ON partition_recovery_consensus_permission BEGIN SELECT RAISE(ABORT, 'injected'); END;")?;
    assert!(
        repository
            .authorize_recovery_consensus(
                authority,
                std::slice::from_ref(&expected),
                recovery_time(70)
            )
            .is_err()
    );
    repository
        .database
        .connection()
        .execute_batch("DROP TRIGGER fail_permission")?;
    drop(repository);
    let mut repository = fixture.candidate.reopen()?;
    assert_eq!(
        repository.database.connection().query_row(
            "SELECT COUNT(*) FROM partition_recovery_consensus_permission",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        0
    );
    repository.authorize_recovery_consensus(authority, &[expected], recovery_time(80))?;
    repository.into_database().check_integrity()?;
    Ok(())
}

#[test]
fn consensus_permission_migration_preserves_existing_signed_receipts() -> TestResult {
    let fixture = Transfer::new()?;
    let transfer = transfer(&fixture, 44)?;
    let authorization = &transfer.claims().authorization;
    let claims = authorization.claims();
    let signature = fixture
        .candidate
        .identity
        .sign_enrolment_transcript(&transfer.installation_message()?)?;
    let mut connection = rusqlite::Connection::open_in_memory()?;
    connection.pragma_update(None, "foreign_keys", true)?;
    crate::migration::migrate_partition_through(&mut connection, 115, 1)?;
    connection.execute(
        "INSERT INTO meshes VALUES (?1, 'Recovery', 'recovery', 1, 1, 1, 1, 1)",
        [claims.mesh_id.as_bytes().as_slice()],
    )?;
    connection.execute(
        "INSERT INTO partition_recovery_preparation VALUES
        (1, ?1, ?2, ?3, ?4, ?5, ?6, 1)",
        rusqlite::params![
            claims.partition_id.as_bytes().as_slice(),
            claims.mesh_id.as_bytes().as_slice(),
            claims.recovery_id.as_bytes().as_slice(),
            i64::try_from(claims.recovery_epoch)?,
            claims.backup_id.as_bytes().as_slice(),
            authorization.encode()?
        ],
    )?;
    connection.execute(
        "INSERT INTO partition_recovery_state_installations VALUES (?1, ?2, 1, ?3, ?4, 2)",
        rusqlite::params![
            transfer.claims().node_id.as_bytes().as_slice(),
            transfer.claims().state_digest.as_slice(),
            transfer.encode()?,
            signature
        ],
    )?;
    crate::migration::migrate_partition_through(&mut connection, 116, 3)?;
    let stored = connection.query_row(
        "SELECT transfer, signature, recorded_at FROM partition_recovery_state_installations",
        [],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
            ))
        },
    )?;
    assert_eq!(stored, (transfer.encode()?, signature, 2));
    assert_eq!(
        connection.query_row(
            "SELECT COUNT(*) FROM partition_recovery_consensus_permission",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        0
    );
    assert_eq!(
        connection.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get::<_, i64>(0)
        })?,
        0
    );
    assert_eq!(
        connection.pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0))?,
        116
    );
    Ok(())
}

pub(super) fn transfer(
    fixture: &Transfer,
    digest: u8,
) -> Result<RecoveryStateTransfer, Box<dyn std::error::Error>> {
    let authority = &fixture.candidate.fixture.authority;
    let verified = fixture.verify(&fixture.bytes, &fixture.key)?;
    Ok(
        authority.authorize_state_transfer(RecoveryStateTransferClaims {
            authorization: fixture
                .candidate
                .reopen()?
                .recovery_preparation_authorization(authority)?,
            node_id: fixture.recipient.node_id,
            incarnation: fixture
                .candidate
                .plan
                .nodes
                .first()
                .ok_or("node absent")?
                .incarnation,
            state_digest: [digest; 32],
            state_length: 4096,
            key_bundle_digest: verified.bundle_digest(),
            key_bundle_length: u64::try_from(fixture.bytes.len())?,
        })?,
    )
}

fn record(
    fixture: &Transfer,
    repository: &mut AuthoritativeRepository,
    expected: &RecoveryStateTransfer,
) -> TestResult {
    let signature = fixture
        .candidate
        .identity
        .sign_enrolment_transcript(&expected.installation_message()?)?;
    repository.record_recovery_state_installation(
        &fixture.candidate.fixture.authority,
        expected,
        &signature,
        recovery_time(60),
    )?;
    Ok(())
}
