// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{ClaimId, NodeId, Revision, UnixMicros};
use tempfile::tempdir;

use crate::{
    LocalClaimError, LocalClaimMutationDisposition, LocalClaimState, LocalDatabase, NewLocalClaim,
};

#[test]
fn first_claim_is_restart_safe_idempotent_and_exclusive() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let file_path = directory.path().join("local.sqlite3");
    let node = NodeId::from_bytes([9; 16])?;
    let first = claim(1, 11, 20)?;
    let mut database = LocalDatabase::open(&file_path, node, UnixMicros::new(10))?;

    assert_eq!(
        database.create_local_claim(first)?,
        LocalClaimMutationDisposition::Applied
    );
    assert_eq!(
        database.create_local_claim(first)?,
        LocalClaimMutationDisposition::Replayed
    );
    assert_eq!(
        database.create_local_claim(claim(2, 12, 21)?),
        Err(LocalClaimError::Conflict)
    );
    drop(database);
    let reopened = LocalDatabase::open(&file_path, node, UnixMicros::new(30))?;
    assert_eq!(
        reopened.active_local_claim()?.map(|record| record.claim_id),
        Some(first.claim_id)
    );
    Ok(())
}

#[test]
fn rotation_is_atomic_restart_safe_and_exactly_replayable() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let file_path = directory.path().join("local.sqlite3");
    let node = NodeId::from_bytes([9; 16])?;
    let first = claim(1, 11, 20)?;
    let replacement = claim(2, 12, 30)?;
    let mut database = LocalDatabase::open(&file_path, node, UnixMicros::new(10))?;
    database.create_local_claim(first)?;

    database.connection().execute_batch(
        "CREATE TRIGGER reject_claim_replacement
         BEFORE INSERT ON local_claim_bundles
         WHEN NEW.claim_id = X'02020202020202020202020202020202'
         BEGIN SELECT RAISE(ABORT, 'injected replacement failure'); END;",
    )?;
    assert_eq!(
        database.rotate_local_claim(first.claim_id, replacement, UnixMicros::new(25)),
        Err(LocalClaimError::Store)
    );
    assert_eq!(
        database.active_local_claim()?.map(|record| record.claim_id),
        Some(first.claim_id)
    );
    database
        .connection()
        .execute_batch("DROP TRIGGER reject_claim_replacement")?;

    assert_eq!(
        database.rotate_local_claim(first.claim_id, replacement, UnixMicros::new(25))?,
        LocalClaimMutationDisposition::Applied
    );
    drop(database);
    let mut reopened = LocalDatabase::open(&file_path, node, UnixMicros::new(40))?;
    let active = reopened
        .active_local_claim()?
        .ok_or("replacement is not active")?;
    assert_eq!(active.claim_id, replacement.claim_id);
    assert_eq!(active.state, LocalClaimState::Active);
    assert_eq!(active.revision, Revision::new(2));
    let prior = reopened
        .local_claim_record(first.claim_id)?
        .ok_or("rotated claim history is missing")?;
    assert_eq!(prior.state, LocalClaimState::Rotated);
    assert_eq!(prior.rotated_at, Some(UnixMicros::new(25)));
    assert_eq!(prior.revision, Revision::new(2));
    assert_eq!(reopened.latest_local_claim()?, Some(active));
    assert_eq!(
        reopened.rotate_local_claim(first.claim_id, replacement, UnixMicros::new(25))?,
        LocalClaimMutationDisposition::Replayed
    );
    assert_eq!(
        reopened.rotate_local_claim(first.claim_id, claim(3, 13, 30)?, UnixMicros::new(25)),
        Err(LocalClaimError::Conflict)
    );
    Ok(())
}

#[test]
fn consumption_rejects_substitution_and_survives_lost_response()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("local.sqlite3");
    let node = NodeId::from_bytes([9; 16])?;
    let first = claim(1, 11, 20)?;
    let mut database = LocalDatabase::open(&file_path, node, UnixMicros::new(10))?;
    database.create_local_claim(first)?;

    assert_eq!(
        database.consume_local_claim(first.claim_id, [99; 32], UnixMicros::new(30)),
        Err(LocalClaimError::Rejected)
    );
    assert_eq!(
        database.active_local_claim()?.map(|record| record.claim_id),
        Some(first.claim_id)
    );
    assert_eq!(
        database.consume_local_claim(first.claim_id, first.secret_digest, UnixMicros::new(30))?,
        LocalClaimMutationDisposition::Applied
    );
    assert!(database.active_local_claim()?.is_none());
    let consumed = database
        .local_claim_record(first.claim_id)?
        .ok_or("consumed claim history is missing")?;
    assert_eq!(consumed.state, LocalClaimState::Consumed);
    assert_eq!(consumed.consumed_at, Some(UnixMicros::new(30)));
    assert_eq!(consumed.revision, Revision::new(2));
    assert_eq!(database.latest_local_claim()?, Some(consumed));
    drop(database);

    let mut reopened = LocalDatabase::open(&file_path, node, UnixMicros::new(40))?;
    assert_eq!(
        reopened.consume_local_claim(first.claim_id, first.secret_digest, UnixMicros::new(30))?,
        LocalClaimMutationDisposition::Replayed
    );
    assert_eq!(
        reopened.consume_local_claim(first.claim_id, first.secret_digest, UnixMicros::new(31)),
        Err(LocalClaimError::Rejected)
    );
    Ok(())
}

#[test]
fn reads_fail_closed_for_semantically_invalid_persisted_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("local.sqlite3");
    let node = NodeId::from_bytes([9; 16])?;
    let first = claim(1, 11, 20)?;
    let mut database = LocalDatabase::open(&file_path, node, UnixMicros::new(10))?;
    database.create_local_claim(first)?;
    database.connection().execute(
        "UPDATE local_claim_bundles SET secret_digest = ?1 WHERE claim_id = ?2",
        rusqlite::params![[0_u8; 32].as_slice(), first.claim_id.as_bytes().as_slice()],
    )?;

    assert_eq!(database.active_local_claim(), Err(LocalClaimError::Invalid));
    Ok(())
}

fn claim(
    claim_byte: u8,
    secret_byte: u8,
    created_at: i64,
) -> Result<NewLocalClaim, meshspan_domain::IdentifierError> {
    Ok(NewLocalClaim {
        claim_id: ClaimId::from_bytes([claim_byte; 16])?,
        node_public_key_fingerprint: [7; 32],
        secret_digest: [secret_byte; 32],
        created_at: UnixMicros::new(created_at),
    })
}
