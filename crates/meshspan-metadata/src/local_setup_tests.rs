// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{ClaimId, NodeId, OperationId, UnixMicros};
use tempfile::tempdir;

use crate::{
    LocalClaimState, LocalDatabase, LocalSetupDisposition, LocalSetupError, LocalSetupKind,
    LocalSetupState, NewLocalClaim, NewLocalSetup,
};

#[test]
fn preparation_verifies_claim_and_binds_one_exact_request() -> Result<(), Box<dyn std::error::Error>>
{
    let (_directory, mut database, setup) = fixture()?;
    let mut substituted = setup;
    substituted.claim_secret_digest = [99; 32];
    assert_eq!(
        database.prepare_local_setup(substituted),
        Err(LocalSetupError::ClaimRejected)
    );
    assert_eq!(
        database.prepare_local_setup(setup)?,
        LocalSetupDisposition::Applied
    );
    let mut later_retry = setup;
    later_retry.created_at = UnixMicros::new(99);
    assert_eq!(
        database.prepare_local_setup(later_retry)?,
        LocalSetupDisposition::Replayed
    );
    let mut changed = setup;
    changed.request_digest = [55; 32];
    assert_eq!(
        database.prepare_local_setup(changed),
        Err(LocalSetupError::Conflict)
    );
    let record = database.local_setup()?.ok_or("setup missing")?;
    assert_eq!(record.state, LocalSetupState::Prepared);
    assert_eq!(record.request_digest, setup.request_digest);
    assert_eq!(
        database
            .local_claim_record(setup.claim_id)?
            .ok_or("claim missing")?
            .state,
        LocalClaimState::Active
    );
    Ok(())
}

#[test]
fn completion_requires_authority_and_consumes_claim_atomically()
-> Result<(), Box<dyn std::error::Error>> {
    let (_directory, mut database, setup) = fixture()?;
    database.prepare_local_setup(setup)?;
    assert_eq!(
        database.complete_local_setup(
            setup.operation_id,
            setup.claim_id,
            setup.claim_secret_digest,
            UnixMicros::new(30),
        ),
        Err(LocalSetupError::Conflict)
    );
    assert_eq!(
        database.record_local_setup_authority_commit(
            setup.operation_id,
            [44; 32],
            UnixMicros::new(20),
        )?,
        LocalSetupDisposition::Applied
    );
    assert_eq!(
        database.record_local_setup_authority_commit(
            setup.operation_id,
            [44; 32],
            UnixMicros::new(21),
        )?,
        LocalSetupDisposition::Replayed
    );
    let mut later_retry = setup;
    later_retry.created_at = UnixMicros::new(99);
    assert_eq!(
        database.prepare_local_setup(later_retry)?,
        LocalSetupDisposition::Replayed
    );
    assert_eq!(
        database.complete_local_setup(
            setup.operation_id,
            setup.claim_id,
            setup.claim_secret_digest,
            UnixMicros::new(30),
        )?,
        LocalSetupDisposition::Applied
    );
    assert_eq!(
        database.complete_local_setup(
            setup.operation_id,
            setup.claim_id,
            setup.claim_secret_digest,
            UnixMicros::new(31),
        )?,
        LocalSetupDisposition::Replayed
    );
    assert_eq!(
        database.local_setup()?.ok_or("setup missing")?.state,
        LocalSetupState::Configured
    );
    assert_eq!(
        database
            .local_claim_record(setup.claim_id)?
            .ok_or("claim missing")?
            .state,
        LocalClaimState::Consumed
    );
    Ok(())
}

#[test]
fn failed_terminal_journal_write_rolls_back_claim_consumption()
-> Result<(), Box<dyn std::error::Error>> {
    let (_directory, mut database, setup) = fixture()?;
    database.prepare_local_setup(setup)?;
    database.record_local_setup_authority_commit(
        setup.operation_id,
        [44; 32],
        UnixMicros::new(20),
    )?;
    database.connection_mut().execute_batch(
        "CREATE TRIGGER reject_setup_completion
         BEFORE UPDATE OF state ON local_setup_operations
         WHEN NEW.state = 3
         BEGIN
             SELECT RAISE(ABORT, 'injected completion failure');
         END;",
    )?;
    assert_eq!(
        database.complete_local_setup(
            setup.operation_id,
            setup.claim_id,
            setup.claim_secret_digest,
            UnixMicros::new(30),
        ),
        Err(LocalSetupError::Store)
    );
    assert_eq!(
        database
            .local_claim_record(setup.claim_id)?
            .ok_or("claim missing")?
            .state,
        LocalClaimState::Active
    );
    assert_eq!(
        database.local_setup()?.ok_or("setup missing")?.state,
        LocalSetupState::AuthorityCommitted
    );
    database
        .connection_mut()
        .execute_batch("DROP TRIGGER reject_setup_completion")?;
    assert_eq!(
        database.complete_local_setup(
            setup.operation_id,
            setup.claim_id,
            setup.claim_secret_digest,
            UnixMicros::new(30),
        )?,
        LocalSetupDisposition::Applied
    );
    Ok(())
}

fn fixture() -> Result<(tempfile::TempDir, LocalDatabase, NewLocalSetup), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let node_id = NodeId::from_bytes([1; 16])?;
    let mut database = LocalDatabase::open(
        &directory.path().join("local.sqlite3"),
        node_id,
        UnixMicros::new(1),
    )?;
    let claim_id = ClaimId::from_bytes([2; 16])?;
    database.create_local_claim(NewLocalClaim {
        claim_id,
        node_public_key_fingerprint: [3; 32],
        secret_digest: [4; 32],
        created_at: UnixMicros::new(10),
    })?;
    let setup = NewLocalSetup {
        operation_id: OperationId::from_bytes([5; 16])?,
        claim_id,
        claim_secret_digest: [4; 32],
        kind: LocalSetupKind::CreateMesh,
        request_digest: [6; 32],
        created_at: UnixMicros::new(11),
    };
    Ok((directory, database, setup))
}
