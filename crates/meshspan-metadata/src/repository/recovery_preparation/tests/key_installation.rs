// SPDX-License-Identifier: GPL-2.0-only

use meshspan_certificates::NodeIdentityKey;
use meshspan_domain::{NodeId, Revision};
use rusqlite::params;

use super::{
    TestResult,
    key_transfer::{Transfer, recovery_time},
};
use crate::{ConsensusStoreError, RecoveryKeyBundleError};

#[test]
fn recovery_key_installation_records_exact_node_attestation_across_reopen() -> TestResult {
    let fixture = Transfer::new()?;
    let node = fixture.recipient.node_id;
    let authority = &fixture.candidate.fixture.authority;
    let verified = fixture.verify(&fixture.bytes, &fixture.key)?;
    let message = verified.installation_message();
    let plan = &fixture.candidate.plan;
    let mut expected = b"MeshSpan recovery key installation v3\0".to_vec();
    for id in [
        plan.mesh_id.as_bytes(),
        plan.partition_id.as_bytes(),
        plan.recovery_id.as_bytes(),
    ] {
        expected.extend_from_slice(&id);
    }
    expected.extend_from_slice(&1_u64.to_be_bytes());
    expected.extend_from_slice(&node.as_bytes());
    expected.extend_from_slice(&1_u64.to_be_bytes());
    expected.extend_from_slice(
        &fixture
            .candidate
            .fixture
            .authorization
            .claims()
            .replacement_manifest_digest,
    );
    expected.extend_from_slice(&verified.bundle_digest());
    expected.extend_from_slice(&5_u64.to_be_bytes());
    assert_eq!(message, expected);
    let signature = fixture
        .candidate
        .identity
        .sign_enrolment_transcript(&message)?;
    let mut repo = fixture.candidate.reopen()?;
    assert_eq!(repo.recovery_key_installation(authority, node)?, None);
    let receipt =
        repo.record_recovery_key_installation(authority, node, &signature, recovery_time(60))?;
    assert_eq!(receipt.bundle_digest, verified.bundle_digest());
    assert_eq!(receipt.node_id, node);
    assert_eq!(receipt.recorded_at, recovery_time(60));
    drop(repo);
    let mut repo = fixture.candidate.reopen()?;
    assert_eq!(
        repo.recovery_key_installation(authority, node)?,
        Some(receipt.clone())
    );
    assert_eq!(
        repo.record_recovery_key_installation(authority, node, &signature, recovery_time(70))?,
        receipt
    );
    assert_eq!(repo.current_revision()?, Revision::new(1));
    assert!(matches!(
        repo.load_consensus_state(2),
        Err(ConsensusStoreError::RecoveryAdmissionRequired)
    ));
    repo.into_database().check_integrity()?;
    Ok(())
}

#[test]
fn recovery_key_installation_rejects_forged_and_substituted_claims() -> TestResult {
    let fixture = Transfer::new()?;
    let node = fixture.recipient.node_id;
    let authority = &fixture.candidate.fixture.authority;
    let message = fixture
        .verify(&fixture.bytes, &fixture.key)?
        .installation_message();
    let signature = fixture
        .candidate
        .identity
        .sign_enrolment_transcript(&message)?;
    let mut substituted = message.clone();
    *substituted.last_mut().ok_or("missing count")? ^= 1;
    let wrong_count = fixture
        .candidate
        .identity
        .sign_enrolment_transcript(&substituted)?;
    let forged = NodeIdentityKey::generate()?.sign_enrolment_transcript(&message)?;
    let mut repo = fixture.candidate.reopen()?;
    for bad in [forged, wrong_count, vec![0; 73], Vec::new()] {
        assert!(
            repo.record_recovery_key_installation(authority, node, &bad, recovery_time(60))
                .is_err()
        );
        assert_eq!(repo.recovery_key_installation(authority, node)?, None);
    }
    assert!(matches!(
        repo.record_recovery_key_installation(authority, node, &signature, recovery_time(49)),
        Err(RecoveryKeyBundleError::Invalid)
    ));
    assert!(
        repo.record_recovery_key_installation(
            authority,
            NodeId::from_bytes([99; 16])?,
            &signature,
            recovery_time(60)
        )
        .is_err()
    );
    assert_eq!(repo.recovery_key_installation(authority, node)?, None);
    repo.record_recovery_key_installation(authority, node, &signature, recovery_time(60))?;
    assert!(
        repo.record_recovery_key_installation(authority, node, &[0; 64], recovery_time(70))
            .is_err()
    );
    assert_eq!(
        repo.recovery_key_installation(authority, node)?
            .ok_or("receipt absent")?
            .recorded_at,
        recovery_time(60)
    );
    Ok(())
}

#[test]
fn recovery_key_installation_rolls_back_failed_write_and_revalidates_stored_proof() -> TestResult {
    let fixture = Transfer::new()?;
    let node = fixture.recipient.node_id;
    let authority = &fixture.candidate.fixture.authority;
    let message = fixture
        .verify(&fixture.bytes, &fixture.key)?
        .installation_message();
    let signature = fixture
        .candidate
        .identity
        .sign_enrolment_transcript(&message)?;
    let mut repo = fixture.candidate.reopen()?;
    repo.database.connection().execute_batch(
        "CREATE TRIGGER fail_installation AFTER INSERT ON partition_recovery_key_installations
         BEGIN SELECT RAISE(ABORT, 'injected persistence failure'); END;",
    )?;
    assert!(
        repo.record_recovery_key_installation(authority, node, &signature, recovery_time(60))
            .is_err()
    );
    drop(repo);
    let mut repo = fixture.candidate.reopen()?;
    assert_eq!(repo.recovery_key_installation(authority, node)?, None);
    repo.database
        .connection()
        .execute_batch("DROP TRIGGER fail_installation")?;
    repo.record_recovery_key_installation(authority, node, &signature, recovery_time(70))?;
    assert!(
        repo.database
            .connection()
            .execute("DELETE FROM partition_recovery_key_installations", [])
            .is_err()
    );
    assert!(
        repo.database
            .connection()
            .execute(
                "UPDATE partition_recovery_key_installations SET recorded_at = 1",
                []
            )
            .is_err()
    );
    // Simulate damaged persisted evidence, not an authorised application update.
    repo.database
        .connection()
        .execute_batch("DROP TRIGGER partition_recovery_key_installations_immutable")?;
    repo.database.connection().execute(
        "UPDATE partition_recovery_key_installations SET signature = ?1",
        params![[0_u8; 64].as_slice()],
    )?;
    drop(repo);
    let mut repo = fixture.candidate.reopen()?;
    assert!(repo.recovery_key_installation(authority, node).is_err());
    assert!(
        repo.record_recovery_key_installation(authority, node, &signature, recovery_time(80))
            .is_err()
    );
    Ok(())
}
