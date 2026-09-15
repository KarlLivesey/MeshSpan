// SPDX-License-Identifier: GPL-2.0-only

use super::{
    TestResult,
    consensus_permission::transfer,
    key_transfer::{Transfer, recovery_time},
};
use crate::{AuthoritativeRepository, ConsensusStoreError};
use meshspan_consensus::{DurableMutation, LogEntry, LogPosition};
use meshspan_domain::{OperationId, Revision};
use meshspan_recovery_bundle::{
    RecoveryConsensusAdmission, RecoveryConsensusAdmissionClaims, RecoveryStateTransfer,
};

#[test]
fn recovery_consensus_activation_preserves_applied_history_and_resumes_normal_votes() -> TestResult
{
    let fixture = Transfer::new()?;
    let (delivery, permission) = permission(&fixture)?;
    let root = fixture.candidate.fixture.authority.root_certificate_der();
    let mut repository = fixture.candidate.reopen()?;
    let original = super::super::super::consensus::load_state_from_connection(
        repository.database.connection(),
        &fixture.candidate.plan.partition_id.as_bytes(),
        1,
    )?;
    inject_unapplied_tail(&repository)?;
    repository.materialise_recovery_node_keys(&fixture.candidate.fixture.authority)?;
    assert_eq!(
        repository.activate_recovery_consensus(root, &permission, &delivery, recovery_time(70))?,
        Revision::new(2)
    );
    drop(repository);
    let mut repository = fixture.candidate.reopen()?;
    let state = repository.load_consensus_state(2)?;
    assert_eq!(state.current_term, 2);
    assert_eq!(state.voted_for, None);
    assert_eq!(state.applied_index, 1);
    assert_eq!(state.log, original.log);
    assert_eq!(repository.current_revision()?, Revision::new(2));
    assert_eq!(
        repository.load_active_consensus_quorum_plan()?,
        Some(fixture.candidate.plan.quorum.clone())
    );
    assert_eq!(
        repository.recovery_consensus_admission(root)?,
        Some(permission.clone())
    );
    assert!(matches!(
        repository.load_consensus_state(1),
        Err(ConsensusStoreError::MembershipEpochMismatch)
    ));
    verify_membership(&repository, fixture.recipient.node_id.as_bytes())?;
    repository.persist_consensus_mutation(
        2,
        &DurableMutation {
            vote_state: Some((3, Some(fixture.recipient.node_id))),
            truncate_from: None,
            append: vec![LogEntry::new(
                LogPosition { index: 2, term: 3 },
                OperationId::from_bytes([88; 16])?,
                1,
                vec![1, 2, 3],
            )?],
            membership_epoch: None,
            quorum_plan: None,
        },
        recovery_time(80),
    )?;
    let advanced = repository.load_consensus_state(2)?;
    assert_eq!(
        repository.activate_recovery_consensus(root, &permission, &delivery, recovery_time(90))?,
        Revision::new(2)
    );
    assert_eq!(repository.load_consensus_state(2)?, advanced);
    assert!(
        repository
            .database
            .connection()
            .execute("DELETE FROM partition_recovery_consensus_activation", [])
            .is_err()
    );
    assert!(
        repository
            .database
            .connection()
            .execute("DELETE FROM partition_recovery_preparation", [])
            .is_err()
    );
    repository.into_database().check_integrity()?;
    Ok(())
}

#[test]
fn recovery_consensus_activation_rolls_back_membership_vote_and_revision_together() -> TestResult {
    let fixture = Transfer::new()?;
    let (delivery, permission) = permission(&fixture)?;
    let root = fixture.candidate.fixture.authority.root_certificate_der();
    let mut repository = fixture.candidate.reopen()?;
    assert!(
        repository
            .activate_recovery_consensus(root, &permission, &delivery, recovery_time(70))
            .is_err()
    );
    repository.materialise_recovery_node_keys(&fixture.candidate.fixture.authority)?;
    for (operation, table) in [
        ("UPDATE", "consensus_vote"),
        ("UPDATE", "applied_state"),
        ("INSERT", "partition_recovery_consensus_activation"),
    ] {
        repository.database.connection().execute_batch(&format!("CREATE TRIGGER fail_activation BEFORE {operation} ON {table} BEGIN SELECT RAISE(ABORT, 'injected'); END;"))?;
        assert!(
            repository
                .activate_recovery_consensus(root, &permission, &delivery, recovery_time(70))
                .is_err()
        );
        repository
            .database
            .connection()
            .execute_batch("DROP TRIGGER fail_activation")?;
        drop(repository);
        repository = fixture.candidate.reopen()?;
        assert_eq!(repository.current_revision()?, Revision::new(1));
        assert_eq!(repository.recovery_consensus_admission(root)?, None);
        assert_eq!(
            repository
                .load_active_consensus_quorum_plan()?
                .ok_or("plan missing")?
                .membership_epoch(),
            1
        );
        assert!(matches!(
            repository.load_consensus_state(2),
            Err(ConsensusStoreError::RecoveryAdmissionRequired)
        ));
    }
    repository.activate_recovery_consensus(root, &permission, &delivery, recovery_time(80))?;
    repository.into_database().check_integrity()?;
    Ok(())
}

#[test]
fn recovery_consensus_activation_rejects_other_state_and_corrupt_root_origin() -> TestResult {
    let fixture = Transfer::new()?;
    let (delivery, permission) = permission(&fixture)?;
    let root = fixture.candidate.fixture.authority.root_certificate_der();
    let other = transfer(&fixture, 52)?;
    let mut repository = fixture.candidate.reopen()?;
    repository.materialise_recovery_node_keys(&fixture.candidate.fixture.authority)?;
    assert!(
        repository
            .activate_recovery_consensus(root, &permission, &other, recovery_time(70))
            .is_err()
    );
    repository.activate_recovery_consensus(root, &permission, &delivery, recovery_time(80))?;
    repository.database.connection().execute(
        "UPDATE consensus_active_quorum_plan SET activation_kind = 1",
        [],
    )?;
    // The source command was never a quorum transition; a forged normal origin cannot pass.
    assert!(repository.load_active_consensus_quorum_plan().is_err());
    repository.database.connection().execute(
        "UPDATE consensus_active_quorum_plan SET activation_kind = 2",
        [],
    )?;
    repository.database.connection().execute_batch("DROP TRIGGER partition_recovery_consensus_activation_immutable; UPDATE partition_recovery_consensus_activation SET permission = x'00';")?;
    assert!(repository.load_consensus_state(2).is_err());
    assert!(repository.load_active_consensus_quorum_plan().is_err());
    Ok(())
}

fn permission(
    fixture: &Transfer,
) -> Result<(RecoveryStateTransfer, RecoveryConsensusAdmission), Box<dyn std::error::Error>> {
    let delivery = transfer(fixture, 51)?;
    let permission = fixture
        .candidate
        .fixture
        .authority
        .authorize_recovery_consensus(RecoveryConsensusAdmissionClaims {
            authorization: delivery.claims().authorization.clone(),
            state_digest: delivery.claims().state_digest,
            state_length: delivery.claims().state_length,
        })?;
    Ok((delivery, permission))
}

fn inject_unapplied_tail(repository: &AuthoritativeRepository) -> TestResult {
    let operation = OperationId::from_bytes([87; 16])?;
    let entry = LogEntry::new(
        LogPosition { index: 2, term: 1 },
        operation,
        1,
        vec![7, 8, 9],
    )?;
    let mut payload = operation.as_bytes().to_vec();
    payload.extend_from_slice(&[7, 8, 9]);
    let transaction = repository.database.connection().unchecked_transaction()?;
    transaction.execute("INSERT INTO consensus_log (log_index, term, entry_kind, entry_version, payload, payload_digest)
        VALUES (2, 1, 1, 1, ?1, ?2)", rusqlite::params![payload, entry.entry_digest().as_slice()])?;
    transaction.execute(
        "UPDATE consensus_log_accounting SET entry_count = entry_count + 1,
        payload_bytes = payload_bytes + 19, revision = revision + 1 WHERE singleton = 1",
        [],
    )?;
    transaction.commit()?;
    Ok(())
}

fn verify_membership(repository: &AuthoritativeRepository, node: [u8; 16]) -> TestResult {
    let membership = repository
        .partition_membership()?
        .ok_or("missing membership")?;
    assert_eq!(membership.active_voters().len(), 1);
    assert!(membership.retiring_members().is_empty());
    let sql = repository.database.connection();
    assert_eq!(sql.query_row("SELECT node_id, membership_revision, member_role, state, revision FROM partition_voters WHERE state = 1", [],
        |row| Ok((row.get::<_, [u8; 16]>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?, row.get::<_, i64>(3)?, row.get::<_, i64>(4)?)))?, (node, 2, 1, 1, 2));
    assert_eq!(
        sql.query_row(
            "SELECT COUNT(*) FROM partition_voters WHERE node_id = ?1",
            [[8_u8; 16].as_slice()],
            |row| row.get::<_, i64>(0)
        )?,
        0
    );
    assert_eq!(
        sql.query_row("SELECT COUNT(*) FROM consensus_quorum_plans", [], |row| row
            .get::<_, i64>(0))?,
        0
    );
    Ok(())
}
