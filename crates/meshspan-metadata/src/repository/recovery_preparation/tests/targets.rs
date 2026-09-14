// SPDX-License-Identifier: GPL-2.0-only

use super::{
    TestResult,
    key_transfer::{Transfer, recovery_time},
};
use crate::{PageLimit, PreparedRecoveryTarget, StorageUsageLimit};
use meshspan_domain::{NodeId, OperationId, TargetId};

#[test]
fn recovery_targets_reopen_page_and_replay_without_becoming_active() -> TestResult {
    let fixture = Transfer::new()?;
    let authority = &fixture.candidate.fixture.authority;
    let mut repo = fixture.candidate.reopen()?;
    let target = target(&fixture, 1)?;
    let signature = fixture
        .candidate
        .identity
        .sign_enrolment_transcript(&target.installation_message()?)?;
    let report = target.encode_report(&signature)?;
    assert_eq!(
        PreparedRecoveryTarget::decode_report(authority.root_certificate_der(), &report)?.0,
        target
    );
    assert_eq!(
        repo.record_recovery_target(authority, &report, recovery_time(60))?,
        target
    );
    assert_eq!(
        repo.record_recovery_target(authority, &report, recovery_time(70))?,
        target
    );
    let other = self::target(&fixture, 2)?;
    let signed = other.encode_report(
        &fixture
            .candidate
            .identity
            .sign_enrolment_transcript(&other.installation_message()?)?,
    )?;
    repo.record_recovery_target(authority, &signed, recovery_time(61))?;
    drop(repo);
    let repo = fixture.candidate.reopen()?;
    assert_eq!(
        repo.recovery_targets(authority, target.node_id, None, PageLimit::new(1)?)?,
        vec![target.clone()]
    );
    assert_eq!(
        repo.recovery_targets(
            authority,
            target.node_id,
            Some(target.target_id),
            PageLimit::new(1)?
        )?,
        vec![other.clone()]
    );
    assert!(
        repo.recovery_targets(
            authority,
            target.node_id,
            Some(other.target_id),
            PageLimit::new(1)?
        )?
        .is_empty()
    );
    assert_eq!(
        repo.recovery_storage_target_marker(target.target_id, 1)?,
        None
    );
    let count: i64 = repo.database.connection().query_row(
        "SELECT COUNT(*) FROM partition_recovery_targets",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 2);
    assert_eq!(
        repo.database.connection().query_row(
            "SELECT recorded_at FROM partition_recovery_targets WHERE target_id = ?1",
            [target.target_id.as_bytes().as_slice()],
            |row| row.get::<_, i64>(0)
        )?,
        recovery_time(60).get()
    );
    Ok(())
}

#[test]
fn recovery_targets_reject_substitution_and_failed_insert_rolls_back() -> TestResult {
    let fixture = Transfer::new()?;
    let authority = &fixture.candidate.fixture.authority;
    let mut repo = fixture.candidate.reopen()?;
    let target = target(&fixture, 1)?;
    let signature = fixture
        .candidate
        .identity
        .sign_enrolment_transcript(&target.installation_message()?)?;
    let report = target.encode_report(&signature)?;
    let mut forged = report.clone();
    *forged.last_mut().ok_or("empty report")? ^= 1;
    assert!(
        repo.record_recovery_target(authority, &forged, recovery_time(60))
            .is_err()
    );
    let mut foreign = target.clone();
    foreign.node_id = NodeId::from_bytes([99; 16])?;
    let foreign = foreign.encode_report(
        &fixture
            .candidate
            .identity
            .sign_enrolment_transcript(&foreign.installation_message()?)?,
    )?;
    assert!(
        repo.record_recovery_target(authority, &foreign, recovery_time(60))
            .is_err()
    );
    repo.database.connection().execute_batch(
        "CREATE TRIGGER injected_target_failure BEFORE INSERT ON partition_recovery_targets
        BEGIN SELECT RAISE(ABORT, 'injected'); END;",
    )?;
    assert!(
        repo.record_recovery_target(authority, &report, recovery_time(60))
            .is_err()
    );
    assert!(
        repo.recovery_targets(authority, target.node_id, None, PageLimit::new(10)?)?
            .is_empty()
    );
    repo.database
        .connection()
        .execute_batch("DROP TRIGGER injected_target_failure;")?;
    repo.record_recovery_target(authority, &report, recovery_time(60))?;
    let mut changed = target.clone();
    changed.marker_fingerprint = [88; 32];
    let changed = changed.encode_report(
        &fixture
            .candidate
            .identity
            .sign_enrolment_transcript(&changed.installation_message()?)?,
    )?;
    assert!(
        repo.record_recovery_target(authority, &changed, recovery_time(61))
            .is_err()
    );
    assert_eq!(
        repo.recovery_targets(authority, target.node_id, None, PageLimit::new(10)?)?,
        vec![target]
    );
    for end in 0..report.len() {
        assert!(
            PreparedRecoveryTarget::decode_report(authority.root_certificate_der(), &report[..end])
                .is_err()
        );
    }
    Ok(())
}

pub(super) fn target(
    fixture: &Transfer,
    seed: u8,
) -> Result<PreparedRecoveryTarget, Box<dyn std::error::Error>> {
    Ok(PreparedRecoveryTarget {
        authorization: fixture.candidate.fixture.authorization.clone(),
        node_id: fixture.recipient.node_id,
        incarnation: 1,
        operation_id: OperationId::from_bytes([seed + 180; 16])?,
        target_id: TargetId::from_bytes([seed + 190; 16])?,
        generation: 1,
        marker_fingerprint: [seed + 200; 32],
        usage_limit: StorageUsageLimit::Percent(95),
    })
}
