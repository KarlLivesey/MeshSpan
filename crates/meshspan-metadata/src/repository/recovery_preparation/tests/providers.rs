// SPDX-License-Identifier: GPL-2.0-only

use super::{
    TestResult,
    key_transfer::{Transfer, recovery_time},
    targets::target,
};
use crate::{AuthoritativeRepository, ConsensusStoreError, PreparedRecoveryTarget};
use meshspan_domain::Revision;

#[test]
fn recovery_provider_projection_uses_root_provenance_and_normal_target_records() -> TestResult {
    let fixture = Transfer::new()?;
    let target = target(&fixture, 1)?;
    let mut repository = collected(&fixture, &target)?;
    let source_revision = repository.current_revision()?;
    repository.materialise_recovery_node_keys(&fixture.candidate.fixture.authority)?;
    drop(repository);
    let repository = fixture.candidate.reopen()?;
    let context = repository
        .storage_target_provider_context(target.node_id, target.target_id)?
        .ok_or("normal provider context missing")?;
    assert_eq!(context.generation, 1);
    assert_eq!(context.usage_limit, target.usage_limit);
    assert_eq!(context.policy_revision, Revision::new(2));
    assert_eq!(context.catalogue_revision, source_revision);
    assert_eq!(
        repository.recovery_storage_target_marker(target.target_id, 1)?,
        Some(target.marker_fingerprint)
    );
    let sql = repository.database.connection();
    let origins: (bool, bool) = sql.query_row(
        "SELECT i.created_by IS NULL AND i.recovery_preparation = 1,
            c.created_by IS NULL AND c.recovery_preparation = 1
         FROM storage_targets t JOIN component_instances i ON i.instance_id = t.provider_instance_id
         JOIN component_configurations c ON c.instance_id = i.instance_id AND c.config_revision = i.active_config_revision
         WHERE t.target_id = ?1", [target.target_id.as_bytes().as_slice()],
         |row| Ok((row.get(0)?, row.get(1)?)))?;
    assert_eq!(origins, (true, true));
    assert!(
        sql.execute(
            "UPDATE component_instances SET recovery_preparation = NULL",
            []
        )
        .is_err()
    );
    assert!(matches!(
        repository.load_consensus_state(2),
        Err(ConsensusStoreError::RecoveryAdmissionRequired)
    ));
    repository.into_database().check_integrity()?;
    Ok(())
}

#[test]
fn recovery_provider_projection_rolls_back_components_nodes_and_markers() -> TestResult {
    let fixture = Transfer::new()?;
    let target = target(&fixture, 1)?;
    let authority = &fixture.candidate.fixture.authority;
    let mut repository = collected(&fixture, &target)?;
    for table in [
        "component_instances",
        "component_configurations",
        "storage_targets",
        "target_generations",
    ] {
        repository.database.connection().execute_batch(&format!(
            "CREATE TRIGGER injected_provider BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT, 'injected'); END;"))?;
        assert!(
            repository
                .materialise_recovery_node_keys(authority)
                .is_err()
        );
        repository
            .database
            .connection()
            .execute_batch("DROP TRIGGER injected_provider")?;
        drop(repository);
        repository = fixture.candidate.reopen()?;
        let sql = repository.database.connection();
        for name in [
            "partition_recovery_node_key_projection",
            "component_instances",
            "storage_targets",
            "target_generations",
        ] {
            assert_eq!(
                sql.query_row(&format!("SELECT COUNT(*) FROM {name}"), [], |row| row
                    .get::<_, i64>(0))?,
                0,
                "{name}"
            );
        }
        assert!(repository.node_wrapping_key(target.node_id)?.is_none());
        assert_eq!(repository.current_revision()?, Revision::new(1));
    }
    repository.materialise_recovery_node_keys(authority)?;
    repository.into_database().check_integrity()?;
    Ok(())
}

#[test]
fn recovery_provider_projection_rechecks_target_signature_after_collection() -> TestResult {
    let fixture = Transfer::new()?;
    let target = target(&fixture, 1)?;
    let mut repository = collected(&fixture, &target)?;
    let sql = repository.database.connection();
    let mut report: Vec<u8> =
        sql.query_row("SELECT report FROM partition_recovery_targets", [], |row| {
            row.get(0)
        })?;
    *report.last_mut().ok_or("empty report")? ^= 1;
    sql.execute_batch("DROP TRIGGER partition_recovery_targets_immutable")?;
    sql.execute(
        "UPDATE partition_recovery_targets SET report = ?1",
        [report],
    )?;
    assert!(
        repository
            .materialise_recovery_node_keys(&fixture.candidate.fixture.authority)
            .is_err()
    );
    drop(repository);
    let repository = fixture.candidate.reopen()?;
    assert!(repository.node_wrapping_key(target.node_id)?.is_none());
    assert!(
        repository
            .recovery_storage_target_marker(target.target_id, 1)?
            .is_none()
    );
    assert_eq!(
        repository.database.connection().query_row(
            "SELECT COUNT(*) FROM component_instances",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        0
    );
    Ok(())
}

fn collected(
    fixture: &Transfer,
    target: &PreparedRecoveryTarget,
) -> Result<AuthoritativeRepository, Box<dyn std::error::Error>> {
    let mut repository = fixture.candidate.reopen()?;
    let signature = fixture
        .candidate
        .identity
        .sign_enrolment_transcript(&target.installation_message()?)?;
    repository.record_recovery_target(
        &fixture.candidate.fixture.authority,
        &target.encode_report(&signature)?,
        recovery_time(60),
    )?;
    Ok(repository)
}
