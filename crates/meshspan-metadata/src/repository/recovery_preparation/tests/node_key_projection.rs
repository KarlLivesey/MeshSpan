// SPDX-License-Identifier: GPL-2.0-only

use super::{
    TestResult,
    key_transfer::{Transfer, recovery_time},
    plan::Candidate,
};
use crate::{ConsensusStoreError, PageLimit, RepositoryError};
use meshspan_domain::{NodeId, Revision, UnixMicros};

#[test]
fn recovery_node_keys_project_normal_records_without_admitting_consensus() -> TestResult {
    let fixture = Transfer::new()?;
    let authority = &fixture.candidate.fixture.authority;
    let node = fixture.recipient.node_id;
    let mesh = fixture.candidate.plan.mesh_id;
    let mut repository = fixture.candidate.reopen()?;
    let old_plan = repository.load_active_consensus_quorum_plan()?;
    assert_eq!(
        repository.materialise_recovery_node_keys(authority)?,
        Revision::new(2)
    );
    drop(repository);
    let mut repository = fixture.candidate.reopen()?;
    assert_eq!(
        repository.verify_recovery_preparation(authority.root_certificate_der())?,
        fixture.candidate.fixture.authorization
    );
    assert_eq!(repository.current_revision()?, Revision::new(1));
    assert_eq!(repository.load_active_consensus_quorum_plan()?, old_plan);
    assert!(matches!(
        repository.load_consensus_state(2),
        Err(ConsensusStoreError::RecoveryAdmissionRequired)
    ));
    assert_eq!(
        repository
            .node_wrapping_key(node)?
            .ok_or("replacement key absent")?
            .public_key,
        fixture.key.public_key()
    );
    assert!(
        repository
            .node_wrapping_key(NodeId::from_bytes([8; 16])?)?
            .is_none()
    );
    assert_eq!(
        repository.latest_online_authority_generation(mesh)?,
        Some(2)
    );
    assert_eq!(repository.latest_storage_permit_generation(mesh)?, Some(2));
    assert_eq!(
        repository
            .online_certificate_authority(mesh)?
            .ok_or("issuer absent")?
            .generation,
        2
    );
    let sql = repository.database.connection();
    let leaf: Vec<u8> = sql.query_row(
        "SELECT certificate_der FROM node_certificates WHERE node_id = ?1 AND state = 1",
        [node.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    assert_eq!(
        leaf,
        fixture
            .verify(&fixture.bytes, &fixture.key)?
            .node_certificate()
            .certificate_der()
    );
    assert_eq!(
        sql.query_row("SELECT COUNT(*) FROM nodes WHERE state = 2", [], |row| row
            .get::<_, i64>(
            0
        ))?,
        1
    );
    assert!(
        sql.execute("DELETE FROM secret_recipient_envelopes", [])
            .is_err()
    );
    assert!(
        sql.execute(
            "UPDATE node_wrapping_keys SET state = 3, retired_at = 1",
            []
        )
        .is_err()
    );
    assert!(
        sql.execute(
            "UPDATE partition_recovery_node_key_projection SET completed = 0",
            []
        )
        .is_err()
    );
    assert!(
        repository
            .materialise_recovery_node_keys(authority)
            .is_err()
    );
    repository.into_database().check_integrity()?;
    Ok(())
}

#[test]
fn recovery_projection_preserves_ciphertext_and_replaces_complete_recipients() -> TestResult {
    let fixture = Transfer::new()?;
    let authority = &fixture.candidate.fixture.authority;
    let mut repository = fixture.candidate.reopen()?;
    let contexts = repository
        .secret_generation_contexts(None, PageLimit::new(128)?)?
        .items;
    let original = contexts
        .iter()
        .map(|context| {
            repository
                .secret_generation(*context)?
                .ok_or(RepositoryError::CorruptState)
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert!(!original.is_empty());
    repository.materialise_recovery_node_keys(authority)?;
    drop(repository);
    let repository = fixture.candidate.reopen()?;
    for before in original {
        let after = repository
            .secret_generation(before.secret.context())?
            .ok_or("retained key absent")?;
        assert_eq!(after.secret.parts(), before.secret.parts());
        assert_eq!(after.recipients.len(), 2);
        let envelope = after
            .recipients
            .iter()
            .find(|envelope| {
                envelope
                    .recipient_public_key()
                    .is_ok_and(|key| key == fixture.key.public_key())
            })
            .ok_or("replacement envelope absent")?;
        assert_eq!(
            after
                .secret
                .decrypt(&envelope.open(&fixture.key)?)?
                .expose(),
            authority
                .open_secret(&before.secret, &before.recipients)?
                .expose()
        );
    }
    repository.into_database().check_integrity()?;
    Ok(())
}

#[test]
fn recovery_node_key_projection_rolls_back_every_boundary() -> TestResult {
    let fixture = Transfer::new()?;
    let authority = &fixture.candidate.fixture.authority;
    for table in [
        "nodes",
        "node_wrapping_keys",
        "secret_recipient_envelopes",
        "online_certificate_authorities",
    ] {
        let mut repository = fixture.candidate.reopen()?;
        repository.database.connection().execute_batch(&format!("CREATE TRIGGER injected_projection BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT, 'injected'); END;"))?;
        assert!(
            repository
                .materialise_recovery_node_keys(authority)
                .is_err()
        );
        repository
            .database
            .connection()
            .execute_batch("DROP TRIGGER injected_projection")?;
        drop(repository);
        let repository = fixture.candidate.reopen()?;
        let sql = repository.database.connection();
        assert_eq!(
            sql.query_row(
                "SELECT COUNT(*) FROM partition_recovery_node_key_projection",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            0
        );
        assert_eq!(
            sql.query_row("SELECT COUNT(*) FROM nodes WHERE state = 2", [], |row| row
                .get::<_, i64>(
                0
            ))?,
            1
        );
        assert!(
            repository
                .node_wrapping_key(fixture.recipient.node_id)?
                .is_none()
        );
        assert!(
            repository
                .node_wrapping_key(NodeId::from_bytes([8; 16])?)?
                .is_some()
        );
        assert_eq!(
            repository.latest_online_authority_generation(fixture.candidate.plan.mesh_id)?,
            Some(1)
        );
        let mut replay = Vec::new();
        repository.export_recovery_key_bundle(authority, fixture.recipient.node_id, &mut replay)?;
        assert_eq!(replay, fixture.bytes);
        repository.into_database().check_integrity()?;
    }
    fixture
        .candidate
        .reopen()?
        .materialise_recovery_node_keys(authority)?;
    Ok(())
}

#[test]
fn recovery_node_projection_requires_fence_and_supports_selected_reincarnation() -> TestResult {
    let mut candidate = Candidate::new()?;
    let node = candidate.plan.nodes.first_mut().ok_or("node absent")?;
    node.node_id = NodeId::from_bytes([8; 16])?;
    node.incarnation = 2;
    let quorum = meshspan_consensus::flat_plan(
        meshspan_domain::QuorumPlanId::from_bytes([43; 16])?,
        2,
        std::collections::BTreeSet::from([node.node_id]),
        std::collections::BTreeSet::new(),
    )?;
    candidate.plan.quorum = meshspan_consensus::ActiveQuorumPlan::Stable(Box::new(
        meshspan_consensus::compile_plan(quorum)?,
    ));
    candidate.sign()?;
    let mut repository = candidate.restore_keys(true)?;
    let authority = &candidate.fixture.authority;
    repository.stage_recovery_replacement_plan(authority, &candidate.plan, UnixMicros::new(40))?;
    assert!(
        repository
            .materialise_recovery_node_keys(authority)
            .is_err()
    );
    repository.fence_recovery_credentials(authority, recovery_time(50))?;
    repository.materialise_recovery_node_keys(authority)?;
    drop(repository);
    let repository = candidate.reopen()?;
    let key = repository
        .node_wrapping_key(NodeId::from_bytes([8; 16])?)?
        .ok_or("key absent")?;
    assert_eq!(key.generation, 2);
    let sql = repository.database.connection();
    let (incarnation, endpoint): (i64, String) = sql.query_row(
        "SELECT current_incarnation, bootstrap_private_endpoint FROM nodes WHERE state = 2",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(incarnation, 2);
    assert_eq!(endpoint, "127.0.0.1:10000");
    assert_eq!(
        sql.query_row(
            "SELECT generation FROM node_certificates WHERE state = 1",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        2
    );
    repository.into_database().check_integrity()?;
    Ok(())
}
