// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{AssuranceLevel, NodeId, PrincipalId, Revision, UnixMicros};
use meshspan_secret_envelope::SecretContext;
use rusqlite::params;

use super::{Fixture, TestResult, plan::Candidate};
use crate::{
    AUTHENTICATION_ROOT_KEY_SECRET_KIND, AuthoritativeRepository, ConsensusStoreError,
    ONLINE_AUTHORITY_KEY_SECRET_KIND, PageLimit, PartitionDatabase, RepositoryError,
    STORAGE_PERMIT_KEY_SECRET_KIND, SessionAccessDecision, SessionAccessDenial,
    SessionAccessRequest,
};

#[test]
fn credential_fence_revokes_source_authority_and_preserves_accounts_after_reopen() -> TestResult {
    let candidate = Candidate::from_fixture(Fixture::with_source(seed_source_credentials)?)?;
    let mut repo = candidate.restore_keys(true)?;
    assert_source_access(&repo, true)?;
    repo.stage_recovery_replacement_plan(
        &candidate.fixture.authority,
        &candidate.plan,
        UnixMicros::new(40),
    )?;
    let receipt =
        repo.fence_recovery_credentials(&candidate.fixture.authority, UnixMicros::new(50))?;
    assert_eq!(
        (receipt.sessions, receipt.join_grants, receipt.activations),
        (1, 1, 1)
    );
    assert_eq!(
        (receipt.node_certificates, receipt.pairing_invitations),
        (1, 1)
    );
    assert_eq!(receipt.federation_activations, 0);
    assert_eq!(
        (receipt.online_generation, receipt.permit_generation),
        (2, 2)
    );
    assert_eq!(receipt.source_revision, Revision::new(1));
    assert_eq!(receipt.recovery_id, candidate.plan.recovery_id);
    drop(repo);
    let mut repo = candidate.reopen()?;
    assert_source_access(&repo, false)?;
    assert_eq!(
        repo.fence_recovery_credentials(&candidate.fixture.authority, UnixMicros::new(51))?,
        receipt
    );
    assert_eq!(repo.current_revision()?, Revision::new(1));
    assert!(matches!(
        repo.load_consensus_state(2),
        Err(ConsensusStoreError::RecoveryAdmissionRequired)
    ));
    assert!(
        repo.staged_recovery_replacement_plan(&candidate.fixture.authority)?
            .is_some()
    );
    let connection = repo.database.connection();
    let retained: (i64, i64, i64) = connection.query_row(
        "SELECT (SELECT COUNT(*) FROM users), (SELECT COUNT(*) FROM authentication_methods WHERE state = 1),
                (SELECT COUNT(*) FROM role_grants)", [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(retained, (1, 1, 1));
    let activation: (Option<i64>, Option<Vec<u8>>, i64) = connection.query_row(
        "SELECT revoked_at, revoked_by, revision FROM access_activations",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(activation, (None, None, 1)); // Original user evidence is not rewritten.
    repo.database.check_integrity()?;
    let source = AuthoritativeRepository::new(PartitionDatabase::open_existing(
        &candidate.fixture.directory.path().join("live.sqlite3"),
        UnixMicros::new(60),
    )?);
    assert_source_access(&source, true)?;
    Ok(())
}

#[test]
fn credential_fence_requires_selection_and_rolls_back_all_changes_on_failed_receipt() -> TestResult
{
    let candidate = Candidate::from_fixture(Fixture::with_source(seed_source_credentials)?)?;
    let mut repo = candidate.restore_keys(true)?;
    assert!(matches!(
        repo.fence_recovery_credentials(&candidate.fixture.authority, UnixMicros::new(50)),
        Err(RepositoryError::InvalidCommand)
    ));
    repo.stage_recovery_replacement_plan(
        &candidate.fixture.authority,
        &candidate.plan,
        UnixMicros::new(40),
    )?;
    assert!(matches!(
        repo.fence_recovery_credentials(&candidate.fixture.authority, UnixMicros::new(39)),
        Err(RepositoryError::InvalidCommand)
    ));
    repo.database.connection().execute_batch(
        "CREATE TRIGGER test_fail_fence AFTER INSERT ON partition_recovery_credential_fence
         BEGIN SELECT RAISE(ABORT, 'injected receipt failure'); END;",
    )?;
    assert!(
        repo.fence_recovery_credentials(&candidate.fixture.authority, UnixMicros::new(50))
            .is_err()
    );
    drop(repo);
    let mut repo = candidate.reopen()?;
    assert_source_access(&repo, true)?;
    repo.database
        .connection()
        .execute_batch("DROP TRIGGER test_fail_fence")?;
    repo.fence_recovery_credentials(&candidate.fixture.authority, UnixMicros::new(50))?;
    assert_source_access(&repo, false)?;
    assert!(
        repo.database
            .connection()
            .execute("DELETE FROM partition_recovery_credential_fence", [])
            .is_err()
    );
    assert!(
        repo.database
            .connection()
            .execute(
                "UPDATE partition_recovery_credential_fence SET permit_generation = 1",
                []
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn recovery_fence_separates_retained_ciphertext_from_runtime_operational_authority() -> TestResult {
    let candidate = Candidate::new()?;
    let mut repo = candidate.restore_keys(true)?;
    let mesh = candidate.plan.mesh_id.as_bytes();
    let permit = SecretContext::new(STORAGE_PERMIT_KEY_SECRET_KIND, mesh, 1)?;
    let online = SecretContext::new(ONLINE_AUTHORITY_KEY_SECRET_KIND, mesh, 1)?;
    let authentication = SecretContext::new(AUTHENTICATION_ROOT_KEY_SECRET_KIND, mesh, 1)?;
    let saved = repo
        .runtime_secret_generation(permit)?
        .ok_or("missing source permit")?;
    repo.stage_recovery_replacement_plan(
        &candidate.fixture.authority,
        &candidate.plan,
        UnixMicros::new(40),
    )?;
    repo.fence_recovery_credentials(&candidate.fixture.authority, UnixMicros::new(50))?;
    drop(repo);
    let repo = candidate.reopen()?;
    assert_eq!(repo.runtime_secret_generation(permit)?, None);
    assert_eq!(repo.runtime_secret_generation(online)?, None);
    assert_eq!(repo.secret_generation(permit)?, Some(saved));
    assert!(repo.runtime_secret_generation(authentication)?.is_some());
    assert_eq!(
        repo.runtime_secret_generation(SecretContext::new(
            STORAGE_PERMIT_KEY_SECRET_KIND,
            mesh,
            2
        )?)?,
        None
    );
    // A staged successor is not installed merely because the floor permits its generation.
    Ok(())
}

#[test]
fn activation_fence_rejects_old_authority_but_allows_a_later_activation_revision() -> TestResult {
    let candidate = Candidate::from_fixture(Fixture::with_source(seed_source_credentials)?)?;
    let mut repo = candidate.restore_keys(true)?;
    assert_group_activation(&repo, true)?;
    repo.stage_recovery_replacement_plan(
        &candidate.fixture.authority,
        &candidate.plan,
        UnixMicros::new(40),
    )?;
    repo.fence_recovery_credentials(&candidate.fixture.authority, UnixMicros::new(50))?;
    assert_group_activation(&repo, false)?;
    // A test-owned later committed projection, not service admission on the prepared copy.
    repo.database.connection().execute(
        "INSERT INTO access_activations(activation_id, principal_id, group_id, policy_id, reason,
         authentication_digest, identity_revision, source_revision, policy_revision, activated_at, expires_at, revision)
         SELECT ?1, principal_id, group_id, policy_id, reason, authentication_digest,
                identity_revision, source_revision, policy_revision, 55, expires_at, 2
         FROM access_activations WHERE activation_id = ?2",
        params![[73_u8; 16].as_slice(), [72_u8; 16].as_slice()],
    )?;
    assert_group_activation(&repo, true)?;
    assert!(matches!(
        repo.load_consensus_state(2),
        Err(ConsensusStoreError::RecoveryAdmissionRequired)
    ));
    Ok(())
}

#[test]
fn credential_fence_rejects_time_before_source_issuance_without_partial_revocation() -> TestResult {
    let candidate = Candidate::from_fixture(Fixture::with_source(|repo| {
        seed_source_credentials(repo)?;
        repo.database
            .connection()
            .execute("UPDATE access_activations SET activated_at = 75", [])?;
        Ok(())
    })?)?;
    let mut repo = candidate.restore_keys(true)?;
    repo.stage_recovery_replacement_plan(
        &candidate.fixture.authority,
        &candidate.plan,
        UnixMicros::new(40),
    )?;
    assert!(matches!(
        repo.fence_recovery_credentials(&candidate.fixture.authority, UnixMicros::new(50)),
        Err(RepositoryError::InvalidCommand)
    ));
    assert_source_access(&repo, true)?;
    repo.fence_recovery_credentials(&candidate.fixture.authority, UnixMicros::new(80))?;
    assert_source_access(&repo, false)?;
    Ok(())
}

fn assert_group_activation(repo: &AuthoritativeRepository, allowed: bool) -> TestResult {
    let subjects =
        crate::repository::access_evaluation::subjects::load_effective_subjects_for_principal(
            &repo.database,
            PrincipalId::from_bytes([2; 16])?,
            Revision::new(1),
            UnixMicros::new(60),
        )?;
    assert_eq!(
        subjects.contains_key(&PrincipalId::from_bytes([71; 16])?),
        allowed
    );
    Ok(())
}

fn assert_source_access(repo: &AuthoritativeRepository, allowed: bool) -> TestResult {
    let decision = repo.evaluate_session_access(SessionAccessRequest {
        token_digest: [61; 32],
        required_assurance: AssuranceLevel::SingleFactor,
        gateway_node_id: NodeId::from_bytes([8; 16])?,
        gateway_incarnation: 1,
        now: UnixMicros::new(60),
    })?;
    if allowed {
        assert!(matches!(decision, SessionAccessDecision::Granted(_)));
    } else {
        assert_eq!(
            decision,
            SessionAccessDecision::Denied(SessionAccessDenial::Unavailable)
        );
    }
    let revoked: Option<i64> =
        repo.database
            .connection()
            .query_row("SELECT revoked_at FROM join_grants", [], |row| row.get(0))?;
    assert_eq!(revoked.is_none(), allowed);
    assert_eq!(
        repo.active_node_certificate(NodeId::from_bytes([8; 16])?)?
            .is_some(),
        allowed
    );
    let activations = repo.unrevoked_access_activations(
        PrincipalId::from_bytes([2; 16])?,
        UnixMicros::new(60),
        None,
        PageLimit::new(10)?,
    )?;
    assert_eq!(activations.items.len(), usize::from(allowed));
    let invitation: i64 = repo.database.connection().query_row(
        "SELECT state FROM federation_pairing_invitations",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(invitation, if allowed { 1 } else { 3 });
    Ok(())
}

// Synthetic committed rows exercise the persistence and public read boundaries; this is not
// a claim of HTTPS/SMB enrolment acceptance. The real encrypted backup includes these rows.
fn seed_source_credentials(repo: &mut AuthoritativeRepository) -> TestResult {
    let connection = repo.database.connection();
    connection.execute(
        "INSERT INTO authentication_sessions(session_id, token_digest, user_principal_id,
         service, assurance, identity_revision, issued_at, expires_at, revoked_at, revision,
         csrf_digest, client_label_state, client_label, persistent_cookie)
         VALUES (?1, ?2, ?3, 1, 1, 1, 10, 1000, NULL, 1, ?4, 1, NULL, 0)",
        params![
            [60_u8; 16].as_slice(),
            [61_u8; 32].as_slice(),
            [2_u8; 16].as_slice(),
            [62_u8; 32].as_slice()
        ],
    )?;
    connection.execute(
        "INSERT INTO authentication_session_factors(session_id, factor_sequence, method_id, method_kind,
         credential_reference, credential_generation, method_revision, authenticated_at, revision)
         VALUES (?1, 1, ?2, 4, ?3, 1, 1, 10, 1)",
        params![[60_u8; 16].as_slice(), [9_u8; 16].as_slice(), [10_u8; 16].as_slice()],
    )?;
    connection.execute(
        "INSERT INTO join_grants(join_grant_id, secret_digest, issued_by, allowed_roles,
         maximum_uses, used_count, created_at, expires_at, revoked_at, revision)
         VALUES (?1, ?2, ?3, 7, 1, 0, 10, 1000, NULL, 1)",
        params![
            [63_u8; 16].as_slice(),
            [64_u8; 32].as_slice(),
            [2_u8; 16].as_slice()
        ],
    )?;
    connection.execute(
        "INSERT INTO federation_pairing_invitations(relationship_id, mesh_id, issuing_node_id,
         issued_by, issuance_operation_id, issuance_key_generation, material_verifier, endpoint,
         certificate_fingerprint, issued_at, expires_at, state, cancellation_reason, revision)
         VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, 'https://peer.example', ?7, 10, 1000, 1, NULL, 1)",
        params![
            [65_u8; 16].as_slice(),
            [5_u8; 16].as_slice(),
            [8_u8; 16].as_slice(),
            [2_u8; 16].as_slice(),
            [66_u8; 16].as_slice(),
            [67_u8; 32].as_slice(),
            [68_u8; 32].as_slice()
        ],
    )?;
    seed_activation(connection)?;
    Ok(())
}

fn seed_activation(connection: &rusqlite::Connection) -> TestResult {
    connection.execute(
        "INSERT INTO access_activation_policies(policy_id, maximum_duration_micros, reason_required,
         minimum_assurance, revision) VALUES (?1, 1000, 1, 1, 1)", [[70_u8; 16].as_slice()],
    )?;
    connection.execute(
        "INSERT INTO principals(principal_id, principal_kind, display_name, canonical_name, state, created_at, revision)
         VALUES (?1, 2, 'Recovery operators', 'recovery operators', 1, 10, 1)", [[71_u8; 16].as_slice()],
    )?;
    connection.execute(
        "INSERT INTO groups(principal_id, activation_policy_id) VALUES (?1, ?2)",
        params![[71_u8; 16].as_slice(), [70_u8; 16].as_slice()],
    )?;
    connection.execute(
        "INSERT INTO group_memberships(containing_group_id, member_principal_id, activation_required,
         created_by, created_at, revision) VALUES (?1, ?2, 1, ?2, 10, 1)",
        params![[71_u8; 16].as_slice(), [2_u8; 16].as_slice()],
    )?;
    connection.execute(
        "INSERT INTO access_activations(activation_id, principal_id, group_id, policy_id, reason,
         authentication_digest, identity_revision, source_revision, policy_revision, activated_at, expires_at, revision)
         VALUES (?1, ?2, ?3, ?4, 'Restore files', ?5, 1, 1, 1, 10, 1000, 1)",
        params![[72_u8; 16].as_slice(), [2_u8; 16].as_slice(), [71_u8; 16].as_slice(),
            [70_u8; 16].as_slice(), [61_u8; 32].as_slice()],
    )?;
    Ok(())
}
