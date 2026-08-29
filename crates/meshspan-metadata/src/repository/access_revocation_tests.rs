// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    ActivationId, ActivationPolicyId, AssuranceLevel, AuditEventId, DurationMicros, GrantId,
    GroupId, OperationId, PrincipalId, Revision, Rights, SessionId, UnixMicros,
};
use rusqlite::{ErrorCode, params};
use tempfile::tempdir;

use super::access_evaluation_tests::{
    Fixture, add_member, apply, build_fixture, build_fixture_at, issue_session, reopen_fixture,
    request,
};
use super::{
    AccessDecision, AccessDenial, ApplyDisposition, LogPosition, PageLimit, RepositoryError,
};
use crate::{
    ActivateGrant, AddGroupMember, AuthoritativeCommand, CommandContext, RemoveGroupMember,
    RevokeAccessActivation, RevokePermissionGrant,
};

#[test]
fn membership_removal_is_immediate_audited_and_reversible() -> Result<(), Box<dyn std::error::Error>>
{
    let mut fixture = build_fixture(false)?;
    let inner = GroupId::from_bytes([11; 16])?;
    let user = fixture.user;
    let administrator = fixture.administrator;
    issue_session(
        &mut fixture,
        user,
        SessionId::from_bytes([60; 16])?,
        [61; 32],
    )?;
    assert!(matches!(
        fixture
            .repository
            .evaluate_access(request(&fixture, [61; 32], Rights::READ_DATA, 200))?,
        AccessDecision::Granted(_)
    ));
    assert_constraint_violation(
        &fixture.repository.database.connection().execute(
            "UPDATE group_memberships SET state = 2
             WHERE containing_group_id = ?1 AND member_principal_id = ?2",
            params![inner.as_bytes().as_slice(), user.as_bytes().as_slice()],
        ),
        "invalid group membership removal evidence",
    );
    assert_rejected(
        &mut fixture,
        administrator,
        205,
        220,
        &AuthoritativeCommand::AddGroupMember(AddGroupMember {
            containing_group_id: inner,
            member_principal_id: user,
            valid_from: None,
            valid_until: Some(UnixMicros::new(800)),
            activation_required: false,
        }),
    )?;

    apply(
        &mut fixture,
        administrator,
        210,
        AuthoritativeCommand::RemoveGroupMember(RemoveGroupMember {
            containing_group_id: inner,
            member_principal_id: user,
            reason: "left the recovery team".to_owned(),
        }),
    )?;
    assert_eq!(
        fixture
            .repository
            .evaluate_access(request(&fixture, [61; 32], Rights::READ_DATA, 211))?,
        AccessDecision::Denied(AccessDenial::StaleIdentity)
    );
    assert!(
        fixture
            .repository
            .direct_group_members(inner, None, PageLimit::new(10)?)?
            .items
            .is_empty()
    );
    issue_session(
        &mut fixture,
        user,
        SessionId::from_bytes([62; 16])?,
        [63; 32],
    )?;
    assert_eq!(
        fixture
            .repository
            .evaluate_access(request(&fixture, [63; 32], Rights::READ_DATA, 220))?,
        AccessDecision::Denied(AccessDenial::MissingRights)
    );

    add_member(&mut fixture, inner, user, 900, 230)?;
    issue_session(
        &mut fixture,
        user,
        SessionId::from_bytes([64; 16])?,
        [65; 32],
    )?;
    assert!(matches!(
        fixture
            .repository
            .evaluate_access(request(&fixture, [65; 32], Rights::READ_DATA, 240))?,
        AccessDecision::Granted(_)
    ));
    assert_eq!(
        fixture
            .repository
            .direct_group_members(inner, None, PageLimit::new(10)?)?
            .items,
        vec![user]
    );
    assert_eq!(fixture.repository.current_revision()?, Revision::new(16));
    assert_membership_history(&fixture, inner, user)
}

#[test]
fn grant_revocation_invalidates_sessions_and_retains_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("grant-revocation.sqlite3");
    let mut fixture = build_fixture_at(&file_path, false)?;
    let user = fixture.user;
    let administrator = fixture.administrator;
    let grant_id = GrantId::from_bytes([25; 16])?;
    issue_session(
        &mut fixture,
        user,
        SessionId::from_bytes([66; 16])?,
        [67; 32],
    )?;
    reject_invalid_grant_revocations(&mut fixture, user, administrator, grant_id)?;
    apply(
        &mut fixture,
        administrator,
        210,
        AuthoritativeCommand::RevokePermissionGrant(RevokePermissionGrant {
            grant_id,
            reason: "access review completed".to_owned(),
        }),
    )?;
    assert_eq!(
        fixture
            .repository
            .evaluate_access(request(&fixture, [67; 32], Rights::READ_DATA, 211))?,
        AccessDecision::Denied(AccessDenial::StaleIdentity)
    );
    issue_session(
        &mut fixture,
        user,
        SessionId::from_bytes([68; 16])?,
        [69; 32],
    )?;
    assert_eq!(
        fixture
            .repository
            .evaluate_access(request(&fixture, [69; 32], Rights::READ_DATA, 220))?,
        AccessDecision::Denied(AccessDenial::MissingRights)
    );
    assert_grant_revocation_evidence(&fixture, grant_id)?;
    assert_grant_revocation_survives_restart(fixture, &file_path, grant_id, administrator)
}

fn reject_invalid_grant_revocations(
    fixture: &mut Fixture,
    user: PrincipalId,
    administrator: PrincipalId,
    grant_id: GrantId,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_constraint_violation(
        &fixture.repository.database.connection().execute(
            "UPDATE permission_grants SET state = 2 WHERE grant_id = ?1",
            [grant_id.as_bytes().as_slice()],
        ),
        "invalid permission grant revocation evidence",
    );
    for (actor, now, operation_byte, reason) in [
        (user, 205, 221, "self escalation"),
        (administrator, 206, 222, "   "),
    ] {
        assert_rejected(
            fixture,
            actor,
            now,
            operation_byte,
            &AuthoritativeCommand::RevokePermissionGrant(RevokePermissionGrant {
                grant_id,
                reason: reason.to_owned(),
            }),
        )?;
    }
    Ok(())
}

fn assert_grant_revocation_evidence(
    fixture: &Fixture,
    grant_id: GrantId,
) -> Result<(), Box<dyn std::error::Error>> {
    let evidence: (i64, i64, Vec<u8>, String, i64) =
        fixture.repository.database.connection().query_row(
            "SELECT state, revoked_at, revoked_by, revocation_reason, revision
         FROM permission_grants WHERE grant_id = ?1",
            [grant_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )?;
    assert_eq!(evidence.0, 2);
    assert_eq!(evidence.1, 210);
    assert_eq!(evidence.2, fixture.administrator.as_bytes());
    assert_eq!(evidence.3, "access review completed");
    assert_eq!(evidence.4, 13);
    assert_eq!(fixture.repository.current_revision()?, Revision::new(14));
    Ok(())
}

fn assert_grant_revocation_survives_restart(
    fixture: Fixture,
    file_path: &std::path::Path,
    grant_id: GrantId,
    administrator: PrincipalId,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = reopen_fixture(fixture, file_path)?;
    assert_eq!(
        fixture
            .repository
            .evaluate_access(request(&fixture, [69; 32], Rights::READ_DATA, 220))?,
        AccessDecision::Denied(AccessDenial::MissingRights)
    );
    let replay = fixture.repository.apply_committed(
        LogPosition { index: 15, term: 1 },
        CommandContext {
            operation_id: OperationId::from_bytes([113; 16])?,
            actor_principal_id: administrator,
            audit_event_id: AuditEventId::from_bytes([193; 16])?,
            occurred_at: UnixMicros::new(210),
            expected_revision: Some(Revision::new(12)),
        },
        &AuthoritativeCommand::RevokePermissionGrant(RevokePermissionGrant {
            grant_id,
            reason: "access review completed".to_owned(),
        }),
    )?;
    assert_eq!(replay.disposition, ApplyDisposition::Replayed);
    assert_eq!(replay.committed_revision, Revision::new(13));
    assert_eq!(fixture.repository.current_revision()?, Revision::new(14));
    Ok(())
}

#[test]
fn activation_revocation_supports_self_service_and_administrator_recovery()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = build_fixture(true)?;
    let user = fixture.user;
    let administrator = fixture.administrator;
    let second_user = fixture.second_user;
    let activation_id = ActivationId::from_bytes([70; 16])?;
    issue_session(
        &mut fixture,
        user,
        SessionId::from_bytes([71; 16])?,
        [72; 32],
    )?;
    activate(&mut fixture, activation_id, user, [72; 32], 210)?;
    assert_constraint_violation(
        &fixture.repository.database.connection().execute(
            "UPDATE access_activations SET revoked_at = 215 WHERE activation_id = ?1",
            [activation_id.as_bytes().as_slice()],
        ),
        "invalid access activation revocation evidence",
    );
    assert!(matches!(
        fixture
            .repository
            .evaluate_access(request(&fixture, [72; 32], Rights::READ_DATA, 220))?,
        AccessDecision::Granted(_)
    ));
    assert_rejected(
        &mut fixture,
        second_user,
        225,
        223,
        &AuthoritativeCommand::RevokeAccessActivation(RevokeAccessActivation {
            activation_id,
            principal_id: user,
            reason: "not my activation".to_owned(),
        }),
    )?;

    apply(
        &mut fixture,
        user,
        230,
        AuthoritativeCommand::RevokeAccessActivation(RevokeAccessActivation {
            activation_id,
            principal_id: user,
            reason: "task finished".to_owned(),
        }),
    )?;
    assert_eq!(
        fixture
            .repository
            .evaluate_access(request(&fixture, [72; 32], Rights::READ_DATA, 231))?,
        AccessDecision::Denied(AccessDenial::StaleIdentity)
    );
    issue_session(
        &mut fixture,
        user,
        SessionId::from_bytes([73; 16])?,
        [74; 32],
    )?;
    assert_eq!(
        fixture
            .repository
            .evaluate_access(request(&fixture, [74; 32], Rights::READ_DATA, 240))?,
        AccessDecision::Denied(AccessDenial::MissingRights)
    );

    let second_activation = ActivationId::from_bytes([75; 16])?;
    activate(&mut fixture, second_activation, user, [74; 32], 245)?;
    apply(
        &mut fixture,
        administrator,
        250,
        AuthoritativeCommand::RevokeAccessActivation(RevokeAccessActivation {
            activation_id: second_activation,
            principal_id: user,
            reason: "emergency access closed".to_owned(),
        }),
    )?;
    assert_activation_evidence(&fixture, activation_id, user, "task finished", 15)?;
    assert_activation_evidence(
        &fixture,
        second_activation,
        administrator,
        "emergency access closed",
        18,
    )
}

fn assert_membership_history(
    fixture: &Fixture,
    containing_group_id: GroupId,
    member_principal_id: PrincipalId,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut statement = fixture.repository.database.connection().prepare(
        "SELECT event_kind, reason, actor_principal_id, revision
         FROM group_membership_events
         WHERE containing_group_id = ?1 AND member_principal_id = ?2
         ORDER BY revision",
    )?;
    let rows = statement.query_map(
        params![
            containing_group_id.as_bytes().as_slice(),
            member_principal_id.as_bytes().as_slice(),
        ],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
            ))
        },
    )?;
    let history = rows.collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        history,
        vec![
            (1, None, fixture.administrator.as_bytes().to_vec(), 6),
            (
                2,
                Some("left the recovery team".to_owned()),
                fixture.administrator.as_bytes().to_vec(),
                13,
            ),
            (1, None, fixture.administrator.as_bytes().to_vec(), 15),
        ]
    );
    Ok(())
}

fn assert_activation_evidence(
    fixture: &Fixture,
    activation_id: ActivationId,
    expected_actor: PrincipalId,
    expected_reason: &str,
    expected_revision: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let evidence: (i64, Vec<u8>, String, i64) =
        fixture.repository.database.connection().query_row(
            "SELECT revoked_at, revoked_by, revocation_reason, revision
         FROM access_activations WHERE activation_id = ?1",
            [activation_id.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
    assert!(evidence.0 >= 230);
    assert_eq!(evidence.1, expected_actor.as_bytes());
    assert_eq!(evidence.2, expected_reason);
    assert_eq!(evidence.3, expected_revision);
    assert_eq!(fixture.repository.current_revision()?, Revision::new(18));
    Ok(())
}

fn activate(
    fixture: &mut Fixture,
    activation_id: ActivationId,
    principal_id: PrincipalId,
    authentication_digest: [u8; 32],
    now: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    apply(
        fixture,
        principal_id,
        now,
        AuthoritativeCommand::ActivateGrant(ActivateGrant {
            activation_id,
            principal_id,
            grant_id: GrantId::from_bytes([25; 16])?,
            policy_id: ActivationPolicyId::from_bytes([24; 16])?,
            reason: "recover one file".to_owned(),
            duration: DurationMicros::new(300),
            session_expires_at: UnixMicros::new(900),
            assurance: AssuranceLevel::MultiFactor,
            authentication_digest,
        }),
    )
}

fn assert_rejected(
    fixture: &mut Fixture,
    actor: PrincipalId,
    now: i64,
    operation_byte: u8,
    command: &AuthoritativeCommand,
) -> Result<(), Box<dyn std::error::Error>> {
    let revision = fixture.next_revision;
    let result = fixture.repository.apply_committed(
        LogPosition {
            index: revision,
            term: 1,
        },
        CommandContext {
            operation_id: OperationId::from_bytes([operation_byte; 16])?,
            actor_principal_id: actor,
            audit_event_id: AuditEventId::from_bytes([operation_byte.wrapping_add(1); 16])?,
            occurred_at: UnixMicros::new(now),
            expected_revision: Some(Revision::new(revision - 1)),
        },
        command,
    );
    assert!(matches!(result, Err(RepositoryError::InvalidCommand)));
    assert_eq!(
        fixture.repository.current_revision()?,
        Revision::new(revision - 1)
    );
    Ok(())
}

fn assert_constraint_violation(result: &Result<usize, rusqlite::Error>, expected_message: &str) {
    assert!(matches!(
        result,
        Err(rusqlite::Error::SqliteFailure(error, Some(message)))
            if error.code == ErrorCode::ConstraintViolation && message == expected_message
    ));
}
