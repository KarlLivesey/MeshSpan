// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    ApiKeyId, AuditEventId, AuthenticationMethodId, AuthenticationService, ObjectId, OperationId,
    OwnerSetId, PrincipalId, Revision, Rights, SessionId, UnixMicros,
};
use rusqlite::{ErrorCode, params};
use tempfile::tempdir;

use super::access_evaluation_tests::{
    Fixture, apply, build_fixture, build_fixture_at, issue_session, reopen_fixture, request,
};
use super::apply::{ApplyFaultPoint, apply_committed_with_fault};
use super::{
    AccessDecision, AccessDenial, ApplyDisposition, AuthoritativeRepository, LogPosition,
    PageLimit, RepositoryError,
};
use crate::{
    AuthoritativeCommand, ChangePrincipalState, CommandContext, PrincipalLifecycleState,
    ReplaceObjectOwners, SessionAuthenticationFactor,
};

const ROOT_OBJECT: [u8; 16] = [23; 16];
const FOLDER_OBJECT: [u8; 16] = [21; 16];
const FILE_OBJECT: [u8; 16] = [22; 16];

#[test]
fn suspension_reactivation_and_retirement_fence_access_and_survive_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("principal-lifecycle.sqlite3");
    let mut fixture = build_fixture_at(&file_path, false)?;
    let user = fixture.user;
    let administrator = fixture.administrator;
    issue_session(
        &mut fixture,
        user,
        SessionId::from_bytes([80; 16])?,
        [81; 32],
    )?;
    assert!(matches!(
        fixture
            .repository
            .evaluate_access(request(&fixture, [81; 32], Rights::READ_DATA, 200))?,
        AccessDecision::Granted(_)
    ));

    change_state(
        &mut fixture,
        administrator,
        user,
        PrincipalLifecycleState::Suspended,
        "leave started",
        210,
    )?;
    assert_eq!(
        fixture
            .repository
            .evaluate_access(request(&fixture, [81; 32], Rights::READ_DATA, 211))?,
        AccessDecision::Denied(AccessDenial::SessionUnavailable)
    );
    assert_rejected_session_issue(&mut fixture, user)?;
    change_state(
        &mut fixture,
        administrator,
        user,
        PrincipalLifecycleState::Active,
        "returned early",
        230,
    )?;
    assert_eq!(
        fixture
            .repository
            .evaluate_access(request(&fixture, [81; 32], Rights::READ_DATA, 231))?,
        AccessDecision::Denied(AccessDenial::StaleIdentity)
    );
    issue_session(
        &mut fixture,
        user,
        SessionId::from_bytes([82; 16])?,
        [83; 32],
    )?;
    assert!(matches!(
        fixture
            .repository
            .evaluate_access(request(&fixture, [83; 32], Rights::READ_DATA, 240))?,
        AccessDecision::Granted(_)
    ));

    change_state(
        &mut fixture,
        administrator,
        user,
        PrincipalLifecycleState::Suspended,
        "account closure",
        250,
    )?;
    change_state(
        &mut fixture,
        administrator,
        user,
        PrincipalLifecycleState::Retired,
        "retention complete",
        260,
    )?;
    assert_terminal_state(&fixture, user)?;
    assert_lifecycle_history(&fixture, user)?;
    assert_lifecycle_ledger_is_immutable_and_consistent(&fixture, user)?;
    assert_retirement_survives_restart_and_replay(fixture, &file_path, user, administrator)
}

#[test]
fn disablement_requires_exact_atomic_last_owner_transfers() -> Result<(), Box<dyn std::error::Error>>
{
    let mut fixture = build_fixture(false)?;
    let target = fixture.second_user;
    let administrator = fixture.administrator;
    let beneficiary = fixture.user;
    assert_rejected_state_change(
        &mut fixture,
        administrator,
        target,
        PrincipalLifecycleState::Suspended,
        Vec::new(),
        210,
        230,
    )?;
    assert_rejected_state_change(
        &mut fixture,
        administrator,
        target,
        PrincipalLifecycleState::Suspended,
        vec![owner_transfer(ROOT_OBJECT, 90, beneficiary)?],
        211,
        231,
    )?;
    assert_rejected_state_change(
        &mut fixture,
        administrator,
        target,
        PrincipalLifecycleState::Suspended,
        vec![
            owner_transfer(ROOT_OBJECT, 90, beneficiary)?,
            owner_transfer(FOLDER_OBJECT, 91, beneficiary)?,
            owner_transfer(FILE_OBJECT, 92, beneficiary)?,
        ],
        212,
        232,
    )?;

    let command = state_command(
        target,
        PrincipalLifecycleState::Suspended,
        "transfer sole ownership",
        all_owner_transfers(beneficiary)?,
    )?;
    apply(
        &mut fixture,
        administrator,
        220,
        AuthoritativeCommand::ChangePrincipalState(command),
    )?;
    assert_eq!(fixture.repository.current_revision()?, Revision::new(12));
    assert_eq!(
        fixture
            .repository
            .principal(target)?
            .ok_or("missing principal")?
            .state,
        2
    );
    assert_current_owner_sets(&fixture.repository, [90, 91, 92])?;
    issue_session(
        &mut fixture,
        beneficiary,
        SessionId::from_bytes([84; 16])?,
        [85; 32],
    )?;
    assert!(matches!(
        fixture
            .repository
            .evaluate_access(request(&fixture, [85; 32], Rights::WRITE_DATA, 230))?,
        AccessDecision::Granted(_)
    ));
    Ok(())
}

#[test]
fn last_administrator_and_every_interrupted_owner_transfer_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = build_fixture(false)?;
    let administrator = fixture.administrator;
    assert_rejected_state_change(
        &mut fixture,
        administrator,
        administrator,
        PrincipalLifecycleState::Suspended,
        Vec::new(),
        205,
        232,
    )?;
    assert_constraint_violation(
        &fixture.repository.database.connection().execute(
            "UPDATE principals SET state = 3 WHERE principal_id = ?1",
            [administrator.as_bytes().as_slice()],
        ),
        "invalid principal lifecycle state",
    );

    for fault in [
        ApplyFaultPoint::AfterCommand,
        ApplyFaultPoint::AfterOperation,
        ApplyFaultPoint::AfterAudit,
        ApplyFaultPoint::BeforeCommit,
    ] {
        assert_owner_transfer_fault_rolls_back(fault)?;
    }
    Ok(())
}

fn change_state(
    fixture: &mut Fixture,
    actor: PrincipalId,
    principal_id: PrincipalId,
    state: PrincipalLifecycleState,
    reason: &str,
    now: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    apply(
        fixture,
        actor,
        now,
        AuthoritativeCommand::ChangePrincipalState(state_command(
            principal_id,
            state,
            reason,
            Vec::new(),
        )?),
    )
}

fn state_command(
    principal_id: PrincipalId,
    state: PrincipalLifecycleState,
    reason: &str,
    owner_transfers: Vec<ReplaceObjectOwners>,
) -> Result<ChangePrincipalState, Box<dyn std::error::Error>> {
    Ok(ChangePrincipalState {
        principal_id,
        state,
        reason: reason.to_owned(),
        owner_transfers: BoundedItems::new(owner_transfers, 1_000)?,
    })
}

fn all_owner_transfers(
    beneficiary: PrincipalId,
) -> Result<Vec<ReplaceObjectOwners>, Box<dyn std::error::Error>> {
    Ok(vec![
        owner_transfer(FOLDER_OBJECT, 91, beneficiary)?,
        owner_transfer(FILE_OBJECT, 92, beneficiary)?,
        owner_transfer(ROOT_OBJECT, 90, beneficiary)?,
    ])
}

fn owner_transfer(
    object: [u8; 16],
    owner_set: u8,
    beneficiary: PrincipalId,
) -> Result<ReplaceObjectOwners, Box<dyn std::error::Error>> {
    Ok(ReplaceObjectOwners {
        object_id: ObjectId::from_bytes(object)?,
        owner_set_id: OwnerSetId::from_bytes([owner_set; 16])?,
        owners: BoundedItems::new(vec![beneficiary], 1_024)?,
    })
}

fn assert_rejected_state_change(
    fixture: &mut Fixture,
    actor: PrincipalId,
    principal_id: PrincipalId,
    state: PrincipalLifecycleState,
    transfers: Vec<ReplaceObjectOwners>,
    now: i64,
    operation_byte: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    let command = AuthoritativeCommand::ChangePrincipalState(state_command(
        principal_id,
        state,
        "rejected transition",
        transfers,
    )?);
    assert_rejected(fixture, actor, now, operation_byte, &command)
}

fn assert_rejected_session_issue(
    fixture: &mut Fixture,
    user: PrincipalId,
) -> Result<(), Box<dyn std::error::Error>> {
    let command =
        AuthoritativeCommand::IssueAuthenticationSession(crate::IssueAuthenticationSession {
            session_id: SessionId::from_bytes([86; 16])?,
            principal_id: user,
            token_digest: [87; 32],
            csrf_digest: [88; 32],
            client_label: None,
            persistent_cookie: false,
            service: AuthenticationService::Https,
            factors: BoundedItems::new(
                vec![SessionAuthenticationFactor::ApiKey {
                    method_id: AuthenticationMethodId::from_bytes([88; 16])?,
                    credential_generation: 1,
                    method_revision: Revision::new(1),
                    key_id: ApiKeyId::from_bytes([89; 16])?,
                }],
                8,
            )?,
            expires_at: UnixMicros::new(900),
        });
    assert_rejected(fixture, user, 220, 233, &command)
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
        context(operation_byte, actor, now, revision - 1)?,
        command,
    );
    assert!(matches!(result, Err(RepositoryError::InvalidCommand)));
    assert_eq!(
        fixture.repository.current_revision()?,
        Revision::new(revision - 1)
    );
    Ok(())
}

fn assert_terminal_state(
    fixture: &Fixture,
    principal_id: PrincipalId,
) -> Result<(), Box<dyn std::error::Error>> {
    let principal = fixture
        .repository
        .principal(principal_id)?
        .ok_or("missing retired principal")?;
    assert_eq!(principal.state, 3);
    assert_eq!(principal.revision, Revision::new(21));
    let retired_at: i64 = fixture.repository.database.connection().query_row(
        "SELECT retired_at FROM principals WHERE principal_id = ?1",
        [principal_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    assert_eq!(retired_at, 260);
    Ok(())
}

fn assert_lifecycle_history(
    fixture: &Fixture,
    principal_id: PrincipalId,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut statement = fixture.repository.database.connection().prepare(
        "SELECT event_kind, prior_state, resulting_state, reason, revision
         FROM principal_lifecycle_events WHERE principal_id = ?1 ORDER BY revision",
    )?;
    let rows = statement.query_map([principal_id.as_bytes().as_slice()], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, Option<i64>>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, i64>(4)?,
        ))
    })?;
    assert_eq!(
        rows.collect::<Result<Vec<_>, _>>()?,
        vec![
            (1, None, 1, None, 2),
            (2, Some(1), 2, Some("leave started".to_owned()), 15),
            (3, Some(2), 1, Some("returned early".to_owned()), 16),
            (2, Some(1), 2, Some("account closure".to_owned()), 20),
            (4, Some(2), 3, Some("retention complete".to_owned()), 21),
        ]
    );
    Ok(())
}

fn assert_lifecycle_ledger_is_immutable_and_consistent(
    fixture: &Fixture,
    principal_id: PrincipalId,
) -> Result<(), Box<dyn std::error::Error>> {
    assert!(
        fixture
            .repository
            .check_invariants(PageLimit::new(10)?)?
            .findings
            .is_empty()
    );
    assert_constraint_violation(
        &fixture.repository.database.connection().execute(
            "UPDATE principal_lifecycle_events SET reason = reason
             WHERE principal_id = ?1 AND revision = 15",
            [principal_id.as_bytes().as_slice()],
        ),
        "principal lifecycle events are immutable",
    );
    Ok(())
}

fn assert_retirement_survives_restart_and_replay(
    fixture: Fixture,
    file_path: &std::path::Path,
    user: PrincipalId,
    administrator: PrincipalId,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = reopen_fixture(fixture, file_path)?;
    assert_terminal_state(&fixture, user)?;
    let command = AuthoritativeCommand::ChangePrincipalState(state_command(
        user,
        PrincipalLifecycleState::Retired,
        "retention complete",
        Vec::new(),
    )?);
    let replay = fixture.repository.apply_committed(
        LogPosition { index: 22, term: 1 },
        context(121, administrator, 260, 20)?,
        &command,
    )?;
    assert_eq!(replay.disposition, ApplyDisposition::Replayed);
    assert_eq!(replay.committed_revision, Revision::new(21));
    assert_eq!(fixture.repository.current_revision()?, Revision::new(21));
    let rejected = fixture.repository.apply_committed(
        LogPosition { index: 23, term: 1 },
        context(234, administrator, 270, 21)?,
        &AuthoritativeCommand::ChangePrincipalState(state_command(
            user,
            PrincipalLifecycleState::Active,
            "must remain retired",
            Vec::new(),
        )?),
    );
    assert!(matches!(rejected, Err(RepositoryError::InvalidCommand)));
    Ok(())
}

fn assert_current_owner_sets(
    repository: &AuthoritativeRepository,
    expected: [u8; 3],
) -> Result<(), Box<dyn std::error::Error>> {
    for (object, owner_set) in [ROOT_OBJECT, FOLDER_OBJECT, FILE_OBJECT]
        .into_iter()
        .zip(expected)
    {
        let stored: Vec<u8> = repository.database.connection().query_row(
            "SELECT owner_set_id FROM namespace_objects WHERE object_id = ?1",
            [object.as_slice()],
            |row| row.get(0),
        )?;
        assert_eq!(stored, [owner_set; 16]);
    }
    Ok(())
}

fn assert_owner_transfer_fault_rolls_back(
    fault: ApplyFaultPoint,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = build_fixture(false)?;
    let target = fixture.second_user;
    let administrator = fixture.administrator;
    let command = AuthoritativeCommand::ChangePrincipalState(state_command(
        target,
        PrincipalLifecycleState::Suspended,
        "fault proof",
        all_owner_transfers(fixture.user)?,
    )?);
    let result = apply_committed_with_fault(
        &mut fixture.repository.database,
        LogPosition { index: 12, term: 1 },
        context(235, administrator, 220, 11)?,
        &command,
        fault,
    );
    assert!(matches!(result, Err(RepositoryError::InjectedFault)));
    assert_eq!(fixture.repository.current_revision()?, Revision::new(11));
    assert_eq!(
        fixture
            .repository
            .principal(target)?
            .ok_or("missing principal")?
            .state,
        1
    );
    assert_current_owner_sets(&fixture.repository, [30, 31, 32])?;
    let new_owner_sets: i64 = fixture.repository.database.connection().query_row(
        "SELECT COUNT(*) FROM owner_sets WHERE owner_set_id IN (?1, ?2, ?3)",
        params![
            [90_u8; 16].as_slice(),
            [91_u8; 16].as_slice(),
            [92_u8; 16].as_slice(),
        ],
        |row| row.get(0),
    )?;
    assert_eq!(new_owner_sets, 0);
    Ok(())
}

fn context(
    operation_byte: u8,
    actor: PrincipalId,
    now: i64,
    expected_revision: u64,
) -> Result<CommandContext, Box<dyn std::error::Error>> {
    Ok(CommandContext {
        operation_id: OperationId::from_bytes([operation_byte; 16])?,
        actor_principal_id: actor,
        audit_event_id: AuditEventId::from_bytes([operation_byte.wrapping_add(80); 16])?,
        occurred_at: UnixMicros::new(now),
        expected_revision: Some(Revision::new(expected_revision)),
    })
}

fn assert_constraint_violation(result: &Result<usize, rusqlite::Error>, expected_message: &str) {
    assert!(matches!(
        result,
        Err(rusqlite::Error::SqliteFailure(error, Some(message)))
            if error.code == ErrorCode::ConstraintViolation && message == expected_message
    ));
}
