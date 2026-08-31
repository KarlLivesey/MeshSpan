// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{AuthenticationChallengeId, NodeId, OperationId, UnixMicros};
use tempfile::tempdir;

use crate::{
    AuthenticationCeremonyDisposition, AuthenticationCeremonyError, AuthenticationCeremonyKind,
    AuthenticationCeremonyState, LocalDatabase, NewAuthenticationCeremony,
    ProtectedAuthenticationState,
};

#[test]
fn ceremony_is_restart_safe_single_attempt_and_exactly_replayable()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("local.sqlite3");
    let node_id = NodeId::from_bytes([1; 16])?;
    let challenge_id = AuthenticationChallengeId::from_bytes([2; 16])?;
    let creation_operation = OperationId::from_bytes([3; 16])?;
    let completion_operation = OperationId::from_bytes([4; 16])?;
    let ceremony = NewAuthenticationCeremony {
        challenge_id,
        creation_operation_id: creation_operation,
        kind: AuthenticationCeremonyKind::PasskeyAuthentication,
        request_digest: [5; 32],
        protected_state: ProtectedAuthenticationState::new(vec![6; 64])?,
        created_at: UnixMicros::new(100),
        expires_at: UnixMicros::new(200),
    };
    let mut database = LocalDatabase::open(&file_path, node_id, UnixMicros::new(1))?;
    assert_eq!(
        database.create_authentication_ceremony(&ceremony)?,
        AuthenticationCeremonyDisposition::Applied
    );
    assert_eq!(
        database.create_authentication_ceremony(&ceremony)?,
        AuthenticationCeremonyDisposition::Replayed
    );
    assert_eq!(
        database
            .authentication_ceremony_by_creation(creation_operation)?
            .ok_or("ceremony missing by creation operation")?
            .challenge_id,
        challenge_id
    );
    drop(database);

    let mut database = LocalDatabase::open(&file_path, node_id, UnixMicros::new(110))?;
    assert_eq!(
        database.begin_authentication_verification(
            challenge_id,
            completion_operation,
            [7; 32],
            UnixMicros::new(120),
        )?,
        AuthenticationCeremonyDisposition::Applied
    );
    assert_eq!(
        database.begin_authentication_verification(
            challenge_id,
            completion_operation,
            [7; 32],
            UnixMicros::new(130),
        )?,
        AuthenticationCeremonyDisposition::Replayed
    );
    assert!(matches!(
        database.begin_authentication_verification(
            challenge_id,
            completion_operation,
            [8; 32],
            UnixMicros::new(130),
        ),
        Err(AuthenticationCeremonyError::Conflict)
    ));
    assert_eq!(
        database.record_authentication_authority_commit(
            challenge_id,
            completion_operation,
            [9; 32],
            UnixMicros::new(210),
        )?,
        AuthenticationCeremonyDisposition::Applied
    );
    assert_eq!(
        database.complete_authentication_ceremony(
            challenge_id,
            completion_operation,
            UnixMicros::new(220),
        )?,
        AuthenticationCeremonyDisposition::Applied
    );
    assert_eq!(
        database
            .authentication_ceremony(challenge_id)?
            .ok_or("ceremony missing")?
            .state,
        AuthenticationCeremonyState::Consumed
    );
    Ok(())
}

#[test]
fn changed_creation_expiry_and_persisted_substitution_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let node_id = NodeId::from_bytes([11; 16])?;
    let challenge_id = AuthenticationChallengeId::from_bytes([12; 16])?;
    let operation_id = OperationId::from_bytes([13; 16])?;
    let mut database = LocalDatabase::open(
        &directory.path().join("local.sqlite3"),
        node_id,
        UnixMicros::new(1),
    )?;
    let mut ceremony = NewAuthenticationCeremony {
        challenge_id,
        creation_operation_id: operation_id,
        kind: AuthenticationCeremonyKind::AdditionalFactor,
        request_digest: [14; 32],
        protected_state: ProtectedAuthenticationState::new(vec![15; 32])?,
        created_at: UnixMicros::new(100),
        expires_at: UnixMicros::new(200),
    };
    database.create_authentication_ceremony(&ceremony)?;
    ceremony.request_digest = [16; 32];
    assert!(matches!(
        database.create_authentication_ceremony(&ceremony),
        Err(AuthenticationCeremonyError::Conflict)
    ));
    assert!(matches!(
        database.begin_authentication_verification(
            challenge_id,
            OperationId::from_bytes([17; 16])?,
            [18; 32],
            UnixMicros::new(200),
        ),
        Err(AuthenticationCeremonyError::Expired)
    ));
    database.connection_mut().execute(
        "UPDATE local_authentication_ceremonies SET protected_state = zeroblob(32)
         WHERE challenge_id = ?1",
        [challenge_id.as_bytes().as_slice()],
    )?;
    assert!(database.authentication_ceremony(challenge_id).is_err());
    Ok(())
}

#[test]
fn totp_registration_has_a_distinct_restart_safe_ceremony_kind()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("totp-registration.sqlite3");
    let node_id = NodeId::from_bytes([21; 16])?;
    let challenge_id = AuthenticationChallengeId::from_bytes([22; 16])?;
    let creation_operation_id = OperationId::from_bytes([23; 16])?;
    let mut database = LocalDatabase::open(&file_path, node_id, UnixMicros::new(1))?;
    database.create_authentication_ceremony(&NewAuthenticationCeremony {
        challenge_id,
        creation_operation_id,
        kind: AuthenticationCeremonyKind::TotpRegistration,
        request_digest: [24; 32],
        protected_state: ProtectedAuthenticationState::new(vec![25; 64])?,
        created_at: UnixMicros::new(100),
        expires_at: UnixMicros::new(200),
    })?;
    drop(database);

    let database = LocalDatabase::open(&file_path, node_id, UnixMicros::new(110))?;
    let record = database
        .authentication_ceremony_by_creation(creation_operation_id)?
        .ok_or("TOTP registration ceremony missing after restart")?;
    assert_eq!(record.challenge_id, challenge_id);
    assert_eq!(record.kind, AuthenticationCeremonyKind::TotpRegistration);
    assert_eq!(database.schema_version(), 10);
    Ok(())
}
