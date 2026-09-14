// SPDX-License-Identifier: GPL-2.0-only

use super::authentication_method_tests::{bootstrap, context, position};
use super::{ApplyDisposition, AuthoritativeRepository, RepositoryError, UserEnrollmentState};
use crate::{
    AuthoritativeCommand, CreateAuthenticationMethod, CreateUser, IssueUserEnrollment,
    NewAuthenticationCredential, PartitionDatabase, RecordName, RedeemUserEnrollment,
    RevokeUserEnrollment,
};
use meshspan_domain::{
    ApiKeyId, AuthenticationMethodId, AuthenticationService, OperationId, PartitionId, PrincipalId,
    Revision, UnixMicros,
};
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn first_credential_redemption_is_atomic_restart_safe_and_exact() -> TestResult {
    let (directory, mut repository, administrator, bob) = fixture()?;
    let issue = issue(bob);
    repository.apply_committed(
        position(3),
        context(10, administrator, 11, 12, None)?,
        &issue,
    )?;
    let request = redeem(bob)?;
    let attempt = context(20, bob, 21, 20, None)?;
    let receipt = repository.apply_committed(position(4), attempt, &request)?;
    assert_eq!(receipt.disposition, ApplyDisposition::Applied);
    let authentication = repository
        .authenticate_api_key(
            [31; 32],
            AuthenticationService::Https,
            AuthenticationService::Https.api_key_login_scope(),
            UnixMicros::new(21),
        )?
        .ok_or("new user's key must authenticate")?;
    assert_eq!(authentication.principal_id, bob);
    assert_ne!(authentication.principal_id, administrator);
    drop(repository.into_database());
    let database = PartitionDatabase::open(
        &directory.path().join("authority.sqlite3"),
        PartitionId::from_bytes([1; 16])?,
        UnixMicros::new(22),
    )?;
    let mut reopened = AuthoritativeRepository::new(database);
    let replay = reopened.apply_committed(position(5), attempt, &request)?;
    assert_eq!(replay.disposition, ApplyDisposition::Replayed);
    assert_eq!(replay.result_digest, receipt.result_digest);
    assert_eq!(replay.committed_revision, Revision::new(4));
    assert!(matches!(
        reopened.apply_committed(position(6), context(22, bob, 23, 22, None)?, &request),
        Err(RepositoryError::InvalidCommand)
    ));
    let mut changed = request;
    if let AuthoritativeCommand::RedeemUserEnrollment(value) = &mut changed {
        value.method.label = "Changed".to_owned();
    }
    assert!(matches!(
        reopened.apply_committed(position(6), attempt, &changed),
        Err(RepositoryError::OperationConflict)
    ));
    let methods: i64 = reopened.database.connection().query_row(
        "SELECT COUNT(*) FROM authentication_methods WHERE user_principal_id = ?1",
        [bob.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    assert_eq!(methods, 1);
    assert!(matches!(
        reopened
            .user_enrollment(OperationId::from_bytes([10; 16])?)?
            .ok_or("invitation")?
            .state,
        UserEnrollmentState::Redeemed(_)
    ));
    Ok(())
}

#[test]
fn invalid_capability_and_expiry_do_not_create_a_method() -> TestResult {
    let (_directory, mut repository, administrator, bob) = fixture()?;
    repository.apply_committed(
        position(3),
        context(10, administrator, 11, 12, None)?,
        &issue(bob),
    )?;
    let mut wrong = redeem(bob)?;
    if let AuthoritativeCommand::RedeemUserEnrollment(value) = &mut wrong {
        value.token_digest = [99; 32];
    }
    assert!(matches!(
        repository.apply_committed(position(4), context(20, bob, 21, 20, None)?, &wrong),
        Err(RepositoryError::InvalidCommand)
    ));
    assert!(matches!(
        repository.apply_committed(position(4), context(22, bob, 23, 100, None)?, &redeem(bob)?),
        Err(RepositoryError::InvalidCommand)
    ));
    assert_eq!(repository.current_revision()?, Revision::new(3));
    assert!(
        repository
            .authenticate_api_key(
                [31; 32],
                AuthenticationService::Https,
                AuthenticationService::Https.api_key_login_scope(),
                UnixMicros::new(21)
            )?
            .is_none()
    );
    Ok(())
}

#[test]
fn invitation_issue_and_revocation_require_manager_consent() -> TestResult {
    let (_directory, mut repository, administrator, bob) = fixture()?;
    assert!(matches!(
        repository.apply_committed(position(3), context(10, bob, 11, 12, None)?, &issue(bob)),
        Err(RepositoryError::InvalidCommand)
    ));
    repository.apply_committed(
        position(3),
        context(10, administrator, 11, 12, None)?,
        &issue(bob),
    )?;
    let revoke = AuthoritativeCommand::RevokeUserEnrollment(RevokeUserEnrollment {
        enrollment_operation_id: OperationId::from_bytes([10; 16])?,
        expected_revision: Revision::new(3),
    });
    assert!(matches!(
        repository.apply_committed(position(4), context(12, bob, 13, 15, None)?, &revoke),
        Err(RepositoryError::InvalidCommand)
    ));
    repository.apply_committed(
        position(4),
        context(12, administrator, 13, 15, None)?,
        &revoke,
    )?;
    assert!(matches!(
        repository.apply_committed(position(5), context(20, bob, 21, 20, None)?, &redeem(bob)?),
        Err(RepositoryError::InvalidCommand)
    ));
    assert_eq!(
        repository
            .user_enrollment(OperationId::from_bytes([10; 16])?)?
            .ok_or("invitation")?
            .state,
        UserEnrollmentState::Revoked
    );
    Ok(())
}

#[test]
fn existing_primary_race_does_not_consume_consent() -> TestResult {
    let (_directory, mut repository, administrator, bob) = fixture()?;
    repository.apply_committed(
        position(3),
        context(10, administrator, 11, 12, None)?,
        &issue(bob),
    )?;
    let AuthoritativeCommand::RedeemUserEnrollment(enrollment) = redeem(bob)? else {
        return Err("expected redemption".into());
    };
    repository.apply_committed(
        position(4),
        context(50, bob, 51, 20, None)?,
        &AuthoritativeCommand::CreateAuthenticationMethod(enrollment.method),
    )?;
    assert!(matches!(
        repository.apply_committed(position(5), context(20, bob, 21, 21, None)?, &redeem(bob)?),
        Err(RepositoryError::InvalidCommand)
    ));
    assert_eq!(
        repository
            .user_enrollment(OperationId::from_bytes([10; 16])?)?
            .ok_or("invitation")?
            .state,
        UserEnrollmentState::Issued
    );
    assert_eq!(repository.current_revision()?, Revision::new(4));
    Ok(())
}

#[test]
fn stale_recipient_consent_and_overlong_invitation_are_rejected() -> TestResult {
    let (_directory, mut repository, administrator, bob) = fixture()?;
    for (revision, expiry) in [(1, 100), (2, 86_400_000_013)] {
        let mut command = issue(bob);
        if let AuthoritativeCommand::IssueUserEnrollment(value) = &mut command {
            value.expected_principal_revision = Revision::new(revision);
            value.expires_at = UnixMicros::new(expiry);
        }
        assert!(matches!(
            repository.apply_committed(
                position(3),
                context(10, administrator, 11, 12, None)?,
                &command
            ),
            Err(RepositoryError::InvalidCommand)
        ));
    }
    assert_eq!(repository.current_revision()?, Revision::new(2));
    Ok(())
}

#[test]
fn enrollment_commands_round_trip_and_reject_trailing_input() -> TestResult {
    let bob = PrincipalId::from_bytes([3; 16])?;
    let context = context(10, bob, 11, 12, None)?;
    let commands = [
        issue(bob),
        redeem(bob)?,
        AuthoritativeCommand::RevokeUserEnrollment(RevokeUserEnrollment {
            enrollment_operation_id: OperationId::from_bytes([10; 16])?,
            expected_revision: Revision::new(3),
        }),
    ];
    for command in commands {
        let mut bytes = crate::encode_authoritative_command(context, &command)?;
        let decoded = crate::decode_authoritative_command(&bytes)?;
        assert_eq!(decoded.context, context);
        assert_eq!(decoded.command, command);
        bytes.push(0);
        assert!(crate::decode_authoritative_command(&bytes).is_err());
    }
    Ok(())
}

#[test]
fn suspended_recipient_cannot_redeem_or_receive_new_consent() -> TestResult {
    let (_directory, mut repository, administrator, bob) = fixture()?;
    repository.apply_committed(
        position(3),
        context(10, administrator, 11, 12, None)?,
        &issue(bob),
    )?;
    repository.apply_committed(
        position(4),
        context(50, administrator, 51, 15, None)?,
        &AuthoritativeCommand::ChangePrincipalState(crate::ChangePrincipalState {
            principal_id: bob,
            state: crate::PrincipalLifecycleState::Suspended,
            reason: "Disable access".to_owned(),
            owner_transfers: meshspan_contracts::BoundedItems::new(Vec::new(), 1_000)?,
        }),
    )?;
    assert!(matches!(
        repository.apply_committed(position(5), context(20, bob, 21, 20, None)?, &redeem(bob)?),
        Err(RepositoryError::InvalidCommand)
    ));
    assert!(matches!(
        repository.apply_committed(
            position(5),
            context(60, administrator, 61, 20, None)?,
            &issue(bob)
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    assert_eq!(repository.current_revision()?, Revision::new(4));
    Ok(())
}

fn fixture()
-> Result<(TempDir, AuthoritativeRepository, PrincipalId, PrincipalId), Box<dyn std::error::Error>>
{
    let directory = tempfile::tempdir()?;
    let administrator = PrincipalId::from_bytes([2; 16])?;
    let bob = PrincipalId::from_bytes([3; 16])?;
    let database = PartitionDatabase::open(
        &directory.path().join("authority.sqlite3"),
        PartitionId::from_bytes([1; 16])?,
        UnixMicros::new(1),
    )?;
    let mut repository = AuthoritativeRepository::new(database);
    bootstrap(&mut repository, administrator)?;
    repository.apply_committed(
        position(2),
        context(6, administrator, 7, 11, None)?,
        &AuthoritativeCommand::CreateUser(CreateUser {
            principal_id: bob,
            name: RecordName::new("Bob")?,
        }),
    )?;
    Ok((directory, repository, administrator, bob))
}
fn issue(bob: PrincipalId) -> AuthoritativeCommand {
    AuthoritativeCommand::IssueUserEnrollment(IssueUserEnrollment {
        principal_id: bob,
        expected_principal_revision: Revision::new(2),
        token_digest: [9; 32],
        expires_at: UnixMicros::new(100),
    })
}
fn redeem(bob: PrincipalId) -> Result<AuthoritativeCommand, meshspan_domain::IdentifierError> {
    Ok(AuthoritativeCommand::RedeemUserEnrollment(
        RedeemUserEnrollment {
            enrollment_operation_id: OperationId::from_bytes([10; 16])?,
            token_digest: [9; 32],
            method: CreateAuthenticationMethod {
                method_id: AuthenticationMethodId::from_bytes([30; 16])?,
                principal_id: bob,
                label: "Bob's key".to_owned(),
                service_scope: 3,
                expires_at: None,
                credential: NewAuthenticationCredential::ApiKey {
                    key_id: ApiKeyId::from_bytes([32; 16])?,
                    key_digest: [31; 32],
                    smb_verifier_ciphertext: None,
                    scopes: 3,
                    valid_from: UnixMicros::new(20),
                },
            },
        },
    ))
}
