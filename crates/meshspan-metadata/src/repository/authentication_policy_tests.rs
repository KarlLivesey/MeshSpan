// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    AuthenticationFactorClasses, AuthenticationMethodKind, AuthenticationOperationClass,
    AuthenticationPolicyId, AuthenticationService, DurationMicros, PartitionId, PrincipalId,
    Revision, UnixMicros,
};
use tempfile::tempdir;

use super::authentication_method_tests::{bootstrap, context, position};
use super::{ApplyDisposition, AuthoritativeRepository, EntityKind, RepositoryError};
use crate::{AuthoritativeCommand, ConfigureAuthenticationPolicy, PartitionDatabase};

#[test]
fn defaults_are_complete_and_policy_replacement_is_replayable_and_durable()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("authentication-policy.sqlite3");
    let partition_id = PartitionId::from_bytes([1; 16])?;
    let administrator = PrincipalId::from_bytes([2; 16])?;
    let database = PartitionDatabase::open(&file_path, partition_id, UnixMicros::new(1))?;
    let mut repository = AuthoritativeRepository::new(database);
    bootstrap(&mut repository, administrator)?;

    let default = repository.authentication_policy(
        AuthenticationService::Https,
        AuthenticationOperationClass::Privileged,
    )?;
    assert_eq!(default.sequence, 1);
    assert_eq!(default.minimum_factor_count, 2);
    assert_eq!(
        default.maximum_step_up_age,
        Some(DurationMicros::new(900_000_000))
    );
    let count: i64 = repository.database.connection().query_row(
        "SELECT count(*) FROM authentication_policy_revisions",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 12);

    let policy_id = AuthenticationPolicyId::from_bytes([50; 16])?;
    let command = policy(
        policy_id,
        AuthenticationOperationClass::Privileged,
        1,
        AuthenticationFactorClasses::ALL,
        2,
        1_000,
        Some(10),
    );
    let command_context = context(51, administrator, 52, 100, Some(Revision::new(1)))?;
    let receipt = repository.apply_committed(position(2), command_context, &command)?;
    assert_eq!(receipt.entity.kind, EntityKind::AuthenticationPolicy);
    assert_eq!(receipt.entity.id, policy_id.as_bytes());
    let current = repository.authentication_policy(
        AuthenticationService::Https,
        AuthenticationOperationClass::Privileged,
    )?;
    assert_eq!(current.sequence, 2);
    assert_eq!(current.maximum_step_up_age, Some(DurationMicros::new(10)));

    let replay = repository.apply_committed(position(3), command_context, &command)?;
    assert_eq!(replay.disposition, ApplyDisposition::Replayed);
    assert_eq!(replay.committed_revision, Revision::new(2));
    assert_eq!(repository.current_revision()?, Revision::new(2));

    let database = repository.into_database();
    assert!(
        database
            .connection()
            .execute(
                "UPDATE authentication_policy_revisions SET minimum_factor_count = 1
         WHERE policy_id = ?1",
                [policy_id.as_bytes().as_slice()],
            )
            .is_err()
    );
    drop(database);
    let reopened = AuthoritativeRepository::new(PartitionDatabase::open(
        &file_path,
        partition_id,
        UnixMicros::new(200),
    )?);
    assert_eq!(
        reopened
            .authentication_policy(
                AuthenticationService::Https,
                AuthenticationOperationClass::Privileged,
            )?
            .policy_id,
        policy_id
    );
    Ok(())
}

#[test]
fn invalid_or_stale_policy_replacements_advance_nothing() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let file_path = directory
        .path()
        .join("invalid-authentication-policy.sqlite3");
    let partition_id = PartitionId::from_bytes([1; 16])?;
    let administrator = PrincipalId::from_bytes([2; 16])?;
    let database = PartitionDatabase::open(&file_path, partition_id, UnixMicros::new(1))?;
    let mut repository = AuthoritativeRepository::new(database);
    bootstrap(&mut repository, administrator)?;

    let totp_only = AuthenticationFactorClasses::new(AuthenticationMethodKind::Totp.class_bit())?;
    let invalid = [
        policy(
            AuthenticationPolicyId::from_bytes([60; 16])?,
            AuthenticationOperationClass::Privileged,
            1,
            AuthenticationFactorClasses::ALL,
            0,
            100,
            Some(10),
        ),
        policy(
            AuthenticationPolicyId::from_bytes([61; 16])?,
            AuthenticationOperationClass::Privileged,
            1,
            totp_only,
            1,
            100,
            Some(10),
        ),
        policy(
            AuthenticationPolicyId::from_bytes([62; 16])?,
            AuthenticationOperationClass::Ordinary,
            1,
            AuthenticationFactorClasses::ALL,
            1,
            100,
            Some(10),
        ),
        policy(
            AuthenticationPolicyId::from_bytes([63; 16])?,
            AuthenticationOperationClass::Privileged,
            1,
            AuthenticationFactorClasses::ALL,
            2,
            10,
            Some(11),
        ),
    ];
    for (offset, command) in invalid.into_iter().enumerate() {
        assert!(matches!(
            repository.apply_committed(
                position(2),
                context(
                    70 + u8::try_from(offset)?,
                    administrator,
                    80 + u8::try_from(offset)?,
                    100,
                    Some(Revision::new(1)),
                )?,
                &command,
            ),
            Err(RepositoryError::InvalidCommand)
        ));
    }
    let stale = policy(
        AuthenticationPolicyId::from_bytes([64; 16])?,
        AuthenticationOperationClass::Privileged,
        2,
        AuthenticationFactorClasses::ALL,
        2,
        100,
        Some(10),
    );
    assert!(matches!(
        repository.apply_committed(
            position(2),
            context(90, administrator, 91, 100, Some(Revision::new(1)))?,
            &stale,
        ),
        Err(RepositoryError::StaleAuthenticationPolicy)
    ));
    assert_eq!(repository.current_revision()?, Revision::new(1));
    Ok(())
}

fn policy(
    policy_id: AuthenticationPolicyId,
    operation_class: AuthenticationOperationClass,
    expected_policy_sequence: u64,
    allowed_factor_classes: AuthenticationFactorClasses,
    minimum_factor_count: u8,
    maximum_session_duration: u64,
    maximum_step_up_age: Option<u64>,
) -> AuthoritativeCommand {
    AuthoritativeCommand::ConfigureAuthenticationPolicy(ConfigureAuthenticationPolicy {
        policy_id,
        service: AuthenticationService::Https,
        operation_class,
        expected_policy_sequence,
        allowed_factor_classes,
        minimum_factor_count,
        maximum_session_duration: DurationMicros::new(maximum_session_duration),
        maximum_step_up_age: maximum_step_up_age.map(DurationMicros::new),
    })
}
