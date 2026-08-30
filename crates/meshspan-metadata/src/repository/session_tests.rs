// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    AssuranceLevel, AuthenticationFactorClasses, AuthenticationMethodId, AuthenticationMethodKind,
    AuthenticationOperationClass, AuthenticationPolicyId, AuthenticationService, DurationMicros,
    RecoveryCodeId, Revision, SessionId, UnixMicros,
};
use tempfile::tempdir;

use super::authentication_method_tests::{bootstrap, context, position};
use super::{AuthoritativeRepository, RepositoryError};
use crate::{
    AuthoritativeCommand, ConfigureAuthenticationPolicy, CreateAuthenticationMethod,
    IssueAuthenticationSession, NewAuthenticationCredential, NewRecoveryCode, PartitionDatabase,
    SessionAuthenticationFactor,
};

#[test]
fn session_establishment_obeys_current_class_and_lifetime_policy()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory
        .path()
        .join("session-establishment-policy.sqlite3");
    let partition_id = meshspan_domain::PartitionId::from_bytes([1; 16])?;
    let administrator = meshspan_domain::PrincipalId::from_bytes([2; 16])?;
    let database = PartitionDatabase::open(&file_path, partition_id, UnixMicros::new(1))?;
    let mut repository = AuthoritativeRepository::new(database);
    bootstrap(&mut repository, administrator)?;
    let passkey_method = AuthenticationMethodId::from_bytes([20; 16])?;
    create_passkey(&mut repository, administrator, passkey_method)?;

    configure_session_policy(
        &mut repository,
        administrator,
        3,
        1,
        AuthenticationFactorClasses::new(AuthenticationMethodKind::ApiKey.class_bit())?,
        100,
        50,
    )?;
    let passkey_session = single_passkey_session(administrator, passkey_method, 70, 150)?;
    assert!(matches!(
        repository.apply_committed(
            position(4),
            context(71, administrator, 72, 120, Some(Revision::new(3)))?,
            &passkey_session,
        ),
        Err(RepositoryError::InvalidCommand)
    ));

    configure_session_policy(
        &mut repository,
        administrator,
        4,
        2,
        AuthenticationFactorClasses::ALL,
        5,
        51,
    )?;
    assert!(matches!(
        repository.apply_committed(
            position(5),
            context(73, administrator, 74, 120, Some(Revision::new(4)))?,
            &passkey_session,
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    assert_eq!(repository.current_revision()?, Revision::new(4));
    Ok(())
}

#[test]
fn current_privileged_policy_controls_step_up_age_without_a_caller_claim()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("session-step-up-policy.sqlite3");
    let partition_id = meshspan_domain::PartitionId::from_bytes([1; 16])?;
    let administrator = meshspan_domain::PrincipalId::from_bytes([2; 16])?;
    let database = PartitionDatabase::open(&file_path, partition_id, UnixMicros::new(1))?;
    let mut repository = AuthoritativeRepository::new(database);
    bootstrap(&mut repository, administrator)?;
    let passkey_method = AuthenticationMethodId::from_bytes([20; 16])?;
    let recovery_method = AuthenticationMethodId::from_bytes([30; 16])?;
    let recovery_code = RecoveryCodeId::from_bytes([31; 16])?;
    create_passkey(&mut repository, administrator, passkey_method)?;
    create_recovery_codes(
        &mut repository,
        administrator,
        recovery_method,
        recovery_code,
    )?;
    let session = session_command(TwoFactorSessionFixture::initial(
        administrator,
        passkey_method,
        recovery_method,
        recovery_code,
        40,
    ))?;
    repository.apply_committed(
        position(4),
        context(41, administrator, 42, 120, Some(Revision::new(3)))?,
        &session,
    )?;
    repository.apply_committed(
        position(5),
        context(80, administrator, 81, 125, Some(Revision::new(4)))?,
        &AuthoritativeCommand::ConfigureAuthenticationPolicy(ConfigureAuthenticationPolicy {
            policy_id: AuthenticationPolicyId::from_bytes([82; 16])?,
            service: AuthenticationService::Https,
            operation_class: AuthenticationOperationClass::Privileged,
            expected_policy_sequence: 1,
            allowed_factor_classes: AuthenticationFactorClasses::ALL,
            minimum_factor_count: 2,
            maximum_session_duration: DurationMicros::new(1_000),
            maximum_step_up_age: Some(DurationMicros::new(10)),
        }),
    )?;
    let factors = super::session::active_factor_state(
        repository.database.connection(),
        &SessionId::from_bytes([40; 16])?.as_bytes(),
        UnixMicros::new(130),
    )?
    .ok_or("session factors unexpectedly unavailable")?;
    assert!(super::session::meets_assurance(
        repository.database.connection(),
        factors,
        AssuranceLevel::RecentStepUp,
        UnixMicros::new(130),
    )?);
    assert!(!super::session::meets_assurance(
        repository.database.connection(),
        factors,
        AssuranceLevel::RecentStepUp,
        UnixMicros::new(131),
    )?);
    Ok(())
}

#[test]
fn session_consumes_exact_typed_factors_and_rolls_back_a_replay()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("session-factor-consumption.sqlite3");
    let partition_id = meshspan_domain::PartitionId::from_bytes([1; 16])?;
    let administrator = meshspan_domain::PrincipalId::from_bytes([2; 16])?;
    let database = PartitionDatabase::open(&file_path, partition_id, UnixMicros::new(1))?;
    let mut repository = AuthoritativeRepository::new(database);
    bootstrap(&mut repository, administrator)?;

    let passkey_method = AuthenticationMethodId::from_bytes([20; 16])?;
    let recovery_method = AuthenticationMethodId::from_bytes([30; 16])?;
    let recovery_code = RecoveryCodeId::from_bytes([31; 16])?;
    create_passkey(&mut repository, administrator, passkey_method)?;
    create_recovery_codes(
        &mut repository,
        administrator,
        recovery_method,
        recovery_code,
    )?;
    let session = session_command(TwoFactorSessionFixture::initial(
        administrator,
        passkey_method,
        recovery_method,
        recovery_code,
        40,
    ))?;
    repository.apply_committed(
        position(4),
        context(41, administrator, 42, 120, Some(Revision::new(3)))?,
        &session,
    )?;

    let database = &repository.database;
    let session_shape: (i64, i64) = database.connection().query_row(
        "SELECT assurance,
                (SELECT count(*) FROM authentication_session_factors AS factor
                 WHERE factor.session_id = session.session_id)
         FROM authentication_sessions AS session",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(session_shape, (2, 2));
    let passkey_state: (i64, i64, i64) = database.connection().query_row(
        "SELECT signature_counter, backup_state, revision FROM webauthn_credentials",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(passkey_state, (1, 1, 4));
    let recovery_state: (i64, i64) = database.connection().query_row(
        "SELECT used_at, revision FROM recovery_codes",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(recovery_state, (120, 4));

    let replay = session_command(TwoFactorSessionFixture {
        principal_id: administrator,
        passkey_method,
        recovery_method,
        recovery_code,
        signature_counter: 2,
        passkey_revision: Revision::new(4),
        recovery_revision: Revision::new(4),
        identity_seed: 43,
    })?;
    assert!(matches!(
        repository.apply_committed(
            position(5),
            context(44, administrator, 45, 121, Some(Revision::new(4)))?,
            &replay,
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    assert_eq!(repository.current_revision()?, Revision::new(4));
    let counter: i64 = repository.database.connection().query_row(
        "SELECT signature_counter FROM webauthn_credentials",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(counter, 1);
    repository.database.connection().execute(
        "DELETE FROM webauthn_credentials WHERE method_id = ?1",
        [passkey_method.as_bytes().as_slice()],
    )?;
    assert!(matches!(
        super::session::active_factor_state(
            repository.database.connection(),
            &SessionId::from_bytes([40; 16])?.as_bytes(),
            UnixMicros::new(122),
        ),
        Err(RepositoryError::CorruptState)
    ));
    Ok(())
}

fn configure_session_policy(
    repository: &mut AuthoritativeRepository,
    administrator: meshspan_domain::PrincipalId,
    position_index: u64,
    expected_policy_sequence: u64,
    allowed_factor_classes: AuthenticationFactorClasses,
    maximum_session_duration: u64,
    identity_seed: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    repository.apply_committed(
        position(position_index),
        context(
            identity_seed,
            administrator,
            identity_seed.wrapping_add(1),
            115,
            Some(Revision::new(position_index - 1)),
        )?,
        &AuthoritativeCommand::ConfigureAuthenticationPolicy(ConfigureAuthenticationPolicy {
            policy_id: AuthenticationPolicyId::from_bytes([identity_seed.wrapping_add(2); 16])?,
            service: AuthenticationService::Https,
            operation_class: AuthenticationOperationClass::SessionEstablishment,
            expected_policy_sequence,
            allowed_factor_classes,
            minimum_factor_count: 1,
            maximum_session_duration: DurationMicros::new(maximum_session_duration),
            maximum_step_up_age: None,
        }),
    )?;
    Ok(())
}

fn single_passkey_session(
    principal_id: meshspan_domain::PrincipalId,
    method_id: AuthenticationMethodId,
    identity_seed: u8,
    expires_at: i64,
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    Ok(AuthoritativeCommand::IssueAuthenticationSession(
        IssueAuthenticationSession {
            session_id: SessionId::from_bytes([identity_seed; 16])?,
            principal_id,
            token_digest: [identity_seed.wrapping_add(1); 32],
            service: AuthenticationService::Https,
            factors: BoundedItems::new(
                vec![SessionAuthenticationFactor::Passkey {
                    method_id,
                    credential_generation: 1,
                    method_revision: Revision::new(2),
                    credential_id: vec![24; 32],
                    signature_counter: 1,
                    backup_state: false,
                }],
                8,
            )?,
            expires_at: UnixMicros::new(expires_at),
        },
    ))
}

fn create_passkey(
    repository: &mut AuthoritativeRepository,
    administrator: meshspan_domain::PrincipalId,
    method_id: AuthenticationMethodId,
) -> Result<(), Box<dyn std::error::Error>> {
    repository.apply_committed(
        position(2),
        context(22, administrator, 23, 110, Some(Revision::new(1)))?,
        &AuthoritativeCommand::CreateAuthenticationMethod(CreateAuthenticationMethod {
            method_id,
            principal_id: administrator,
            label: "Passkey".to_owned(),
            service_scope: AuthenticationService::Https.scope_bit(),
            expires_at: None,
            credential: NewAuthenticationCredential::Passkey {
                credential_id: vec![24; 32],
                public_key_algorithm: -7,
                public_key: vec![25; 77],
                signature_counter: 0,
                authenticator_guid: Some([26; 16]),
                transports: 1,
                backup_eligible: true,
                backup_state: false,
            },
        }),
    )?;
    Ok(())
}

fn create_recovery_codes(
    repository: &mut AuthoritativeRepository,
    administrator: meshspan_domain::PrincipalId,
    method_id: AuthenticationMethodId,
    code_id: RecoveryCodeId,
) -> Result<(), Box<dyn std::error::Error>> {
    repository.apply_committed(
        position(3),
        context(32, administrator, 33, 111, Some(Revision::new(2)))?,
        &AuthoritativeCommand::CreateAuthenticationMethod(CreateAuthenticationMethod {
            method_id,
            principal_id: administrator,
            label: "Recovery codes".to_owned(),
            service_scope: AuthenticationService::Https.scope_bit(),
            expires_at: None,
            credential: NewAuthenticationCredential::RecoveryCodes {
                codes: BoundedItems::new(
                    vec![NewRecoveryCode {
                        code_id,
                        code_digest: [34; 32],
                    }],
                    64,
                )?,
            },
        }),
    )?;
    Ok(())
}

#[derive(Clone, Copy)]
struct TwoFactorSessionFixture {
    principal_id: meshspan_domain::PrincipalId,
    passkey_method: AuthenticationMethodId,
    recovery_method: AuthenticationMethodId,
    recovery_code: RecoveryCodeId,
    signature_counter: u64,
    passkey_revision: Revision,
    recovery_revision: Revision,
    identity_seed: u8,
}

impl TwoFactorSessionFixture {
    fn initial(
        principal_id: meshspan_domain::PrincipalId,
        passkey_method: AuthenticationMethodId,
        recovery_method: AuthenticationMethodId,
        recovery_code: RecoveryCodeId,
        identity_seed: u8,
    ) -> Self {
        Self {
            principal_id,
            passkey_method,
            recovery_method,
            recovery_code,
            signature_counter: 1,
            passkey_revision: Revision::new(2),
            recovery_revision: Revision::new(3),
            identity_seed,
        }
    }
}

fn session_command(
    fixture: TwoFactorSessionFixture,
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    Ok(AuthoritativeCommand::IssueAuthenticationSession(
        IssueAuthenticationSession {
            session_id: SessionId::from_bytes([fixture.identity_seed; 16])?,
            principal_id: fixture.principal_id,
            token_digest: [fixture.identity_seed.wrapping_add(1); 32],
            service: AuthenticationService::Https,
            factors: BoundedItems::new(
                vec![
                    SessionAuthenticationFactor::Passkey {
                        method_id: fixture.passkey_method,
                        credential_generation: 1,
                        method_revision: fixture.passkey_revision,
                        credential_id: vec![24; 32],
                        signature_counter: fixture.signature_counter,
                        backup_state: true,
                    },
                    SessionAuthenticationFactor::RecoveryCode {
                        method_id: fixture.recovery_method,
                        credential_generation: 1,
                        method_revision: fixture.recovery_revision,
                        code_id: fixture.recovery_code,
                    },
                ],
                8,
            )?,
            expires_at: UnixMicros::new(500),
        },
    ))
}
