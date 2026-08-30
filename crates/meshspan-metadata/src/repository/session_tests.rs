// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    AuthenticationMethodId, AuthenticationService, RecoveryCodeId, Revision, SessionId, UnixMicros,
};
use tempfile::tempdir;

use super::authentication_method_tests::{bootstrap, context, position};
use super::{AuthoritativeRepository, RepositoryError};
use crate::{
    AuthoritativeCommand, CreateAuthenticationMethod, IssueAuthenticationSession,
    NewAuthenticationCredential, NewRecoveryCode, PartitionDatabase, SessionAuthenticationFactor,
};

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
    let session = session_command(
        administrator,
        passkey_method,
        recovery_method,
        recovery_code,
        1,
        Revision::new(2),
        Revision::new(3),
        40,
    )?;
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

    let replay = session_command(
        administrator,
        passkey_method,
        recovery_method,
        recovery_code,
        2,
        Revision::new(4),
        Revision::new(4),
        43,
    )?;
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

#[allow(
    clippy::too_many_arguments,
    reason = "complete two-factor session fixture"
)]
fn session_command(
    principal_id: meshspan_domain::PrincipalId,
    passkey_method: AuthenticationMethodId,
    recovery_method: AuthenticationMethodId,
    recovery_code: RecoveryCodeId,
    signature_counter: u64,
    passkey_revision: Revision,
    recovery_revision: Revision,
    identity_seed: u8,
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    Ok(AuthoritativeCommand::IssueAuthenticationSession(
        IssueAuthenticationSession {
            session_id: SessionId::from_bytes([identity_seed; 16])?,
            principal_id,
            token_digest: [identity_seed.wrapping_add(1); 32],
            service: AuthenticationService::Https,
            factors: BoundedItems::new(
                vec![
                    SessionAuthenticationFactor::Passkey {
                        method_id: passkey_method,
                        credential_generation: 1,
                        method_revision: passkey_revision,
                        credential_id: vec![24; 32],
                        signature_counter,
                        backup_state: true,
                    },
                    SessionAuthenticationFactor::RecoveryCode {
                        method_id: recovery_method,
                        credential_generation: 1,
                        method_revision: recovery_revision,
                        code_id: recovery_code,
                    },
                ],
                8,
            )?,
            expires_at: UnixMicros::new(500),
        },
    ))
}
