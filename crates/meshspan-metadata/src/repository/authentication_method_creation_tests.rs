// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    AuthenticationMethodId, PartitionId, PrincipalId, RecoveryCodeId, Revision, UnixMicros,
};
use tempfile::tempdir;

use super::authentication_method_tests::{bootstrap, context, position};
use super::{AuthoritativeRepository, EntityKind, RepositoryError};
use crate::{
    AuthoritativeCommand, CreateAuthenticationMethod, NewAuthenticationCredential, NewRecoveryCode,
    PartitionDatabase, TotpAlgorithm,
};

#[test]
fn passkey_totp_and_recovery_methods_commit_exact_typed_rows()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("typed-methods.sqlite3");
    let partition_id = PartitionId::from_bytes([1; 16])?;
    let administrator = PrincipalId::from_bytes([2; 16])?;
    let database = PartitionDatabase::open(&file_path, partition_id, UnixMicros::new(1))?;
    let mut repository = AuthoritativeRepository::new(database);
    bootstrap(&mut repository, administrator)?;

    for (index, operation, audit, method_id, command) in [
        (
            2,
            50,
            51,
            AuthenticationMethodId::from_bytes([52; 16])?,
            passkey(AuthenticationMethodId::from_bytes([52; 16])?, administrator),
        ),
        (
            3,
            53,
            54,
            AuthenticationMethodId::from_bytes([55; 16])?,
            totp(AuthenticationMethodId::from_bytes([55; 16])?, administrator),
        ),
        (
            4,
            56,
            57,
            AuthenticationMethodId::from_bytes([58; 16])?,
            recovery(AuthenticationMethodId::from_bytes([58; 16])?, administrator)?,
        ),
    ] {
        let receipt = repository.apply_committed(
            position(index),
            context(
                operation,
                administrator,
                audit,
                18 + i64::try_from(index)?,
                Some(Revision::new(index - 1)),
            )?,
            &command,
        )?;
        assert_eq!(receipt.entity.kind, EntityKind::AuthenticationMethod);
        assert_eq!(receipt.entity.id, method_id.as_bytes());
    }
    let database = repository.into_database();
    let passkey_algorithm: i64 = database.connection().query_row(
        "SELECT public_key_algorithm FROM webauthn_credentials",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(passkey_algorithm, -7);
    let totp_shape: (i64, i64, i64, i64) = database.connection().query_row(
        "SELECT length(secret_ciphertext), algorithm, digits, period_seconds
         FROM totp_credentials",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    assert_eq!(totp_shape, (64, 2, 6, 30));
    let recovery_count: i64 =
        database
            .connection()
            .query_row("SELECT count(*) FROM recovery_codes", [], |row| row.get(0))?;
    assert_eq!(recovery_count, 2);
    assert_eq!(database.check_integrity()?.schema_version, 44);
    Ok(())
}

#[test]
fn typed_creation_rejects_incompatible_or_ambiguous_evidence_atomically()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("invalid-typed-methods.sqlite3");
    let partition_id = PartitionId::from_bytes([1; 16])?;
    let administrator = PrincipalId::from_bytes([2; 16])?;
    let database = PartitionDatabase::open(&file_path, partition_id, UnixMicros::new(1))?;
    let mut repository = AuthoritativeRepository::new(database);
    bootstrap(&mut repository, administrator)?;

    let mut smb_passkey = passkey(AuthenticationMethodId::from_bytes([60; 16])?, administrator);
    if let AuthoritativeCommand::CreateAuthenticationMethod(value) = &mut smb_passkey {
        value.service_scope = 4;
    }
    let short_totp = method(
        AuthenticationMethodId::from_bytes([61; 16])?,
        administrator,
        1,
        NewAuthenticationCredential::Totp {
            secret_ciphertext: vec![1; 8],
            algorithm: TotpAlgorithm::Sha256,
            digits: 6,
            period_seconds: 30,
            accepted_step_window: 1,
        },
    );
    let duplicate_digest = method(
        AuthenticationMethodId::from_bytes([62; 16])?,
        administrator,
        1,
        NewAuthenticationCredential::RecoveryCodes {
            codes: BoundedItems::new(vec![code(63, 70)?, code(64, 70)?], 64)?,
        },
    );
    for (operation, audit, command) in [
        (65, 66, smb_passkey),
        (67, 68, short_totp),
        (69, 71, duplicate_digest),
    ] {
        assert!(matches!(
            repository.apply_committed(
                position(2),
                context(operation, administrator, audit, 20, Some(Revision::new(1)),)?,
                &command,
            ),
            Err(RepositoryError::InvalidCommand)
        ));
    }
    assert_eq!(repository.current_revision()?, Revision::new(1));
    Ok(())
}

fn passkey(method_id: AuthenticationMethodId, owner: PrincipalId) -> AuthoritativeCommand {
    method(
        method_id,
        owner,
        1 | 2,
        NewAuthenticationCredential::Passkey {
            credential_id: vec![10; 32],
            public_key_algorithm: -7,
            public_key: vec![11; 77],
            signature_counter: 0,
            authenticator_guid: Some([12; 16]),
            transports: 1,
            backup_eligible: true,
            backup_state: false,
        },
    )
}

fn totp(method_id: AuthenticationMethodId, owner: PrincipalId) -> AuthoritativeCommand {
    method(
        method_id,
        owner,
        1 | 2,
        NewAuthenticationCredential::Totp {
            secret_ciphertext: vec![13; 64],
            algorithm: TotpAlgorithm::Sha256,
            digits: 6,
            period_seconds: 30,
            accepted_step_window: 1,
        },
    )
}

fn recovery(
    method_id: AuthenticationMethodId,
    owner: PrincipalId,
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    Ok(method(
        method_id,
        owner,
        1 | 2,
        NewAuthenticationCredential::RecoveryCodes {
            codes: BoundedItems::new(vec![code(14, 15)?, code(16, 17)?], 64)?,
        },
    ))
}

fn method(
    method_id: AuthenticationMethodId,
    principal_id: PrincipalId,
    service_scope: u8,
    credential: NewAuthenticationCredential,
) -> AuthoritativeCommand {
    AuthoritativeCommand::CreateAuthenticationMethod(CreateAuthenticationMethod {
        method_id,
        principal_id,
        label: "Authentication method".to_owned(),
        service_scope,
        expires_at: Some(UnixMicros::new(200)),
        credential,
    })
}

fn code(identity: u8, digest: u8) -> Result<NewRecoveryCode, meshspan_domain::IdentifierError> {
    Ok(NewRecoveryCode {
        code_id: RecoveryCodeId::from_bytes([identity; 16])?,
        code_digest: [digest; 32],
    })
}
