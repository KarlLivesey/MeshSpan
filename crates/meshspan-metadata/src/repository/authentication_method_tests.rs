// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    ApiKeyId, AuditEventId, AuthenticationMethodId, HostId, MeshId, NodeId, OperationId,
    PartitionId, PrincipalId, RecoveryCodeId, Revision, RoleId, UnixMicros,
};
use tempfile::tempdir;

use super::{
    ApplyDisposition, AuthenticationService, AuthoritativeRepository, EntityKind, LogPosition,
    RepositoryError,
};
use crate::{
    AuthoritativeCommand, BootstrapMesh, CommandContext, CreateAuthenticationMethod,
    NewAuthenticationCredential, PartitionDatabase, RecordName, RevokeAuthenticationMethod,
};

#[test]
fn api_key_creation_is_atomic_restart_safe_and_exactly_replayable()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("api-key-authority.sqlite3");
    let partition_id = PartitionId::from_bytes([1; 16])?;
    let administrator = PrincipalId::from_bytes([2; 16])?;
    let database = PartitionDatabase::open(&file_path, partition_id, UnixMicros::new(1))?;
    let mut repository = AuthoritativeRepository::new(database);
    bootstrap(&mut repository, administrator)?;

    let method_id = AuthenticationMethodId::from_bytes([7; 16])?;
    let create_context = context(8, administrator, 9, 20, Some(Revision::new(1)))?;
    let create = api_key_command(method_id, administrator)?;
    let applied = repository.apply_committed(position(2), create_context, &create)?;
    assert_eq!(applied.disposition, ApplyDisposition::Applied);
    assert_eq!(applied.entity.kind, EntityKind::AuthenticationMethod);
    assert_eq!(applied.entity.id, method_id.as_bytes());

    let substituted = match &create {
        AuthoritativeCommand::CreateAuthenticationMethod(value) => {
            let mut changed = value.clone();
            changed.credential = NewAuthenticationCredential::ApiKey {
                key_id: ApiKeyId::from_bytes([10; 16])?,
                key_digest: [11; 32],
                scopes: 0b111,
                valid_from: UnixMicros::new(20),
            };
            AuthoritativeCommand::CreateAuthenticationMethod(changed)
        }
        _ => return Err("unexpected command family".into()),
    };
    assert!(matches!(
        repository.apply_committed(position(3), create_context, &substituted),
        Err(RepositoryError::OperationConflict)
    ));
    drop(repository.into_database());

    let database = PartitionDatabase::open(&file_path, partition_id, UnixMicros::new(25))?;
    let mut repository = AuthoritativeRepository::new(database);
    let replayed = repository.apply_committed(position(3), create_context, &create)?;
    assert_eq!(replayed.disposition, ApplyDisposition::Replayed);
    assert_eq!(replayed.result_digest, applied.result_digest);
    assert_eq!(replayed.committed_revision, Revision::new(2));

    let invalid_context = context(12, administrator, 13, 26, Some(Revision::new(2)))?;
    let mut invalid = match &create {
        AuthoritativeCommand::CreateAuthenticationMethod(value) => value.clone(),
        _ => return Err("unexpected command family".into()),
    };
    invalid.method_id = AuthenticationMethodId::from_bytes([14; 16])?;
    invalid.credential = NewAuthenticationCredential::ApiKey {
        key_id: ApiKeyId::from_bytes([15; 16])?,
        key_digest: [0; 32],
        scopes: 0b101,
        valid_from: UnixMicros::new(20),
    };
    assert!(matches!(
        repository.apply_committed(
            position(4),
            invalid_context,
            &AuthoritativeCommand::CreateAuthenticationMethod(invalid),
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    assert_eq!(repository.current_revision()?, Revision::new(2));
    assert_eq!(
        repository.into_database().check_integrity()?.schema_version,
        55
    );
    Ok(())
}

#[test]
fn api_key_revocation_is_audited_restart_safe_and_exactly_replayable()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("api-key-revocation.sqlite3");
    let partition_id = PartitionId::from_bytes([1; 16])?;
    let administrator = PrincipalId::from_bytes([2; 16])?;
    let database = PartitionDatabase::open(&file_path, partition_id, UnixMicros::new(1))?;
    let mut repository = AuthoritativeRepository::new(database);
    bootstrap(&mut repository, administrator)?;
    let method_id = AuthenticationMethodId::from_bytes([7; 16])?;
    repository.apply_committed(
        position(2),
        context(8, administrator, 9, 20, Some(Revision::new(1)))?,
        &api_key_command(method_id, administrator)?,
    )?;

    let revoke_context = context(16, administrator, 17, 30, Some(Revision::new(2)))?;
    let revoke = AuthoritativeCommand::RevokeAuthenticationMethod(RevokeAuthenticationMethod {
        method_id,
        principal_id: administrator,
        reason: "Rotating the automation credential".to_owned(),
    });
    let revoked = repository.apply_committed(position(3), revoke_context, &revoke)?;
    assert_eq!(revoked.entity.kind, EntityKind::AuthenticationMethod);
    assert_eq!(revoked.committed_revision, Revision::new(3));
    drop(repository.into_database());

    let database = PartitionDatabase::open(&file_path, partition_id, UnixMicros::new(40))?;
    let mut repository = AuthoritativeRepository::new(database);
    let replayed_revoke = repository.apply_committed(position(4), revoke_context, &revoke)?;
    assert_eq!(replayed_revoke.disposition, ApplyDisposition::Replayed);
    assert_eq!(replayed_revoke.result_digest, revoked.result_digest);
    let resolved = repository
        .resolve_authentication_method_revocation(revoke_context.operation_id)?
        .ok_or("authentication-method revocation replay missing")?;
    assert_eq!(
        resolved.request_digest,
        revoke.request_digest(revoke_context)
    );
    assert_eq!(resolved.result_digest, revoked.result_digest);
    assert_eq!(resolved.method_id, method_id);
    assert_eq!(resolved.principal_id, administrator);
    assert_eq!(resolved.actor_principal_id, administrator);
    assert_eq!(resolved.revoked_at, UnixMicros::new(30));
    let database = repository.into_database();
    let stored: (i64, i64, Vec<u8>, i64, i64) = database.connection().query_row(
        "SELECT method.method_kind, method.state, key.key_digest,
                method.service_scope, key.scopes
         FROM authentication_methods AS method
         JOIN api_keys AS key ON key.method_id = method.method_id
         WHERE method.method_id = ?1",
        [method_id.as_bytes().as_slice()],
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
    assert_eq!(stored, (4, 3, vec![11; 32], 7, 5));
    let revocation: (String, i64, Vec<u8>) = database.connection().query_row(
        "SELECT reason, changed_at, changed_by
         FROM authentication_method_events
         WHERE method_id = ?1 AND event_sequence = 2",
        [method_id.as_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(
        revocation,
        (
            "Rotating the automation credential".to_owned(),
            30,
            administrator.as_bytes().to_vec(),
        )
    );
    assert_eq!(database.check_integrity()?.schema_version, 55);
    Ok(())
}

#[test]
fn api_key_authentication_applies_service_scope_capability_time_and_revocation()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("api-key-verifier.sqlite3");
    let partition_id = PartitionId::from_bytes([1; 16])?;
    let administrator = PrincipalId::from_bytes([2; 16])?;
    let database = PartitionDatabase::open(&file_path, partition_id, UnixMicros::new(1))?;
    let mut repository = AuthoritativeRepository::new(database);
    bootstrap(&mut repository, administrator)?;
    let method_id = AuthenticationMethodId::from_bytes([7; 16])?;
    repository.apply_committed(
        position(2),
        context(8, administrator, 9, 20, Some(Revision::new(1)))?,
        &api_key_command(method_id, administrator)?,
    )?;

    let accepted = repository
        .authenticate_api_key(
            [11; 32],
            AuthenticationService::HeadlessApi,
            0b001,
            UnixMicros::new(20),
        )?
        .ok_or("valid API key was rejected")?;
    assert_eq!(accepted.principal_id, administrator);
    assert_eq!(accepted.method_id, method_id);
    assert_eq!(accepted.key_id, ApiKeyId::from_bytes([10; 16])?);
    assert_eq!(accepted.scopes, 0b101);
    assert_eq!(accepted.credential_generation, 1);
    assert_eq!(accepted.revision, Revision::new(2));

    for rejected in [
        repository.authenticate_api_key(
            [0; 32],
            AuthenticationService::HeadlessApi,
            0b001,
            UnixMicros::new(20),
        )?,
        repository.authenticate_api_key(
            [11; 32],
            AuthenticationService::HeadlessApi,
            0,
            UnixMicros::new(20),
        )?,
        repository.authenticate_api_key(
            [12; 32],
            AuthenticationService::HeadlessApi,
            0b001,
            UnixMicros::new(20),
        )?,
        repository.authenticate_api_key(
            [11; 32],
            AuthenticationService::HeadlessApi,
            0b010,
            UnixMicros::new(20),
        )?,
        repository.authenticate_api_key(
            [11; 32],
            AuthenticationService::Https,
            0b001,
            UnixMicros::new(19),
        )?,
        repository.authenticate_api_key(
            [11; 32],
            AuthenticationService::Smb,
            0b001,
            UnixMicros::new(200),
        )?,
    ] {
        assert_eq!(rejected, None);
    }

    repository.apply_committed(
        position(3),
        context(16, administrator, 17, 30, Some(Revision::new(2)))?,
        &AuthoritativeCommand::RevokeAuthenticationMethod(RevokeAuthenticationMethod {
            method_id,
            principal_id: administrator,
            reason: "Credential retired".to_owned(),
        }),
    )?;
    assert_eq!(
        repository.authenticate_api_key(
            [11; 32],
            AuthenticationService::Https,
            0b001,
            UnixMicros::new(31),
        )?,
        None
    );
    Ok(())
}

#[test]
fn api_key_authentication_fails_closed_for_matching_corrupt_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("corrupt-api-key.sqlite3");
    let partition_id = PartitionId::from_bytes([1; 16])?;
    let administrator = PrincipalId::from_bytes([2; 16])?;
    let database = PartitionDatabase::open(&file_path, partition_id, UnixMicros::new(1))?;
    let mut repository = AuthoritativeRepository::new(database);
    bootstrap(&mut repository, administrator)?;
    let method_id = AuthenticationMethodId::from_bytes([7; 16])?;
    repository.apply_committed(
        position(2),
        context(8, administrator, 9, 20, Some(Revision::new(1)))?,
        &api_key_command(method_id, administrator)?,
    )?;
    let database = repository.into_database();
    database
        .connection()
        .execute_batch("PRAGMA ignore_check_constraints = ON")?;
    database.connection().execute(
        "UPDATE authentication_methods SET credential_generation = 0 WHERE method_id = ?1",
        [method_id.as_bytes().as_slice()],
    )?;
    database
        .connection()
        .execute_batch("PRAGMA ignore_check_constraints = OFF")?;
    let repository = AuthoritativeRepository::new(database);
    assert!(matches!(
        repository.authenticate_api_key(
            [11; 32],
            AuthenticationService::Https,
            0b001,
            UnixMicros::new(21),
        ),
        Err(RepositoryError::CorruptState)
    ));
    Ok(())
}

#[test]
fn passkey_material_is_current_service_scoped_and_never_claimed_authenticated()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("passkey-verifier.sqlite3");
    let partition_id = PartitionId::from_bytes([1; 16])?;
    let administrator = PrincipalId::from_bytes([2; 16])?;
    let database = PartitionDatabase::open(&file_path, partition_id, UnixMicros::new(1))?;
    let mut repository = AuthoritativeRepository::new(database);
    bootstrap(&mut repository, administrator)?;
    let method_id = AuthenticationMethodId::from_bytes([52; 16])?;
    repository.apply_committed(
        position(2),
        context(50, administrator, 51, 20, Some(Revision::new(1)))?,
        &super::authentication_method_creation_tests::passkey(method_id, administrator),
    )?;

    let material = repository
        .passkey_verification_material(
            &[10; 32],
            AuthenticationService::Https,
            UnixMicros::new(21),
        )?
        .ok_or("current passkey material was withheld")?;
    assert_eq!(material.principal_id, administrator);
    assert_eq!(material.method_id, method_id);
    assert_eq!(material.credential_generation, 1);
    assert_eq!(material.revision, Revision::new(2));
    assert_eq!(material.credential_id, vec![10; 32]);
    assert_eq!(material.public_key_algorithm, -7);
    assert_eq!(material.public_key.len(), 65);
    assert_eq!(material.signature_counter, 0);
    assert!(material.backup_eligible);
    assert!(!material.backup_state);

    assert_eq!(
        repository.passkey_verification_material(
            &[10; 32],
            AuthenticationService::Smb,
            UnixMicros::new(21),
        )?,
        None
    );
    assert_eq!(
        repository.passkey_verification_material(
            &[11; 32],
            AuthenticationService::Https,
            UnixMicros::new(21),
        )?,
        None
    );
    Ok(())
}

#[test]
fn passkey_material_fails_closed_for_matching_corrupt_key_shape()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("corrupt-passkey.sqlite3");
    let partition_id = PartitionId::from_bytes([1; 16])?;
    let administrator = PrincipalId::from_bytes([2; 16])?;
    let database = PartitionDatabase::open(&file_path, partition_id, UnixMicros::new(1))?;
    let mut repository = AuthoritativeRepository::new(database);
    bootstrap(&mut repository, administrator)?;
    let method_id = AuthenticationMethodId::from_bytes([52; 16])?;
    repository.apply_committed(
        position(2),
        context(50, administrator, 51, 20, Some(Revision::new(1)))?,
        &super::authentication_method_creation_tests::passkey(method_id, administrator),
    )?;
    let database = repository.into_database();
    database.connection().execute(
        "UPDATE webauthn_credentials SET public_key = zeroblob(64) WHERE method_id = ?1",
        [method_id.as_bytes().as_slice()],
    )?;
    let repository = AuthoritativeRepository::new(database);
    assert!(matches!(
        repository.passkey_verification_material(
            &[10; 32],
            AuthenticationService::Https,
            UnixMicros::new(21),
        ),
        Err(RepositoryError::CorruptState)
    ));
    Ok(())
}

#[test]
fn recovery_code_material_is_principal_bound_digest_matched_and_consumption_visible()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let partition_id = PartitionId::from_bytes([1; 16])?;
    let administrator = PrincipalId::from_bytes([2; 16])?;
    let database = PartitionDatabase::open(
        &directory.path().join("recovery-code-verifier.sqlite3"),
        partition_id,
        UnixMicros::new(1),
    )?;
    let mut repository = AuthoritativeRepository::new(database);
    bootstrap(&mut repository, administrator)?;
    let method_id = AuthenticationMethodId::from_bytes([58; 16])?;
    repository.apply_committed(
        position(2),
        context(50, administrator, 51, 20, Some(Revision::new(1)))?,
        &super::authentication_method_creation_tests::recovery(method_id, administrator)?,
    )?;
    let code_id = RecoveryCodeId::from_bytes([14; 16])?;
    let material = repository
        .recovery_code_verification_material(
            administrator,
            code_id,
            [15; 32],
            AuthenticationService::Https,
            UnixMicros::new(21),
        )?
        .ok_or("current recovery code was withheld")?;
    assert_eq!(material.principal_id, administrator);
    assert_eq!(material.method_id, method_id);
    assert_eq!(material.code_id, code_id);
    assert_eq!(material.credential_generation, 1);
    assert_eq!(material.revision, Revision::new(2));
    assert_eq!(material.used_at, None);

    for rejected in [
        repository.recovery_code_verification_material(
            administrator,
            code_id,
            [0; 32],
            AuthenticationService::Https,
            UnixMicros::new(21),
        )?,
        repository.recovery_code_verification_material(
            administrator,
            code_id,
            [16; 32],
            AuthenticationService::Https,
            UnixMicros::new(21),
        )?,
        repository.recovery_code_verification_material(
            PrincipalId::from_bytes([3; 16])?,
            code_id,
            [15; 32],
            AuthenticationService::Https,
            UnixMicros::new(21),
        )?,
        repository.recovery_code_verification_material(
            administrator,
            code_id,
            [15; 32],
            AuthenticationService::Smb,
            UnixMicros::new(21),
        )?,
        repository.recovery_code_verification_material(
            administrator,
            code_id,
            [15; 32],
            AuthenticationService::Https,
            UnixMicros::new(200),
        )?,
    ] {
        assert_eq!(rejected, None);
    }

    let database = repository.into_database();
    database.connection().execute(
        "UPDATE recovery_codes SET used_at = 22, revision = 3
         WHERE method_id = ?1 AND code_id = ?2",
        rusqlite::params![
            method_id.as_bytes().as_slice(),
            code_id.as_bytes().as_slice()
        ],
    )?;
    let repository = AuthoritativeRepository::new(database);
    let used = repository
        .recovery_code_verification_material(
            administrator,
            code_id,
            [15; 32],
            AuthenticationService::Https,
            UnixMicros::new(23),
        )?
        .ok_or("used recovery-code replay evidence was withheld")?;
    assert_eq!(used.used_at, Some(UnixMicros::new(22)));
    Ok(())
}

fn api_key_command(
    method_id: AuthenticationMethodId,
    administrator: PrincipalId,
) -> Result<AuthoritativeCommand, meshspan_domain::IdentifierError> {
    Ok(AuthoritativeCommand::CreateAuthenticationMethod(
        CreateAuthenticationMethod {
            method_id,
            principal_id: administrator,
            label: "Primary headless key".to_owned(),
            service_scope: 1 | 2 | 4,
            expires_at: Some(UnixMicros::new(200)),
            credential: NewAuthenticationCredential::ApiKey {
                key_id: ApiKeyId::from_bytes([10; 16])?,
                key_digest: [11; 32],
                scopes: 0b101,
                valid_from: UnixMicros::new(20),
            },
        },
    ))
}

pub(super) fn bootstrap(
    repository: &mut AuthoritativeRepository,
    administrator: PrincipalId,
) -> Result<(), Box<dyn std::error::Error>> {
    repository.apply_committed(
        position(1),
        context(40, administrator, 41, 10, Some(Revision::ZERO))?,
        &AuthoritativeCommand::BootstrapMesh(BootstrapMesh {
            mesh_id: MeshId::from_bytes([42; 16])?,
            mesh_name: RecordName::new("Authentication proof")?,
            administrator_id: administrator,
            administrator_name: RecordName::new("Administrator")?,
            administrator_role_id: RoleId::from_bytes([43; 16])?,
            host_id: HostId::from_bytes([44; 16])?,
            host_name: RecordName::new("Authentication host")?,
            node_id: NodeId::from_bytes([45; 16])?,
            node_name: RecordName::new("Authentication node")?,
            partition_name: RecordName::new("Authentication authority")?,
        }),
    )?;
    assert_eq!(repository.current_revision()?, Revision::new(1));
    Ok(())
}

pub(super) fn context(
    operation: u8,
    actor: PrincipalId,
    audit: u8,
    occurred_at: i64,
    expected_revision: Option<Revision>,
) -> Result<CommandContext, meshspan_domain::IdentifierError> {
    Ok(CommandContext {
        operation_id: OperationId::from_bytes([operation; 16])?,
        actor_principal_id: actor,
        audit_event_id: AuditEventId::from_bytes([audit; 16])?,
        occurred_at: UnixMicros::new(occurred_at),
        expected_revision,
    })
}

pub(super) const fn position(index: u64) -> LogPosition {
    LogPosition { index, term: 1 }
}
