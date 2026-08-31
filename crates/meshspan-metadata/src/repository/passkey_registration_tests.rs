// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{AuthenticationMethodId, PartitionId, PrincipalId, Revision, UnixMicros};
use tempfile::tempdir;

use super::authentication_method_tests::{bootstrap, context, position};
use super::{AuthoritativeRepository, RepositoryError};
use crate::PartitionDatabase;

#[test]
fn registration_profile_returns_current_user_and_bounded_active_passkeys()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory
        .path()
        .join("passkey-registration-profile.sqlite3");
    let partition_id = PartitionId::from_bytes([1; 16])?;
    let administrator = PrincipalId::from_bytes([2; 16])?;
    let database = PartitionDatabase::open(&file_path, partition_id, UnixMicros::new(1))?;
    let mut repository = AuthoritativeRepository::new(database);
    bootstrap(&mut repository, administrator)?;
    repository.apply_committed(
        position(2),
        context(50, administrator, 51, 20, Some(Revision::new(1)))?,
        &super::authentication_method_creation_tests::passkey(
            AuthenticationMethodId::from_bytes([52; 16])?,
            administrator,
        ),
    )?;

    let profile = repository
        .passkey_registration_profile(administrator)?
        .ok_or("active administrator profile was absent")?;
    assert_eq!(profile.principal_id, administrator);
    assert_eq!(profile.user_name, "administrator");
    assert_eq!(profile.display_name, "Administrator");
    assert_eq!(profile.identity_revision, Revision::new(1));
    assert_eq!(profile.exclude_credential_ids, vec![vec![10; 32]]);
    let replay = repository
        .resolve_passkey_registration(meshspan_domain::OperationId::from_bytes([50; 16])?)?
        .ok_or("passkey registration replay was absent")?;
    assert_eq!(
        replay.method_id,
        AuthenticationMethodId::from_bytes([52; 16])?
    );
    assert_eq!(replay.principal_id, administrator);
    assert_eq!(replay.created_at, UnixMicros::new(20));
    assert_ne!(replay.request_digest, [0; 32]);
    assert_ne!(replay.result_digest, [0; 32]);
    assert_eq!(
        repository.passkey_registration_profile(PrincipalId::from_bytes([99; 16])?)?,
        None
    );
    Ok(())
}

#[test]
fn registration_profile_fails_closed_for_malformed_matching_credential()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory
        .path()
        .join("corrupt-passkey-registration-profile.sqlite3");
    let partition_id = PartitionId::from_bytes([1; 16])?;
    let administrator = PrincipalId::from_bytes([2; 16])?;
    let database = PartitionDatabase::open(&file_path, partition_id, UnixMicros::new(1))?;
    let mut repository = AuthoritativeRepository::new(database);
    bootstrap(&mut repository, administrator)?;
    repository.apply_committed(
        position(2),
        context(50, administrator, 51, 20, Some(Revision::new(1)))?,
        &super::authentication_method_creation_tests::passkey(
            AuthenticationMethodId::from_bytes([52; 16])?,
            administrator,
        ),
    )?;
    let database = repository.into_database();
    database
        .connection()
        .execute_batch("PRAGMA ignore_check_constraints = ON")?;
    database.connection().execute(
        "UPDATE webauthn_credentials SET credential_id = zeroblob(0)",
        [],
    )?;
    database
        .connection()
        .execute_batch("PRAGMA ignore_check_constraints = OFF")?;
    let repository = AuthoritativeRepository::new(database);
    assert!(matches!(
        repository.passkey_registration_profile(administrator),
        Err(RepositoryError::CorruptState)
    ));
    Ok(())
}

#[test]
fn registration_profile_query_uses_the_user_method_index() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let file_path = directory.path().join("passkey-registration-plan.sqlite3");
    let partition_id = PartitionId::from_bytes([1; 16])?;
    let administrator = PrincipalId::from_bytes([2; 16])?;
    let database = PartitionDatabase::open(&file_path, partition_id, UnixMicros::new(1))?;
    let mut repository = AuthoritativeRepository::new(database);
    bootstrap(&mut repository, administrator)?;
    let database = repository.into_database();
    let plan: String = database.connection().query_row(
        "EXPLAIN QUERY PLAN
         SELECT credential.credential_id
         FROM authentication_methods AS method INDEXED BY authentication_methods_by_user
         JOIN webauthn_credentials AS credential USING(method_id)
         WHERE method.user_principal_id = ?1 AND method.state = 1 AND method.method_kind = 1
         ORDER BY method.user_principal_id, method.state, method.method_kind,
                  method.method_id, credential.credential_id
         LIMIT 64",
        [administrator.as_bytes().as_slice()],
        |row| row.get(3),
    )?;
    assert!(plan.contains("authentication_methods_by_user"), "{plan}");
    Ok(())
}
