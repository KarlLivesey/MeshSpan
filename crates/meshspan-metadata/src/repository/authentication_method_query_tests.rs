// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    ApiKeyId, AuthenticationMethodId, AuthenticationMethodKind, PartitionId, PrincipalId, Revision,
    UnixMicros,
};
use tempfile::tempdir;

use super::authentication_method_creation_tests::{passkey, recovery};
use super::authentication_method_tests::{bootstrap, context, position};
use super::{
    AuthenticationMethodCursor, AuthenticationMethodRecordDetails, AuthoritativeRepository,
    PageLimit, RepositoryError,
};
use crate::{
    AuthoritativeCommand, CreateAuthenticationMethod, NewAuthenticationCredential,
    PartitionDatabase, RevokeAuthenticationMethod, TotpAlgorithm,
};

#[test]
fn authentication_method_inventory_pages_every_kind_and_retains_revocations()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let administrator = PrincipalId::from_bytes([2; 16])?;
    let mut repository = repository(directory.path(), administrator)?;
    let commands = [
        passkey(AuthenticationMethodId::from_bytes([52; 16])?, administrator),
        totp(AuthenticationMethodId::from_bytes([55; 16])?, administrator),
        recovery(AuthenticationMethodId::from_bytes([58; 16])?, administrator)?,
        api_key(AuthenticationMethodId::from_bytes([61; 16])?, administrator)?,
    ];
    for (offset, command) in commands.into_iter().enumerate() {
        let revision = u64::try_from(offset)?.saturating_add(2);
        repository.apply_committed(
            position(revision),
            context(
                u8::try_from(70 + offset)?,
                administrator,
                u8::try_from(80 + offset)?,
                i64::try_from(20 + offset)?,
                Some(Revision::new(revision - 1)),
            )?,
            &command,
        )?;
    }

    let first = repository.authentication_methods(administrator, None, PageLimit::new(2)?)?;
    assert_eq!(first.items.len(), 2);
    assert_eq!(first.items[0].kind, AuthenticationMethodKind::Passkey);
    assert_eq!(first.items[1].kind, AuthenticationMethodKind::Totp);
    let next = first.next.ok_or("missing inventory cursor")?;
    let second =
        repository.authentication_methods(administrator, Some(next), PageLimit::new(2)?)?;
    assert_eq!(second.items.len(), 2);
    assert!(second.next.is_none());
    assert!(matches!(
        second.items[0].details,
        AuthenticationMethodRecordDetails::RecoveryCodes { remaining_codes: 2 }
    ));
    assert!(matches!(
        second.items[1].details,
        AuthenticationMethodRecordDetails::ApiKey { scopes: 5, .. }
    ));

    let another_user = PrincipalId::from_bytes([3; 16])?;
    let substituted =
        AuthenticationMethodCursor::new(another_user, next.state(), next.kind(), next.method_id());
    assert!(matches!(
        repository.authentication_methods(administrator, Some(substituted), PageLimit::new(2)?,),
        Err(RepositoryError::StaleRevision)
    ));

    repository.apply_committed(
        position(6),
        context(90, administrator, 91, 30, Some(Revision::new(5)))?,
        &AuthoritativeCommand::RevokeAuthenticationMethod(RevokeAuthenticationMethod {
            method_id: AuthenticationMethodId::from_bytes([52; 16])?,
            principal_id: administrator,
            reason: "Device retired".to_owned(),
        }),
    )?;
    let current = repository.authentication_methods(administrator, None, PageLimit::new(10)?)?;
    assert_eq!(current.items.len(), 4);
    assert_eq!(current.items[3].state, 3);
    assert_eq!(current.items[3].kind, AuthenticationMethodKind::Passkey);
    Ok(())
}

#[test]
fn authentication_method_inventory_fails_closed_for_missing_typed_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let administrator = PrincipalId::from_bytes([2; 16])?;
    let mut repository = repository(directory.path(), administrator)?;
    repository.apply_committed(
        position(2),
        context(70, administrator, 80, 20, Some(Revision::new(1)))?,
        &passkey(AuthenticationMethodId::from_bytes([52; 16])?, administrator),
    )?;
    let database = repository.into_database();
    database
        .connection()
        .execute("DELETE FROM webauthn_credentials", [])?;
    let repository = AuthoritativeRepository::new(database);
    assert!(matches!(
        repository.authentication_methods(administrator, None, PageLimit::new(10)?),
        Err(RepositoryError::CorruptState)
    ));
    Ok(())
}

fn repository(
    directory: &std::path::Path,
    administrator: PrincipalId,
) -> Result<AuthoritativeRepository, Box<dyn std::error::Error>> {
    let database = PartitionDatabase::open(
        &directory.join("authentication-method-inventory.sqlite3"),
        PartitionId::from_bytes([1; 16])?,
        UnixMicros::new(1),
    )?;
    let mut repository = AuthoritativeRepository::new(database);
    bootstrap(&mut repository, administrator)?;
    Ok(repository)
}

fn totp(method_id: AuthenticationMethodId, principal_id: PrincipalId) -> AuthoritativeCommand {
    AuthoritativeCommand::CreateAuthenticationMethod(CreateAuthenticationMethod {
        method_id,
        principal_id,
        label: "Authenticator app".to_owned(),
        service_scope: 1 | 2,
        expires_at: Some(UnixMicros::new(200)),
        credential: NewAuthenticationCredential::Totp {
            secret_ciphertext: vec![13; 64],
            algorithm: TotpAlgorithm::Sha256,
            digits: 6,
            period_seconds: 30,
            accepted_step_window: 1,
        },
    })
}

fn api_key(
    method_id: AuthenticationMethodId,
    principal_id: PrincipalId,
) -> Result<AuthoritativeCommand, meshspan_domain::IdentifierError> {
    Ok(AuthoritativeCommand::CreateAuthenticationMethod(
        CreateAuthenticationMethod {
            method_id,
            principal_id,
            label: "Laptop automation".to_owned(),
            service_scope: 1 | 2 | 4,
            expires_at: Some(UnixMicros::new(200)),
            credential: NewAuthenticationCredential::ApiKey {
                key_id: ApiKeyId::from_bytes([62; 16])?,
                key_digest: [63; 32],
                smb_verifier_ciphertext: Some(vec![64; 65]),
                scopes: 0b101,
                valid_from: UnixMicros::new(20),
            },
        },
    ))
}
