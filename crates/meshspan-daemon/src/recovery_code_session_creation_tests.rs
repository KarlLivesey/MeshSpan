// SPDX-License-Identifier: GPL-2.0-only

use meshspan_api_contract::{AssuranceLevel, CreateSessionRequest, decode_create_session_request};
use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    AuditEventId, AuthenticationMethodId, AuthenticationService, ClaimBundle,
    InitialBootstrapMaterial, OperationId, RecoveryCodeBundle, RecoveryCodeIssuanceKey, UnixMicros,
};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, CreateAuthenticationMethod, LogPosition,
    NewAuthenticationCredential, NewRecoveryCode, PartitionDatabase,
};
use tempfile::tempdir;

use crate::create_session_tests::{RepositorySessionAuthority, bootstrap};
use crate::passkey_test_support::CountingRandom;
use crate::{CreateSessionError, CreateSessionService};

const SESSION_OPERATION: &str = "00000000-0000-4000-8000-0000000000a1";
const SECOND_SESSION_OPERATION: &str = "00000000-0000-4000-8000-0000000000a2";

#[test]
fn api_key_recovery_code_is_consumed_once_and_exactly_replayed()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let bootstrap_operation = OperationId::from_bytes([8; 16])?;
    let claim = ClaimBundle::generate(&mut CountingRandom::default())?;
    let material = InitialBootstrapMaterial::derive(&claim, bootstrap_operation)?;
    let database = PartitionDatabase::open(
        &directory.path().join("root.sqlite3"),
        material.partition_id,
        UnixMicros::new(1),
    )?;
    let mut authority = RepositorySessionAuthority {
        repository: meshspan_metadata::AuthoritativeRepository::new(database),
        next_index: 1,
    };
    bootstrap(&mut authority, &material, bootstrap_operation)?;
    let codes = create_recovery_method(&mut authority, &material)?;
    let request = session_request(&material, SESSION_OPERATION, &codes[0].expose_encoded())?;
    let mut service = CreateSessionService::new(authority);

    let first = service.create(&request, UnixMicros::new(10))?;
    assert_eq!(first.response.assurance, AssuranceLevel::MultiFactor);
    let replay = service.create(&request, UnixMicros::new(20))?;
    assert_eq!(replay.response, first.response);
    assert_eq!(replay.bearer.token_digest(), first.bearer.token_digest());
    assert_eq!(replay.csrf.token_digest(), first.csrf.token_digest());

    let changed = session_request(&material, SESSION_OPERATION, &codes[1].expose_encoded())?;
    assert!(matches!(
        service.create(&changed, UnixMicros::new(21)),
        Err(CreateSessionError::Authority(_))
    ));
    let reused = session_request(
        &material,
        SECOND_SESSION_OPERATION,
        &codes[0].expose_encoded(),
    )?;
    assert!(matches!(
        service.create(&reused, UnixMicros::new(22)),
        Err(CreateSessionError::Rejected)
    ));
    assert!(matches!(
        service.create(
            &session_request(&material, SECOND_SESSION_OPERATION, "not-a-code")?,
            UnixMicros::new(22)
        ),
        Err(CreateSessionError::Rejected)
    ));

    let authority = service.into_authority();
    let consumed = authority
        .repository
        .recovery_code_verification_material(
            material.administrator_id,
            codes[0].code_id(),
            codes[0].secret_digest(),
            AuthenticationService::Https,
            UnixMicros::new(23),
        )?
        .ok_or("consumed recovery code evidence missing")?;
    assert_eq!(consumed.used_at, Some(UnixMicros::new(10)));
    let unused = authority
        .repository
        .recovery_code_verification_material(
            material.administrator_id,
            codes[1].code_id(),
            codes[1].secret_digest(),
            AuthenticationService::Https,
            UnixMicros::new(23),
        )?
        .ok_or("unused recovery code evidence missing")?;
    assert_eq!(unused.used_at, None);
    Ok(())
}

fn create_recovery_method(
    authority: &mut RepositorySessionAuthority,
    material: &InitialBootstrapMaterial,
) -> Result<Vec<RecoveryCodeBundle>, Box<dyn std::error::Error>> {
    let operation_id = OperationId::from_bytes([31; 16])?;
    let key = RecoveryCodeIssuanceKey::from_bytes([32; 32])?;
    let codes = (1..=2)
        .map(|sequence| {
            RecoveryCodeBundle::derive_issued(
                &key,
                material.administrator_id,
                operation_id,
                sequence,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let credentials = codes
        .iter()
        .map(|code| NewRecoveryCode {
            code_id: code.code_id(),
            code_digest: code.secret_digest(),
        })
        .collect();
    let revision = authority.repository.current_revision()?;
    authority.repository.apply_committed(
        LogPosition {
            index: authority.next_index,
            term: 1,
        },
        CommandContext {
            operation_id,
            actor_principal_id: material.administrator_id,
            audit_event_id: AuditEventId::from_bytes([33; 16])?,
            occurred_at: UnixMicros::new(2),
            expected_revision: Some(revision),
        },
        &AuthoritativeCommand::CreateAuthenticationMethod(CreateAuthenticationMethod {
            method_id: AuthenticationMethodId::from_bytes([34; 16])?,
            principal_id: material.administrator_id,
            label: "Emergency recovery".to_owned(),
            service_scope: AuthenticationService::Https.scope_bit(),
            expires_at: None,
            credential: NewAuthenticationCredential::RecoveryCodes {
                codes: BoundedItems::new(credentials, 64)?,
            },
        }),
    )?;
    authority.next_index = authority.next_index.saturating_add(1);
    Ok(codes)
}

fn session_request(
    material: &InitialBootstrapMaterial,
    operation_id: &str,
    recovery_code: &str,
) -> Result<CreateSessionRequest, Box<dyn std::error::Error>> {
    Ok(decode_create_session_request(&serde_json::to_vec(
        &serde_json::json!({
            "operation_id": operation_id,
            "authentication": {
                "method": "api_key",
                "secret": material.api_key.expose_encoded().as_str()
            },
            "additional_factor": {
                "method": "recovery_code",
                "code": recovery_code
            },
            "client_label": "Recovery browser",
            "remember": false
        }),
    )?)?)
}
