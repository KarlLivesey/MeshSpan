// SPDX-License-Identifier: GPL-2.0-only

use meshspan_api_contract::{AssuranceLevel, CreateSessionRequest, decode_create_session_request};
use meshspan_domain::{
    AuditEventId, AuthenticationMethodId, AuthenticationService, ClaimBundle,
    InitialBootstrapMaterial, OperationId, UnixMicros,
};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, CreateAuthenticationMethod, LogPosition,
    NewAuthenticationCredential, PartitionDatabase, TotpAlgorithm,
};
use tempfile::tempdir;

use crate::create_session_tests::{RepositorySessionAuthority, bootstrap};
use crate::passkey_test_support::CountingRandom;
use crate::{
    CreateSessionError, CreateSessionService, DisabledPasskeySessions, TotpEnvelopeKey,
    TotpSecretBinding, TotpSecretCipher, TotpSessionError, TotpSessionVerifier,
};

const SESSION_OPERATION: &str = "00000000-0000-4000-8000-000000000061";
const TOTP_METHOD_BYTES: [u8; 16] = [90; 16];

#[test]
fn api_key_and_totp_commit_once_and_replay_after_the_code_expires()
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
    create_totp_method(&mut authority, &material)?;
    let available = authority
        .repository
        .totp_verification_materials(
            material.administrator_id,
            AuthenticationService::Https,
            UnixMicros::new(10),
        )
        .map_err(|error| format!("TOTP material preflight failed: {error:?}"))?;
    assert_eq!(available.len(), 1);

    let verifier =
        TotpSessionVerifier::new(TotpSecretCipher::new(TotpEnvelopeKey::from_bytes([8; 32])?));
    let mut service =
        CreateSessionService::with_factors(authority, DisabledPasskeySessions, verifier);
    let request = session_request(&material, SESSION_OPERATION, "755224")?;
    let first = service
        .create(&request, UnixMicros::new(10))
        .map_err(|error| format!("first multi-factor session failed: {error:?}"))?;
    assert_eq!(first.response.assurance, AssuranceLevel::MultiFactor);

    let replay = service
        .create(&request, UnixMicros::new(180_000_000))
        .map_err(|error| format!("multi-factor replay failed: {error:?}"))?;
    assert_eq!(replay.response, first.response);
    assert_eq!(replay.bearer.token_digest(), first.bearer.token_digest());
    assert_eq!(replay.csrf.token_digest(), first.csrf.token_digest());

    let changed = session_request(&material, SESSION_OPERATION, "287082")?;
    assert!(matches!(
        service.create(&changed, UnixMicros::new(180_000_000)),
        Err(CreateSessionError::Totp(TotpSessionError::Rejected))
    ));
    let reused_step = session_request(&material, "00000000-0000-4000-8000-000000000062", "755224")?;
    assert!(matches!(
        service.create(&reused_step, UnixMicros::new(11)),
        Err(CreateSessionError::Authority(_))
    ));

    let authority = service.into_authority();
    let retained = authority
        .repository
        .resolve_authentication_session(parse_operation(SESSION_OPERATION)?)?
        .ok_or("multi-factor session replay missing")?;
    assert_eq!(retained.factors.len(), 2);
    assert!(retained.factors.iter().any(|factor| matches!(
        factor.credential,
        meshspan_metadata::AuthenticationSessionReplayCredential::Totp { accepted_step: 0 }
    )));
    Ok(())
}

fn create_totp_method(
    authority: &mut RepositorySessionAuthority,
    material: &InitialBootstrapMaterial,
) -> Result<(), Box<dyn std::error::Error>> {
    let method_id = AuthenticationMethodId::from_bytes(TOTP_METHOD_BYTES)?;
    let cipher = TotpSecretCipher::new(TotpEnvelopeKey::from_bytes([8; 32])?);
    let secret_ciphertext = cipher.encrypt(
        TotpSecretBinding {
            method_id,
            principal_id: material.administrator_id,
            algorithm: 1,
            digits: 6,
            period_seconds: 30,
            accepted_step_window: 1,
        },
        b"12345678901234567890",
        &mut CountingRandom::default(),
    )?;
    let revision = authority.repository.current_revision()?;
    authority.repository.apply_committed(
        LogPosition {
            index: authority.next_index,
            term: 1,
        },
        CommandContext {
            operation_id: OperationId::from_bytes([91; 16])?,
            actor_principal_id: material.administrator_id,
            audit_event_id: AuditEventId::from_bytes([92; 16])?,
            occurred_at: UnixMicros::new(2),
            expected_revision: Some(revision),
        },
        &AuthoritativeCommand::CreateAuthenticationMethod(CreateAuthenticationMethod {
            method_id,
            principal_id: material.administrator_id,
            label: "Primary authenticator".to_owned(),
            service_scope: AuthenticationService::Https.scope_bit()
                | AuthenticationService::HeadlessApi.scope_bit(),
            expires_at: None,
            credential: NewAuthenticationCredential::Totp {
                secret_ciphertext,
                algorithm: TotpAlgorithm::Sha1,
                digits: 6,
                period_seconds: 30,
                accepted_step_window: 1,
            },
        }),
    )?;
    authority.next_index = authority.next_index.saturating_add(1);
    Ok(())
}

fn session_request(
    material: &InitialBootstrapMaterial,
    operation_id: &str,
    code: &str,
) -> Result<CreateSessionRequest, Box<dyn std::error::Error>> {
    let key = material.api_key.expose_encoded();
    Ok(decode_create_session_request(&serde_json::to_vec(
        &serde_json::json!({
            "operation_id": operation_id,
            "authentication": {
                "method": "api_key",
                "secret": key.as_str()
            },
            "additional_factor": {
                "method": "totp",
                "code": code
            },
            "client_label": "Office browser",
            "remember": false
        }),
    )?)?)
}

fn parse_operation(value: &str) -> Result<OperationId, Box<dyn std::error::Error>> {
    crate::passkey_registration_model::parse_operation(value)
        .map_err(|error| Box::new(error) as Box<dyn std::error::Error>)
}
