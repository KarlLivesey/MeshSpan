// SPDX-License-Identifier: GPL-2.0-only

use axum::http::header::COOKIE;
use axum::http::{HeaderMap, HeaderValue};
use meshspan_api_contract::{
    AssuranceLevel, CreateSessionRequest, StepUpCurrentSessionRequest,
    decode_create_session_request, decode_step_up_current_session_request,
};
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

use crate::browser_session::CSRF_HEADER;
use crate::create_session_tests::{RepositorySessionAuthority, SequentialRandom, bootstrap};
use crate::{
    CreateSessionService, DisabledTotpFactors, GatewaySessionIdentity, SessionAuthorityError,
    StepUpCurrentSessionError, StepUpCurrentSessionService,
};

const SOURCE_OPERATION: &str = "00000000-0000-4000-8000-0000000000b1";
const STEP_UP_OPERATION: &str = "00000000-0000-4000-8000-0000000000b2";

#[test]
fn recovery_step_up_rotates_atomically_and_replays_exactly()
-> Result<(), Box<dyn std::error::Error>> {
    let claim = ClaimBundle::generate(&mut SequentialRandom(1))?;
    let bootstrap_operation = OperationId::from_bytes([8; 16])?;
    let material = InitialBootstrapMaterial::derive(&claim, bootstrap_operation)?;
    let directory = tempdir()?;
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
    let source_request = source_request(&material, true)?;
    let mut creation = CreateSessionService::new(authority);
    let source = creation.create(&source_request, UnixMicros::new(10))?;
    let source_headers = session_headers(&source)?;
    let request = step_up_request(STEP_UP_OPERATION, &codes[0])?;
    let gateway = GatewaySessionIdentity::new(material.node_id, 1)?;
    let mut step_up =
        StepUpCurrentSessionService::new(creation.into_authority(), gateway, DisabledTotpFactors);

    let first = step_up.step_up(&request, &source_headers, UnixMicros::new(20))?;
    assert_eq!(first.response.assurance, AssuranceLevel::RecentStepUp);
    assert!(first.persistent_cookie);
    assert_ne!(first.bearer.session_id(), source.bearer.session_id());
    let replay = step_up.step_up(&request, &source_headers, UnixMicros::new(21))?;
    assert_eq!(replay.response, first.response);
    assert_eq!(replay.bearer.token_digest(), first.bearer.token_digest());
    assert_eq!(replay.csrf.token_digest(), first.csrf.token_digest());

    let changed = step_up_request(STEP_UP_OPERATION, &codes[1])?;
    assert!(matches!(
        step_up.step_up(&changed, &source_headers, UnixMicros::new(22)),
        Err(StepUpCurrentSessionError::Authority(
            SessionAuthorityError::Conflict
        ))
    ));
    let other_operation = step_up_request("00000000-0000-4000-8000-0000000000b3", &codes[1])?;
    assert!(matches!(
        step_up.step_up(&other_operation, &source_headers, UnixMicros::new(22)),
        Err(StepUpCurrentSessionError::Authentication(_))
    ));
    Ok(())
}

fn create_recovery_method(
    authority: &mut RepositorySessionAuthority,
    material: &InitialBootstrapMaterial,
) -> Result<Vec<RecoveryCodeBundle>, Box<dyn std::error::Error>> {
    let operation_id = OperationId::from_bytes([41; 16])?;
    let key = RecoveryCodeIssuanceKey::from_bytes([42; 32])?;
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
            audit_event_id: AuditEventId::from_bytes([43; 16])?,
            occurred_at: UnixMicros::new(2),
            expected_revision: Some(revision),
        },
        &AuthoritativeCommand::CreateAuthenticationMethod(CreateAuthenticationMethod {
            method_id: AuthenticationMethodId::from_bytes([44; 16])?,
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

fn source_request(
    material: &InitialBootstrapMaterial,
    remember: bool,
) -> Result<CreateSessionRequest, Box<dyn std::error::Error>> {
    Ok(decode_create_session_request(&serde_json::to_vec(
        &serde_json::json!({
            "operation_id": SOURCE_OPERATION,
            "authentication": {
                "method": "api_key",
                "secret": material.api_key.expose_encoded().as_str()
            },
            "client_label": "Step-up browser",
            "remember": remember
        }),
    )?)?)
}

fn step_up_request(
    operation_id: &str,
    code: &RecoveryCodeBundle,
) -> Result<StepUpCurrentSessionRequest, Box<dyn std::error::Error>> {
    Ok(decode_step_up_current_session_request(
        &serde_json::to_vec(&serde_json::json!({
            "operation_id": operation_id,
            "additional_factor": {
                "method": "recovery_code",
                "code": code.expose_encoded().as_str()
            }
        }))?,
    )?)
}

fn session_headers(
    result: &crate::CreateSessionResult,
) -> Result<HeaderMap, Box<dyn std::error::Error>> {
    let mut headers = HeaderMap::new();
    headers.insert(
        COOKIE,
        HeaderValue::from_str(&format!(
            "meshspan_session={}",
            result.bearer.expose_encoded().as_str()
        ))?,
    );
    headers.insert(
        CSRF_HEADER,
        HeaderValue::from_str(&result.csrf.expose_encoded())?,
    );
    Ok(headers)
}
