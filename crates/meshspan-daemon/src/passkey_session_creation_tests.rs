// SPDX-License-Identifier: GPL-2.0-only

use axum::body::{Body, to_bytes};
use axum::http::{Error as HttpError, Request, StatusCode};
use meshspan_api_contract::{
    CreatePasskeyChallengeRequest, CreateSessionRequest, SessionAuthentication,
    decode_create_session_request,
};
use meshspan_domain::{
    AuditEventId, AuthenticationMethodId, AuthenticationService, ClaimBundle, DurationMicros,
    InitialBootstrapMaterial, NodeId, OperationId, Revision, UnixMicros,
};
use meshspan_metadata::{
    AuthoritativeCommand, AuthoritativeRepository, CommandContext, CreateAuthenticationMethod,
    LocalDatabase, LogPosition, NewAuthenticationCredential, PartitionDatabase, TotpAlgorithm,
};
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::{TempDir, tempdir};
use tower::ServiceExt;

use crate::create_session_tests::{RepositorySessionAuthority, bootstrap};
use crate::passkey_test_support::{
    CREDENTIAL_ID, CountingRandom, ORIGIN, RELYING_PARTY, assertion, public_key,
};
use crate::{
    CreateSessionService, PasskeyCeremonyKey, PasskeyChallengeConfiguration,
    PasskeyChallengeService, PasskeySessionService, TotpEnvelopeKey, TotpSecretBinding,
    TotpSecretCipher, TotpSessionVerifier, session_api_router,
};

const CHALLENGE_OPERATION: &str = "00000000-0000-4000-8000-000000000071";
const SESSION_OPERATION: &str = "00000000-0000-4000-8000-000000000072";

#[test]
fn passkey_session_commits_and_exactly_replays_after_gateway_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new(UnixMicros::new(20))?;
    let request = fixture.session_request(false)?;
    let passkeys = fixture.open_passkeys()?;
    let mut service = CreateSessionService::with_passkeys(fixture.authority, passkeys);
    let first = service.create(&request, UnixMicros::new(30))?;
    let retry = service.create(&request, UnixMicros::new(31))?;
    assert_eq!(first.response.session_id, retry.response.session_id);
    assert_eq!(first.bearer.expose_encoded(), retry.bearer.expose_encoded());
    assert_eq!(first.csrf.expose_encoded(), retry.csrf.expose_encoded());
    assert_eq!(first.response.expires_at_epoch_micros, 43_200_000_030);

    fixture.authority = service.into_authority();
    let passkeys = fixture.open_passkeys()?;
    let mut restarted = CreateSessionService::with_passkeys(fixture.authority, passkeys);
    let replay = restarted.create(&request, UnixMicros::new(32))?;
    assert_eq!(
        first.bearer.expose_encoded(),
        replay.bearer.expose_encoded()
    );
    assert_eq!(first.csrf.expose_encoded(), replay.csrf.expose_encoded());
    let material = restarted
        .into_authority()
        .repository
        .passkey_verification_material(
            CREDENTIAL_ID,
            AuthenticationService::Https,
            UnixMicros::new(33),
        )?
        .ok_or("passkey material missing")?;
    assert_eq!(material.signature_counter, 7);
    Ok(())
}

#[test]
fn passkey_and_totp_commit_once_and_replay_after_both_local_and_time_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new(UnixMicros::new(20))?;
    let request = fixture.session_request_with_totp(false, "755224")?;
    let passkeys = fixture.open_passkeys()?;
    let totp =
        TotpSessionVerifier::new(TotpSecretCipher::new(TotpEnvelopeKey::from_bytes([8; 32])?));
    let mut service = CreateSessionService::with_factors(fixture.authority, passkeys, totp);
    let first = service.create(&request, UnixMicros::new(30))?;
    assert_eq!(
        first.response.assurance,
        meshspan_api_contract::AssuranceLevel::MultiFactor
    );

    fixture.authority = service.into_authority();
    let passkeys = fixture.open_passkeys()?;
    let totp =
        TotpSessionVerifier::new(TotpSecretCipher::new(TotpEnvelopeKey::from_bytes([8; 32])?));
    let mut restarted = CreateSessionService::with_factors(fixture.authority, passkeys, totp);
    let replay = restarted.create(&request, UnixMicros::new(180_000_000))?;
    assert_eq!(replay.response, first.response);
    assert_eq!(replay.bearer.token_digest(), first.bearer.token_digest());
    assert_eq!(replay.csrf.token_digest(), first.csrf.token_digest());
    Ok(())
}

#[tokio::test]
async fn public_http_passkey_session_returns_cookie_csrf_and_exact_replay()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(current_time()?)?;
    let request = fixture.session_request(false)?;
    let body = serde_json::to_vec(&request)?;
    let passkeys = fixture.open_passkeys()?;
    let router = session_api_router(CreateSessionService::with_passkeys(
        fixture.authority,
        passkeys,
    ))?;
    let first = router.clone().oneshot(http_request(&body)?).await?;
    assert_eq!(first.status(), StatusCode::CREATED);
    let cookie = first
        .headers()
        .get("set-cookie")
        .ok_or("cookie missing")?
        .clone();
    let csrf = first
        .headers()
        .get("meshspan-csrf-token")
        .ok_or("CSRF missing")?
        .clone();
    let response_body = to_bytes(first.into_body(), 2_048).await?;

    let replay = router.oneshot(http_request(&body)?).await?;
    assert_eq!(replay.status(), StatusCode::CREATED);
    assert_eq!(replay.headers().get("set-cookie"), Some(&cookie));
    assert_eq!(replay.headers().get("meshspan-csrf-token"), Some(&csrf));
    assert_eq!(to_bytes(replay.into_body(), 2_048).await?, response_body);
    Ok(())
}

struct Fixture {
    _directory: TempDir,
    local_path: std::path::PathBuf,
    node_id: NodeId,
    material: InitialBootstrapMaterial,
    authority: RepositorySessionAuthority,
    challenge_id: String,
    challenge: String,
}

impl Fixture {
    fn new(challenge_created_at: UnixMicros) -> Result<Self, Box<dyn std::error::Error>> {
        let claim = ClaimBundle::generate(&mut CountingRandom::default())?;
        let bootstrap_operation = OperationId::from_bytes([8; 16])?;
        let material = InitialBootstrapMaterial::derive(&claim, bootstrap_operation)?;
        let directory = tempdir()?;
        let database = PartitionDatabase::open(
            &directory.path().join("root.sqlite3"),
            material.partition_id,
            UnixMicros::new(1),
        )?;
        let mut authority = RepositorySessionAuthority {
            repository: AuthoritativeRepository::new(database),
            next_index: 1,
        };
        bootstrap(&mut authority, &material, bootstrap_operation)?;
        enrol_passkey(&mut authority, &material)?;
        enrol_totp(&mut authority, &material)?;
        let local_path = directory.path().join("local.sqlite3");
        let response = create_challenge(&local_path, material.node_id, challenge_created_at)?;
        Ok(Self {
            _directory: directory,
            local_path,
            node_id: material.node_id,
            material,
            authority,
            challenge_id: response.challenge_id.as_str().to_owned(),
            challenge: response.challenge,
        })
    }

    fn open_passkeys(
        &self,
    ) -> Result<PasskeySessionService<LocalDatabase>, Box<dyn std::error::Error>> {
        let database = LocalDatabase::open(&self.local_path, self.node_id, UnixMicros::new(20))?;
        Ok(PasskeySessionService::new(
            database,
            PasskeyCeremonyKey::from_bytes([9; 32])?,
        ))
    }

    fn session_request(
        &self,
        remember: bool,
    ) -> Result<CreateSessionRequest, Box<dyn std::error::Error>> {
        let authentication = assertion(
            &self.challenge_id,
            &self.challenge,
            self.material.administrator_id,
            7,
        )?;
        let SessionAuthentication::Passkey {
            challenge_id,
            credential_id,
            client_data_json,
            authenticator_data,
            signature,
            user_handle,
        } = authentication
        else {
            return Err("passkey fixture returned wrong authentication kind".into());
        };
        let value = serde_json::json!({
            "operation_id": SESSION_OPERATION,
            "authentication": {
                "method": "passkey",
                "challenge_id": challenge_id,
                "credential_id": credential_id,
                "client_data_json": client_data_json,
                "authenticator_data": authenticator_data,
                "signature": signature,
                "user_handle": user_handle
            },
            "client_label": null,
            "remember": remember
        });
        Ok(decode_create_session_request(&serde_json::to_vec(&value)?)?)
    }

    fn session_request_with_totp(
        &self,
        remember: bool,
        code: &str,
    ) -> Result<CreateSessionRequest, Box<dyn std::error::Error>> {
        let request = self.session_request(remember)?;
        let value = serde_json::json!({
            "operation_id": request.operation_id,
            "authentication": request.authentication,
            "additional_factor": {
                "method": "totp",
                "code": code
            },
            "client_label": null,
            "remember": remember
        });
        Ok(decode_create_session_request(&serde_json::to_vec(&value)?)?)
    }
}

fn enrol_passkey(
    authority: &mut RepositorySessionAuthority,
    material: &InitialBootstrapMaterial,
) -> Result<(), Box<dyn std::error::Error>> {
    authority.repository.apply_committed(
        LogPosition { index: 2, term: 1 },
        CommandContext {
            operation_id: OperationId::from_bytes([9; 16])?,
            actor_principal_id: material.administrator_id,
            audit_event_id: AuditEventId::from_bytes([10; 16])?,
            occurred_at: UnixMicros::new(20),
            expected_revision: Some(Revision::new(1)),
        },
        &AuthoritativeCommand::CreateAuthenticationMethod(CreateAuthenticationMethod {
            method_id: AuthenticationMethodId::from_bytes([5; 16])?,
            principal_id: material.administrator_id,
            label: "Passkey".to_owned(),
            service_scope: AuthenticationService::Https.scope_bit(),
            expires_at: None,
            credential: NewAuthenticationCredential::Passkey {
                credential_id: CREDENTIAL_ID.to_vec(),
                public_key_algorithm: -7,
                public_key: public_key()?,
                signature_counter: 6,
                authenticator_guid: Some([11; 16]),
                transports: 1,
                backup_eligible: false,
                backup_state: false,
            },
        }),
    )?;
    authority.next_index = 3;
    Ok(())
}

fn enrol_totp(
    authority: &mut RepositorySessionAuthority,
    material: &InitialBootstrapMaterial,
) -> Result<(), Box<dyn std::error::Error>> {
    let method_id = AuthenticationMethodId::from_bytes([12; 16])?;
    let secret_ciphertext = TotpSecretCipher::new(TotpEnvelopeKey::from_bytes([8; 32])?).encrypt(
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
            operation_id: OperationId::from_bytes([13; 16])?,
            actor_principal_id: material.administrator_id,
            audit_event_id: AuditEventId::from_bytes([14; 16])?,
            occurred_at: UnixMicros::new(21),
            expected_revision: Some(revision),
        },
        &AuthoritativeCommand::CreateAuthenticationMethod(CreateAuthenticationMethod {
            method_id,
            principal_id: material.administrator_id,
            label: "TOTP".to_owned(),
            service_scope: AuthenticationService::Https.scope_bit(),
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

fn create_challenge(
    local_path: &std::path::Path,
    node_id: NodeId,
    created_at: UnixMicros,
) -> Result<meshspan_api_contract::CreatePasskeyChallengeResponse, Box<dyn std::error::Error>> {
    let database = LocalDatabase::open(local_path, node_id, UnixMicros::new(1))?;
    let mut service = PasskeyChallengeService::new(
        database,
        CountingRandom::default(),
        PasskeyCeremonyKey::from_bytes([9; 32])?,
        PasskeyChallengeConfiguration::new(
            RELYING_PARTY.to_owned(),
            vec![ORIGIN.to_owned()],
            DurationMicros::new(120_000_000),
        )?,
    );
    let request: CreatePasskeyChallengeRequest =
        serde_json::from_value(serde_json::json!({ "operation_id": CHALLENGE_OPERATION }))?;
    Ok(service.create(&request, created_at)?)
}

fn current_time() -> Result<UnixMicros, Box<dyn std::error::Error>> {
    Ok(UnixMicros::new(i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros(),
    )?))
}

fn http_request(body: &[u8]) -> Result<Request<Body>, HttpError> {
    Request::post("/api/latest/sessions")
        .header("content-type", "application/json")
        .body(Body::from(body.to_vec()))
}
