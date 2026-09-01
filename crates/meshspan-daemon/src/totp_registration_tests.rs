// SPDX-License-Identifier: GPL-2.0-only

use axum::http::header::COOKIE;
use axum::http::{HeaderMap, HeaderValue};
use meshspan_api_contract::{
    CreateTotpRegistrationChallengeRequest, CreateTotpRegistrationRequest,
    decode_create_totp_registration_challenge_request, decode_create_totp_registration_request,
};
use meshspan_domain::{
    AuthenticationMethodKind, ClaimBundle, EntropyError, InitialBootstrapMaterial, OperationId,
    RandomSource, UnixMicros,
};
use meshspan_metadata::{
    AuthenticationRegistrationProfile, AuthoritativeCommand, CommandContext, LocalDatabase,
    LogPosition, PartitionDatabase, RepositoryError,
};
use std::path::Path;

use tempfile::tempdir;

use crate::browser_session::CSRF_HEADER;
use crate::create_session_tests::{RepositorySessionAuthority, bootstrap};
use crate::passkey_test_support::CountingRandom;
use crate::{
    CreateSessionService, GatewaySessionIdentity, TotpCeremonyKey, TotpEnvelopeKey,
    TotpRegistrationAuthority, TotpRegistrationAuthorityError, TotpRegistrationCommit,
    TotpRegistrationConfiguration, TotpRegistrationError, TotpRegistrationService,
};

const CHALLENGE_OPERATION: &str = "00000000-0000-4000-8000-000000000031";
const REGISTRATION_OPERATION: &str = "00000000-0000-4000-8000-000000000032";
type TestService =
    TotpRegistrationService<LocalDatabase, RepositorySessionAuthority, TotpRegistrationRandom>;

#[test]
fn registration_commits_and_replays_after_code_expiry_and_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let bootstrap_operation = OperationId::from_bytes([8; 16])?;
    let claim = ClaimBundle::generate(&mut CountingRandom::default())?;
    let material = InitialBootstrapMaterial::derive(
        &claim,
        bootstrap_operation,
        InitialBootstrapMaterial::node_id([99; 32])?,
    )?;
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
    let mut sessions = CreateSessionService::new(authority);
    let session = sessions.create(&session_request(&material)?, UnixMicros::new(20))?;
    let headers = browser_headers(&session)?;
    let authority = sessions.into_authority();
    let local_path = directory.path().join("local.sqlite3");
    let local = LocalDatabase::open(&local_path, material.node_id, UnixMicros::new(1))?;
    let gateway = GatewaySessionIdentity::new(material.node_id, 1)?;
    let configuration = TotpRegistrationConfiguration::new(
        "MeshSpan Home".to_owned(),
        meshspan_domain::DurationMicros::new(120_000_000),
    )?;
    let mut service = TotpRegistrationService::new(
        local,
        authority,
        TotpRegistrationRandom::default(),
        TotpCeremonyKey::from_bytes([7; 32])?,
        TotpEnvelopeKey::from_bytes([8; 32])?,
        configuration.clone(),
        gateway,
    );
    let initial_request = challenge_request("Primary authenticator")?;
    let challenge = service.create_challenge(&initial_request, &headers, UnixMicros::new(30))?;
    assert_eq!(challenge.secret, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    assert!(
        challenge
            .provisioning_uri
            .contains("MeshSpan%20Home%3Aadministrator")
    );

    let (local, authority, _) = service.into_parts();
    let mut replay_service = restart_service(
        &local_path,
        local,
        authority,
        configuration,
        gateway,
        material.node_id,
        UnixMicros::new(31),
    )?;
    let replayed_challenge =
        replay_service.create_challenge(&initial_request, &headers, UnixMicros::new(31))?;
    assert_eq!(replayed_challenge.secret, challenge.secret);
    assert_eq!(
        replayed_challenge.provisioning_uri,
        challenge.provisioning_uri
    );
    assert!(matches!(
        replay_service.create_challenge(
            &challenge_request("Changed label")?,
            &headers,
            UnixMicros::new(31)
        ),
        Err(TotpRegistrationError::Conflict)
    ));

    let confirmation = registration_request(challenge.challenge_id.as_str(), "755224")?;
    let first = replay_service.register(&confirmation, &headers, UnixMicros::new(32))?;
    assert_eq!(first.created_at_epoch_micros, 32);

    let (local, authority, _) = replay_service.into_parts();
    let completed_replay = restart_service(
        &local_path,
        local,
        authority,
        TotpRegistrationConfiguration::new(
            "MeshSpan Home".to_owned(),
            meshspan_domain::DurationMicros::new(120_000_000),
        )?,
        gateway,
        material.node_id,
        UnixMicros::new(180_000_000),
    )?;
    assert_completed_replay(
        completed_replay,
        &confirmation,
        &headers,
        challenge.challenge_id.as_str(),
        &first,
    )?;
    Ok(())
}

fn assert_completed_replay(
    mut service: TestService,
    confirmation: &CreateTotpRegistrationRequest,
    headers: &HeaderMap,
    challenge_id: &str,
    expected: &meshspan_api_contract::CreateTotpRegistrationResponse,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        &service.register(confirmation, headers, UnixMicros::new(180_000_000))?,
        expected
    );
    let changed = registration_request(challenge_id, "287082")?;
    assert!(matches!(
        service.register(&changed, headers, UnixMicros::new(180_000_000)),
        Err(TotpRegistrationError::Store(
            crate::AuthenticationRegistrationStoreError::Conflict
        ))
    ));
    let (_, authority, _) = service.into_parts();
    assert!(
        authority
            .repository
            .resolve_authentication_method_creation(
                parse_operation(REGISTRATION_OPERATION)?,
                AuthenticationMethodKind::Totp,
            )?
            .is_some()
    );
    Ok(())
}

fn restart_service(
    local_path: &Path,
    local: LocalDatabase,
    authority: RepositorySessionAuthority,
    configuration: TotpRegistrationConfiguration,
    gateway: GatewaySessionIdentity,
    node_id: meshspan_domain::NodeId,
    now: UnixMicros,
) -> Result<TestService, Box<dyn std::error::Error>> {
    drop(local);
    Ok(TotpRegistrationService::new(
        LocalDatabase::open(local_path, node_id, now)?,
        authority,
        TotpRegistrationRandom::default(),
        TotpCeremonyKey::from_bytes([7; 32])?,
        TotpEnvelopeKey::from_bytes([8; 32])?,
        configuration,
        gateway,
    ))
}

impl TotpRegistrationAuthority for RepositorySessionAuthority {
    fn registration_profile(
        &self,
        principal_id: meshspan_domain::PrincipalId,
    ) -> Result<Option<AuthenticationRegistrationProfile>, TotpRegistrationAuthorityError> {
        self.repository
            .authentication_registration_profile(principal_id)
            .map_err(|error| map_repository_error(&error))
    }

    fn resolve_registration(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<TotpRegistrationCommit>, TotpRegistrationAuthorityError> {
        Ok(self
            .repository
            .resolve_authentication_method_creation(operation_id, AuthenticationMethodKind::Totp)
            .map_err(|error| map_repository_error(&error))?
            .map(|replay| TotpRegistrationCommit {
                request_digest: replay.request_digest,
                result_digest: replay.result_digest,
                method_id: replay.method_id,
                principal_id: replay.principal_id,
                created_at: replay.created_at,
            }))
    }

    fn commit_or_resolve_registration(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<TotpRegistrationCommit, TotpRegistrationAuthorityError> {
        let expected_digest = command.request_digest(context);
        if let Some(replay) = self
            .repository
            .resolve_authentication_method_creation(
                context.operation_id,
                AuthenticationMethodKind::Totp,
            )
            .map_err(|error| map_repository_error(&error))?
        {
            if replay.request_digest != expected_digest {
                return Err(TotpRegistrationAuthorityError::Conflict);
            }
            return Ok(commit_from_replay(replay));
        }
        self.repository
            .apply_committed(
                LogPosition {
                    index: self.next_index,
                    term: 1,
                },
                context,
                command,
            )
            .map_err(|error| map_repository_error(&error))?;
        self.next_index = self.next_index.saturating_add(1);
        self.repository
            .resolve_authentication_method_creation(
                context.operation_id,
                AuthenticationMethodKind::Totp,
            )
            .map_err(|error| map_repository_error(&error))?
            .map(commit_from_replay)
            .ok_or(TotpRegistrationAuthorityError::Failed)
    }
}

fn commit_from_replay(
    replay: meshspan_metadata::AuthenticationMethodCreationReplay,
) -> TotpRegistrationCommit {
    TotpRegistrationCommit {
        request_digest: replay.request_digest,
        result_digest: replay.result_digest,
        method_id: replay.method_id,
        principal_id: replay.principal_id,
        created_at: replay.created_at,
    }
}

fn challenge_request(
    label: &str,
) -> Result<CreateTotpRegistrationChallengeRequest, Box<dyn std::error::Error>> {
    Ok(decode_create_totp_registration_challenge_request(
        &serde_json::to_vec(&serde_json::json!({
            "operation_id": CHALLENGE_OPERATION,
            "label": label
        }))?,
    )?)
}

fn registration_request(
    challenge_id: &str,
    code: &str,
) -> Result<CreateTotpRegistrationRequest, Box<dyn std::error::Error>> {
    Ok(decode_create_totp_registration_request(
        &serde_json::to_vec(&serde_json::json!({
            "operation_id": REGISTRATION_OPERATION,
            "challenge_id": challenge_id,
            "code": code
        }))?,
    )?)
}

fn session_request(
    material: &InitialBootstrapMaterial,
) -> Result<meshspan_api_contract::CreateSessionRequest, Box<dyn std::error::Error>> {
    let api_key = material.api_key.expose_encoded();
    Ok(meshspan_api_contract::decode_create_session_request(
        &serde_json::to_vec(&serde_json::json!({
            "operation_id": "00000000-0000-4000-8000-000000000030",
            "authentication": {
                "method": "api_key",
                "secret": api_key.as_str()
            },
            "client_label": null,
            "remember": false
        }))?,
    )?)
}

fn browser_headers(
    result: &crate::CreateSessionResult,
) -> Result<HeaderMap, Box<dyn std::error::Error>> {
    let mut headers = HeaderMap::new();
    let cookie = format!(
        "meshspan_session={}",
        result.bearer.expose_encoded().as_str()
    );
    headers.insert(COOKIE, HeaderValue::from_str(&cookie)?);
    headers.insert(
        CSRF_HEADER,
        HeaderValue::from_str(result.csrf.expose_encoded().as_str())?,
    );
    Ok(headers)
}

fn parse_operation(value: &str) -> Result<OperationId, Box<dyn std::error::Error>> {
    crate::passkey_registration_model::parse_operation(value)
        .map_err(|error| Box::new(error) as Box<dyn std::error::Error>)
}

fn map_repository_error(error: &RepositoryError) -> TotpRegistrationAuthorityError {
    match error {
        RepositoryError::OperationConflict => TotpRegistrationAuthorityError::Conflict,
        RepositoryError::Store(_) | RepositoryError::Sqlite(_) | RepositoryError::Io(_) => {
            TotpRegistrationAuthorityError::Unavailable
        }
        _ => TotpRegistrationAuthorityError::Failed,
    }
}

#[derive(Default)]
struct TotpRegistrationRandom {
    calls: u8,
}

impl RandomSource for TotpRegistrationRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        self.calls = self.calls.checked_add(1).ok_or(EntropyError)?;
        if destination.len() == 20 {
            destination.copy_from_slice(b"12345678901234567890");
        } else {
            destination.fill(self.calls);
        }
        Ok(())
    }
}
