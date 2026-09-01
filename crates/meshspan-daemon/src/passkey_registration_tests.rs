// SPDX-License-Identifier: GPL-2.0-only

use axum::http::header::COOKIE;
use axum::http::{HeaderMap, HeaderValue};
use meshspan_api_contract::{
    CreatePasskeyRegistrationChallengeRequest, CreatePasskeyRegistrationRequest,
    decode_create_passkey_registration_challenge_request,
    decode_create_passkey_registration_request,
};
use meshspan_domain::{ClaimBundle, InitialBootstrapMaterial, OperationId, UnixMicros};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, LocalDatabase, LogPosition, PartitionDatabase,
    PasskeyRegistrationProfile, RepositoryError,
};
use tempfile::tempdir;

use crate::browser_session::CSRF_HEADER;
use crate::create_session_tests::{RepositorySessionAuthority, bootstrap};
use crate::passkey_test_support::{
    CountingRandom, REGISTERED_CREDENTIAL_ID, RELYING_PARTY, registration_fixture,
};
use crate::{
    CreateSessionService, GatewaySessionIdentity, PasskeyCeremonyKey, PasskeyRegistrationAuthority,
    PasskeyRegistrationAuthorityError, PasskeyRegistrationCommit, PasskeyRegistrationConfiguration,
    PasskeyRegistrationError, PasskeyRegistrationService,
};

const CHALLENGE_OPERATION: &str = "00000000-0000-4000-8000-000000000021";
const REGISTRATION_OPERATION: &str = "00000000-0000-4000-8000-000000000022";

#[test]
fn authenticated_registration_commits_and_replays_after_local_restart()
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
    let configuration = configuration()?;
    let mut service = PasskeyRegistrationService::new(
        local,
        authority,
        CountingRandom::default(),
        PasskeyCeremonyKey::from_bytes([9; 32])?,
        configuration.clone(),
        gateway,
    );
    let challenge_request = challenge_request()?;
    let challenge = service.create_challenge(&challenge_request, &headers, UnixMicros::new(30))?;
    assert_eq!(challenge.user_name, "administrator");
    assert_eq!(challenge.relying_party_id, RELYING_PARTY);
    assert!(challenge.exclude_credentials.is_empty());
    let completion_request = registration_request(&challenge.challenge, "Laptop passkey")?;
    let first = service
        .register(&completion_request, &headers, UnixMicros::new(31))
        .map_err(|error| format!("first registration failed: {error:?}"))?;
    assert_eq!(first.created_at_epoch_micros, 31);

    let (local, authority, _) = service.into_parts();
    drop(local);
    let reopened = LocalDatabase::open(&local_path, material.node_id, UnixMicros::new(32))?;
    let mut replay_service = PasskeyRegistrationService::new(
        reopened,
        authority,
        CountingRandom::default(),
        PasskeyCeremonyKey::from_bytes([9; 32])?,
        configuration,
        gateway,
    );
    let replay = replay_service
        .register(&completion_request, &headers, UnixMicros::new(32))
        .map_err(|error| format!("registration replay failed: {error:?}"))?;
    assert_eq!(replay, first);
    let changed = registration_request(&challenge.challenge, "Changed label")?;
    assert!(matches!(
        replay_service.register(&changed, &headers, UnixMicros::new(33)),
        Err(PasskeyRegistrationError::Store(
            crate::PasskeyRegistrationStoreError::Conflict
        ))
    ));
    let (_, authority, _) = replay_service.into_parts();
    let profile = authority
        .repository
        .passkey_registration_profile(material.administrator_id)?
        .ok_or("registered profile missing")?;
    assert_eq!(
        profile.exclude_credential_ids,
        vec![REGISTERED_CREDENTIAL_ID.to_vec()]
    );
    Ok(())
}

impl PasskeyRegistrationAuthority for RepositorySessionAuthority {
    fn registration_profile(
        &self,
        principal_id: meshspan_domain::PrincipalId,
    ) -> Result<Option<PasskeyRegistrationProfile>, PasskeyRegistrationAuthorityError> {
        self.repository
            .passkey_registration_profile(principal_id)
            .map_err(|error| map_repository_error(&error))
    }

    fn resolve_registration(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<PasskeyRegistrationCommit>, PasskeyRegistrationAuthorityError> {
        self.repository
            .resolve_passkey_registration(operation_id)
            .map_err(|error| map_repository_error(&error))?
            .map(|replay| {
                Ok(PasskeyRegistrationCommit {
                    request_digest: replay.request_digest,
                    result_digest: replay.result_digest,
                    method_id: replay.method_id,
                    principal_id: replay.principal_id,
                    created_at: replay.created_at,
                })
            })
            .transpose()
    }

    fn commit_or_resolve_registration(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<PasskeyRegistrationCommit, PasskeyRegistrationAuthorityError> {
        let expected_digest = command.request_digest(context);
        if let Some(replay) = self
            .repository
            .resolve_passkey_registration(context.operation_id)
            .map_err(|error| map_repository_error(&error))?
        {
            if replay.request_digest != expected_digest {
                return Err(PasskeyRegistrationAuthorityError::Conflict);
            }
            return Ok(PasskeyRegistrationCommit {
                request_digest: replay.request_digest,
                result_digest: replay.result_digest,
                method_id: replay.method_id,
                principal_id: replay.principal_id,
                created_at: replay.created_at,
            });
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
        let replay = self
            .repository
            .resolve_passkey_registration(context.operation_id)
            .map_err(|error| map_repository_error(&error))?
            .ok_or(PasskeyRegistrationAuthorityError::Failed)?;
        Ok(PasskeyRegistrationCommit {
            request_digest: replay.request_digest,
            result_digest: replay.result_digest,
            method_id: replay.method_id,
            principal_id: replay.principal_id,
            created_at: replay.created_at,
        })
    }
}

fn session_request(
    material: &InitialBootstrapMaterial,
) -> Result<meshspan_api_contract::CreateSessionRequest, Box<dyn std::error::Error>> {
    let api_key = material.api_key.expose_encoded();
    let value = serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000020",
        "authentication": {
            "method": "api_key",
            "secret": api_key.as_str()
        },
        "client_label": null,
        "remember": false
    });
    Ok(meshspan_api_contract::decode_create_session_request(
        &serde_json::to_vec(&value)?,
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

fn challenge_request()
-> Result<CreatePasskeyRegistrationChallengeRequest, Box<dyn std::error::Error>> {
    Ok(decode_create_passkey_registration_challenge_request(
        &serde_json::to_vec(&serde_json::json!({ "operation_id": CHALLENGE_OPERATION }))?,
    )?)
}

fn registration_request(
    challenge: &str,
    label: &str,
) -> Result<CreatePasskeyRegistrationRequest, Box<dyn std::error::Error>> {
    let fixture = registration_fixture(challenge)?;
    Ok(decode_create_passkey_registration_request(
        &serde_json::to_vec(&serde_json::json!({
            "operation_id": REGISTRATION_OPERATION,
            "challenge_id": "01010101-0101-4101-8101-010101010101",
            "label": label,
            "credential_id": fixture.credential_id,
            "client_data_json": fixture.client_data_json,
            "attestation_object": fixture.attestation_object,
            "transports": ["internal"]
        }))?,
    )?)
}

fn configuration()
-> Result<PasskeyRegistrationConfiguration, crate::PasskeyRegistrationConfigurationError> {
    PasskeyRegistrationConfiguration::new(
        RELYING_PARTY.to_owned(),
        "MeshSpan".to_owned(),
        vec![crate::passkey_test_support::ORIGIN.to_owned()],
        meshspan_domain::DurationMicros::new(120_000_000),
    )
}

fn map_repository_error(error: &RepositoryError) -> PasskeyRegistrationAuthorityError {
    match error {
        RepositoryError::OperationConflict => PasskeyRegistrationAuthorityError::Conflict,
        RepositoryError::Store(_) | RepositoryError::Sqlite(_) | RepositoryError::Io(_) => {
            PasskeyRegistrationAuthorityError::Unavailable
        }
        _ => PasskeyRegistrationAuthorityError::Failed,
    }
}
