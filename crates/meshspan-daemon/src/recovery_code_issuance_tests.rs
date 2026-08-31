// SPDX-License-Identifier: GPL-2.0-only

use axum::http::header::COOKIE;
use axum::http::{HeaderMap, HeaderValue};
use meshspan_api_contract::{
    CreateRecoveryCodesRequest, decode_create_recovery_codes_request,
    encode_create_recovery_codes_response,
};
use meshspan_domain::{
    AuthenticationMethodKind, AuthenticationService, ClaimBundle, InitialBootstrapMaterial,
    OperationId, RecoveryCodeBundle, RecoveryCodeIssuanceKey, UnixMicros,
};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, LogPosition, PartitionDatabase, RepositoryError,
};
use tempfile::tempdir;

use crate::browser_session::CSRF_HEADER;
use crate::create_session_tests::{RepositorySessionAuthority, bootstrap};
use crate::passkey_test_support::CountingRandom;
use crate::totp_session_creation_tests::{create_totp_method, session_request};
use crate::{
    CreateSessionService, DisabledPasskeySessions, GatewaySessionIdentity,
    RecoveryCodeIssuanceAuthority, RecoveryCodeIssuanceAuthorityError, RecoveryCodeIssuanceCommit,
    RecoveryCodeIssuanceError, RecoveryCodeIssuanceService, TotpEnvelopeKey, TotpSecretCipher,
    TotpSessionVerifier,
};

const ISSUE_OPERATION: &str = "00000000-0000-4000-8000-000000000081";

#[test]
fn recovery_codes_issue_once_replay_across_gateways_and_persist_only_digests()
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
    let verifier =
        TotpSessionVerifier::new(TotpSecretCipher::new(TotpEnvelopeKey::from_bytes([8; 32])?));
    let mut sessions =
        CreateSessionService::with_factors(authority, DisabledPasskeySessions, verifier);
    let session = sessions.create(
        &session_request(&material, "00000000-0000-4000-8000-000000000080", "755224")?,
        UnixMicros::new(10),
    )?;
    let headers = browser_headers(&session)?;
    let gateway = GatewaySessionIdentity::new(material.node_id, 1)?;
    let request = issuance_request("Emergency recovery")?;
    let mut issuer = RecoveryCodeIssuanceService::new(
        sessions.into_authority(),
        RecoveryCodeIssuanceKey::from_bytes([21; 32])?,
        gateway,
    );
    let first = issuer.issue(&request, &headers, UnixMicros::new(20))?;
    assert_eq!(first.codes.len(), 10);
    assert_eq!(first.created_at_epoch_micros, 20);
    let encoded = encode_create_recovery_codes_response(&first)?;

    let mut replay = RecoveryCodeIssuanceService::new(
        issuer.into_authority(),
        RecoveryCodeIssuanceKey::from_bytes([21; 32])?,
        gateway,
    );
    let retried = replay.issue(&request, &headers, UnixMicros::new(30))?;
    assert_eq!(encode_create_recovery_codes_response(&retried)?, encoded);
    assert!(matches!(
        replay.issue(
            &issuance_request("Changed recovery label")?,
            &headers,
            UnixMicros::new(31)
        ),
        Err(RecoveryCodeIssuanceError::Conflict)
    ));

    let authority = replay.into_authority();
    let mut identities = std::collections::BTreeSet::new();
    for code in &first.codes {
        let parsed = RecoveryCodeBundle::parse(code.expose_for_delivery())?;
        assert!(identities.insert(parsed.code_id()));
        let material = authority
            .repository
            .recovery_code_verification_material(
                material.administrator_id,
                parsed.code_id(),
                parsed.secret_digest(),
                AuthenticationService::Https,
                UnixMicros::new(32),
            )?
            .ok_or("issued recovery-code digest was not committed")?;
        assert_eq!(material.used_at, None);
        assert_eq!(
            authority.repository.recovery_code_verification_material(
                material.principal_id,
                parsed.code_id(),
                [99; 32],
                AuthenticationService::Https,
                UnixMicros::new(32),
            )?,
            None
        );
    }
    Ok(())
}

impl RecoveryCodeIssuanceAuthority for RepositorySessionAuthority {
    fn resolve_recovery_code_issuance(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<RecoveryCodeIssuanceCommit>, RecoveryCodeIssuanceAuthorityError> {
        self.repository
            .resolve_authentication_method_creation(
                operation_id,
                AuthenticationMethodKind::RecoveryCode,
            )
            .map_err(|error| map_repository_error(&error))?
            .map(|replay| {
                Ok(RecoveryCodeIssuanceCommit {
                    request_digest: replay.request_digest,
                    result_digest: replay.result_digest,
                    method_id: replay.method_id,
                    principal_id: replay.principal_id,
                    created_at: replay.created_at,
                })
            })
            .transpose()
    }

    fn commit_or_resolve_recovery_code_issuance(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<RecoveryCodeIssuanceCommit, RecoveryCodeIssuanceAuthorityError> {
        let expected_digest = command.request_digest(context);
        if let Some(replay) = self.resolve_recovery_code_issuance(context.operation_id)? {
            if replay.request_digest != expected_digest {
                return Err(RecoveryCodeIssuanceAuthorityError::Conflict);
            }
            return Ok(replay);
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
        self.resolve_recovery_code_issuance(context.operation_id)?
            .ok_or(RecoveryCodeIssuanceAuthorityError::Failed)
    }
}

fn issuance_request(label: &str) -> Result<CreateRecoveryCodesRequest, Box<dyn std::error::Error>> {
    Ok(decode_create_recovery_codes_request(&serde_json::to_vec(
        &serde_json::json!({
            "operation_id": ISSUE_OPERATION,
            "label": label
        }),
    )?)?)
}

fn browser_headers(
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
        HeaderValue::from_str(result.csrf.expose_encoded().as_str())?,
    );
    Ok(headers)
}

fn map_repository_error(error: &RepositoryError) -> RecoveryCodeIssuanceAuthorityError {
    match error {
        RepositoryError::OperationConflict => RecoveryCodeIssuanceAuthorityError::Conflict,
        RepositoryError::Store(_) | RepositoryError::Sqlite(_) | RepositoryError::Io(_) => {
            RecoveryCodeIssuanceAuthorityError::Unavailable
        }
        _ => RecoveryCodeIssuanceAuthorityError::Failed,
    }
}
