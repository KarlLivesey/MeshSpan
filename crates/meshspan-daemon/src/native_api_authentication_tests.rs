// SPDX-License-Identifier: GPL-2.0-only

//! Hostile and valid direct-authentication proofs for the native specialised API.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::http::HeaderMap;
use axum::http::header::{AUTHORIZATION, COOKIE};
use meshspan_domain::{
    ApiKeyBundle, ApiKeyId, AssuranceLevel, AuditEventId, AuthenticationMethodId, EntropyError,
    HostId, MeshId, NodeId, OperationId, PartitionId, PrincipalId, RandomSource, Revision, RoleId,
    SessionCsrfBundle, SessionTokenBundle, UnixMicros,
};
use meshspan_metadata::{
    ApiKeyAuthentication, AuthoritativeCommand, AuthoritativeRepository, BootstrapMesh,
    BrowserSessionAccessRequest, CommandContext, CreateAuthenticationMethod, LogPosition,
    NewAuthenticationCredential, PartitionDatabase, RecordName, SessionAccessCapability,
    SessionAccessDecision, SessionAccessDenial,
};

use crate::{
    BrowserSessionAuthenticator, BrowserSessionAuthority, BrowserSessionAuthorityError,
    FileApiAuthenticationError, GatewaySessionIdentity, NativeApiAuthenticator,
    NativeApiKeyAuthenticator, NativeApiKeyAuthority, NativeApiKeyAuthorityError,
    NativeFileApiAuthenticator, NativeFileRequestProtection,
};

#[test]
fn exact_bearer_key_produces_only_headless_digest_context() -> Result<(), Box<dyn std::error::Error>>
{
    let (encoded, key_id, digest) = key_material()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let authenticator = NativeApiKeyAuthenticator::new(
        KeyAuthority {
            expected_key_id: key_id,
            expected_digest: digest,
            calls: Arc::clone(&calls),
        },
        gateway()?,
    );
    let context = authenticator.authenticate_file_request(
        &bearer_headers(&encoded)?,
        NativeFileRequestProtection::Read,
        UnixMicros::new(200),
    )?;
    assert_eq!(
        context.authentication_service,
        meshspan_domain::AuthenticationService::HeadlessApi
    );
    assert_eq!(context.credential_digest, digest);
    assert_eq!(context.required_assurance, AssuranceLevel::SingleFactor);
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    Ok(())
}

#[test]
fn real_replicated_repository_accepts_the_issued_native_api_key()
-> Result<(), Box<dyn std::error::Error>> {
    let mut random = SequentialRandom(30);
    let key = ApiKeyBundle::generate(&mut random)?;
    let encoded = key.expose_encoded().to_string();
    let administrator = PrincipalId::from_bytes(versioned(40))?;
    let gateway = gateway()?;
    let database = PartitionDatabase::open(
        std::path::Path::new(":memory:"),
        PartitionId::from_bytes(versioned(41))?,
        UnixMicros::new(1),
    )?;
    let mut repository = AuthoritativeRepository::new(database);
    repository.apply_committed(
        LogPosition { index: 1, term: 1 },
        command_context(1, administrator, Revision::ZERO)?,
        &AuthoritativeCommand::BootstrapMesh(BootstrapMesh {
            mesh_id: MeshId::from_bytes(versioned(42))?,
            mesh_name: RecordName::new("Native API proof")?,
            administrator_id: administrator,
            administrator_name: RecordName::new("Administrator")?,
            administrator_role_id: RoleId::from_bytes(versioned(43))?,
            host_id: HostId::from_bytes(versioned(44))?,
            host_name: RecordName::new("Host")?,
            node_id: gateway.node_id,
            node_name: RecordName::new("Gateway")?,
            partition_name: RecordName::new("Root authority")?,
        }),
    )?;
    repository.apply_committed(
        LogPosition { index: 2, term: 1 },
        command_context(2, administrator, Revision::new(1))?,
        &AuthoritativeCommand::CreateAuthenticationMethod(CreateAuthenticationMethod {
            method_id: AuthenticationMethodId::from_bytes(versioned(45))?,
            principal_id: administrator,
            label: "Native API".to_owned(),
            service_scope: meshspan_domain::AuthenticationService::HeadlessApi.scope_bit(),
            expires_at: None,
            credential: NewAuthenticationCredential::ApiKey {
                key_id: key.key_id(),
                key_digest: key.secret_digest(),
                smb_verifier_ciphertext: None,
                scopes: meshspan_domain::AuthenticationService::HeadlessApi.api_key_login_scope(),
                valid_from: UnixMicros::new(20),
            },
        }),
    )?;

    let context = NativeApiKeyAuthenticator::new(repository, gateway).authenticate_file_request(
        &bearer_headers(&encoded)?,
        NativeFileRequestProtection::Read,
        UnixMicros::new(200),
    )?;
    assert_eq!(context.credential_digest, key.secret_digest());
    assert_eq!(context.gateway_node_id, gateway.node_id);
    Ok(())
}

#[test]
fn malformed_ambiguous_and_mismatched_presentations_fail_before_acceptance()
-> Result<(), Box<dyn std::error::Error>> {
    let (encoded, key_id, digest) = key_material()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let authenticator = NativeApiKeyAuthenticator::new(
        KeyAuthority {
            expected_key_id: key_id,
            expected_digest: digest,
            calls: Arc::clone(&calls),
        },
        gateway()?,
    );
    for value in [
        String::new(),
        encoded.clone(),
        format!("Basic {encoded}"),
        format!("Bearer  {encoded}"),
        format!("Bearer {encoded} "),
    ] {
        let mut headers = HeaderMap::new();
        if !value.is_empty() {
            headers.insert(AUTHORIZATION, value.parse()?);
        }
        assert_eq!(
            authenticator.authenticate_file_request(
                &headers,
                NativeFileRequestProtection::Read,
                UnixMicros::new(200),
            ),
            Err(FileApiAuthenticationError::Rejected)
        );
    }

    let mut duplicated = bearer_headers(&encoded)?;
    duplicated.append(AUTHORIZATION, format!("Bearer {encoded}").parse()?);
    assert_eq!(
        authenticator.authenticate_file_request(
            &duplicated,
            NativeFileRequestProtection::Read,
            UnixMicros::new(200),
        ),
        Err(FileApiAuthenticationError::Rejected)
    );

    let mut changed_identity = encoded.clone().into_bytes();
    let identity_index = "meshspan-key-v1.".len();
    changed_identity[identity_index] = if changed_identity[identity_index] == b'a' {
        b'b'
    } else {
        b'a'
    };
    let changed_identity = String::from_utf8(changed_identity)?;
    assert_eq!(
        authenticator.authenticate_file_request(
            &bearer_headers(&changed_identity)?,
            NativeFileRequestProtection::Read,
            UnixMicros::new(200),
        ),
        Err(FileApiAuthenticationError::Rejected)
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    Ok(())
}

#[test]
fn cookie_and_bearer_cannot_create_ambiguous_native_api_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let (encoded, key_id, digest) = key_material()?;
    let gateway = gateway()?;
    let authenticator = NativeApiAuthenticator::new(
        BrowserSessionAuthenticator::new(RejectingBrowserAuthority, gateway),
        NativeApiKeyAuthenticator::new(
            KeyAuthority {
                expected_key_id: key_id,
                expected_digest: digest,
                calls: Arc::new(AtomicUsize::new(0)),
            },
            gateway,
        ),
    );
    let mut headers = bearer_headers(&encoded)?;
    headers.insert(COOKIE, "unrelated=value".parse()?);
    assert_eq!(
        authenticator.authenticate_file_request(
            &headers,
            NativeFileRequestProtection::Read,
            UnixMicros::new(200),
        ),
        Err(FileApiAuthenticationError::Rejected)
    );
    Ok(())
}

#[test]
fn browser_upload_mutations_require_csrf_while_upload_reads_do_not()
-> Result<(), Box<dyn std::error::Error>> {
    let gateway = gateway()?;
    let authority = BrowserProtectionAuthority { gateway };
    let authenticator = BrowserSessionAuthenticator::new(authority, gateway);
    let (mut headers, csrf) = browser_headers()?;

    authenticator.authenticate_file_request(
        &headers,
        NativeFileRequestProtection::Read,
        UnixMicros::new(200),
    )?;
    assert_eq!(
        authenticator.authenticate_file_request(
            &headers,
            NativeFileRequestProtection::Mutation,
            UnixMicros::new(200),
        ),
        Err(FileApiAuthenticationError::Rejected)
    );

    headers.insert("MeshSpan-CSRF-Token", csrf.parse()?);
    authenticator.authenticate_file_request(
        &headers,
        NativeFileRequestProtection::Mutation,
        UnixMicros::new(200),
    )?;
    Ok(())
}

fn key_material() -> Result<(String, ApiKeyId, [u8; 32]), Box<dyn std::error::Error>> {
    let key = ApiKeyBundle::generate(&mut SequentialRandom(1))?;
    let encoded = key.expose_encoded().to_string();
    Ok((encoded, key.key_id(), key.secret_digest()))
}

fn bearer_headers(encoded: &str) -> Result<HeaderMap, Box<dyn std::error::Error>> {
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, format!("Bearer {encoded}").parse()?);
    Ok(headers)
}

fn gateway() -> Result<GatewaySessionIdentity, Box<dyn std::error::Error>> {
    let mut node = [8; 16];
    node[6] = 0x48;
    node[8] = 0x88;
    Ok(GatewaySessionIdentity::new(NodeId::from_bytes(node)?, 3)?)
}

fn command_context(
    seed: u8,
    actor_principal_id: PrincipalId,
    expected_revision: Revision,
) -> Result<CommandContext, Box<dyn std::error::Error>> {
    Ok(CommandContext {
        operation_id: OperationId::from_bytes(versioned(seed))?,
        actor_principal_id,
        audit_event_id: AuditEventId::from_bytes(versioned(seed.wrapping_add(10)))?,
        occurred_at: UnixMicros::new(i64::from(seed) * 10),
        expected_revision: Some(expected_revision),
    })
}

struct KeyAuthority {
    expected_key_id: ApiKeyId,
    expected_digest: [u8; 32],
    calls: Arc<AtomicUsize>,
}

impl NativeApiKeyAuthority for KeyAuthority {
    fn authenticate_native_api_key(
        &self,
        key_id: ApiKeyId,
        digest: [u8; 32],
        required_assurance: AssuranceLevel,
        _now: UnixMicros,
    ) -> Result<Option<ApiKeyAuthentication>, NativeApiKeyAuthorityError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if key_id != self.expected_key_id
            || digest != self.expected_digest
            || required_assurance != AssuranceLevel::SingleFactor
        {
            return Ok(None);
        }
        Ok(Some(ApiKeyAuthentication {
            principal_id: PrincipalId::from_bytes(versioned(4))
                .map_err(|_| NativeApiKeyAuthorityError::Failed)?,
            method_id: AuthenticationMethodId::from_bytes(versioned(5))
                .map_err(|_| NativeApiKeyAuthorityError::Failed)?,
            key_id,
            scopes: 2,
            credential_generation: 1,
            revision: Revision::new(1),
            expires_at: None,
        }))
    }
}

struct RejectingBrowserAuthority;

impl BrowserSessionAuthority for RejectingBrowserAuthority {
    fn evaluate_browser_session(
        &self,
        _request: BrowserSessionAccessRequest,
    ) -> Result<SessionAccessDecision, BrowserSessionAuthorityError> {
        Ok(SessionAccessDecision::Denied(
            SessionAccessDenial::Unavailable,
        ))
    }
}

#[derive(Clone, Copy)]
struct BrowserProtectionAuthority {
    gateway: GatewaySessionIdentity,
}

impl BrowserSessionAuthority for BrowserProtectionAuthority {
    fn evaluate_browser_session(
        &self,
        request: BrowserSessionAccessRequest,
    ) -> Result<SessionAccessDecision, BrowserSessionAuthorityError> {
        Ok(SessionAccessDecision::Granted(SessionAccessCapability {
            session_id: request.expected_session_id,
            principal_id: PrincipalId::from_bytes(versioned(70))
                .map_err(|_| BrowserSessionAuthorityError::Failed)?,
            gateway_node_id: self.gateway.node_id,
            gateway_incarnation: self.gateway.incarnation,
            identity_revision: Revision::new(1),
            gateway_revision: Revision::new(1),
            expires_at: UnixMicros::new(300),
            persistent_cookie: false,
            system_management_expires_at: None,
            capability_digest: [71; 32],
        }))
    }
}

fn browser_headers() -> Result<(HeaderMap, String), Box<dyn std::error::Error>> {
    let api_key = ApiKeyBundle::generate(&mut SequentialRandom(80))?;
    let operation_id = OperationId::from_bytes(versioned(81))?;
    let bearer = SessionTokenBundle::derive(&api_key, operation_id)?.expose_encoded();
    let csrf = SessionCsrfBundle::derive(&api_key, operation_id)?.expose_encoded();
    let mut headers = HeaderMap::new();
    headers.insert(
        COOKIE,
        format!("meshspan_session={}", bearer.as_str()).parse()?,
    );
    Ok((headers, csrf.to_string()))
}

struct SequentialRandom(u8);

impl RandomSource for SequentialRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        for byte in destination {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}

const fn versioned(seed: u8) -> [u8; 16] {
    let mut bytes = [seed; 16];
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes
}
