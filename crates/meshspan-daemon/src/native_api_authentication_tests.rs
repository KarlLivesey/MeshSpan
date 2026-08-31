// SPDX-License-Identifier: GPL-2.0-only

//! Hostile and valid direct-authentication proofs for the native specialised API.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::http::HeaderMap;
use axum::http::header::{AUTHORIZATION, COOKIE};
use meshspan_domain::{
    ApiKeyBundle, ApiKeyId, AssuranceLevel, AuthenticationMethodId, EntropyError, NodeId,
    PrincipalId, RandomSource, Revision, UnixMicros,
};
use meshspan_metadata::{
    ApiKeyAuthentication, BrowserSessionAccessRequest, SessionAccessDecision, SessionAccessDenial,
};

use crate::{
    BrowserSessionAuthenticator, BrowserSessionAuthority, BrowserSessionAuthorityError,
    FileApiAuthenticationError, FileApiAuthenticator, GatewaySessionIdentity,
    NativeApiAuthenticator, NativeApiKeyAuthenticator, NativeApiKeyAuthority,
    NativeApiKeyAuthorityError,
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
    let context =
        authenticator.authenticate_file_read(&bearer_headers(&encoded)?, UnixMicros::new(200))?;
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
            authenticator.authenticate_file_read(&headers, UnixMicros::new(200)),
            Err(FileApiAuthenticationError::Rejected)
        );
    }

    let mut duplicated = bearer_headers(&encoded)?;
    duplicated.append(AUTHORIZATION, format!("Bearer {encoded}").parse()?);
    assert_eq!(
        authenticator.authenticate_file_read(&duplicated, UnixMicros::new(200)),
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
        authenticator
            .authenticate_file_read(&bearer_headers(&changed_identity)?, UnixMicros::new(200),),
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
        authenticator.authenticate_file_read(&headers, UnixMicros::new(200)),
        Err(FileApiAuthenticationError::Rejected)
    );
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
