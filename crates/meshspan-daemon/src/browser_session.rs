// SPDX-License-Identifier: GPL-2.0-only

//! Hostile browser credential headers reduced to digest-only session evidence.

use axum::http::header::COOKIE;
use axum::http::{HeaderMap, HeaderName};
use meshspan_domain::{SessionCsrfBundle, SessionId, SessionTokenBundle};
use thiserror::Error;

pub(crate) const SESSION_COOKIE_NAME: &str = "meshspan_session";
pub(crate) const CSRF_HEADER: HeaderName = HeaderName::from_static("meshspan-csrf-token");
const MAXIMUM_COOKIE_HEADERS: usize = 4;
const MAXIMUM_COOKIE_BYTES: usize = 8_192;

/// Whether a browser request can change state and therefore requires CSRF proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrowserRequestProtection {
    /// Safe read which requires only the secure session cookie.
    Read,
    /// State-changing request which also requires the session-bound CSRF header.
    Mutation,
}

/// Secret-free browser session evidence safe to pass into authoritative evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrowserSessionEvidence {
    /// Session identity embedded independently in both presented tokens.
    pub session_id: SessionId,
    /// Digest of the bearer secret stored in replicated authentication metadata.
    pub token_digest: [u8; 32],
    /// Digest of the independently presented CSRF secret for a mutation.
    pub csrf_digest: Option<[u8; 32]>,
}

/// Parses one request's browser credentials without retaining their plaintext.
///
/// All credential failures intentionally collapse to one non-disclosing error. Multiple session
/// cookies or CSRF headers are rejected rather than relying on intermediary-specific precedence.
///
/// # Errors
///
/// Rejects missing, duplicate, oversized, non-canonical or cross-session credential material.
pub fn parse_browser_session(
    headers: &HeaderMap,
    protection: BrowserRequestProtection,
) -> Result<BrowserSessionEvidence, BrowserSessionError> {
    let bearer = parse_session_cookie(headers)?;
    let csrf = parse_csrf(headers)?;
    if protection == BrowserRequestProtection::Mutation && csrf.is_none() {
        return Err(BrowserSessionError);
    }
    if csrf
        .as_ref()
        .is_some_and(|csrf| csrf.session_id() != bearer.session_id())
    {
        return Err(BrowserSessionError);
    }
    Ok(BrowserSessionEvidence {
        session_id: bearer.session_id(),
        token_digest: bearer.token_digest(),
        csrf_digest: csrf.as_ref().map(SessionCsrfBundle::token_digest),
    })
}

fn parse_session_cookie(headers: &HeaderMap) -> Result<SessionTokenBundle, BrowserSessionError> {
    let mut header_count = 0_usize;
    let mut total_bytes = 0_usize;
    let mut token = None;
    for header in headers.get_all(COOKIE) {
        header_count = header_count.checked_add(1).ok_or(BrowserSessionError)?;
        total_bytes = total_bytes
            .checked_add(header.as_bytes().len())
            .ok_or(BrowserSessionError)?;
        if header_count > MAXIMUM_COOKIE_HEADERS || total_bytes > MAXIMUM_COOKIE_BYTES {
            return Err(BrowserSessionError);
        }
        let value = header.to_str().map_err(|_| BrowserSessionError)?;
        for pair in value.split(';') {
            let Some((name, value)) = pair.trim().split_once('=') else {
                return Err(BrowserSessionError);
            };
            if name == SESSION_COOKIE_NAME {
                if token.is_some() {
                    return Err(BrowserSessionError);
                }
                token = Some(SessionTokenBundle::parse(value).map_err(|_| BrowserSessionError)?);
            }
        }
    }
    token.ok_or(BrowserSessionError)
}

fn parse_csrf(headers: &HeaderMap) -> Result<Option<SessionCsrfBundle>, BrowserSessionError> {
    let mut values = headers.get_all(&CSRF_HEADER).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(BrowserSessionError);
    }
    let value = value.to_str().map_err(|_| BrowserSessionError)?;
    SessionCsrfBundle::parse(value)
        .map(Some)
        .map_err(|_| BrowserSessionError)
}

/// Non-disclosing rejection of browser credential presentation.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("browser session was not accepted")]
pub struct BrowserSessionError;

#[cfg(test)]
mod tests {
    use axum::http::header::COOKIE;
    use axum::http::{HeaderMap, HeaderValue};
    use meshspan_domain::{ApiKeyBundle, OperationId, SessionCsrfBundle, SessionTokenBundle};

    use super::{BrowserRequestProtection, CSRF_HEADER, parse_browser_session};

    const API_KEY: &str = concat!(
        "meshspan-key-v1.00000000000040008000000000000031.",
        "1111111111111111111111111111111111111111111111111111111111111111"
    );

    #[test]
    fn read_and_mutation_reduce_tokens_to_matching_digest_only_evidence()
    -> Result<(), Box<dyn std::error::Error>> {
        let (bearer, csrf) = credentials(1)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            HeaderValue::from_str(&format!("theme=dark; meshspan_session={bearer}"))?,
        );
        let read = parse_browser_session(&headers, BrowserRequestProtection::Read)?;
        assert_eq!(read.csrf_digest, None);
        headers.insert(CSRF_HEADER, HeaderValue::from_str(&csrf)?);
        let mutation = parse_browser_session(&headers, BrowserRequestProtection::Mutation)?;
        assert_eq!(mutation.session_id, read.session_id);
        assert_eq!(mutation.token_digest, read.token_digest);
        assert!(mutation.csrf_digest.is_some());
        Ok(())
    }

    #[test]
    fn missing_duplicate_oversized_and_cross_session_credentials_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let (bearer, _) = credentials(1)?;
        let (_, other_csrf) = credentials(2)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            HeaderValue::from_str(&format!("meshspan_session={bearer}"))?,
        );
        assert!(parse_browser_session(&headers, BrowserRequestProtection::Mutation).is_err());
        headers.insert(CSRF_HEADER, HeaderValue::from_str(&other_csrf)?);
        assert!(parse_browser_session(&headers, BrowserRequestProtection::Mutation).is_err());
        headers.append(
            COOKIE,
            HeaderValue::from_str(&format!("meshspan_session={bearer}"))?,
        );
        assert!(parse_browser_session(&headers, BrowserRequestProtection::Read).is_err());

        let mut oversized = HeaderMap::new();
        oversized.insert(COOKIE, HeaderValue::from_bytes(&vec![b'a'; 8_193])?);
        assert!(parse_browser_session(&oversized, BrowserRequestProtection::Read).is_err());
        Ok(())
    }

    fn credentials(discriminator: u8) -> Result<(String, String), Box<dyn std::error::Error>> {
        let api_key = ApiKeyBundle::parse(API_KEY)?;
        let mut operation = [discriminator; 16];
        operation[6] = 0x40;
        operation[8] = 0x80;
        let operation = OperationId::from_bytes(operation)?;
        let bearer = SessionTokenBundle::derive(&api_key, operation)?.expose_encoded();
        let csrf = SessionCsrfBundle::derive(&api_key, operation)?.expose_encoded();
        Ok((bearer.to_string(), csrf.to_string()))
    }
}
