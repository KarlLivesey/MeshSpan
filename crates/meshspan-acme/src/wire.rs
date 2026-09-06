// SPDX-License-Identifier: GPL-2.0-only

//! Bounded RFC 8555 resource parsing and request construction.

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use thiserror::Error;

use crate::{AcmeAccountBinding, AcmeJwsSigner, AcmeSignedRequest};

pub(crate) const MAXIMUM_BODY_BYTES: usize = 1024 * 1024;
const MAXIMUM_HEADER_COUNT: usize = 64;
const MAXIMUM_HEADER_NAME_BYTES: usize = 64;
const MAXIMUM_HEADER_VALUE_BYTES: usize = 8 * 1024;
const MAXIMUM_URL_BYTES: usize = 2_048;
const MAXIMUM_IDENTIFIERS: usize = 256;
const MAXIMUM_AUTHORIZATIONS: usize = 256;
const MAXIMUM_CHALLENGES: usize = 16;
const MAXIMUM_DNS_NAME_BYTES: usize = 253;
const MAXIMUM_TOKEN_BYTES: usize = 512;
const MAXIMUM_PROBLEM_DETAIL_BYTES: usize = 4_096;

/// Strictly bounded response headers needed by the ACME protocol.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AcmeResponseHeaders(Vec<(String, String)>);

impl AcmeResponseHeaders {
    /// Parses one unambiguous retry hint without consulting the host clock.
    ///
    /// # Errors
    ///
    /// Rejects duplicate fields, malformed dates, signs, fractions and overflow.
    pub fn retry_after(&self) -> Result<Option<crate::AcmeRetryAfter>, AcmeProtocolError> {
        self.optional("retry-after")?
            .map(crate::AcmeRetryAfter::parse)
            .transpose()
    }

    /// Validates lower-case HTTP field names and bounded ASCII values.
    ///
    /// # Errors
    ///
    /// Rejects excessive, malformed or ambiguous header input.
    pub fn new(values: Vec<(String, String)>) -> Result<Self, AcmeProtocolError> {
        if values.len() > MAXIMUM_HEADER_COUNT {
            return Err(AcmeProtocolError::CapacityExceeded);
        }
        for (name, value) in &values {
            if name.is_empty()
                || name.len() > MAXIMUM_HEADER_NAME_BYTES
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
                || value.len() > MAXIMUM_HEADER_VALUE_BYTES
                || !value.is_ascii()
                || value
                    .bytes()
                    .any(|byte| byte.is_ascii_control() && byte != b'\t')
            {
                return Err(AcmeProtocolError::InvalidResponse);
            }
        }
        Ok(Self(values))
    }

    fn optional(&self, name: &str) -> Result<Option<&str>, AcmeProtocolError> {
        let mut matches = self
            .0
            .iter()
            .filter(|(candidate, _)| candidate == name)
            .map(|(_, value)| value.as_str());
        let value = matches.next();
        if matches.next().is_some() {
            Err(AcmeProtocolError::InvalidResponse)
        } else {
            Ok(value)
        }
    }

    fn required(&self, name: &str) -> Result<&str, AcmeProtocolError> {
        self.optional(name)?
            .ok_or(AcmeProtocolError::InvalidResponse)
    }
}

/// One bounded HTTP response returned by the replaceable ACME transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcmeHttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Strict response headers.
    pub headers: AcmeResponseHeaders,
    /// Bounded response bytes.
    pub body: Vec<u8>,
}

impl AcmeHttpResponse {
    /// Constructs a response only after transport-size validation.
    ///
    /// # Errors
    ///
    /// Rejects invalid status codes and oversized bodies.
    pub fn new(
        status: u16,
        headers: AcmeResponseHeaders,
        body: Vec<u8>,
    ) -> Result<Self, AcmeProtocolError> {
        if !(100..=599).contains(&status) {
            return Err(AcmeProtocolError::InvalidResponse);
        }
        if body.len() > MAXIMUM_BODY_BYTES {
            return Err(AcmeProtocolError::CapacityExceeded);
        }
        Ok(Self {
            status,
            headers,
            body,
        })
    }
}

/// Required endpoints discovered from one ACME directory.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeDirectory {
    /// Fresh nonce endpoint.
    pub new_nonce: String,
    /// Account creation endpoint.
    pub new_account: String,
    /// Order creation endpoint.
    pub new_order: String,
}

/// Requested DNS identifiers for a new order.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AcmeOrderRequest {
    dns_names: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcmeOrderRequestFields {
    dns_names: Vec<String>,
}

impl<'de> Deserialize<'de> for AcmeOrderRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let fields = AcmeOrderRequestFields::deserialize(deserializer)?;
        Self::new(fields.dns_names).map_err(serde::de::Error::custom)
    }
}

impl AcmeOrderRequest {
    /// Creates one non-empty, canonical, strictly ordered DNS identifier set.
    ///
    /// # Errors
    ///
    /// Rejects invalid, duplicate, unsorted or excessive DNS names.
    pub fn new(dns_names: Vec<String>) -> Result<Self, AcmeProtocolError> {
        if dns_names.is_empty() || dns_names.len() > MAXIMUM_IDENTIFIERS {
            return Err(AcmeProtocolError::InvalidRequest);
        }
        let mut previous: Option<&str> = None;
        for name in &dns_names {
            if !valid_dns_name(name) || previous.is_some_and(|value| value >= name.as_str()) {
                return Err(AcmeProtocolError::InvalidRequest);
            }
            previous = Some(name);
        }
        Ok(Self { dns_names })
    }

    /// Borrows the canonical requested names.
    #[must_use]
    pub fn dns_names(&self) -> &[String] {
        &self.dns_names
    }
}

/// ACME resource lifecycle values used by orders, authorizations and challenges.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcmeResourceStatus {
    /// Awaiting further work.
    Pending,
    /// Server-side verification is in progress.
    Processing,
    /// Resource is valid.
    Valid,
    /// Resource has failed permanently.
    Invalid,
    /// Order is ready for finalisation.
    Ready,
    /// Authorization was explicitly deactivated.
    Deactivated,
    /// Authorization expired before validation completed.
    Expired,
    /// Authorization was revoked by the server.
    Revoked,
}

/// One parsed ACME order resource.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeOrder {
    /// Current order status.
    pub status: AcmeResourceStatus,
    /// Exact canonical DNS identifiers covered by this order.
    pub dns_names: Vec<String>,
    /// Bounded authorization resource URLs.
    pub authorizations: Vec<String>,
    /// CSR finalisation URL.
    pub finalize: String,
    /// Issued certificate URL once valid.
    pub certificate: Option<String>,
}

/// One parsed challenge offered for an authorization.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeChallengeRecord {
    /// Exact challenge type such as `http-01` or `dns-01`.
    pub kind: String,
    /// Challenge resource URL.
    pub url: String,
    /// Server-provided challenge token.
    pub token: String,
    /// Current challenge status.
    pub status: AcmeResourceStatus,
}

/// One DNS identifier authorization and its bounded challenge choices.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeAuthorization {
    /// Canonical DNS identifier.
    pub dns_name: String,
    /// Whether this authorization covers the wildcard form of `dns_name`.
    pub wildcard: bool,
    /// Current authorization status.
    pub status: AcmeResourceStatus,
    /// Server-offered challenge records.
    pub challenges: Vec<AcmeChallengeRecord>,
}

/// Bounded ACME problem document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcmeProblem {
    /// Registered ACME problem type URI.
    pub problem_type: String,
    /// Optional bounded human-readable detail for local diagnostics.
    pub detail: Option<String>,
}

impl AcmeProblem {
    /// Whether this error requires exactly one retry with a fresh nonce.
    #[must_use]
    pub fn is_bad_nonce(&self) -> bool {
        self.problem_type == "urn:ietf:params:acme:error:badNonce"
    }
}

/// Per-request guard permitting at most one RFC 8555 `badNonce` retry.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AcmeBadNonceRetry {
    consumed: bool,
}

impl AcmeBadNonceRetry {
    /// Returns the fresh response nonce for the sole permitted `badNonce` retry.
    ///
    /// # Errors
    ///
    /// Rejects a second retry or a bad-nonce response without one exact valid replay nonce.
    pub fn consume(
        &mut self,
        problem: &AcmeProblem,
        response: &AcmeHttpResponse,
    ) -> Result<Option<String>, AcmeProtocolError> {
        if !problem.is_bad_nonce() {
            return Ok(None);
        }
        if self.consumed {
            return Err(AcmeProtocolError::RetryExhausted);
        }
        let nonce = AcmeWire::replay_nonce(response)?;
        self.consumed = true;
        Ok(Some(nonce))
    }
}

/// Stateless RFC 8555 request/response boundary.
#[derive(Clone, Copy, Debug, Default)]
pub struct AcmeWire;

impl AcmeWire {
    /// Parses the required directory endpoints from a successful response.
    ///
    /// # Errors
    ///
    /// Rejects non-success, duplicate fields, missing endpoints and invalid URLs. Unknown bounded
    /// extension fields are ignored as RFC 8555 requires.
    pub fn directory(response: &AcmeHttpResponse) -> Result<AcmeDirectory, AcmeProtocolError> {
        require_status(response, &[200])?;
        let object = response_object(&response.body)?;
        Ok(AcmeDirectory {
            new_nonce: required_url(&object, "newNonce")?,
            new_account: required_url(&object, "newAccount")?,
            new_order: required_url(&object, "newOrder")?,
        })
    }

    /// Extracts one non-ambiguous replay nonce from any ACME response.
    ///
    /// # Errors
    ///
    /// Rejects missing, duplicate or malformed nonce headers.
    pub fn replay_nonce(response: &AcmeHttpResponse) -> Result<String, AcmeProtocolError> {
        let nonce = response.headers.required("replay-nonce")?;
        if nonce.is_empty()
            || nonce.len() > 512
            || !nonce
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(AcmeProtocolError::InvalidResponse);
        }
        Ok(nonce.to_owned())
    }

    /// Accepts one successful response whose only required result is a fresh nonce.
    ///
    /// # Errors
    ///
    /// Rejects unexpected statuses and missing, duplicate or malformed nonce headers.
    pub fn nonce_response(response: &AcmeHttpResponse) -> Result<String, AcmeProtocolError> {
        require_status(response, &[200, 204])?;
        Self::replay_nonce(response)
    }

    /// Reads the account resource URL from a successful account response.
    ///
    /// # Errors
    ///
    /// Rejects missing, duplicate or non-HTTPS `Location` headers.
    pub fn account_location(response: &AcmeHttpResponse) -> Result<String, AcmeProtocolError> {
        require_status(response, &[200, 201])?;
        let value = response.headers.required("location")?;
        bounded_url(value)?;
        Ok(value.to_owned())
    }

    /// Reads a canonical resource URL from a successful creation response.
    ///
    /// # Errors
    ///
    /// Rejects missing, duplicate or non-HTTPS `Location` headers.
    pub fn resource_location(response: &AcmeHttpResponse) -> Result<String, AcmeProtocolError> {
        require_status(response, &[200, 201])?;
        let value = response.headers.required("location")?;
        bounded_url(value)?;
        Ok(value.to_owned())
    }

    /// Accepts a successful challenge notification and returns its next nonce.
    ///
    /// # Errors
    ///
    /// Rejects a non-200 response or missing, duplicate or malformed nonce.
    pub fn challenge_acknowledgement(
        response: &AcmeHttpResponse,
    ) -> Result<String, AcmeProtocolError> {
        require_status(response, &[200])?;
        Self::replay_nonce(response)
    }

    /// Parses one successful order and validates every returned resource URL.
    ///
    /// # Errors
    ///
    /// Rejects malformed, excessive, duplicated or semantically inconsistent fields.
    pub fn order(response: &AcmeHttpResponse) -> Result<AcmeOrder, AcmeProtocolError> {
        require_status(response, &[200, 201])?;
        parse_order(&response.body)
    }

    /// Parses one successful authorization and its offered challenge set.
    ///
    /// # Errors
    ///
    /// Rejects malformed identifiers, challenge records and excessive collections.
    pub fn authorization(
        response: &AcmeHttpResponse,
    ) -> Result<AcmeAuthorization, AcmeProtocolError> {
        require_status(response, &[200])?;
        parse_authorization(&response.body)
    }

    /// Parses a non-success problem response without trusting its diagnostic detail.
    ///
    /// # Errors
    ///
    /// Rejects success statuses, malformed or duplicate JSON fields and oversized detail.
    pub fn problem(response: &AcmeHttpResponse) -> Result<AcmeProblem, AcmeProtocolError> {
        if (200..300).contains(&response.status) {
            return Err(AcmeProtocolError::InvalidResponse);
        }
        let object = response_object(&response.body)?;
        let problem_type = required_text(&object, "type", MAXIMUM_URL_BYTES)?;
        let detail = optional_text(&object, "detail", MAXIMUM_PROBLEM_DETAIL_BYTES)?;
        Ok(AcmeProblem {
            problem_type,
            detail,
        })
    }

    /// Builds a signed new-account request.
    ///
    /// # Errors
    ///
    /// Rejects invalid endpoint, nonce, account binding or signer output.
    pub fn new_account<S: AcmeJwsSigner>(
        endpoint: &str,
        nonce: &str,
        signer: &S,
    ) -> Result<AcmeSignedRequest, AcmeProtocolError> {
        let payload = serde_json::to_vec(&json!({ "termsOfServiceAgreed": true }))?;
        AcmeSignedRequest::create(
            endpoint,
            nonce,
            &AcmeAccountBinding::NewAccount,
            &payload,
            signer,
        )
    }

    /// Builds a signed new-order request for the exact canonical DNS name set.
    ///
    /// # Errors
    ///
    /// Rejects invalid endpoint, nonce, account binding, names or signer output.
    pub fn new_order<S: AcmeJwsSigner>(
        endpoint: &str,
        nonce: &str,
        binding: &AcmeAccountBinding,
        request: &AcmeOrderRequest,
        signer: &S,
    ) -> Result<AcmeSignedRequest, AcmeProtocolError> {
        require_existing_account(binding)?;
        let identifiers = request
            .dns_names()
            .iter()
            .map(|name| json!({ "type": "dns", "value": name }))
            .collect::<Vec<_>>();
        let payload = serde_json::to_vec(&json!({ "identifiers": identifiers }))?;
        AcmeSignedRequest::create(endpoint, nonce, binding, &payload, signer)
    }

    /// Builds a signed POST-as-GET resource request with an empty JWS payload.
    ///
    /// # Errors
    ///
    /// Rejects invalid endpoint, nonce, binding or signer output.
    pub fn post_as_get<S: AcmeJwsSigner>(
        endpoint: &str,
        nonce: &str,
        binding: &AcmeAccountBinding,
        signer: &S,
    ) -> Result<AcmeSignedRequest, AcmeProtocolError> {
        require_existing_account(binding)?;
        AcmeSignedRequest::create(endpoint, nonce, binding, b"", signer)
    }

    /// Builds a signed challenge-ready notification with the required empty object payload.
    ///
    /// # Errors
    ///
    /// Rejects invalid endpoint, nonce, binding or signer output.
    pub fn challenge_ready<S: AcmeJwsSigner>(
        endpoint: &str,
        nonce: &str,
        binding: &AcmeAccountBinding,
        signer: &S,
    ) -> Result<AcmeSignedRequest, AcmeProtocolError> {
        require_existing_account(binding)?;
        AcmeSignedRequest::create(endpoint, nonce, binding, b"{}", signer)
    }

    /// Builds a signed order finalisation request carrying a DER CSR.
    ///
    /// # Errors
    ///
    /// Rejects an empty or oversized CSR and invalid signing inputs.
    pub fn finalize<S: AcmeJwsSigner>(
        endpoint: &str,
        nonce: &str,
        binding: &AcmeAccountBinding,
        csr_der: &[u8],
        signer: &S,
    ) -> Result<AcmeSignedRequest, AcmeProtocolError> {
        require_existing_account(binding)?;
        if csr_der.is_empty() || csr_der.len() > 256 * 1024 {
            return Err(AcmeProtocolError::InvalidRequest);
        }
        let payload = serde_json::to_vec(&json!({ "csr": encode_base64url(csr_der) }))?;
        AcmeSignedRequest::create(endpoint, nonce, binding, &payload, signer)
    }

    /// Returns a bounded issued certificate body from a successful certificate response.
    ///
    /// # Errors
    ///
    /// Rejects empty, excessive or non-success responses.
    pub fn certificate(response: &AcmeHttpResponse) -> Result<Vec<u8>, AcmeProtocolError> {
        require_status(response, &[200])?;
        if response.body.is_empty() {
            Err(AcmeProtocolError::InvalidResponse)
        } else {
            Ok(response.body.clone())
        }
    }
}

fn parse_order(bytes: &[u8]) -> Result<AcmeOrder, AcmeProtocolError> {
    let object = response_object(bytes)?;
    let status = parse_order_status(required_text(&object, "status", 32)?.as_str())?;
    let dns_names = required_identifiers(&object)?;
    let authorizations = required_url_array(&object, "authorizations", MAXIMUM_AUTHORIZATIONS)?;
    let finalize = required_url(&object, "finalize")?;
    let certificate = optional_url(&object, "certificate")?;
    if status == AcmeResourceStatus::Valid && certificate.is_none() {
        return Err(AcmeProtocolError::InvalidResponse);
    }
    Ok(AcmeOrder {
        status,
        dns_names,
        authorizations,
        finalize,
        certificate,
    })
}

fn parse_authorization(bytes: &[u8]) -> Result<AcmeAuthorization, AcmeProtocolError> {
    let object = response_object(bytes)?;
    let identifier = object
        .get("identifier")
        .and_then(Value::as_object)
        .ok_or(AcmeProtocolError::InvalidResponse)?;
    if required_text(identifier, "type", 16)? != "dns" {
        return Err(AcmeProtocolError::InvalidResponse);
    }
    let dns_name = required_text(identifier, "value", MAXIMUM_DNS_NAME_BYTES)?;
    if dns_name.starts_with("*.") || !valid_dns_name(&dns_name) {
        return Err(AcmeProtocolError::InvalidResponse);
    }
    let wildcard = match object.get("wildcard") {
        None => false,
        Some(Value::Bool(value)) => *value,
        Some(_) => return Err(AcmeProtocolError::InvalidResponse),
    };
    let challenges = object
        .get("challenges")
        .and_then(Value::as_array)
        .ok_or(AcmeProtocolError::InvalidResponse)?;
    if challenges.is_empty() || challenges.len() > MAXIMUM_CHALLENGES {
        return Err(AcmeProtocolError::InvalidResponse);
    }
    let mut parsed = Vec::with_capacity(challenges.len());
    let mut identities = BTreeSet::new();
    for challenge in challenges {
        let challenge = challenge
            .as_object()
            .ok_or(AcmeProtocolError::InvalidResponse)?;
        let kind = required_text(challenge, "type", 32)?;
        if kind != "http-01" && kind != "dns-01" {
            continue;
        }
        let url = required_url(challenge, "url")?;
        let token = required_text(challenge, "token", MAXIMUM_TOKEN_BYTES)?;
        if token.is_empty()
            || !token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || !identities.insert((kind.clone(), url.clone()))
        {
            return Err(AcmeProtocolError::InvalidResponse);
        }
        parsed.push(AcmeChallengeRecord {
            kind,
            url,
            token,
            status: parse_challenge_status(required_text(challenge, "status", 32)?.as_str())?,
        });
    }
    if parsed.is_empty() {
        return Err(AcmeProtocolError::UnsupportedChallenge);
    }
    Ok(AcmeAuthorization {
        dns_name,
        wildcard,
        status: parse_authorization_status(required_text(&object, "status", 32)?.as_str())?,
        challenges: parsed,
    })
}

fn required_identifiers(object: &Map<String, Value>) -> Result<Vec<String>, AcmeProtocolError> {
    let values = object
        .get("identifiers")
        .and_then(Value::as_array)
        .ok_or(AcmeProtocolError::InvalidResponse)?;
    if values.is_empty() || values.len() > MAXIMUM_IDENTIFIERS {
        return Err(AcmeProtocolError::InvalidResponse);
    }
    let mut names = Vec::with_capacity(values.len());
    let mut unique = BTreeSet::new();
    for value in values {
        let identifier = value
            .as_object()
            .ok_or(AcmeProtocolError::InvalidResponse)?;
        if required_text(identifier, "type", 16)? != "dns" {
            return Err(AcmeProtocolError::InvalidResponse);
        }
        let name = required_text(identifier, "value", MAXIMUM_DNS_NAME_BYTES)?;
        if !valid_dns_name(&name) || !unique.insert(name.clone()) {
            return Err(AcmeProtocolError::InvalidResponse);
        }
        names.push(name);
    }
    names.sort_unstable();
    Ok(names)
}

fn response_object(bytes: &[u8]) -> Result<Map<String, Value>, AcmeProtocolError> {
    let value = crate::strict_json::from_slice(bytes)?;
    let object = value
        .as_object()
        .ok_or(AcmeProtocolError::InvalidResponse)?;
    Ok(object.clone())
}

fn required_text(
    object: &Map<String, Value>,
    name: &str,
    maximum: usize,
) -> Result<String, AcmeProtocolError> {
    let value = object
        .get(name)
        .and_then(Value::as_str)
        .ok_or(AcmeProtocolError::InvalidResponse)?;
    if value.is_empty() || value.len() > maximum {
        Err(AcmeProtocolError::InvalidResponse)
    } else {
        Ok(value.to_owned())
    }
}

fn optional_text(
    object: &Map<String, Value>,
    name: &str,
    maximum: usize,
) -> Result<Option<String>, AcmeProtocolError> {
    match object.get(name) {
        None => Ok(None),
        Some(Value::String(value)) if value.len() <= maximum => Ok(Some(value.clone())),
        _ => Err(AcmeProtocolError::InvalidResponse),
    }
}

fn required_url(object: &Map<String, Value>, name: &str) -> Result<String, AcmeProtocolError> {
    let value = required_text(object, name, MAXIMUM_URL_BYTES)?;
    bounded_url(&value)?;
    Ok(value)
}

fn optional_url(
    object: &Map<String, Value>,
    name: &str,
) -> Result<Option<String>, AcmeProtocolError> {
    optional_text(object, name, MAXIMUM_URL_BYTES)?
        .map(|value| {
            bounded_url(&value)?;
            Ok(value)
        })
        .transpose()
}

fn required_url_array(
    object: &Map<String, Value>,
    name: &str,
    maximum: usize,
) -> Result<Vec<String>, AcmeProtocolError> {
    let values = object
        .get(name)
        .and_then(Value::as_array)
        .ok_or(AcmeProtocolError::InvalidResponse)?;
    if values.is_empty() || values.len() > maximum {
        return Err(AcmeProtocolError::InvalidResponse);
    }
    let mut result = Vec::with_capacity(values.len());
    let mut unique = BTreeSet::new();
    for value in values {
        let value = value.as_str().ok_or(AcmeProtocolError::InvalidResponse)?;
        bounded_url(value)?;
        if !unique.insert(value) {
            return Err(AcmeProtocolError::InvalidResponse);
        }
        result.push(value.to_owned());
    }
    Ok(result)
}

fn parse_order_status(value: &str) -> Result<AcmeResourceStatus, AcmeProtocolError> {
    match value {
        "pending" => Ok(AcmeResourceStatus::Pending),
        "processing" => Ok(AcmeResourceStatus::Processing),
        "valid" => Ok(AcmeResourceStatus::Valid),
        "invalid" => Ok(AcmeResourceStatus::Invalid),
        "ready" => Ok(AcmeResourceStatus::Ready),
        _ => Err(AcmeProtocolError::InvalidResponse),
    }
}

fn parse_authorization_status(value: &str) -> Result<AcmeResourceStatus, AcmeProtocolError> {
    match value {
        "pending" => Ok(AcmeResourceStatus::Pending),
        "valid" => Ok(AcmeResourceStatus::Valid),
        "invalid" => Ok(AcmeResourceStatus::Invalid),
        "deactivated" => Ok(AcmeResourceStatus::Deactivated),
        "expired" => Ok(AcmeResourceStatus::Expired),
        "revoked" => Ok(AcmeResourceStatus::Revoked),
        _ => Err(AcmeProtocolError::InvalidResponse),
    }
}

fn parse_challenge_status(value: &str) -> Result<AcmeResourceStatus, AcmeProtocolError> {
    match value {
        "pending" => Ok(AcmeResourceStatus::Pending),
        "processing" => Ok(AcmeResourceStatus::Processing),
        "valid" => Ok(AcmeResourceStatus::Valid),
        "invalid" => Ok(AcmeResourceStatus::Invalid),
        _ => Err(AcmeProtocolError::InvalidResponse),
    }
}

fn require_existing_account(binding: &AcmeAccountBinding) -> Result<(), AcmeProtocolError> {
    if matches!(binding, AcmeAccountBinding::ExistingAccount(_)) {
        Ok(())
    } else {
        Err(AcmeProtocolError::InvalidRequest)
    }
}

fn require_status(response: &AcmeHttpResponse, allowed: &[u16]) -> Result<(), AcmeProtocolError> {
    if allowed.contains(&response.status) {
        Ok(())
    } else {
        Err(AcmeProtocolError::UnexpectedStatus(response.status))
    }
}

pub(crate) fn bounded_url(value: &str) -> Result<(), AcmeProtocolError> {
    let remainder = value
        .strip_prefix("https://")
        .ok_or(AcmeProtocolError::InvalidResponse)?;
    let authority = remainder
        .split(['/', '?'])
        .next()
        .ok_or(AcmeProtocolError::InvalidResponse)?;
    if value.len() > MAXIMUM_URL_BYTES
        || authority.contains('@')
        || value.contains('#')
        || value.contains('\\')
        || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
        || !valid_authority(authority)
    {
        Err(AcmeProtocolError::InvalidResponse)
    } else {
        Ok(())
    }
}

fn valid_authority(authority: &str) -> bool {
    if let Some(bracketed) = authority.strip_prefix('[') {
        let Some((address, suffix)) = bracketed.split_once(']') else {
            return false;
        };
        return !address.is_empty()
            && address.parse::<Ipv6Addr>().is_ok()
            && (suffix.is_empty() || suffix.strip_prefix(':').is_some_and(valid_port));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => {
            if host.contains(':') {
                return false;
            }
            (host, Some(port))
        }
        None => (authority, None),
    };
    !host.is_empty()
        && port.is_none_or(valid_port)
        && (host.parse::<Ipv4Addr>().is_ok() || valid_host_name(host))
}

fn valid_port(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<u16>().is_ok_and(|port| port != 0)
}

fn valid_host_name(value: &str) -> bool {
    value.len() <= MAXIMUM_DNS_NAME_BYTES
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn valid_dns_name(value: &str) -> bool {
    let name = value.strip_prefix("*.").unwrap_or(value);
    !name.is_empty()
        && value.len() <= MAXIMUM_DNS_NAME_BYTES
        && name.contains('.')
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.' | b'*')
        })
}

pub(crate) fn encode_base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        encoded.push(char::from(ALPHABET[usize::from(first >> 2)]));
        let second_index = (first & 0x03) << 4 | chunk.get(1).copied().unwrap_or(0) >> 4;
        encoded.push(char::from(ALPHABET[usize::from(second_index)]));
        if let Some(second) = chunk.get(1).copied() {
            let third_index = (second & 0x0f) << 2 | chunk.get(2).copied().unwrap_or(0) >> 6;
            encoded.push(char::from(ALPHABET[usize::from(third_index)]));
        }
        if let Some(third) = chunk.get(2).copied() {
            encoded.push(char::from(ALPHABET[usize::from(third & 0x3f)]));
        }
    }
    encoded
}

/// Closed protocol-boundary failure.
#[derive(Debug, Error)]
pub enum AcmeProtocolError {
    /// Locally constructed request is invalid.
    #[error("ACME request is invalid")]
    InvalidRequest,
    /// Untrusted response violates the bounded ACME contract.
    #[error("ACME response is invalid")]
    InvalidResponse,
    /// Input exceeds a fixed protocol bound.
    #[error("ACME protocol capacity exceeded")]
    CapacityExceeded,
    /// The server returned an HTTP status not valid for this transition.
    #[error("ACME server returned unexpected HTTP status {0}")]
    UnexpectedStatus(u16),
    /// No supported challenge was offered.
    #[error("ACME authorization offers no supported challenge")]
    UnsupportedChallenge,
    /// The sole permitted fresh-nonce retry has already been consumed.
    #[error("ACME bad-nonce retry is exhausted")]
    RetryExhausted,
    /// Account signer output is invalid or unavailable.
    #[error("ACME account signer failed closed")]
    InvalidSigner,
    /// JSON input or output failed the closed wire shape.
    #[error("ACME JSON processing failed closed")]
    Json(#[from] serde_json::Error),
}
