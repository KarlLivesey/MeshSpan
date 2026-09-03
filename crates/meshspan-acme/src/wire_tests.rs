// SPDX-License-Identifier: GPL-2.0-only

use std::sync::Mutex;

use serde_json::{Value, json};

use crate::{
    AcmeAccountBinding, AcmeBadNonceRetry, AcmeHttpResponse, AcmeJwsSigner, AcmeOrderRequest,
    AcmeProtocolError, AcmePublicJwk, AcmeResourceStatus, AcmeResponseHeaders, AcmeWire,
};

#[test]
fn directory_headers_and_problem_documents_reject_ambiguity()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = response(
        200,
        vec![("replay-nonce", "nonce_1")],
        serde_json::to_vec(&json!({
            "newNonce": "https://ca.example.test/new-nonce",
            "newAccount": "https://ca.example.test/new-account",
            "newOrder": "https://ca.example.test/new-order",
            "newAuthz": "https://ca.example.test/extension"
        }))?,
    )?;
    let parsed = AcmeWire::directory(&directory)?;
    assert_eq!(parsed.new_nonce, "https://ca.example.test/new-nonce");
    assert_eq!(AcmeWire::replay_nonce(&directory)?, "nonce_1");

    let duplicate_header = response(
        204,
        vec![("replay-nonce", "first"), ("replay-nonce", "second")],
        Vec::new(),
    )?;
    assert!(matches!(
        AcmeWire::replay_nonce(&duplicate_header),
        Err(AcmeProtocolError::InvalidResponse)
    ));
    let duplicate_json = br#"{
        "newNonce":"https://ca.example.test/one",
        "newNonce":"https://ca.example.test/two",
        "newAccount":"https://ca.example.test/account",
        "newOrder":"https://ca.example.test/order"
    }"#;
    assert!(AcmeWire::directory(&response(200, vec![], duplicate_json.to_vec())?).is_err());

    let problem = response(
        400,
        vec![("replay-nonce", "nonce_2")],
        serde_json::to_vec(&json!({
            "type": "urn:ietf:params:acme:error:badNonce",
            "detail": "nonce was already consumed",
            "status": 400
        }))?,
    )?;
    let problem_document = AcmeWire::problem(&problem)?;
    assert!(problem_document.is_bad_nonce());
    let mut retry = AcmeBadNonceRetry::default();
    assert_eq!(
        retry.consume(&problem_document, &problem)?,
        Some("nonce_2".to_owned())
    );
    assert!(matches!(
        retry.consume(&problem_document, &problem),
        Err(AcmeProtocolError::RetryExhausted)
    ));
    Ok(())
}

#[test]
fn base64url_encoding_matches_rfc_4648_unpadded_vectors() {
    for (plain, encoded) in [
        (b"".as_slice(), ""),
        (b"f".as_slice(), "Zg"),
        (b"fo".as_slice(), "Zm8"),
        (b"foo".as_slice(), "Zm9v"),
        (b"foob".as_slice(), "Zm9vYg"),
        (b"fooba".as_slice(), "Zm9vYmE"),
        (b"foobar".as_slice(), "Zm9vYmFy"),
    ] {
        assert_eq!(crate::wire::encode_base64url(plain), encoded);
    }
}

#[test]
fn signed_order_request_binds_nonce_url_account_and_exact_names()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = RecordingSigner::default();
    let binding =
        AcmeAccountBinding::ExistingAccount("https://ca.example.test/accounts/7".to_owned());
    let order = AcmeOrderRequest::new(vec![
        "files.example.test".to_owned(),
        "www.example.test".to_owned(),
    ])?;
    let jose_request = AcmeWire::new_order(
        "https://ca.example.test/new-order",
        "nonce_3",
        &binding,
        &order,
        &signer,
    )?;
    let body: Value = serde_json::from_slice(&jose_request.body)?;
    let protected = decode_json_field(&body, "protected")?;
    assert_eq!(protected["alg"], "ES256");
    assert_eq!(protected["nonce"], "nonce_3");
    assert_eq!(protected["url"], "https://ca.example.test/new-order");
    assert_eq!(protected["kid"], "https://ca.example.test/accounts/7");
    assert!(protected.get("jwk").is_none());
    let payload = decode_json_field(&body, "payload")?;
    assert_eq!(
        payload,
        json!({
            "identifiers": [
                { "type": "dns", "value": "files.example.test" },
                { "type": "dns", "value": "www.example.test" }
            ]
        })
    );
    let signing_input = signer.input.lock().map_err(|_| "signer mutex poisoned")?;
    let expected = format!(
        "{}.{}",
        body["protected"].as_str().ok_or("protected missing")?,
        body["payload"].as_str().ok_or("payload missing")?
    );
    assert_eq!(signing_input.as_slice(), expected.as_bytes());
    Ok(())
}

#[test]
fn new_account_uses_the_signers_public_key_and_never_a_key_id()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = RecordingSigner::default();
    let request = AcmeWire::new_account(
        "https://ca.example.test/new-account",
        "nonce_account",
        &signer,
    )?;
    let body: Value = serde_json::from_slice(&request.body)?;
    let protected = decode_json_field(&body, "protected")?;
    assert!(protected.get("kid").is_none());
    assert_eq!(
        protected["jwk"],
        json!({
            "crv": "P-256",
            "kty": "EC",
            "x": "A".repeat(43),
            "y": "Q".repeat(43)
        })
    );
    assert_eq!(
        decode_json_field(&body, "payload")?,
        json!({ "termsOfServiceAgreed": true })
    );
    Ok(())
}

#[test]
fn urls_require_a_bounded_https_authority() {
    for valid in [
        "https://ca.example.test/path",
        "https://localhost:14000/directory",
        "https://127.0.0.1:443/order",
        "https://[::1]:14000/order",
    ] {
        assert!(crate::wire::bounded_url(valid).is_ok(), "{valid}");
    }
    for invalid in [
        "http://ca.example.test/order",
        "https://",
        "https://:",
        "https://ca.example.test:0/order",
        "https://ca.example.test:65536/order",
        "https://user@ca.example.test/order",
        "https://bad..example/order",
        "https://[not-ipv6]/order",
        "https://ca.example.test/order#fragment",
    ] {
        assert!(crate::wire::bounded_url(invalid).is_err(), "{invalid}");
    }
}

#[test]
fn order_and_authorization_parse_only_bounded_supported_resources()
-> Result<(), Box<dyn std::error::Error>> {
    let order = response(
        201,
        vec![("location", "https://ca.example.test/orders/1")],
        serde_json::to_vec(&json!({
            "status": "pending",
            "identifiers": [{ "type": "dns", "value": "files.example.test" }],
            "authorizations": ["https://ca.example.test/authz/1"],
            "finalize": "https://ca.example.test/orders/1/finalize",
            "extension": { "ignored": true }
        }))?,
    )?;
    let parsed = AcmeWire::order(&order)?;
    assert_eq!(parsed.status, AcmeResourceStatus::Pending);
    assert_eq!(parsed.dns_names, ["files.example.test"]);
    assert_eq!(parsed.authorizations.len(), 1);
    assert!(parsed.certificate.is_none());

    let authorization = response(
        200,
        vec![("replay-nonce", "nonce_4")],
        serde_json::to_vec(&json!({
            "identifier": { "type": "dns", "value": "files.example.test" },
            "status": "pending",
            "challenges": [
                {
                    "type": "tls-alpn-01",
                    "url": "https://ca.example.test/challenge/unsupported",
                    "token": "unsupported",
                    "status": "pending"
                },
                {
                    "type": "http-01",
                    "url": "https://ca.example.test/challenge/http",
                    "token": "token_1",
                    "status": "pending",
                    "extension": "ignored"
                }
            ]
        }))?,
    )?;
    let parsed = AcmeWire::authorization(&authorization)?;
    assert_eq!(parsed.dns_name, "files.example.test");
    assert_eq!(parsed.challenges.len(), 1);
    assert_eq!(parsed.challenges[0].kind, "http-01");

    let invalid_valid_order = response(
        200,
        vec![],
        serde_json::to_vec(&json!({
            "status": "valid",
            "identifiers": [{ "type": "dns", "value": "files.example.test" }],
            "authorizations": ["https://ca.example.test/authz/1"],
            "finalize": "https://ca.example.test/orders/1/finalize"
        }))?,
    )?;
    assert!(matches!(
        AcmeWire::order(&invalid_valid_order),
        Err(AcmeProtocolError::InvalidResponse)
    ));
    Ok(())
}

fn response(
    status: u16,
    headers: Vec<(&str, &str)>,
    body: Vec<u8>,
) -> Result<AcmeHttpResponse, AcmeProtocolError> {
    AcmeHttpResponse::new(
        status,
        AcmeResponseHeaders::new(
            headers
                .into_iter()
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .collect(),
        )?,
        body,
    )
}

pub(crate) fn decode_json_field(
    value: &Value,
    field: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let encoded = value
        .get(field)
        .and_then(Value::as_str)
        .ok_or("JWS field missing")?;
    Ok(serde_json::from_slice(&decode_base64url(encoded)?)?)
}

fn decode_base64url(value: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut sextets = Vec::with_capacity(value.len());
    for byte in value.bytes() {
        sextets.push(match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return Err("invalid base64url fixture".into()),
        });
    }
    let mut decoded = Vec::with_capacity(value.len() * 3 / 4);
    for chunk in sextets.chunks(4) {
        if chunk.len() < 2 {
            return Err("truncated base64url fixture".into());
        }
        decoded.push(chunk[0] << 2 | chunk[1] >> 4);
        if chunk.len() > 2 {
            decoded.push(chunk[1] << 4 | chunk[2] >> 2);
        }
        if chunk.len() > 3 {
            decoded.push(chunk[2] << 6 | chunk[3]);
        }
    }
    Ok(decoded)
}

#[derive(Default)]
struct RecordingSigner {
    input: Mutex<Vec<u8>>,
}

impl AcmeJwsSigner for RecordingSigner {
    fn public_jwk(&self) -> Result<AcmePublicJwk, AcmeProtocolError> {
        AcmePublicJwk::new("A".repeat(43), "Q".repeat(43))
    }

    fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, AcmeProtocolError> {
        *self
            .input
            .lock()
            .map_err(|_| AcmeProtocolError::InvalidSigner)? = signing_input.to_vec();
        Ok(vec![9; 64])
    }
}
