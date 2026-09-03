// SPDX-License-Identifier: GPL-2.0-only

//! Canonical bounded ACME JWS construction around a non-exporting account signer.

use serde_json::{Map, Value};

use crate::wire::{AcmeProtocolError, bounded_url, encode_base64url};

const MAXIMUM_NONCE_BYTES: usize = 512;
const MAXIMUM_KEY_ID_BYTES: usize = 2_048;
const MAXIMUM_PAYLOAD_BYTES: usize = 1024 * 1024;
const MAXIMUM_SIGNED_BODY_BYTES: usize = 1_500_000;
const ES256_SIGNATURE_BYTES: usize = 64;

/// Whether an ACME request identifies a new account by key or an existing account by URL.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AcmeAccountBinding {
    /// Initial account request using the signing key's own ES256 public JWK.
    NewAccount,
    /// Existing account URL returned by the ACME server.
    ExistingAccount(String),
}

/// Canonical public half of one protected ES256 ACME account key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcmePublicJwk {
    x: String,
    y: String,
}

impl AcmePublicJwk {
    /// Validates canonical unpadded base64url P-256 coordinates.
    ///
    /// # Errors
    ///
    /// Rejects malformed or non-canonical coordinate encodings.
    pub fn new(x: String, y: String) -> Result<Self, AcmeProtocolError> {
        validate_coordinate(&x)?;
        validate_coordinate(&y)?;
        Ok(Self { x, y })
    }
}

/// Non-exporting signer for one ACME account generation.
pub trait AcmeJwsSigner: Send + Sync {
    /// Returns the public JWK belonging to the protected private signing key.
    ///
    /// # Errors
    ///
    /// Fails closed when the signer cannot prove a canonical ES256 public identity.
    fn public_jwk(&self) -> Result<AcmePublicJwk, AcmeProtocolError>;

    /// Signs the exact ASCII `protected.payload` input and returns raw JOSE signature bytes.
    ///
    /// # Errors
    ///
    /// Fails closed when the protected account key cannot sign the input.
    fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, AcmeProtocolError>;
}

/// Complete `application/jose+json` request body and its target resource URL.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcmeSignedRequest {
    /// Exact HTTPS ACME resource URL.
    pub url: String,
    /// Canonical bounded JWS JSON body.
    pub body: Vec<u8>,
}

impl AcmeSignedRequest {
    pub(crate) fn create<S: AcmeJwsSigner>(
        url: &str,
        nonce: &str,
        binding: &AcmeAccountBinding,
        payload: &[u8],
        signer: &S,
    ) -> Result<Self, AcmeProtocolError> {
        bounded_url(url)?;
        validate_nonce(nonce)?;
        if payload.len() > MAXIMUM_PAYLOAD_BYTES {
            return Err(AcmeProtocolError::CapacityExceeded);
        }
        let protected = protected_header(url, nonce, binding, signer)?;
        let protected = encode_base64url(&serde_json::to_vec(&protected)?);
        let payload = encode_base64url(payload);
        let signing_input = format!("{protected}.{payload}");
        let signature = signer.sign(signing_input.as_bytes())?;
        if signature.len() != ES256_SIGNATURE_BYTES {
            return Err(AcmeProtocolError::InvalidSigner);
        }
        let mut body = Map::new();
        body.insert("payload".to_owned(), Value::String(payload));
        body.insert("protected".to_owned(), Value::String(protected));
        body.insert(
            "signature".to_owned(),
            Value::String(encode_base64url(&signature)),
        );
        let body = serde_json::to_vec(&Value::Object(body))?;
        if body.len() > MAXIMUM_SIGNED_BODY_BYTES {
            return Err(AcmeProtocolError::CapacityExceeded);
        }
        Ok(Self {
            url: url.to_owned(),
            body,
        })
    }
}

fn protected_header(
    url: &str,
    nonce: &str,
    binding: &AcmeAccountBinding,
    signer: &impl AcmeJwsSigner,
) -> Result<Value, AcmeProtocolError> {
    let mut header = Map::new();
    header.insert("alg".to_owned(), Value::String("ES256".to_owned()));
    match binding {
        AcmeAccountBinding::NewAccount => {
            let public = signer.public_jwk()?;
            let mut jwk = Map::new();
            jwk.insert("crv".to_owned(), Value::String("P-256".to_owned()));
            jwk.insert("kty".to_owned(), Value::String("EC".to_owned()));
            jwk.insert("x".to_owned(), Value::String(public.x));
            jwk.insert("y".to_owned(), Value::String(public.y));
            header.insert("jwk".to_owned(), Value::Object(jwk));
        }
        AcmeAccountBinding::ExistingAccount(key_id) => {
            if key_id.len() > MAXIMUM_KEY_ID_BYTES {
                return Err(AcmeProtocolError::CapacityExceeded);
            }
            bounded_url(key_id)?;
            header.insert("kid".to_owned(), Value::String(key_id.clone()));
        }
    }
    header.insert("nonce".to_owned(), Value::String(nonce.to_owned()));
    header.insert("url".to_owned(), Value::String(url.to_owned()));
    Ok(Value::Object(header))
}

fn validate_nonce(value: &str) -> Result<(), AcmeProtocolError> {
    if value.is_empty()
        || value.len() > MAXIMUM_NONCE_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        Err(AcmeProtocolError::InvalidResponse)
    } else {
        Ok(())
    }
}

fn validate_coordinate(value: &str) -> Result<(), AcmeProtocolError> {
    if value.len() != 43
        || value.ends_with('=')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || !matches!(value.as_bytes().last(), Some(b'A' | b'Q' | b'g' | b'w'))
    {
        Err(AcmeProtocolError::InvalidSigner)
    } else {
        Ok(())
    }
}
