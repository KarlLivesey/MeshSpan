// SPDX-License-Identifier: GPL-2.0-only

//! Closed challenge payloads shared by the order worker and challenge implementations.

use meshspan_contracts::{BoundedBytes, VersionedPayload};
const FORMAT_VERSION: u32 = 1;
const MAXIMUM_TOKEN_BYTES: usize = 128;
const MAXIMUM_KEY_AUTHORIZATION_BYTES: usize = 512;
const MAXIMUM_DNS_NAME_BYTES: usize = 253;
const MAXIMUM_DNS_VALUE_BYTES: usize = 512;
const MAXIMUM_PAYLOAD_BYTES: usize = 1_024;

/// Exact HTTP-01 token and key authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Http01Payload {
    token: String,
    key_authorization: Vec<u8>,
}

impl Http01Payload {
    /// Validates one base64url token and bounded ASCII key authorization.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized or non-canonical values.
    pub fn new(token: &str, key_authorization: &[u8]) -> Result<Self, PayloadError> {
        if !valid_token(token)
            || key_authorization.is_empty()
            || key_authorization.len() > MAXIMUM_KEY_AUTHORIZATION_BYTES
            || !key_authorization.is_ascii()
            || key_authorization.iter().any(u8::is_ascii_whitespace)
        {
            return Err(PayloadError::Invalid);
        }
        Ok(Self {
            token: token.to_owned(),
            key_authorization: key_authorization.to_vec(),
        })
    }

    /// Returns the exact URL-safe token.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Returns the exact response body.
    #[must_use]
    pub fn key_authorization(&self) -> &[u8] {
        &self.key_authorization
    }

    /// Encodes the canonical contract payload.
    ///
    /// # Errors
    ///
    /// Returns an error only if internal checked lengths cannot be represented.
    pub fn encode(&self) -> Result<VersionedPayload, PayloadError> {
        encode_pair(self.token.as_bytes(), &self.key_authorization)
    }

    /// Decodes and revalidates one hostile contract payload.
    ///
    /// # Errors
    ///
    /// Rejects unknown versions, malformed lengths, trailing bytes and invalid values.
    pub fn decode(value: &VersionedPayload) -> Result<Self, PayloadError> {
        let (token, key_authorization) = decode_pair(value)?;
        let token = std::str::from_utf8(token).map_err(|_| PayloadError::Invalid)?;
        Self::new(token, key_authorization)
    }
}

/// Exact DNS-01 TXT owner name and value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Dns01Payload {
    record_name: String,
    record_value: Vec<u8>,
}

impl Dns01Payload {
    /// Validates a canonical lower-case `_acme-challenge` name and bounded ASCII TXT value.
    ///
    /// # Errors
    ///
    /// Rejects malformed, empty, oversized or ambiguous values.
    pub fn new(record_name: &str, record_value: &[u8]) -> Result<Self, PayloadError> {
        if !valid_dns_record_name(record_name)
            || record_value.is_empty()
            || record_value.len() > MAXIMUM_DNS_VALUE_BYTES
            || !record_value.is_ascii()
            || record_value.iter().any(u8::is_ascii_whitespace)
        {
            return Err(PayloadError::Invalid);
        }
        Ok(Self {
            record_name: record_name.to_owned(),
            record_value: record_value.to_vec(),
        })
    }

    /// Returns the canonical TXT owner name.
    #[must_use]
    pub fn record_name(&self) -> &str {
        &self.record_name
    }

    /// Returns the exact TXT value bytes.
    #[must_use]
    pub fn record_value(&self) -> &[u8] {
        &self.record_value
    }

    /// Encodes the canonical contract payload.
    ///
    /// # Errors
    ///
    /// Returns an error only if internal checked lengths cannot be represented.
    pub fn encode(&self) -> Result<VersionedPayload, PayloadError> {
        encode_pair(self.record_name.as_bytes(), &self.record_value)
    }

    /// Decodes and revalidates one hostile contract payload.
    ///
    /// # Errors
    ///
    /// Rejects unknown versions, malformed lengths, trailing bytes and invalid values.
    pub fn decode(value: &VersionedPayload) -> Result<Self, PayloadError> {
        let (name, record_value) = decode_pair(value)?;
        let name = std::str::from_utf8(name).map_err(|_| PayloadError::Invalid)?;
        Self::new(name, record_value)
    }
}

fn encode_pair(first: &[u8], second: &[u8]) -> Result<VersionedPayload, PayloadError> {
    let first_length = u16::try_from(first.len()).map_err(|_| PayloadError::Invalid)?;
    let second_length = u16::try_from(second.len()).map_err(|_| PayloadError::Invalid)?;
    let mut bytes = Vec::with_capacity(4 + first.len() + second.len());
    bytes.extend_from_slice(&first_length.to_be_bytes());
    bytes.extend_from_slice(first);
    bytes.extend_from_slice(&second_length.to_be_bytes());
    bytes.extend_from_slice(second);
    Ok(VersionedPayload {
        format_version: FORMAT_VERSION,
        bytes: BoundedBytes::from_vec(bytes, MAXIMUM_PAYLOAD_BYTES)
            .map_err(|_| PayloadError::Invalid)?,
    })
}

fn decode_pair(value: &VersionedPayload) -> Result<(&[u8], &[u8]), PayloadError> {
    if value.format_version != FORMAT_VERSION || value.bytes.len() > MAXIMUM_PAYLOAD_BYTES {
        return Err(PayloadError::Invalid);
    }
    let bytes = value.bytes.as_slice();
    let first_length = read_length(bytes, 0)?;
    let first_start = 2;
    let first_end = first_start + first_length;
    let second_length = read_length(bytes, first_end)?;
    let second_start = first_end + 2;
    let second_end = second_start + second_length;
    if second_end != bytes.len() {
        return Err(PayloadError::Invalid);
    }
    Ok((
        &bytes[first_start..first_end],
        &bytes[second_start..second_end],
    ))
}

fn read_length(bytes: &[u8], offset: usize) -> Result<usize, PayloadError> {
    let encoded: [u8; 2] = bytes
        .get(offset..offset + 2)
        .ok_or(PayloadError::Invalid)?
        .try_into()
        .map_err(|_| PayloadError::Invalid)?;
    let length = usize::from(u16::from_be_bytes(encoded));
    if offset + 2 + length <= bytes.len() {
        Ok(length)
    } else {
        Err(PayloadError::Invalid)
    }
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAXIMUM_TOKEN_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_dns_record_name(value: &str) -> bool {
    value.starts_with("_acme-challenge.")
        && value.len() <= MAXIMUM_DNS_NAME_BYTES
        && value.is_ascii()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
        && value
            .split('.')
            .all(|label| !label.is_empty() && label.len() <= 63)
}

/// Closed challenge-payload validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayloadError {
    /// The payload is malformed, ambiguous or outside its explicit bounds.
    Invalid,
}

impl std::fmt::Display for PayloadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ACME challenge payload is invalid")
    }
}

impl std::error::Error for PayloadError {}

#[cfg(test)]
mod tests {
    use super::{Dns01Payload, Http01Payload};

    #[test]
    fn payloads_round_trip_and_reject_ambiguous_tokens() -> Result<(), Box<dyn std::error::Error>> {
        let http = Http01Payload::new("abc_DEF-123", b"abc_DEF-123.thumbprint")?;
        assert_eq!(Http01Payload::decode(&http.encode()?)?, http);
        assert!(Http01Payload::new("../escape", b"x").is_err());
        let dns = Dns01Payload::new("_acme-challenge.files.example.test", b"txt-value")?;
        assert_eq!(Dns01Payload::decode(&dns.encode()?)?, dns);
        assert!(Dns01Payload::new("_acme-challenge..example.test", b"x").is_err());
        Ok(())
    }
}
