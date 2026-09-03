// SPDX-License-Identifier: GPL-2.0-only

//! Canonical bounded plaintext held only inside an encrypted DNS-provider secret generation.

use std::net::SocketAddr;

use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"MSDNS\0\0\0";
const VERSION: u8 = 1;
const RFC2136: u8 = 1;
const CLOUDFLARE: u8 = 2;
const WEBHOOK: u8 = 3;
const MAXIMUM_SETTINGS_BYTES: usize = 16 * 1_024;
const MAXIMUM_URL_BYTES: usize = 2_048;
const MAXIMUM_SECRET_BYTES: usize = 2_048;

/// Supported RFC 2136 TSIG algorithms for authenticated dynamic updates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rfc2136TsigAlgorithm {
    /// HMAC-SHA-256 as named by RFC 8945.
    HmacSha256,
    /// HMAC-SHA-512 as named by RFC 8945.
    HmacSha512,
}

/// Exact RFC 2136 endpoint, zone and protected TSIG key material.
pub struct Rfc2136DnsSettings {
    server: SocketAddr,
    zone: String,
    key_name: String,
    algorithm: Rfc2136TsigAlgorithm,
    secret: Zeroizing<Vec<u8>>,
}

impl Rfc2136DnsSettings {
    /// Creates validated dynamic-update settings without resolving or contacting the endpoint.
    ///
    /// # Errors
    ///
    /// Rejects invalid zone/key names and secrets outside the fixed bound.
    pub fn new(
        server: SocketAddr,
        zone: String,
        key_name: String,
        algorithm: Rfc2136TsigAlgorithm,
        secret: Vec<u8>,
    ) -> Result<Self, DnsProviderSettingsError> {
        if !valid_dns_name(&zone)
            || !valid_dns_name(&key_name)
            || !(16..=MAXIMUM_SECRET_BYTES).contains(&secret.len())
        {
            return Err(DnsProviderSettingsError::InvalidInput);
        }
        Ok(Self {
            server,
            zone,
            key_name,
            algorithm,
            secret: Zeroizing::new(secret),
        })
    }

    /// Returns the configured DNS update socket.
    #[must_use]
    pub const fn server(&self) -> SocketAddr {
        self.server
    }

    /// Returns the canonical zone apex.
    #[must_use]
    pub fn zone(&self) -> &str {
        &self.zone
    }

    /// Returns the canonical TSIG key name.
    #[must_use]
    pub fn key_name(&self) -> &str {
        &self.key_name
    }

    /// Returns the selected TSIG algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> Rfc2136TsigAlgorithm {
        self.algorithm
    }

    /// Borrows the TSIG secret only inside the provider implementation.
    #[must_use]
    pub fn secret(&self) -> &[u8] {
        &self.secret
    }
}

impl Drop for Rfc2136DnsSettings {
    fn drop(&mut self) {
        self.zone.zeroize();
        self.key_name.zeroize();
    }
}

/// Exact Cloudflare zone and protected API token.
pub struct CloudflareDnsSettings {
    zone_id: String,
    api_token: Zeroizing<Vec<u8>>,
}

impl CloudflareDnsSettings {
    /// Creates settings for the fixed Cloudflare v4 API origin.
    ///
    /// # Errors
    ///
    /// Rejects non-canonical zone identities and invalid or excessive API tokens.
    pub fn new(zone_id: String, api_token: Vec<u8>) -> Result<Self, DnsProviderSettingsError> {
        if !valid_cloudflare_zone_id(&zone_id)
            || !(16..=MAXIMUM_SECRET_BYTES).contains(&api_token.len())
            || !api_token.is_ascii()
        {
            return Err(DnsProviderSettingsError::InvalidInput);
        }
        Ok(Self {
            zone_id,
            api_token: Zeroizing::new(api_token),
        })
    }

    /// Returns the provider zone identity.
    #[must_use]
    pub fn zone_id(&self) -> &str {
        &self.zone_id
    }

    /// Borrows the API token only inside the provider implementation.
    #[must_use]
    pub fn api_token(&self) -> &[u8] {
        &self.api_token
    }
}

impl Drop for CloudflareDnsSettings {
    fn drop(&mut self) {
        self.zone_id.zeroize();
    }
}

/// Exact allow-listed HTTPS webhook endpoint and protected bearer token.
pub struct WebhookDnsSettings {
    endpoint: String,
    bearer_token: Zeroizing<Vec<u8>>,
}

impl WebhookDnsSettings {
    /// Creates authenticated webhook settings without contacting the endpoint.
    ///
    /// # Errors
    ///
    /// Rejects non-HTTPS endpoints and invalid or excessive bearer tokens.
    pub fn new(endpoint: String, bearer_token: Vec<u8>) -> Result<Self, DnsProviderSettingsError> {
        if !valid_https_url(&endpoint)
            || !(16..=MAXIMUM_SECRET_BYTES).contains(&bearer_token.len())
            || !bearer_token.is_ascii()
        {
            return Err(DnsProviderSettingsError::InvalidInput);
        }
        Ok(Self {
            endpoint,
            bearer_token: Zeroizing::new(bearer_token),
        })
    }

    /// Returns the exact configured HTTPS endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Borrows the bearer token only inside the provider implementation.
    #[must_use]
    pub fn bearer_token(&self) -> &[u8] {
        &self.bearer_token
    }
}

impl Drop for WebhookDnsSettings {
    fn drop(&mut self) {
        self.endpoint.zeroize();
    }
}

/// One decoded automatic DNS-01 provider configuration.
pub enum DnsProviderSettings {
    /// Authenticated RFC 2136 dynamic DNS update.
    Rfc2136(Rfc2136DnsSettings),
    /// Cloudflare DNS API scoped to one zone.
    Cloudflare(CloudflareDnsSettings),
    /// Explicit authenticated HTTPS automation endpoint.
    Webhook(WebhookDnsSettings),
}

impl DnsProviderSettings {
    /// Encodes one canonical versioned secret payload.
    ///
    /// # Errors
    ///
    /// Rejects any value whose encoded size exceeds the encrypted-settings bound.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, DnsProviderSettingsError> {
        let mut output = Zeroizing::new(Vec::with_capacity(256));
        output.extend_from_slice(MAGIC);
        output.push(VERSION);
        match self {
            Self::Rfc2136(settings) => {
                output.push(RFC2136);
                field(&mut output, settings.server.to_string().as_bytes())?;
                field(&mut output, settings.zone.as_bytes())?;
                field(&mut output, settings.key_name.as_bytes())?;
                output.push(match settings.algorithm {
                    Rfc2136TsigAlgorithm::HmacSha256 => 1,
                    Rfc2136TsigAlgorithm::HmacSha512 => 2,
                });
                field(&mut output, &settings.secret)?;
            }
            Self::Cloudflare(settings) => {
                output.push(CLOUDFLARE);
                field(&mut output, settings.zone_id.as_bytes())?;
                field(&mut output, &settings.api_token)?;
            }
            Self::Webhook(settings) => {
                output.push(WEBHOOK);
                field(&mut output, settings.endpoint.as_bytes())?;
                field(&mut output, &settings.bearer_token)?;
            }
        }
        if output.len() > MAXIMUM_SETTINGS_BYTES {
            return Err(DnsProviderSettingsError::Capacity);
        }
        Ok(output)
    }

    /// Decodes an exact canonical payload while copying secrets only into zeroising storage.
    ///
    /// # Errors
    ///
    /// Rejects unknown versions/providers, truncation, trailing bytes and invalid fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, DnsProviderSettingsError> {
        if bytes.len() < MAGIC.len() + 2 || bytes.len() > MAXIMUM_SETTINGS_BYTES {
            return Err(DnsProviderSettingsError::InvalidEncoding);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.take(MAGIC.len())? != MAGIC || decoder.byte()? != VERSION {
            return Err(DnsProviderSettingsError::InvalidEncoding);
        }
        let settings = match decoder.byte()? {
            RFC2136 => decode_rfc2136(&mut decoder)?,
            CLOUDFLARE => decode_cloudflare(&mut decoder)?,
            WEBHOOK => decode_webhook(&mut decoder)?,
            _ => return Err(DnsProviderSettingsError::InvalidEncoding),
        };
        if !decoder.finished() {
            return Err(DnsProviderSettingsError::InvalidEncoding);
        }
        Ok(settings)
    }
}

fn decode_rfc2136(
    decoder: &mut Decoder<'_>,
) -> Result<DnsProviderSettings, DnsProviderSettingsError> {
    let server = text(decoder.field()?)?
        .parse()
        .map_err(|_| DnsProviderSettingsError::InvalidInput)?;
    let zone = text(decoder.field()?)?;
    let key_name = text(decoder.field()?)?;
    let algorithm = match decoder.byte()? {
        1 => Rfc2136TsigAlgorithm::HmacSha256,
        2 => Rfc2136TsigAlgorithm::HmacSha512,
        _ => return Err(DnsProviderSettingsError::InvalidEncoding),
    };
    let secret = decoder.field()?.to_vec();
    Ok(DnsProviderSettings::Rfc2136(Rfc2136DnsSettings::new(
        server, zone, key_name, algorithm, secret,
    )?))
}

fn decode_cloudflare(
    decoder: &mut Decoder<'_>,
) -> Result<DnsProviderSettings, DnsProviderSettingsError> {
    Ok(DnsProviderSettings::Cloudflare(CloudflareDnsSettings::new(
        text(decoder.field()?)?,
        decoder.field()?.to_vec(),
    )?))
}

fn decode_webhook(
    decoder: &mut Decoder<'_>,
) -> Result<DnsProviderSettings, DnsProviderSettingsError> {
    Ok(DnsProviderSettings::Webhook(WebhookDnsSettings::new(
        text(decoder.field()?)?,
        decoder.field()?.to_vec(),
    )?))
}

fn field(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), DnsProviderSettingsError> {
    let length = u16::try_from(bytes.len()).map_err(|_| DnsProviderSettingsError::Capacity)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn text(bytes: &[u8]) -> Result<String, DnsProviderSettingsError> {
    String::from_utf8(bytes.to_vec()).map_err(|_| DnsProviderSettingsError::InvalidEncoding)
}

fn valid_dns_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.is_ascii()
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

fn valid_cloudflare_zone_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_https_url(value: &str) -> bool {
    value.starts_with("https://")
        && value.len() > "https://".len()
        && value.len() <= MAXIMUM_URL_BYTES
        && !value.contains('#')
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn byte(&mut self) -> Result<u8, DnsProviderSettingsError> {
        Ok(self.take(1)?[0])
    }

    fn field(&mut self) -> Result<&'a [u8], DnsProviderSettingsError> {
        let length_bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| DnsProviderSettingsError::InvalidEncoding)?;
        self.take(usize::from(u16::from_be_bytes(length_bytes)))
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], DnsProviderSettingsError> {
        let end = self
            .offset
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(DnsProviderSettingsError::InvalidEncoding)?;
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    const fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

/// Closed settings failure without secret bytes or provider diagnostics.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DnsProviderSettingsError {
    /// A semantic field is invalid or outside its fixed provider policy.
    #[error("DNS provider settings are invalid")]
    InvalidInput,
    /// The versioned settings payload is malformed, unknown or non-canonical.
    #[error("DNS provider settings encoding is invalid")]
    InvalidEncoding,
    /// The encoded settings exceed their fixed encrypted-secret limit.
    #[error("DNS provider settings exceed capacity")]
    Capacity,
}
