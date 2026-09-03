// SPDX-License-Identifier: GPL-2.0-only

//! Public administrator models for automatic public-certificate provisioning.

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::OperationId;

macro_rules! public_identifier {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
        #[serde(transparent)]
        pub struct $name(
            #[schemars(
                length(equal = 36),
                pattern(
                    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
                )
            )]
            String,
        );

        impl $name {
            /// Constructs canonical UUID text from validated versioned UUID bytes.
            #[must_use]
            pub fn from_uuid_bytes(value: [u8; 16]) -> Option<Self> {
                let version = value[6] >> 4;
                if !(1..=8).contains(&version) || value[8] >> 6 != 2 {
                    return None;
                }
                Some(Self(crate::model::format_uuid(value)))
            }
        }
    };
}

public_identifier!(
    AcmeConfigurationId,
    "Stable identity of one immutable public-certificate configuration."
);
public_identifier!(
    CertificateOrderId,
    "Stable identity of one durable public-certificate order."
);

/// Sensitive text accepted once and encrypted before authoritative persistence.
#[derive(Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ProtectedText(
    #[schemars(length(min = 16, max = 2_048), pattern(r"^[\x21-\x7e]+$"))] String,
);

impl ProtectedText {
    /// Moves the value into zeroising storage without retaining another plaintext copy.
    #[must_use]
    pub fn into_bytes(mut self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(std::mem::take(&mut self.0).into_bytes())
    }
}

impl fmt::Debug for ProtectedText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProtectedText([redacted])")
    }
}

impl Drop for ProtectedText {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Supported RFC 2136 TSIG algorithms.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Rfc2136TsigAlgorithm {
    /// HMAC-SHA-256.
    HmacSha256,
    /// HMAC-SHA-512.
    HmacSha512,
}

/// Exact HTTP-01 or DNS-01 execution configuration.
#[derive(Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "kind")]
pub enum CertificateChallenge {
    /// Serve challenges through every eligible embedded HTTP gateway.
    Http01,
    /// Surface durable publish/remove tasks to the administrator.
    Dns01Manual,
    /// Publish through an authenticated RFC 2136 dynamic-DNS server.
    Dns01Rfc2136 {
        /// Literal DNS server socket address, including port.
        #[schemars(length(min = 3, max = 128))]
        server: String,
        /// Canonical lower-case zone apex.
        #[schemars(length(min = 1, max = 253))]
        zone: String,
        /// Canonical lower-case TSIG key name.
        #[schemars(length(min = 1, max = 253))]
        key_name: String,
        /// TSIG HMAC family.
        algorithm: Rfc2136TsigAlgorithm,
        /// Raw printable TSIG secret supplied by the administrator.
        secret: ProtectedText,
    },
    /// Publish through the Cloudflare v4 DNS API.
    Dns01Cloudflare {
        /// Exact 32-character lower-case hexadecimal Cloudflare zone identity.
        #[schemars(length(equal = 32), pattern(r"^[0-9a-f]{32}$"))]
        zone_id: String,
        /// Scoped Cloudflare API token.
        api_token: ProtectedText,
    },
    /// Publish through an administrator-selected authenticated HTTPS webhook.
    Dns01Webhook {
        /// HTTPS webhook endpoint.
        #[schemars(length(min = 9, max = 2_048), pattern(r"^https://"))]
        endpoint: String,
        /// Bearer token sent only to the configured endpoint.
        bearer_token: ProtectedText,
    },
}

/// Idempotent request to provision automatic public certificates.
#[derive(Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisionCertificateRequest {
    /// Client-generated exact-retry identity.
    pub operation_id: OperationId,
    /// HTTPS ACME directory endpoint.
    #[schemars(length(min = 9, max = 2_048), pattern(r"^https://"))]
    pub directory_url: String,
    /// Sorted, unique lower-case DNS names requested on the certificate.
    #[schemars(length(min = 1, max = 256))]
    pub certificate_names: Vec<String>,
    /// HTTP-01 or one DNS-01 publication method.
    pub challenge: CertificateChallenge,
}

/// Durable result of one public-certificate provisioning operation.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisionCertificateResponse {
    /// Exact idempotency identity whose result was resolved.
    pub operation_id: OperationId,
    /// Immutable configuration created by the operation.
    pub configuration_id: AcmeConfigurationId,
    /// Initial durable order created by the operation.
    pub order_id: CertificateOrderId,
    /// Canonical certificate names retained by the authority.
    #[schemars(length(min = 1, max = 256))]
    pub certificate_names: Vec<String>,
    /// Authoritative revision created by the operation.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub revision: u64,
}
