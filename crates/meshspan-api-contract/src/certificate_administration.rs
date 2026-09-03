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
public_identifier!(
    ExternalCertificatePublicationId,
    "Stable identity of one automated external-certificate publication."
);
public_identifier!(
    MeshLocalCertificateAuthorityId,
    "Stable identity of the mesh-local HTTPS trust authority."
);
public_identifier!(
    MeshLocalCertificateIssuanceId,
    "Stable identity of one mesh-local HTTPS certificate issuance."
);
public_identifier!(
    PublicCertificateId,
    "Stable identity of one public-certificate generation."
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
    pub fn into_bytes(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0).into_bytes()
    }

    /// Borrows bytes solely for canonical intent hashing before encryption.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
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

/// One bounded leaf-first PEM certificate chain supplied by an automated issuer.
#[derive(Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct CertificateChainPem(#[schemars(length(min = 64, max = 98_304))] String);

impl CertificateChainPem {
    /// Borrows the public PEM bytes for semantic and cryptographic validation.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// Sensitive unencrypted PKCS#8 PEM accepted once from an automated issuer.
#[derive(Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ExternalCertificatePrivateKeyPem(#[schemars(length(min = 64, max = 16_384))] String);

impl ExternalCertificatePrivateKeyPem {
    /// Moves the key into zeroising storage for immediate validation and envelope encryption.
    #[must_use]
    pub fn into_zeroizing(mut self) -> Zeroizing<String> {
        Zeroizing::new(std::mem::take(&mut self.0))
    }
}

impl fmt::Debug for ExternalCertificatePrivateKeyPem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExternalCertificatePrivateKeyPem([redacted])")
    }
}

impl Drop for ExternalCertificatePrivateKeyPem {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Positive externally assigned generation represented exactly outside JavaScript numbers.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct CertificateGeneration(
    #[schemars(length(min = 1, max = 20), pattern(r"^[1-9][0-9]{0,19}$"))] String,
);

impl CertificateGeneration {
    /// Constructs canonical decimal text for one positive generation.
    #[must_use]
    pub fn from_value(value: u64) -> Option<Self> {
        (value > 0).then(|| Self(value.to_string()))
    }

    /// Parses the canonical positive decimal generation.
    #[must_use]
    pub fn value(&self) -> Option<u64> {
        self.0.parse().ok().filter(|value| *value > 0)
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

/// Exact-retry automated publication of a certificate issued outside `MeshSpan`.
#[derive(Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublishExternalCertificateRequest {
    /// Client-generated identity binding exact retries.
    pub operation_id: OperationId,
    /// Monotonic generation chosen by the external issuer integration.
    pub generation: CertificateGeneration,
    /// Sorted, unique lower-case DNS names expected in the leaf certificate.
    #[schemars(length(min = 1, max = 256))]
    pub certificate_names: Vec<String>,
    /// Complete leaf-first certificate chain in PEM form.
    pub certificate_chain_pem: CertificateChainPem,
    /// Matching unencrypted PKCS#8 PEM private key, accepted only on this protected request.
    #[schemars(extend("x-meshspan-sensitive" = true))]
    pub private_key_pkcs8_pem: ExternalCertificatePrivateKeyPem,
}

/// Secret-free durable result of one automated external-certificate publication.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublishExternalCertificateResponse {
    /// Exact idempotency identity whose result was committed or resolved.
    pub operation_id: OperationId,
    /// Stable publication identity.
    pub publication_id: ExternalCertificatePublicationId,
    /// Immutable public-certificate identity.
    pub certificate_id: PublicCertificateId,
    /// Accepted external generation.
    pub generation: CertificateGeneration,
    /// Canonical DNS names bound to the leaf certificate.
    #[schemars(length(min = 1, max = 256))]
    pub certificate_names: Vec<String>,
    /// Lower-case SHA-256 fingerprint of the leaf subject public key.
    #[schemars(length(equal = 64), pattern(r"^[0-9a-f]{64}$"))]
    pub public_key_fingerprint: String,
    /// Inclusive leaf validity start as epoch microseconds.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_u64))]
    pub not_before_epoch_micros: u64,
    /// Exclusive leaf validity end as epoch microseconds.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub not_after_epoch_micros: u64,
    /// Authoritative revision containing the encrypted generation.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub revision: u64,
}

/// Exact-retry request for an automatically trusted mesh-local HTTPS identity.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisionMeshLocalCertificateRequest {
    /// Client-generated identity binding exact retries.
    pub operation_id: OperationId,
    /// Sorted, unique lower-case DNS names requested on the endpoint certificate.
    #[schemars(length(min = 1, max = 256))]
    pub certificate_names: Vec<String>,
}

/// Secret-free result of one mesh-local HTTPS certificate issuance.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisionMeshLocalCertificateResponse {
    /// Exact idempotency identity whose result was committed or resolved.
    pub operation_id: OperationId,
    /// Immutable mesh-local trust-authority identity.
    pub authority_id: MeshLocalCertificateAuthorityId,
    /// Immutable issuance identity.
    pub issuance_id: MeshLocalCertificateIssuanceId,
    /// Immutable public-certificate identity.
    pub certificate_id: PublicCertificateId,
    /// Monotonic mesh-local endpoint generation.
    pub generation: CertificateGeneration,
    /// Canonical DNS names bound to the leaf certificate.
    #[schemars(length(min = 1, max = 256))]
    pub certificate_names: Vec<String>,
    /// Public trust anchor in PEM form; no private material is returned.
    #[schemars(length(min = 64, max = 32_768))]
    pub trust_anchor_pem: String,
    /// Lower-case SHA-256 fingerprint of the leaf subject public key.
    #[schemars(length(equal = 64), pattern(r"^[0-9a-f]{64}$"))]
    pub public_key_fingerprint: String,
    /// Inclusive leaf validity start as epoch microseconds.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_u64))]
    pub not_before_epoch_micros: u64,
    /// Exclusive leaf validity end as epoch microseconds.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub not_after_epoch_micros: u64,
    /// Authoritative revision containing the encrypted endpoint generation.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub revision: u64,
}

/// Authority which produced the currently selected HTTPS certificate.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateStatusSource {
    /// `MeshSpan`'s automatic ACME lifecycle.
    Acme,
    /// An authenticated external issuer integration.
    External,
    /// `MeshSpan`'s self-contained local trust authority.
    MeshLocal,
}

/// Plain-language operational state of the selected HTTPS certificate.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateOperationalState {
    /// The certificate is valid and every intended gateway acknowledged it.
    Active,
    /// The certificate is valid but at least one intended gateway has not acknowledged it.
    Distributing,
    /// The certificate's validity window has not opened.
    NotYetValid,
    /// The certificate validity window has ended.
    Expired,
}

/// Current secret-free HTTPS certificate and gateway-delivery status.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentCertificateStatus {
    /// Certificate authority family.
    pub source: CertificateStatusSource,
    /// Stable source identity as canonical UUID text.
    #[schemars(
        length(equal = 36),
        pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    )]
    pub source_id: String,
    /// Current encrypted delivery generation represented exactly outside JavaScript numbers.
    pub delivery_generation: CertificateGeneration,
    /// Inclusive certificate validity start as epoch microseconds.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_u64))]
    pub not_before_epoch_micros: u64,
    /// Exclusive certificate validity end as epoch microseconds.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub not_after_epoch_micros: u64,
    /// Gateways included in the current encrypted delivery generation.
    #[schemars(range(max = 1_000_000_u64))]
    pub required_gateway_count: u64,
    /// Gateways which acknowledged live selection of the current generation.
    #[schemars(range(max = 1_000_000_u64))]
    pub installed_gateway_count: u64,
    /// Derived state at the response's authority-agreed observation time.
    pub state: CertificateOperationalState,
    /// Authoritative source revision represented exactly outside JavaScript numbers.
    pub source_revision: CertificateGeneration,
}

/// Current certificate status; `certificate` is `null` before a source is configured.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateStatusResponse {
    /// Authority-agreed time used for validity classification.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_u64))]
    pub observed_at_epoch_micros: u64,
    /// Current secret-free certificate state, or `null` when HTTPS has no configured identity.
    pub certificate: Option<CurrentCertificateStatus>,
}
