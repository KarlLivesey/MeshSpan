// SPDX-License-Identifier: GPL-2.0-only

//! Closed authoritative inputs for durable ACME configuration and fenced order execution.

use meshspan_contracts::BoundedItems;
use meshspan_domain::{AcmeConfigurationId, CertificateOrderId, NodeId, UnixMicros};

use crate::CommitSecretGeneration;

/// Encrypted secret generation referenced without exposing its plaintext through metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecretGenerationReference {
    /// Stable secret identity.
    pub secret_id: [u8; 16],
    /// Exact immutable generation.
    pub generation: u64,
}

/// Closed ACME challenge family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcmeChallengeKind {
    /// Serve a bounded token only on eligible HTTPS gateways.
    Http01,
    /// Publish and independently probe the required authoritative DNS TXT record.
    Dns01,
}

/// Immutable ACME account, challenge and requested-name configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigureAcme {
    /// Stable configuration revision identity.
    pub config_id: AcmeConfigurationId,
    /// HTTPS ACME directory endpoint.
    pub directory_url: String,
    /// Encrypted account private-key generation.
    pub account_key: SecretGenerationReference,
    /// HTTP-01 or DNS-01 execution mode.
    pub challenge_kind: AcmeChallengeKind,
    /// Optional encrypted DNS publisher configuration; absent for HTTP-01 or manual DNS-01.
    pub challenge_settings: Option<SecretGenerationReference>,
    /// Bounded, canonical lower-case DNS names placed on the certificate.
    pub certificate_names: BoundedItems<String>,
}

/// Creates one durable order for an immutable configuration revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueCertificateOrder {
    /// Stable order identity.
    pub order_id: CertificateOrderId,
    /// Exact immutable configuration used throughout the order.
    pub config_id: AcmeConfigurationId,
    /// Earliest authority-agreed attempt instant.
    pub next_attempt_at: UnixMicros,
}

/// Fences one eligible node as the sole executor of an actionable certificate order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimCertificateOrder {
    /// Existing queued or expired-claim order.
    pub order_id: CertificateOrderId,
    /// Next monotonic claim generation.
    pub claim_generation: u64,
    /// Authenticated worker node.
    pub worker_node_id: NodeId,
    /// Exact current process incarnation.
    pub worker_incarnation: u64,
    /// Positive unpredictable token carried by every result.
    pub fence: u64,
    /// Bounded authoritative lease end.
    pub lease_expires_at: UnixMicros,
}

/// Extends one still-current certificate-order claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RenewCertificateOrder {
    /// Claimed order.
    pub order_id: CertificateOrderId,
    /// Exact live claim generation.
    pub claim_generation: u64,
    /// Current worker node.
    pub worker_node_id: NodeId,
    /// Exact current process incarnation.
    pub worker_incarnation: u64,
    /// Unchanged live fence.
    pub fence: u64,
    /// Later bounded lease end.
    pub lease_expires_at: UnixMicros,
}

/// Result of one exact fenced ACME attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CertificateOrderCompletion {
    /// Return the order to the queue without making any certificate safety claim.
    Retry {
        /// Typed and redacted failure evidence digest.
        failure_digest: [u8; 32],
        /// Future authority-agreed retry instant.
        retry_at: UnixMicros,
    },
    /// Bind a validated encrypted certificate/private-key generation to the order.
    Issued {
        /// Encrypted certificate and private-key bundle for every exact gateway recipient.
        certificate: Box<CommitSecretGeneration>,
        /// Validated certificate lower validity bound.
        not_before: UnixMicros,
        /// Validated certificate upper validity bound.
        not_after: UnixMicros,
        /// Digest of the validated names, chain and matching public key.
        result_digest: [u8; 32],
    },
}

/// Completes or retries one still-current certificate-order claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteCertificateOrder {
    /// Claimed order.
    pub order_id: CertificateOrderId,
    /// Exact live claim generation.
    pub claim_generation: u64,
    /// Current worker node.
    pub worker_node_id: NodeId,
    /// Exact current process incarnation.
    pub worker_incarnation: u64,
    /// Unchanged live fence.
    pub fence: u64,
    /// Retry or validated issuance result.
    pub outcome: CertificateOrderCompletion,
}
