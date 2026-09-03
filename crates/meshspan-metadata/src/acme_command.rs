// SPDX-License-Identifier: GPL-2.0-only

//! Closed authoritative inputs for durable ACME configuration and fenced order execution.

use meshspan_contracts::BoundedItems;
use meshspan_domain::{AcmeConfigurationId, CertificateOrderId, NodeId, UnixMicros};

use crate::CommitSecretGeneration;

/// Maximum encoded ACME checkpoint accepted into one authoritative command.
pub const MAXIMUM_CERTIFICATE_ORDER_CHECKPOINT_BYTES: usize = 900 * 1_024;

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

/// Persists one validated restart point under the exact current certificate-order fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointCertificateOrder {
    /// Claimed order.
    pub order_id: CertificateOrderId,
    /// Exact live claim generation.
    pub claim_generation: u64,
    /// Current worker node.
    pub worker_node_id: NodeId,
    /// Exact current process incarnation.
    pub worker_incarnation: u64,
    /// Unchanged live fence and ACME order epoch.
    pub fence: u64,
    /// Protected leaf-key generation used by this order and every replacement worker.
    pub certificate_key: SecretGenerationReference,
    /// Complete versioned `meshspan-acme` checkpoint for the next side effect.
    pub checkpoint: Vec<u8>,
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

/// Records one gateway's proof that it selected an exact issued generation for new handshakes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcknowledgePublicCertificateInstallation {
    /// Completed order whose encrypted generation was installed.
    pub order_id: CertificateOrderId,
    /// Gateway reporting its own installation.
    pub gateway_node_id: NodeId,
    /// Exact current gateway process incarnation.
    pub gateway_incarnation: u64,
    /// Immutable encrypted generation decrypted and installed by the gateway.
    pub certificate: SecretGenerationReference,
    /// Digest of the canonical decrypted bundle installed by the gateway.
    pub bundle_digest: [u8; 32],
    /// Order revision the gateway observed before loading the certificate.
    pub observed_order_revision: meshspan_domain::Revision,
}
