// SPDX-License-Identifier: GPL-2.0-only

//! Closed authoritative inputs for durable ACME configuration and fenced order execution.

use meshspan_contracts::BoundedItems;
use meshspan_domain::{AcmeConfigurationId, CertificateOrderId, NodeId, UnixMicros};

use crate::CommitSecretGeneration;

/// Maximum encoded ACME checkpoint accepted into one authoritative command.
pub const MAXIMUM_CERTIFICATE_ORDER_CHECKPOINT_BYTES: usize = 900 * 1_024;
/// Maximum exact manual DNS TXT value accepted into authoritative metadata.
pub const MAXIMUM_MANUAL_DNS_VALUE_BYTES: usize = 512;

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

/// Monotonic operator-facing state of one manual DNS challenge task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManualDnsTaskPhase {
    /// The exact TXT value must be published.
    AwaitingPublication,
    /// Authoritative DNS returned the exact value.
    PublicationObserved,
    /// The exact value should now be removed.
    AwaitingRemoval,
    /// Authoritative DNS proved the value absent.
    Complete,
}

/// Creates or monotonically advances one manual DNS task under the live order fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdvanceManualDnsTask {
    /// Deterministic identity of the exact task.
    pub task_digest: [u8; 32],
    /// Claimed order which owns the task.
    pub order_id: CertificateOrderId,
    /// Exact live claim generation.
    pub claim_generation: u64,
    /// Current worker node.
    pub worker_node_id: NodeId,
    /// Exact current process incarnation.
    pub worker_incarnation: u64,
    /// Unchanged live fence and task order epoch.
    pub fence: u64,
    /// Canonical TXT owner name.
    pub record_name: String,
    /// Exact unquoted TXT value.
    pub record_value: Vec<u8>,
    /// Authoritative challenge deadline.
    pub expires_at: UnixMicros,
    /// Requested monotonic task phase.
    pub phase: ManualDnsTaskPhase,
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

/// Atomically commits protected ACME credentials, one immutable configuration and its first order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvisionAcme {
    /// Non-secret digest of the complete canonical administrator intent, including credentials.
    pub intent_digest: [u8; 32],
    /// Immutable public-certificate configuration.
    pub configuration: ConfigureAcme,
    /// Encrypted account private key referenced by `configuration`.
    pub account_key_generation: Box<CommitSecretGeneration>,
    /// Optional encrypted DNS publisher settings referenced by `configuration`.
    pub challenge_settings_generation: Option<Box<CommitSecretGeneration>>,
    /// Initial order created in the same authoritative transaction.
    pub initial_order: QueueCertificateOrder,
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
    /// Atomically consume an exactly retired checkpoint and queue a fresh protocol order.
    Restart {
        /// Typed and redacted failure evidence digest.
        failure_digest: [u8; 32],
        /// Future authority-agreed retry instant.
        retry_at: UnixMicros,
        /// Exact current-claim checkpoint proving cleanup has completed.
        retired_checkpoint_digest: [u8; 32],
    },
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
