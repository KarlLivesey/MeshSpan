// SPDX-License-Identifier: GPL-2.0-only

//! Protocol-neutral evidence describing what one acknowledged write actually proved.

use meshspan_domain::DurabilityScope;

/// Whether publication may complete as a local branch or requires the converged namespace head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentAcknowledgementClass {
    /// A durable local/cell branch is a successful publication at its declared scope.
    Eventual,
    /// Successful publication additionally requires the globally converged namespace transition.
    Strong,
}

/// Immutable storage evidence collected before the namespace transition is published.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContentAcknowledgementEvidence {
    /// Policy class fixed when the content layout was prepared.
    pub class: ContentAcknowledgementClass,
    /// Strongest scope proved by the required durable shard receipts alone.
    pub content_scope: DurabilityScope,
    /// Number of required shard receipts included in the evidence digest.
    pub required_shard_receipts: u64,
    /// Number of non-blocking shard receipts already completed.
    pub eventual_shard_receipts: u64,
    /// Number of planned non-blocking shards still owed by reconciliation.
    pub pending_eventual_shards: u64,
    /// Digest of the exact fixed-revision acknowledgement predicates used by every stripe.
    pub policy_evidence_digest: [u8; 32],
    /// Digest of the exact durable shard receipts present when publication was acknowledged.
    pub achieved_protection_digest: [u8; 32],
    /// Digest of the exact planned non-blocking shards still missing at acknowledgement.
    pub pending_debt_digest: [u8; 32],
}

/// Connector-visible acknowledgement after the namespace transition succeeds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationAcknowledgement {
    /// Honest durability scope reached by this publication.
    pub durability_scope: DurabilityScope,
    /// Whether every predicate required by the configured acknowledgement policy committed.
    pub policy_committed: bool,
    /// Number of required shard receipts included in the evidence digest.
    pub required_shard_receipts: u64,
    /// Number of non-blocking shard receipts already completed.
    pub eventual_shard_receipts: u64,
    /// Number of non-blocking shard placements still owed.
    pub pending_eventual_shards: u64,
    /// Immutable digest of the fixed-revision policy predicates.
    pub policy_evidence_digest: [u8; 32],
    /// Immutable digest of achieved durable receipt evidence.
    pub achieved_protection_digest: [u8; 32],
    /// Immutable digest of outstanding locality/protection debt.
    pub pending_debt_digest: [u8; 32],
}

impl ContentAcknowledgementEvidence {
    /// Finalises content evidence after the atomic namespace transition has succeeded.
    #[must_use]
    pub const fn namespace_committed(self) -> PublicationAcknowledgement {
        PublicationAcknowledgement {
            durability_scope: match self.class {
                ContentAcknowledgementClass::Eventual => self.content_scope,
                ContentAcknowledgementClass::Strong => DurabilityScope::GloballyConverged,
            },
            policy_committed: true,
            required_shard_receipts: self.required_shard_receipts,
            eventual_shard_receipts: self.eventual_shard_receipts,
            pending_eventual_shards: self.pending_eventual_shards,
            policy_evidence_digest: self.policy_evidence_digest,
            achieved_protection_digest: self.achieved_protection_digest,
            pending_debt_digest: self.pending_debt_digest,
        }
    }
}
