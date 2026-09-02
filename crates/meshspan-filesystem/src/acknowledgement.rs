// SPDX-License-Identifier: GPL-2.0-only

//! Protocol-neutral evidence describing what one acknowledged write actually proved.

use meshspan_domain::{DurabilityScope, DurationMicros};

/// Whether publication may complete as a local branch or requires the converged namespace head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentAcknowledgementClass {
    /// A durable local/cell branch is a successful publication at its declared scope.
    Eventual,
    /// Successful publication additionally requires the globally converged namespace transition.
    Strong,
}

/// Explicit result once a strong write reaches its configured wait deadline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentStrongFallback {
    /// Preserve durable staged work and keep the exact publication pending.
    RemainPending,
    /// Report a typed deadline failure while retaining safe staged work for explicit retry.
    FailAtDeadline,
    /// Permit the separately proved eventual barrier to publish an honest weaker receipt.
    Eventual,
}

/// Fixed strong-write timing and fallback behaviour.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContentAcknowledgementPolicy {
    /// Selected consistency class.
    pub class: ContentAcknowledgementClass,
    /// Maximum strong-barrier wait from the first publication attempt; none has no policy cutoff.
    pub strong_wait: Option<DurationMicros>,
    /// Explicit action at the cutoff.
    pub fallback: ContentStrongFallback,
}

/// Durable result used to finish one protected content publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentAcknowledgementOutcome {
    /// The configured eventual or strong barrier was satisfied.
    PolicyCommitted,
    /// A strong policy explicitly permitted publication at its weaker eventual barrier.
    EventualFallback,
}

/// Immutable storage evidence collected before the namespace transition is published.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContentAcknowledgementEvidence {
    /// Policy class fixed when the content layout was prepared.
    pub configured_class: ContentAcknowledgementClass,
    /// Class actually acknowledged by this immutable receipt.
    pub acknowledged_class: ContentAcknowledgementClass,
    /// Whether the policy's explicit eventual fallback was used.
    pub fallback_applied: bool,
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
    /// Policy class fixed when the content layout was prepared.
    pub configured_class: ContentAcknowledgementClass,
    /// Class actually acknowledged by this immutable receipt.
    pub acknowledged_class: ContentAcknowledgementClass,
    /// Whether the policy's explicit eventual fallback was used.
    pub fallback_applied: bool,
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
    /// Finalises content evidence after the local branch transition has succeeded.
    #[must_use]
    pub const fn branch_committed(self) -> PublicationAcknowledgement {
        PublicationAcknowledgement {
            configured_class: self.configured_class,
            acknowledged_class: self.acknowledged_class,
            fallback_applied: self.fallback_applied,
            durability_scope: self.content_scope,
            policy_committed: matches!(
                (self.configured_class, self.acknowledged_class),
                (
                    ContentAcknowledgementClass::Eventual,
                    ContentAcknowledgementClass::Eventual
                )
            ),
            required_shard_receipts: self.required_shard_receipts,
            eventual_shard_receipts: self.eventual_shard_receipts,
            pending_eventual_shards: self.pending_eventual_shards,
            policy_evidence_digest: self.policy_evidence_digest,
            achieved_protection_digest: self.achieved_protection_digest,
            pending_debt_digest: self.pending_debt_digest,
        }
    }
}

impl PublicationAcknowledgement {
    /// Marks a strong acknowledgement complete only after replicated metadata commits its head.
    #[must_use]
    pub const fn globally_converged(self) -> Option<Self> {
        if matches!(
            (self.configured_class, self.acknowledged_class),
            (
                ContentAcknowledgementClass::Strong,
                ContentAcknowledgementClass::Strong
            )
        ) && !self.fallback_applied
        {
            Some(Self {
                durability_scope: DurabilityScope::GloballyConverged,
                policy_committed: true,
                ..self
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strong_content_never_claims_global_convergence_before_metadata_commit()
    -> Result<(), &'static str> {
        let branch = evidence(
            ContentAcknowledgementClass::Strong,
            ContentAcknowledgementClass::Strong,
            false,
        )
        .branch_committed();

        assert_eq!(branch.durability_scope, DurabilityScope::CellReplicated);
        assert!(!branch.policy_committed);
        let converged = branch
            .globally_converged()
            .ok_or("strong acknowledgement was not promoted")?;
        assert_eq!(
            converged.durability_scope,
            DurabilityScope::GloballyConverged
        );
        assert!(converged.policy_committed);
        Ok(())
    }

    #[test]
    fn eventual_fallback_cannot_be_promoted_to_strong_success() {
        let fallback = evidence(
            ContentAcknowledgementClass::Strong,
            ContentAcknowledgementClass::Eventual,
            true,
        )
        .branch_committed();

        assert!(!fallback.policy_committed);
        assert_eq!(fallback.globally_converged(), None);
    }

    const fn evidence(
        configured_class: ContentAcknowledgementClass,
        acknowledged_class: ContentAcknowledgementClass,
        fallback_applied: bool,
    ) -> ContentAcknowledgementEvidence {
        ContentAcknowledgementEvidence {
            configured_class,
            acknowledged_class,
            fallback_applied,
            content_scope: DurabilityScope::CellReplicated,
            required_shard_receipts: 2,
            eventual_shard_receipts: 1,
            pending_eventual_shards: 1,
            policy_evidence_digest: [1; 32],
            achieved_protection_digest: [2; 32],
            pending_debt_digest: [3; 32],
        }
    }
}
