// SPDX-License-Identifier: GPL-2.0-only

//! Canonical plan/proof digest independent of construction ordering.

use meshspan_domain::NodeId;
use sha2::{Digest, Sha256};

use super::{FamilyProof, QuorumPlanSpec, QuorumPredicate, WeightedVoter};

pub(super) fn plan_digest(
    spec: &QuorumPlanSpec,
    ordered_voters: &[NodeId],
    election: &FamilyProof,
    commit: &FamilyProof,
    read: &FamilyProof,
) -> [u8; 32] {
    let mut digest = CanonicalDigest::new();
    digest.bytes(b"meshspan.consensus.quorum-plan.v1");
    digest.bytes(&spec.plan_id.as_bytes());
    digest.unsigned(u64::from(spec.format_version));
    digest.unsigned(spec.membership_epoch);
    digest.identifiers(ordered_voters.iter().copied());
    digest.identifiers(spec.learners.iter().copied());
    digest.identifiers(spec.eligible_leaders.iter().copied());
    digest.bytes(&predicate_bytes(&spec.election));
    digest.bytes(&predicate_bytes(&spec.commit));
    digest.bytes(&predicate_bytes(&spec.read));
    digest.family(election);
    digest.family(commit);
    digest.family(read);
    digest.finish()
}

fn predicate_bytes(predicate: &QuorumPredicate) -> Vec<u8> {
    match predicate {
        QuorumPredicate::Voter(voter) => {
            let mut bytes = vec![1];
            bytes.extend_from_slice(&voter.as_bytes());
            bytes
        }
        QuorumPredicate::AtLeast {
            threshold,
            children,
        } => composite_bytes(2, u64::from(*threshold), children),
        QuorumPredicate::WeightedAtLeast { threshold, voters } => {
            weighted_bytes(*threshold, voters)
        }
        QuorumPredicate::All { children } => composite_bytes(
            4,
            u64::try_from(children.len()).unwrap_or(u64::MAX),
            children,
        ),
    }
}

fn composite_bytes(tag: u8, threshold: u64, children: &[QuorumPredicate]) -> Vec<u8> {
    let mut encoded: Vec<Vec<u8>> = children.iter().map(predicate_bytes).collect();
    encoded.sort_unstable();
    let mut bytes = vec![tag];
    bytes.extend_from_slice(&threshold.to_be_bytes());
    bytes.extend_from_slice(
        &u64::try_from(encoded.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for child in encoded {
        bytes.extend_from_slice(&u64::try_from(child.len()).unwrap_or(u64::MAX).to_be_bytes());
        bytes.extend_from_slice(&child);
    }
    bytes
}

fn weighted_bytes(threshold: u32, voters: &[WeightedVoter]) -> Vec<u8> {
    let mut ordered = voters.to_vec();
    ordered.sort_unstable_by_key(|item| item.voter);
    let mut bytes = vec![3];
    bytes.extend_from_slice(&threshold.to_be_bytes());
    bytes.extend_from_slice(
        &u64::try_from(ordered.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for item in ordered {
        bytes.extend_from_slice(&item.voter.as_bytes());
        bytes.extend_from_slice(&item.weight.to_be_bytes());
    }
    bytes
}

struct CanonicalDigest(Sha256);

impl CanonicalDigest {
    fn new() -> Self {
        Self(Sha256::new())
    }

    fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }

    fn bytes(&mut self, value: &[u8]) {
        self.unsigned(u64::try_from(value.len()).unwrap_or(u64::MAX));
        self.0.update(value);
    }

    fn unsigned(&mut self, value: u64) {
        self.0.update(value.to_be_bytes());
    }

    fn identifiers(&mut self, values: impl Iterator<Item = NodeId>) {
        let values: Vec<NodeId> = values.collect();
        self.unsigned(u64::try_from(values.len()).unwrap_or(u64::MAX));
        for value in values {
            self.0.update(value.as_bytes());
        }
    }

    fn family(&mut self, family: &FamilyProof) {
        self.unsigned(u64::try_from(family.minimal_quorums().len()).unwrap_or(u64::MAX));
        for quorum in family.minimal_quorums() {
            self.0.update(quorum.bits().to_be_bytes());
        }
        self.unsigned(u64::try_from(family.minimal_cut_sets().len()).unwrap_or(u64::MAX));
        for cut in family.minimal_cut_sets() {
            self.0.update(cut.bits().to_be_bytes());
        }
    }
}
