// SPDX-License-Identifier: GPL-2.0-only

//! Small upward-closed quorum expression language with no ambiguous double counting.

use std::collections::{BTreeMap, BTreeSet};

use meshspan_domain::NodeId;

use super::{QuorumPlanError, VoterSet};

const MAXIMUM_PREDICATE_DEPTH: usize = 8;
const MAXIMUM_PREDICATE_NODES: usize = 256;

/// One stable voter weight in a weighted threshold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WeightedVoter {
    /// Referenced voter.
    pub voter: NodeId,
    /// Positive deliberate voting weight.
    pub weight: u16,
}

/// Bounded upward-closed expression over stable voter identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QuorumPredicate {
    /// One exact voter must acknowledge.
    Voter(NodeId),
    /// At least `threshold` disjoint child predicates must qualify.
    AtLeast {
        /// Positive threshold no larger than the child count.
        threshold: u8,
        /// Non-empty child predicates with disjoint voter references.
        children: Vec<Self>,
    },
    /// Referenced voter weights must reach a positive threshold.
    WeightedAtLeast {
        /// Positive threshold no larger than the checked total weight.
        threshold: u32,
        /// Non-empty unique voters with positive weights.
        voters: Vec<WeightedVoter>,
    },
    /// Every disjoint child predicate must qualify.
    All {
        /// Non-empty child predicates with disjoint voter references.
        children: Vec<Self>,
    },
}

impl QuorumPredicate {
    pub(super) fn validate(
        &self,
        voters: &BTreeSet<NodeId>,
    ) -> Result<BTreeSet<NodeId>, QuorumPlanError> {
        let mut node_count = 0_usize;
        validate_node(self, voters, 1, &mut node_count)
    }

    pub(super) fn evaluate(
        &self,
        acknowledged: VoterSet,
        voter_bits: &BTreeMap<NodeId, u8>,
    ) -> bool {
        match self {
            Self::Voter(voter) => voter_bits
                .get(voter)
                .is_some_and(|bit| acknowledged.contains_bit(*bit)),
            Self::AtLeast {
                threshold,
                children,
            } => {
                children
                    .iter()
                    .filter(|child| child.evaluate(acknowledged, voter_bits))
                    .count()
                    >= usize::from(*threshold)
            }
            Self::WeightedAtLeast { threshold, voters } => voters
                .iter()
                .filter(|weighted| {
                    voter_bits
                        .get(&weighted.voter)
                        .is_some_and(|bit| acknowledged.contains_bit(*bit))
                })
                .try_fold(0_u32, |total, weighted| {
                    total.checked_add(u32::from(weighted.weight))
                })
                .is_some_and(|total| total >= *threshold),
            Self::All { children } => children
                .iter()
                .all(|child| child.evaluate(acknowledged, voter_bits)),
        }
    }
}

fn validate_node(
    predicate: &QuorumPredicate,
    voters: &BTreeSet<NodeId>,
    depth: usize,
    node_count: &mut usize,
) -> Result<BTreeSet<NodeId>, QuorumPlanError> {
    *node_count = node_count
        .checked_add(1)
        .ok_or(QuorumPlanError::InvalidPredicate)?;
    if depth > MAXIMUM_PREDICATE_DEPTH || *node_count > MAXIMUM_PREDICATE_NODES {
        return Err(QuorumPlanError::InvalidPredicate);
    }
    match predicate {
        QuorumPredicate::Voter(voter) if voters.contains(voter) => Ok(BTreeSet::from([*voter])),
        QuorumPredicate::Voter(_) => Err(QuorumPlanError::InvalidMember),
        QuorumPredicate::AtLeast {
            threshold,
            children,
        } => {
            if *threshold == 0 || usize::from(*threshold) > children.len() {
                return Err(QuorumPlanError::InvalidPredicate);
            }
            validate_disjoint_children(children, voters, depth, node_count)
        }
        QuorumPredicate::All { children } => {
            validate_disjoint_children(children, voters, depth, node_count)
        }
        QuorumPredicate::WeightedAtLeast {
            threshold,
            voters: weighted,
        } => validate_weighted(*threshold, weighted, voters),
    }
}

fn validate_disjoint_children(
    children: &[QuorumPredicate],
    voters: &BTreeSet<NodeId>,
    depth: usize,
    node_count: &mut usize,
) -> Result<BTreeSet<NodeId>, QuorumPlanError> {
    if children.is_empty() {
        return Err(QuorumPlanError::InvalidPredicate);
    }
    let mut referenced = BTreeSet::new();
    for child in children {
        let child_references = validate_node(child, voters, depth + 1, node_count)?;
        if !referenced.is_disjoint(&child_references) {
            return Err(QuorumPlanError::InvalidPredicate);
        }
        referenced.extend(child_references);
    }
    Ok(referenced)
}

fn validate_weighted(
    threshold: u32,
    weighted: &[WeightedVoter],
    voters: &BTreeSet<NodeId>,
) -> Result<BTreeSet<NodeId>, QuorumPlanError> {
    if threshold == 0 || weighted.is_empty() {
        return Err(QuorumPlanError::InvalidPredicate);
    }
    let mut referenced = BTreeSet::new();
    let mut total = 0_u32;
    for item in weighted {
        if item.weight == 0 || !voters.contains(&item.voter) || !referenced.insert(item.voter) {
            return Err(QuorumPlanError::InvalidPredicate);
        }
        total = total
            .checked_add(u32::from(item.weight))
            .ok_or(QuorumPlanError::InvalidPredicate)?;
    }
    if threshold > total {
        Err(QuorumPlanError::InvalidPredicate)
    } else {
        Ok(referenced)
    }
}
