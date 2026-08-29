// SPDX-License-Identifier: GPL-2.0-only

//! Bounded horizontal and acyclic governance relationships between autonomous swarms.

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use crate::MeshId;

/// User-visible relationship class between two autonomous swarms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FederationRelationshipKind {
    /// Neither swarm governs the other.
    Horizontal,
    /// The first swarm governs the second within a bounded delegation.
    Governance,
}

/// Deterministic relationship graph with one parent per subordinate and no governance cycles.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FederationGraph {
    governance_parent: BTreeMap<MeshId, MeshId>,
    horizontal: BTreeSet<(MeshId, MeshId)>,
}

impl FederationGraph {
    /// Creates an empty federation graph.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            governance_parent: BTreeMap::new(),
            horizontal: BTreeSet::new(),
        }
    }

    /// Adds one governing parent for a subordinate swarm.
    ///
    /// Exact retries are idempotent. A different existing parent, self-edge or cycle fails without
    /// modifying the graph.
    ///
    /// # Errors
    ///
    /// Returns a typed structural rejection for an unsafe relationship.
    pub fn add_governance(
        &mut self,
        governing: MeshId,
        subordinate: MeshId,
    ) -> Result<(), FederationGraphError> {
        if governing == subordinate {
            return Err(FederationGraphError::SelfRelationship);
        }
        if let Some(existing) = self.governance_parent.get(&subordinate) {
            return if *existing == governing {
                Ok(())
            } else {
                Err(FederationGraphError::ParentAlreadyExists)
            };
        }
        if self.is_ancestor(subordinate, governing) {
            return Err(FederationGraphError::GovernanceCycle);
        }
        self.governance_parent.insert(subordinate, governing);
        Ok(())
    }

    /// Adds a horizontal peer relationship in canonical identity order.
    ///
    /// Horizontal cycles are valid because these edges carry no governance authority.
    ///
    /// # Errors
    ///
    /// Rejects a self-edge.
    pub fn add_horizontal(
        &mut self,
        left: MeshId,
        right: MeshId,
    ) -> Result<(), FederationGraphError> {
        if left == right {
            return Err(FederationGraphError::SelfRelationship);
        }
        self.horizontal.insert(canonical_pair(left, right));
        Ok(())
    }

    /// Returns the immediate governing parent, if any.
    #[must_use]
    pub fn governing_parent(&self, subordinate: MeshId) -> Option<MeshId> {
        self.governance_parent.get(&subordinate).copied()
    }

    /// Returns the bounded governance chain from immediate parent to root.
    #[must_use]
    pub fn governance_chain(&self, subordinate: MeshId) -> Vec<MeshId> {
        let mut chain = Vec::new();
        let mut current = subordinate;
        while let Some(parent) = self.governance_parent.get(&current).copied() {
            chain.push(parent);
            current = parent;
        }
        chain
    }

    /// Reports whether two swarms have an explicit horizontal relationship.
    #[must_use]
    pub fn is_horizontal(&self, left: MeshId, right: MeshId) -> bool {
        left != right && self.horizontal.contains(&canonical_pair(left, right))
    }

    fn is_ancestor(&self, possible_ancestor: MeshId, descendant: MeshId) -> bool {
        let mut current = descendant;
        while let Some(parent) = self.governance_parent.get(&current).copied() {
            if parent == possible_ancestor {
                return true;
            }
            current = parent;
        }
        false
    }
}

/// Invalid federation relationship graph mutation.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FederationGraphError {
    /// A swarm cannot federate with or govern itself.
    #[error("federation relationship cannot target the same swarm")]
    SelfRelationship,
    /// One subordinate already has a different immediate governing parent.
    #[error("subordinate swarm already has a governing parent")]
    ParentAlreadyExists,
    /// The proposed governing edge would make governance cyclic.
    #[error("federation governance relationship would create a cycle")]
    GovernanceCycle,
}

fn canonical_pair(left: MeshId, right: MeshId) -> (MeshId, MeshId) {
    if left <= right {
        (left, right)
    } else {
        (right, left)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn governance_is_acyclic_and_has_one_parent() -> Result<(), Box<dyn std::error::Error>> {
        let root = mesh(1)?;
        let region = mesh(2)?;
        let shop = mesh(3)?;
        let alternative = mesh(4)?;
        let mut graph = FederationGraph::new();
        graph.add_governance(root, region)?;
        graph.add_governance(region, shop)?;
        graph.add_governance(region, shop)?;

        assert_eq!(graph.governance_chain(shop), vec![region, root]);
        assert_eq!(
            graph.add_governance(alternative, shop),
            Err(FederationGraphError::ParentAlreadyExists)
        );
        assert_eq!(
            graph.add_governance(shop, root),
            Err(FederationGraphError::GovernanceCycle)
        );
        Ok(())
    }

    #[test]
    fn horizontal_graph_may_form_cycles_without_governance()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = mesh(10)?;
        let second = mesh(11)?;
        let third = mesh(12)?;
        let mut graph = FederationGraph::new();
        graph.add_horizontal(first, second)?;
        graph.add_horizontal(second, third)?;
        graph.add_horizontal(third, first)?;

        assert!(graph.is_horizontal(second, first));
        assert!(graph.is_horizontal(second, third));
        assert!(graph.is_horizontal(first, third));
        assert_eq!(graph.governance_chain(first), Vec::<MeshId>::new());
        Ok(())
    }

    fn mesh(value: u8) -> Result<MeshId, crate::IdentifierError> {
        MeshId::from_bytes([value; 16])
    }
}
