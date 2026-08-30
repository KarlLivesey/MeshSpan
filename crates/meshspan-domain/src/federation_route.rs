// SPDX-License-Identifier: GPL-2.0-only

//! Exact, bounded and acyclic swarm ancestry for a federated grant.

use std::collections::BTreeSet;

use thiserror::Error;

use crate::MeshId;

/// Maximum number of distinct swarms in one signed delegation route.
pub const MAXIMUM_FEDERATION_ROUTE_MESHES: usize = 64;

/// Immutable route from a resource authority through each downstream recipient.
///
/// The first mesh owns or supplies the resource. Every following mesh receives
/// authority from its immediate predecessor. A downstream recipient therefore
/// contacts that predecessor rather than bypassing it to an earlier swarm.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationGrantRoute {
    meshes: Box<[MeshId]>,
}

impl FederationGrantRoute {
    /// Constructs a direct authority-to-recipient route.
    ///
    /// # Errors
    ///
    /// Rejects a self-grant.
    pub fn direct(
        authority_mesh_id: MeshId,
        recipient_mesh_id: MeshId,
    ) -> Result<Self, FederationGrantRouteError> {
        Self::from_meshes(vec![authority_mesh_id, recipient_mesh_id])
    }

    /// Validates an exact route decoded from an untrusted contract or store.
    ///
    /// # Errors
    ///
    /// Rejects fewer than two meshes, excessive depth, or any repeated mesh.
    pub fn from_meshes(meshes: Vec<MeshId>) -> Result<Self, FederationGrantRouteError> {
        if meshes.len() < 2 {
            return Err(FederationGrantRouteError::MissingRecipient);
        }
        if meshes.len() > MAXIMUM_FEDERATION_ROUTE_MESHES {
            return Err(FederationGrantRouteError::TooDeep);
        }
        let unique = meshes.iter().copied().collect::<BTreeSet<_>>();
        if unique.len() != meshes.len() {
            return Err(FederationGrantRouteError::Cycle);
        }
        Ok(Self {
            meshes: meshes.into_boxed_slice(),
        })
    }

    /// Extends this route by exactly one recipient.
    ///
    /// # Errors
    ///
    /// Rejects a repeated swarm or a route beyond the bounded maximum.
    pub fn delegate_to(
        &self,
        recipient_mesh_id: MeshId,
    ) -> Result<Self, FederationGrantRouteError> {
        let mut meshes = Vec::with_capacity(self.meshes.len().saturating_add(1));
        meshes.extend_from_slice(&self.meshes);
        meshes.push(recipient_mesh_id);
        Self::from_meshes(meshes)
    }

    /// Returns the resource-owning or resource-providing swarm.
    #[must_use]
    pub fn authority_mesh_id(&self) -> MeshId {
        self.meshes[0]
    }

    /// Returns the swarm issuing the final hop.
    #[must_use]
    pub fn issuer_mesh_id(&self) -> MeshId {
        self.meshes[self.meshes.len() - 2]
    }

    /// Returns the swarm receiving the final hop.
    #[must_use]
    pub fn recipient_mesh_id(&self) -> MeshId {
        self.meshes[self.meshes.len() - 1]
    }

    /// Returns zero for a direct grant and one for each additional downstream hop.
    #[must_use]
    pub fn downstream_depth(&self) -> usize {
        self.meshes.len() - 2
    }

    /// Returns the complete immutable route in authority-to-recipient order.
    #[must_use]
    pub fn meshes(&self) -> &[MeshId] {
        &self.meshes
    }
}

/// Invalid or unsafe federation-grant ancestry.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FederationGrantRouteError {
    /// A grant route must contain an authority and a distinct recipient.
    #[error("federation grant route requires an authority and recipient")]
    MissingRecipient,
    /// The bounded signed route cannot safely carry another delegation hop.
    #[error("federation grant route exceeds the maximum depth")]
    TooDeep,
    /// A repeated swarm would create a direct or transitive delegation cycle.
    #[error("federation grant route contains a cycle")]
    Cycle,
}

#[cfg(test)]
#[path = "federation_route_tests.rs"]
mod tests;
