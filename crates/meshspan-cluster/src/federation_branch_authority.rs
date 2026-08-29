// SPDX-License-Identifier: GPL-2.0-only

//! Replaceable bilateral grant-authority boundary for federated branch exchange.

use meshspan_domain::{FederationGrantId, FederationRelationshipId, UnixMicros};
use meshspan_metadata::{AuthoritativeRepository, LocalDatabase};

use crate::{
    EffectiveFederationGrantAuthority, EffectiveFederationGrantAuthorityError,
    effective_federation_grant_authority,
};

/// Authority source consulted after peer authentication and before history lookup.
pub trait FederationBranchAuthoritySource {
    /// Returns current bilateral authority or `None` when either swarm withholds it.
    ///
    /// # Errors
    ///
    /// Fails closed when local consensus or the authenticated remote observation is corrupt.
    fn effective_grant_authority(
        &self,
        relationship_id: FederationRelationshipId,
        grant_id: FederationGrantId,
        now: UnixMicros,
    ) -> Result<Option<EffectiveFederationGrantAuthority>, EffectiveFederationGrantAuthorityError>;
}

/// Production composition of authoritative metadata and the node-local remote observation cache.
pub struct MetadataFederationBranchAuthority<'a> {
    repository: &'a AuthoritativeRepository,
    remote_cache: &'a LocalDatabase,
}

impl<'a> MetadataFederationBranchAuthority<'a> {
    /// Binds both independently durable authority stores without opening a cross-store transaction.
    #[must_use]
    pub const fn new(
        repository: &'a AuthoritativeRepository,
        remote_cache: &'a LocalDatabase,
    ) -> Self {
        Self {
            repository,
            remote_cache,
        }
    }
}

impl FederationBranchAuthoritySource for MetadataFederationBranchAuthority<'_> {
    fn effective_grant_authority(
        &self,
        relationship_id: FederationRelationshipId,
        grant_id: FederationGrantId,
        now: UnixMicros,
    ) -> Result<Option<EffectiveFederationGrantAuthority>, EffectiveFederationGrantAuthorityError>
    {
        effective_federation_grant_authority(
            self.repository,
            self.remote_cache,
            relationship_id,
            grant_id,
            now,
        )
    }
}
