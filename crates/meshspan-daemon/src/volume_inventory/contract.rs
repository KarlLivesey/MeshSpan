// SPDX-License-Identifier: GPL-2.0-only

//! Replaceable volume-candidate and permission authority.

use meshspan_domain::Rights;
use meshspan_filesystem::FilesystemAccessContext;
use meshspan_metadata::{
    AccessDecision, AccessRequest, AuthoritativeRepository, Page, PageLimit, RepositoryError,
    VolumeInventoryCursor, VolumeInventoryRecord,
};
use thiserror::Error;

/// Replicated reads required by a permission-filtered volume inventory.
pub trait VolumeInventoryAuthority: Send + 'static {
    /// Returns one stable global candidate page before caller-specific permission filtering.
    ///
    /// # Errors
    ///
    /// Rejects malformed cursor or committed candidate state.
    fn volume_candidates(
        &self,
        after: Option<&VolumeInventoryCursor>,
        limit: PageLimit,
    ) -> Result<Page<VolumeInventoryRecord, VolumeInventoryCursor>, VolumeInventoryAuthorityError>;

    /// Returns complete effective root rights only when the request may browse this volume.
    ///
    /// # Errors
    ///
    /// Fails closed when current authentication or permission authority cannot be trusted.
    fn volume_rights(
        &self,
        context: FilesystemAccessContext,
        volume: &VolumeInventoryRecord,
    ) -> Result<Option<Rights>, VolumeInventoryAuthorityError>;
}

impl VolumeInventoryAuthority for AuthoritativeRepository {
    fn volume_candidates(
        &self,
        after: Option<&VolumeInventoryCursor>,
        limit: PageLimit,
    ) -> Result<Page<VolumeInventoryRecord, VolumeInventoryCursor>, VolumeInventoryAuthorityError>
    {
        self.volume_inventory_candidates(after, limit)
            .map_err(|error| map_repository_error(&error))
    }

    fn volume_rights(
        &self,
        context: FilesystemAccessContext,
        volume: &VolumeInventoryRecord,
    ) -> Result<Option<Rights>, VolumeInventoryAuthorityError> {
        let requested = Rights::TRAVERSE.union(Rights::LIST);
        self.evaluate_access(AccessRequest {
            authentication_service: context.authentication_service,
            credential_digest: context.credential_digest,
            required_assurance: context.required_assurance,
            gateway_node_id: context.gateway_node_id,
            gateway_incarnation: context.gateway_incarnation,
            volume_id: volume.volume_id,
            object_id: volume.root_object_id,
            requested_rights: requested,
            now: context.now,
        })
        .map(|decision| match decision {
            AccessDecision::Granted(capability) => Some(capability.effective_rights),
            AccessDecision::Denied(_) => None,
        })
        .map_err(|error| map_repository_error(&error))
    }
}

fn map_repository_error(error: &RepositoryError) -> VolumeInventoryAuthorityError {
    match error {
        RepositoryError::Store(_) | RepositoryError::Sqlite(_) | RepositoryError::Io(_) => {
            VolumeInventoryAuthorityError::Unavailable
        }
        _ => VolumeInventoryAuthorityError::Failed,
    }
}

/// Closed replicated-authority failures safe for public classification.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum VolumeInventoryAuthorityError {
    /// Current replicated authority cannot be reached.
    #[error("volume inventory authority is unavailable")]
    Unavailable,
    /// Persisted authority failed validation.
    #[error("volume inventory authority failed closed")]
    Failed,
}

/// Stable inventory failure without credential or cursor material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum VolumeInventoryError {
    /// Query bounds or cursor structure are invalid.
    #[error("volume inventory request is invalid")]
    InvalidRequest,
    /// Authentication was rejected.
    #[error("volume inventory authentication was rejected")]
    Rejected,
    /// Current authority or bounded scan capacity is temporarily unavailable.
    #[error("volume inventory is unavailable")]
    Unavailable,
    /// Persisted or projected evidence failed closed.
    #[error("volume inventory evidence is invalid")]
    Failed,
}
