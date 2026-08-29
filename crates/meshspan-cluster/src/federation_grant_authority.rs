// SPDX-License-Identifier: GPL-2.0-only

//! Bilateral federation authority derived from local consensus and remote observation.

use meshspan_domain::{
    FederationGrant, FederationGrantId, FederationRelationshipId, Revision, UnixMicros,
};
use meshspan_metadata::{
    AuthoritativeRepository, CachedFederationGrantAuthority, FederationGovernanceDirection,
    FederationGrantRecord, FederationGrantState, FederationRemoteAuthorityCacheError,
    FederationTransportAuthority, LocalDatabase, RepositoryError,
};
use thiserror::Error;

use crate::{
    FederationAuthorityError, FederationConnectionAuthority, federation_connection_authority,
};

/// Current grant authority proved independently by both autonomous swarms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectiveFederationGrantAuthority {
    /// Exact immutable authority envelope agreed by both sides.
    pub grant: FederationGrant,
    /// Local committed relationship snapshot used for admission.
    pub local_authority_revision: Revision,
    /// Local committed grant revision used for admission.
    pub local_grant_revision: Revision,
    /// Remote committed authority revision carried by the authenticated observation.
    pub remote_authority_revision: Revision,
    /// Remote committed grant revision carried by the authenticated observation.
    pub remote_grant_revision: Revision,
    /// Local mesh time when the complete remote observation became durable.
    pub remote_observed_at: UnixMicros,
}

/// Derives authority only from current local consensus intersected with authenticated peer state.
///
/// A missing, revoked, expired or merely stale side returns `None`. The remote cache can therefore
/// remove authority but can never create it. Equal-identity contradictions return an error rather
/// than being treated as eventual-consistency lag.
///
/// # Errors
///
/// Fails closed when either store is corrupt or both sides claim contradictory authority under the
/// same relationship epoch, identity generation or immutable grant identity.
pub fn effective_federation_grant_authority(
    repository: &AuthoritativeRepository,
    remote_cache: &LocalDatabase,
    relationship_id: FederationRelationshipId,
    grant_id: FederationGrantId,
    now: UnixMicros,
) -> Result<Option<EffectiveFederationGrantAuthority>, EffectiveFederationGrantAuthorityError> {
    let Some(local_authority) = federation_connection_authority(repository, relationship_id, now)?
    else {
        return Ok(None);
    };
    let Some(local_grant) = repository.active_federation_grant(grant_id)? else {
        return Ok(None);
    };
    let Some(remote) = remote_cache.remote_federation_grant_authority(relationship_id, grant_id)?
    else {
        return Ok(None);
    };
    evaluate_authority(&local_authority, &local_grant, &remote, now)
}

fn evaluate_authority(
    local_authority: &FederationConnectionAuthority,
    local_grant: &FederationGrantRecord,
    remote: &CachedFederationGrantAuthority,
    now: UnixMicros,
) -> Result<Option<EffectiveFederationGrantAuthority>, EffectiveFederationGrantAuthorityError> {
    if !relationship_shape_is_mirrored(local_authority, &remote.relationship) {
        return Err(EffectiveFederationGrantAuthorityError::ContradictoryAuthority);
    }
    if local_authority.peer.authority_epoch != remote.relationship.relationship.authority_epoch
        || !identity_generations_match(local_authority, &remote.relationship)
    {
        return Ok(None);
    }
    if !identity_values_match(local_authority, &remote.relationship) {
        return Err(EffectiveFederationGrantAuthorityError::ContradictoryAuthority);
    }
    if remote.grant.state != FederationGrantState::Active {
        return Ok(None);
    }
    if local_grant.grant.authority_epoch() != local_authority.peer.authority_epoch
        || remote.grant.grant.authority_epoch() != local_authority.peer.authority_epoch
    {
        return Ok(None);
    }
    if local_grant.grant != remote.grant.grant
        || local_grant.restrictions != remote.grant.restrictions
    {
        return Err(EffectiveFederationGrantAuthorityError::ContradictoryAuthority);
    }
    let grant = local_grant.grant;
    if now < grant.valid_from() || grant.valid_until().is_some_and(|until| now >= until) {
        return Ok(None);
    }
    Ok(Some(EffectiveFederationGrantAuthority {
        grant,
        local_authority_revision: local_authority.authority_revision,
        local_grant_revision: local_grant.revision,
        remote_authority_revision: remote.authority_revision,
        remote_grant_revision: remote.grant.revision,
        remote_observed_at: remote.observed_at,
    }))
}

fn relationship_shape_is_mirrored(
    local: &FederationConnectionAuthority,
    remote: &FederationTransportAuthority,
) -> bool {
    let relationship = &remote.relationship;
    relationship.relationship_id == local.peer.relationship_id
        && relationship.local_mesh_id == local.peer.remote_mesh_id
        && relationship.remote_mesh_id == local.peer.local_mesh_id
        && relationship.kind == local.relationship_kind
        && relationship.governance_direction == mirrored_direction(local.governance_direction)
}

fn identity_generations_match(
    local: &FederationConnectionAuthority,
    remote: &FederationTransportAuthority,
) -> bool {
    remote.local_identity.identity.generation == local.peer.identity_generation
        && remote.remote_identity.identity.generation == local.local_identity.identity_generation
}

fn identity_values_match(
    local: &FederationConnectionAuthority,
    remote: &FederationTransportAuthority,
) -> bool {
    let remote_local = remote.local_identity.identity;
    let remote_peer = remote.remote_identity.identity;
    remote_local.certificate_fingerprint == local.peer.certificate_fingerprint
        && remote_local.verifying_key == local.peer.verifying_key
        && remote_local.valid_from == local.peer.valid_from
        && remote_local.valid_until == local.peer.valid_until
        && remote_peer.certificate_fingerprint == local.local_identity.certificate_fingerprint
        && remote_peer.verifying_key == local.local_identity.verifying_key
        && remote_peer.valid_from == local.local_identity.valid_from
        && remote_peer.valid_until == local.local_identity.valid_until
}

const fn mirrored_direction(
    direction: FederationGovernanceDirection,
) -> FederationGovernanceDirection {
    match direction {
        FederationGovernanceDirection::None => FederationGovernanceDirection::None,
        FederationGovernanceDirection::LocalGovernsRemote => {
            FederationGovernanceDirection::RemoteGovernsLocal
        }
        FederationGovernanceDirection::RemoteGovernsLocal => {
            FederationGovernanceDirection::LocalGovernsRemote
        }
    }
}

/// Closed failures while intersecting independent federation authorities.
#[derive(Debug, Error)]
pub enum EffectiveFederationGrantAuthorityError {
    /// Local relationship or identity authority was unreadable or invalid.
    #[error("local federation relationship authority is unavailable")]
    LocalAuthority(#[from] FederationAuthorityError),
    /// Local replicated grant evidence was unreadable or corrupt.
    #[error("local federation grant authority is unavailable")]
    LocalGrant(#[from] RepositoryError),
    /// The authenticated remote observation was unreadable or corrupt.
    #[error("remote federation grant observation is unavailable")]
    RemoteObservation(#[from] FederationRemoteAuthorityCacheError),
    /// Both sides claim incompatible authority under one supposedly identical fence.
    #[error("federation authorities contradict one another")]
    ContradictoryAuthority,
}

#[cfg(test)]
#[path = "federation_grant_authority_tests.rs"]
mod tests;
