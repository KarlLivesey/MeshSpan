// SPDX-License-Identifier: GPL-2.0-only

//! Composition from authoritative relationship metadata into transport-only peer bindings.

use meshspan_domain::{FederationRelationshipId, FederationRelationshipKind, Revision, UnixMicros};
use meshspan_metadata::{
    AuthoritativeRepository, FederationGovernanceDirection, FederationIdentityOwner,
    FederationRelationshipState, FederationTransportAuthority, FederationTrustIdentity,
    RepositoryError,
};
use meshspan_transport::{FederationLocalIdentityBinding, FederationPeerBinding};
use thiserror::Error;

/// Complete local/remote authority required to configure one federation connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationConnectionAuthority {
    /// Exact committed partition revision producing both identities and the relationship fence.
    pub authority_revision: Revision,
    /// Horizontal or hierarchical relationship expected from both perspectives.
    pub relationship_kind: FederationRelationshipKind,
    /// Hierarchical direction from this local swarm's perspective.
    pub governance_direction: FederationGovernanceDirection,
    /// Remote certificate and signing identity accepted by transport.
    pub peer: FederationPeerBinding,
    /// Local public identity whose private material remains outside replicated metadata.
    pub local_identity: FederationLocalIdentityBinding,
}

/// Loads one relationship only when authoritative metadata currently admits transport use.
///
/// # Errors
///
/// Fails closed on corrupt metadata or an internally inconsistent authority projection.
pub fn federation_connection_authority(
    repository: &AuthoritativeRepository,
    relationship_id: FederationRelationshipId,
    now: UnixMicros,
) -> Result<Option<FederationConnectionAuthority>, FederationAuthorityError> {
    repository
        .federation_transport_authority(relationship_id)?
        .map(|authority| connection_authority(&authority, now))
        .transpose()
}

fn connection_authority(
    authority: &FederationTransportAuthority,
    now: UnixMicros,
) -> Result<FederationConnectionAuthority, FederationAuthorityError> {
    let relationship = &authority.relationship;
    let local = authority.local_identity;
    let remote = authority.remote_identity;
    let identity_mismatch = local.relationship_id != relationship.relationship_id
        || remote.relationship_id != relationship.relationship_id
        || local.owner != FederationIdentityOwner::Local
        || remote.owner != FederationIdentityOwner::Remote
        || local.identity.certificate_fingerprint == remote.identity.certificate_fingerprint
        || local.identity.verifying_key == remote.identity.verifying_key;
    if !matches!(
        relationship.state,
        FederationRelationshipState::Active | FederationRelationshipState::Restricted
    ) || identity_mismatch
    {
        return Err(FederationAuthorityError::InvalidProjection);
    }
    if !identity_is_current(local.identity, now) || !identity_is_current(remote.identity, now) {
        return Err(FederationAuthorityError::IdentityNotCurrent);
    }
    Ok(FederationConnectionAuthority {
        authority_revision: authority.authority_revision,
        relationship_kind: relationship.kind,
        governance_direction: relationship.governance_direction,
        peer: FederationPeerBinding {
            relationship_id: relationship.relationship_id,
            local_mesh_id: relationship.local_mesh_id,
            remote_mesh_id: relationship.remote_mesh_id,
            authority_epoch: relationship.authority_epoch,
            identity_generation: remote.identity.generation,
            certificate_fingerprint: remote.identity.certificate_fingerprint,
            verifying_key: remote.identity.verifying_key,
            valid_from: remote.identity.valid_from,
            valid_until: remote.identity.valid_until,
        },
        local_identity: FederationLocalIdentityBinding {
            relationship_id: relationship.relationship_id,
            local_mesh_id: relationship.local_mesh_id,
            remote_mesh_id: relationship.remote_mesh_id,
            authority_epoch: relationship.authority_epoch,
            identity_generation: local.identity.generation,
            certificate_fingerprint: local.identity.certificate_fingerprint,
            verifying_key: local.identity.verifying_key,
            valid_from: local.identity.valid_from,
            valid_until: local.identity.valid_until,
        },
    })
}

const fn identity_is_current(identity: FederationTrustIdentity, now: UnixMicros) -> bool {
    identity.valid_from.get() <= now.get() && now.get() < identity.valid_until.get()
}

/// Failure to derive live federation transport authority from committed metadata.
#[derive(Debug, Error)]
pub enum FederationAuthorityError {
    /// Authoritative metadata was missing, corrupt or unreadable.
    #[error("federation authority metadata could not be read")]
    Metadata(#[from] RepositoryError),
    /// A supposedly complete projection contradicts its relationship or identity owners.
    #[error("federation authority projection is inconsistent")]
    InvalidProjection,
    /// Either side's current public identity is not valid at authoritative mesh time.
    #[error("federation authority identity is not currently valid")]
    IdentityNotCurrent,
}

#[cfg(test)]
mod tests {
    use meshspan_domain::{
        FederationRelationshipId, FederationRelationshipKind, MeshId, Revision, UnixMicros,
    };
    use meshspan_metadata::{
        FederationGovernanceDirection, FederationIdentityOwner, FederationRelationshipRecord,
        FederationRelationshipState, FederationTransportAuthority, FederationTrustIdentityRecord,
    };

    use super::{FederationAuthorityError, connection_authority};

    #[test]
    fn only_current_consistent_active_or_restricted_authority_becomes_transport_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        let active = authority(FederationRelationshipState::Active)?;
        let admitted = connection_authority(&active, UnixMicros::new(50))?;
        assert_eq!(
            admitted.peer.relationship_id,
            active.relationship.relationship_id
        );
        assert_eq!(admitted.peer.identity_generation, 2);
        assert_eq!(admitted.authority_revision, Revision::new(5));
        assert_eq!(admitted.local_identity.identity_generation, 1);
        assert_eq!(
            admitted.local_identity.local_mesh_id,
            active.relationship.local_mesh_id
        );
        assert_eq!(
            admitted.local_identity.remote_mesh_id,
            active.relationship.remote_mesh_id
        );

        let restricted = authority(FederationRelationshipState::Restricted)?;
        assert!(connection_authority(&restricted, UnixMicros::new(50)).is_ok());

        let revoked = authority(FederationRelationshipState::Revoked)?;
        assert!(matches!(
            connection_authority(&revoked, UnixMicros::new(50)),
            Err(FederationAuthorityError::InvalidProjection)
        ));

        assert!(matches!(
            connection_authority(&active, UnixMicros::new(100)),
            Err(FederationAuthorityError::IdentityNotCurrent)
        ));

        let mut swapped = active.clone();
        swapped.remote_identity.owner = FederationIdentityOwner::Local;
        assert!(matches!(
            connection_authority(&swapped, UnixMicros::new(50)),
            Err(FederationAuthorityError::InvalidProjection)
        ));
        Ok(())
    }

    fn authority(
        state: FederationRelationshipState,
    ) -> Result<FederationTransportAuthority, Box<dyn std::error::Error>> {
        let relationship_id = FederationRelationshipId::from_bytes([1; 16])?;
        Ok(FederationTransportAuthority {
            authority_revision: Revision::new(5),
            relationship: FederationRelationshipRecord {
                relationship_id,
                local_mesh_id: MeshId::from_bytes([2; 16])?,
                remote_mesh_id: MeshId::from_bytes([3; 16])?,
                kind: FederationRelationshipKind::Horizontal,
                governance_direction: FederationGovernanceDirection::None,
                state,
                authority_epoch: 4,
                remote_display_name: "Partner".to_owned(),
                revision: Revision::new(5),
            },
            local_identity: identity(relationship_id, FederationIdentityOwner::Local, 1, 6, 7),
            remote_identity: identity(relationship_id, FederationIdentityOwner::Remote, 2, 8, 9),
        })
    }

    fn identity(
        relationship_id: FederationRelationshipId,
        owner: FederationIdentityOwner,
        generation: u64,
        certificate: u8,
        key: u8,
    ) -> FederationTrustIdentityRecord {
        FederationTrustIdentityRecord {
            relationship_id,
            owner,
            identity: meshspan_metadata::FederationTrustIdentity {
                generation,
                certificate_fingerprint: [certificate; 32],
                verifying_key: ed25519_dalek::SigningKey::from_bytes(&[key; 32])
                    .verifying_key()
                    .to_bytes(),
                valid_from: UnixMicros::new(1),
                valid_until: UnixMicros::new(100),
            },
            revision: Revision::new(5),
        }
    }
}
