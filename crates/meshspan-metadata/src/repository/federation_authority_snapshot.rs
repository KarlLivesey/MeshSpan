// SPDX-License-Identifier: GPL-2.0-only

//! Canonical, engine-independent representation of current relationship authority.

mod codec;

use ed25519_dalek::VerifyingKey;
use meshspan_domain::{FederationRelationshipId, FederationRelationshipKind, Revision};
use thiserror::Error;

use super::federation_query::{
    FederationRelationshipState, FederationTransportAuthority, FederationTrustIdentityRecord,
};
use crate::{FederationGovernanceDirection, FederationIdentityOwner, RecordName};

/// Encoding or decoding failure for one relationship authority snapshot.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum FederationAuthoritySnapshotError {
    /// The byte representation is truncated, excessive or semantically inconsistent.
    #[error("federation authority snapshot is invalid")]
    Invalid,
    /// The snapshot uses a format this implementation does not understand.
    #[error("federation authority snapshot format is unsupported")]
    UnsupportedVersion,
}

impl FederationTransportAuthority {
    /// Encodes this complete projection into deterministic, engine-independent bytes.
    ///
    /// # Errors
    ///
    /// Rejects an inconsistent projection instead of serialising ambiguous authority.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FederationAuthoritySnapshotError> {
        validate_authority(self)?;
        codec::encode(self)
    }

    /// Decodes and fully validates one canonical relationship authority snapshot.
    ///
    /// # Errors
    ///
    /// Rejects unknown versions, trailing bytes and inconsistent relationship or identity fields.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, FederationAuthoritySnapshotError> {
        let authority = codec::decode(bytes)?;
        validate_authority(&authority)?;
        Ok(authority)
    }
}

pub(super) fn validate_authority(
    authority: &FederationTransportAuthority,
) -> Result<(), FederationAuthoritySnapshotError> {
    let relationship = &authority.relationship;
    let valid_name = RecordName::new(&relationship.remote_display_name)
        .is_ok_and(|name| name.display() == relationship.remote_display_name);
    let valid_shape = relationship.local_mesh_id != relationship.remote_mesh_id
        && relationship.authority_epoch > 0
        && relationship.revision.get() > 0
        && relationship.revision <= authority.authority_revision
        && valid_name
        && valid_relationship_shape(relationship.kind, relationship.governance_direction)
        && matches!(
            relationship.state,
            FederationRelationshipState::Active | FederationRelationshipState::Restricted
        );
    if !valid_shape
        || !valid_identity(
            authority.local_identity,
            FederationIdentityOwner::Local,
            relationship.relationship_id,
            authority.authority_revision,
        )
        || !valid_identity(
            authority.remote_identity,
            FederationIdentityOwner::Remote,
            relationship.relationship_id,
            authority.authority_revision,
        )
        || authority.local_identity.identity.certificate_fingerprint
            == authority.remote_identity.identity.certificate_fingerprint
        || authority.local_identity.identity.verifying_key
            == authority.remote_identity.identity.verifying_key
    {
        Err(FederationAuthoritySnapshotError::Invalid)
    } else {
        Ok(())
    }
}

fn valid_identity(
    record: FederationTrustIdentityRecord,
    owner: FederationIdentityOwner,
    relationship_id: FederationRelationshipId,
    authority_revision: Revision,
) -> bool {
    record.relationship_id == relationship_id
        && record.owner == owner
        && record.identity.generation > 0
        && record.identity.valid_until > record.identity.valid_from
        && record.identity.certificate_fingerprint != [0; 32]
        && record.identity.verifying_key != [0; 32]
        && VerifyingKey::from_bytes(&record.identity.verifying_key).is_ok()
        && record.revision.get() > 0
        && record.revision <= authority_revision
}

const fn valid_relationship_shape(
    kind: FederationRelationshipKind,
    direction: FederationGovernanceDirection,
) -> bool {
    matches!(
        (kind, direction),
        (
            FederationRelationshipKind::Horizontal,
            FederationGovernanceDirection::None
        ) | (
            FederationRelationshipKind::Governance,
            FederationGovernanceDirection::LocalGovernsRemote
                | FederationGovernanceDirection::RemoteGovernsLocal
        )
    )
}

pub(super) const fn kind_code(kind: FederationRelationshipKind) -> u8 {
    match kind {
        FederationRelationshipKind::Horizontal => 1,
        FederationRelationshipKind::Governance => 2,
    }
}

pub(super) const fn direction_code(direction: FederationGovernanceDirection) -> u8 {
    match direction {
        FederationGovernanceDirection::None => 0,
        FederationGovernanceDirection::LocalGovernsRemote => 1,
        FederationGovernanceDirection::RemoteGovernsLocal => 2,
    }
}

pub(super) const fn state_code(state: FederationRelationshipState) -> u8 {
    match state {
        FederationRelationshipState::Proposed => 1,
        FederationRelationshipState::Active => 2,
        FederationRelationshipState::Restricted => 3,
        FederationRelationshipState::Revoked => 4,
        FederationRelationshipState::Retired => 5,
    }
}

pub(super) const fn owner_code(owner: FederationIdentityOwner) -> u8 {
    match owner {
        FederationIdentityOwner::Local => 1,
        FederationIdentityOwner::Remote => 2,
    }
}

pub(super) fn decode_kind(
    value: u8,
) -> Result<FederationRelationshipKind, FederationAuthoritySnapshotError> {
    match value {
        1 => Ok(FederationRelationshipKind::Horizontal),
        2 => Ok(FederationRelationshipKind::Governance),
        _ => Err(FederationAuthoritySnapshotError::Invalid),
    }
}

pub(super) fn decode_direction(
    value: u8,
) -> Result<FederationGovernanceDirection, FederationAuthoritySnapshotError> {
    match value {
        0 => Ok(FederationGovernanceDirection::None),
        1 => Ok(FederationGovernanceDirection::LocalGovernsRemote),
        2 => Ok(FederationGovernanceDirection::RemoteGovernsLocal),
        _ => Err(FederationAuthoritySnapshotError::Invalid),
    }
}

pub(super) fn decode_state(
    value: u8,
) -> Result<FederationRelationshipState, FederationAuthoritySnapshotError> {
    match value {
        1 => Ok(FederationRelationshipState::Proposed),
        2 => Ok(FederationRelationshipState::Active),
        3 => Ok(FederationRelationshipState::Restricted),
        4 => Ok(FederationRelationshipState::Revoked),
        5 => Ok(FederationRelationshipState::Retired),
        _ => Err(FederationAuthoritySnapshotError::Invalid),
    }
}

pub(super) fn decode_owner(
    value: u8,
) -> Result<FederationIdentityOwner, FederationAuthoritySnapshotError> {
    match value {
        1 => Ok(FederationIdentityOwner::Local),
        2 => Ok(FederationIdentityOwner::Remote),
        _ => Err(FederationAuthoritySnapshotError::Invalid),
    }
}

pub(super) fn positive_revision(value: u64) -> Result<Revision, FederationAuthoritySnapshotError> {
    if value == 0 {
        Err(FederationAuthoritySnapshotError::Invalid)
    } else {
        Ok(Revision::new(value))
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use meshspan_domain::{
        FederationRelationshipId, FederationRelationshipKind, MeshId, Revision, UnixMicros,
    };

    use super::{FederationAuthoritySnapshotError, FederationTransportAuthority};
    use crate::{
        FederationGovernanceDirection, FederationIdentityOwner, FederationRelationshipRecord,
        FederationRelationshipState, FederationTrustIdentity, FederationTrustIdentityRecord,
    };

    #[test]
    fn canonical_snapshot_round_trips_and_rejects_substitution()
    -> Result<(), Box<dyn std::error::Error>> {
        let authority = authority()?;
        let encoded = authority.canonical_bytes()?;
        assert_eq!(
            FederationTransportAuthority::from_canonical_bytes(&encoded)?,
            authority
        );

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            FederationTransportAuthority::from_canonical_bytes(&trailing),
            Err(FederationAuthoritySnapshotError::Invalid)
        );
        assert_eq!(
            FederationTransportAuthority::from_canonical_bytes(&encoded[..encoded.len() - 1]),
            Err(FederationAuthoritySnapshotError::Invalid)
        );
        let mut unsupported = encoded;
        unsupported[super::codec::DOMAIN.len() + 1] = 2;
        assert_eq!(
            FederationTransportAuthority::from_canonical_bytes(&unsupported),
            Err(FederationAuthoritySnapshotError::UnsupportedVersion)
        );
        let mut reflected = authority;
        reflected.remote_identity.identity.verifying_key =
            reflected.local_identity.identity.verifying_key;
        assert_eq!(
            reflected.canonical_bytes(),
            Err(FederationAuthoritySnapshotError::Invalid)
        );
        Ok(())
    }

    fn authority() -> Result<FederationTransportAuthority, Box<dyn std::error::Error>> {
        let relationship_id = FederationRelationshipId::from_bytes([1; 16])?;
        Ok(FederationTransportAuthority {
            authority_revision: Revision::new(9),
            relationship: FederationRelationshipRecord {
                relationship_id,
                local_mesh_id: MeshId::from_bytes([2; 16])?,
                remote_mesh_id: MeshId::from_bytes([3; 16])?,
                kind: FederationRelationshipKind::Horizontal,
                governance_direction: FederationGovernanceDirection::None,
                state: FederationRelationshipState::Restricted,
                authority_epoch: 4,
                remote_display_name: "Remote swarm".to_owned(),
                revision: Revision::new(9),
            },
            local_identity: identity(relationship_id, FederationIdentityOwner::Local, 4, 5),
            remote_identity: identity(relationship_id, FederationIdentityOwner::Remote, 6, 7),
        })
    }

    fn identity(
        relationship_id: FederationRelationshipId,
        owner: FederationIdentityOwner,
        generation: u64,
        seed: u8,
    ) -> FederationTrustIdentityRecord {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        FederationTrustIdentityRecord {
            relationship_id,
            owner,
            identity: FederationTrustIdentity {
                generation,
                certificate_fingerprint: [seed.saturating_add(1); 32],
                verifying_key: signing_key.verifying_key().to_bytes(),
                valid_from: UnixMicros::new(100),
                valid_until: UnixMicros::new(10_000),
            },
            revision: Revision::new(8),
        }
    }
}
