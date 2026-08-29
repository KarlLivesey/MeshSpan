// SPDX-License-Identifier: GPL-2.0-only

//! Validated typed reads for federation admission and transport authentication.

use meshspan_domain::{
    FederationRelationshipId, FederationRelationshipKind, MeshId, Revision, UnixMicros,
};
use rusqlite::{OptionalExtension, params};

use super::RepositoryError;
use crate::{
    FederationGovernanceDirection, FederationIdentityOwner, FederationTrustIdentity,
    PartitionDatabase,
};

/// Closed relationship lifecycle visible to callers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FederationRelationshipState {
    /// Waiting for mutual approval and both trust identities.
    Proposed,
    /// Fully active.
    Active,
    /// Connected but deliberately narrowed.
    Restricted,
    /// Authority has been revoked.
    Revoked,
    /// Historical only.
    Retired,
}

/// Validated current relationship projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationRelationshipRecord {
    /// Stable relationship identity.
    pub relationship_id: FederationRelationshipId,
    /// This autonomous swarm.
    pub local_mesh_id: MeshId,
    /// Peer autonomous swarm.
    pub remote_mesh_id: MeshId,
    /// Horizontal or hierarchical relationship.
    pub kind: FederationRelationshipKind,
    /// Hierarchical direction from the local perspective.
    pub governance_direction: FederationGovernanceDirection,
    /// Current fenced lifecycle state.
    pub state: FederationRelationshipState,
    /// Exact current authority epoch.
    pub authority_epoch: u64,
    /// Display-only peer name.
    pub remote_display_name: String,
    /// Last authoritative revision.
    pub revision: Revision,
}

/// One validated active public identity used to authenticate federation envelopes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationTrustIdentityRecord {
    /// Relationship carrying the identity.
    pub relationship_id: FederationRelationshipId,
    /// Side presenting it.
    pub owner: FederationIdentityOwner,
    /// Public identity and validity interval.
    pub identity: FederationTrustIdentity,
    /// Last authoritative revision.
    pub revision: Revision,
}

/// Complete active relationship authority needed to construct one federation transport binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationTransportAuthority {
    /// Independently evidence-verified active or restricted relationship.
    pub relationship: FederationRelationshipRecord,
    /// Current identity which this swarm presents.
    pub local_identity: FederationTrustIdentityRecord,
    /// Current identity which the remote swarm presents.
    pub remote_identity: FederationTrustIdentityRecord,
}

pub(super) fn relationship(
    database: &PartitionDatabase,
    relationship_id: FederationRelationshipId,
) -> Result<Option<FederationRelationshipRecord>, RepositoryError> {
    let row = database
        .connection()
        .query_row(
            "SELECT local_mesh_id, remote_mesh_id, relationship_kind,
                    governance_direction, state, authority_epoch,
                    remote_display_name, revision
             FROM federation_relationships WHERE relationship_id = ?1",
            [relationship_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            },
        )
        .optional()?;
    row.map(|row| {
        let kind = parse_kind(row.2)?;
        let governance_direction = parse_direction(row.3)?;
        validate_shape(kind, governance_direction)?;
        if row.6.is_empty() || row.6.len() > 256 {
            return Err(RepositoryError::CorruptState);
        }
        let record = FederationRelationshipRecord {
            relationship_id,
            local_mesh_id: parse_mesh(&row.0)?,
            remote_mesh_id: parse_mesh(&row.1)?,
            kind,
            governance_direction,
            state: parse_state(row.4)?,
            authority_epoch: positive(row.5)?,
            remote_display_name: row.6,
            revision: Revision::new(positive(row.7)?),
        };
        super::federation_relationship_evidence::verify(database, &record)?;
        Ok(record)
    })
    .transpose()
}

pub(super) fn active_identity(
    database: &PartitionDatabase,
    relationship_id: FederationRelationshipId,
    owner: FederationIdentityOwner,
) -> Result<Option<FederationTrustIdentityRecord>, RepositoryError> {
    let mut statement = database.connection().prepare(
        "SELECT generation, certificate_fingerprint, verifying_key,
                valid_from, valid_until, revision
         FROM federation_trust_identities
         WHERE relationship_id = ?1 AND identity_owner = ?2 AND state = 1
         ORDER BY generation DESC LIMIT 2",
    )?;
    let rows = statement
        .query_map(
            params![relationship_id.as_bytes().as_slice(), owner.code()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.len() > 1 {
        return Err(RepositoryError::CorruptState);
    }
    rows.into_iter()
        .next()
        .map(|row| {
            let valid_from = UnixMicros::new(row.3);
            let valid_until = UnixMicros::new(row.4);
            if valid_until <= valid_from {
                return Err(RepositoryError::CorruptState);
            }
            Ok(FederationTrustIdentityRecord {
                relationship_id,
                owner,
                identity: FederationTrustIdentity {
                    generation: positive(row.0)?,
                    certificate_fingerprint: exact_32(&row.1)?,
                    verifying_key: exact_32(&row.2)?,
                    valid_from,
                    valid_until,
                },
                revision: Revision::new(positive(row.5)?),
            })
        })
        .transpose()
}

pub(super) fn transport_authority(
    database: &PartitionDatabase,
    relationship_id: FederationRelationshipId,
) -> Result<Option<FederationTransportAuthority>, RepositoryError> {
    let Some(relationship) = relationship(database, relationship_id)? else {
        return Ok(None);
    };
    if !matches!(
        relationship.state,
        FederationRelationshipState::Active | FederationRelationshipState::Restricted
    ) {
        return Ok(None);
    }
    let local_identity =
        active_identity(database, relationship_id, FederationIdentityOwner::Local)?
            .ok_or(RepositoryError::CorruptState)?;
    let remote_identity =
        active_identity(database, relationship_id, FederationIdentityOwner::Remote)?
            .ok_or(RepositoryError::CorruptState)?;
    Ok(Some(FederationTransportAuthority {
        relationship,
        local_identity,
        remote_identity,
    }))
}

fn parse_kind(value: i64) -> Result<FederationRelationshipKind, RepositoryError> {
    match value {
        1 => Ok(FederationRelationshipKind::Horizontal),
        2 => Ok(FederationRelationshipKind::Governance),
        _ => Err(RepositoryError::CorruptState),
    }
}

fn parse_direction(value: i64) -> Result<FederationGovernanceDirection, RepositoryError> {
    match value {
        0 => Ok(FederationGovernanceDirection::None),
        1 => Ok(FederationGovernanceDirection::LocalGovernsRemote),
        2 => Ok(FederationGovernanceDirection::RemoteGovernsLocal),
        _ => Err(RepositoryError::CorruptState),
    }
}

fn validate_shape(
    kind: FederationRelationshipKind,
    direction: FederationGovernanceDirection,
) -> Result<(), RepositoryError> {
    match (kind, direction) {
        (FederationRelationshipKind::Horizontal, FederationGovernanceDirection::None)
        | (
            FederationRelationshipKind::Governance,
            FederationGovernanceDirection::LocalGovernsRemote
            | FederationGovernanceDirection::RemoteGovernsLocal,
        ) => Ok(()),
        _ => Err(RepositoryError::CorruptState),
    }
}

fn parse_state(value: i64) -> Result<FederationRelationshipState, RepositoryError> {
    match value {
        1 => Ok(FederationRelationshipState::Proposed),
        2 => Ok(FederationRelationshipState::Active),
        3 => Ok(FederationRelationshipState::Restricted),
        4 => Ok(FederationRelationshipState::Revoked),
        5 => Ok(FederationRelationshipState::Retired),
        _ => Err(RepositoryError::CorruptState),
    }
}

fn parse_mesh(value: &[u8]) -> Result<MeshId, RepositoryError> {
    let bytes = value
        .try_into()
        .map_err(|_| RepositoryError::CorruptState)?;
    MeshId::from_bytes(bytes).map_err(|_| RepositoryError::CorruptState)
}

fn exact_32(value: &[u8]) -> Result<[u8; 32], RepositoryError> {
    value.try_into().map_err(|_| RepositoryError::CorruptState)
}

fn positive(value: i64) -> Result<u64, RepositoryError> {
    let value = u64::try_from(value).map_err(|_| RepositoryError::CorruptState)?;
    if value == 0 {
        Err(RepositoryError::CorruptState)
    } else {
        Ok(value)
    }
}
