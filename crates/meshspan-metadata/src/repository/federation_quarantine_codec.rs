// SPDX-License-Identifier: GPL-2.0-only

//! Strict SQLite representation codecs for federated quarantine evidence.

use meshspan_domain::{
    FederationGrantId, FederationRelationshipId, FederationResourceScope, MeshId, ObjectId,
    OperationId, PrincipalId, QuarantineReason, Rights, VolumeId,
};

use super::RepositoryError;
use crate::FederationQuarantineResolution;

pub(super) fn resource_columns(
    resource: FederationResourceScope,
) -> (i64, MeshId, Option<Vec<u8>>, Option<Vec<u8>>) {
    match resource {
        FederationResourceScope::Volume {
            owner_mesh_id,
            volume_id,
        } => (1, owner_mesh_id, Some(volume_id.as_bytes().to_vec()), None),
        FederationResourceScope::Subtree {
            owner_mesh_id,
            volume_id,
            root_object_id,
        } => (
            2,
            owner_mesh_id,
            Some(volume_id.as_bytes().to_vec()),
            Some(root_object_id.as_bytes().to_vec()),
        ),
        FederationResourceScope::File {
            owner_mesh_id,
            volume_id,
            object_id,
        } => (
            3,
            owner_mesh_id,
            Some(volume_id.as_bytes().to_vec()),
            Some(object_id.as_bytes().to_vec()),
        ),
        FederationResourceScope::StorageCapacity { provider_mesh_id } => {
            (4, provider_mesh_id, None, None)
        }
    }
}

pub(super) fn parse_resource(
    kind: i64,
    authority: &[u8],
    volume: Option<&[u8]>,
    object: Option<&[u8]>,
) -> Result<FederationResourceScope, RepositoryError> {
    let authority = parse_mesh(authority)?;
    match (kind, volume, object) {
        (1, Some(volume), None) => Ok(FederationResourceScope::Volume {
            owner_mesh_id: authority,
            volume_id: parse_volume(volume)?,
        }),
        (2, Some(volume), Some(object)) => Ok(FederationResourceScope::Subtree {
            owner_mesh_id: authority,
            volume_id: parse_volume(volume)?,
            root_object_id: parse_object(object)?,
        }),
        (3, Some(volume), Some(object)) => Ok(FederationResourceScope::File {
            owner_mesh_id: authority,
            volume_id: parse_volume(volume)?,
            object_id: parse_object(object)?,
        }),
        (4, None, None) => Ok(FederationResourceScope::StorageCapacity {
            provider_mesh_id: authority,
        }),
        _ => Err(RepositoryError::CorruptState),
    }
}

pub(super) const fn reason_code(reason: QuarantineReason) -> i64 {
    match reason {
        QuarantineReason::BeforeValidity => 1,
        QuarantineReason::Expired => 2,
        QuarantineReason::Revoked => 3,
        QuarantineReason::OutsideRights => 4,
        QuarantineReason::OutsideStorageLimit => 5,
        QuarantineReason::PrincipalInactive => 6,
    }
}

pub(super) fn parse_reason(value: i64) -> Result<QuarantineReason, RepositoryError> {
    match value {
        1 => Ok(QuarantineReason::BeforeValidity),
        2 => Ok(QuarantineReason::Expired),
        3 => Ok(QuarantineReason::Revoked),
        4 => Ok(QuarantineReason::OutsideRights),
        5 => Ok(QuarantineReason::OutsideStorageLimit),
        6 => Ok(QuarantineReason::PrincipalInactive),
        _ => Err(RepositoryError::CorruptState),
    }
}

pub(super) fn parse_resolution(
    value: i64,
) -> Result<FederationQuarantineResolution, RepositoryError> {
    match value {
        1 => Ok(FederationQuarantineResolution::Restore),
        2 => Ok(FederationQuarantineResolution::RestoreAsCopy),
        3 => Ok(FederationQuarantineResolution::Discard),
        _ => Err(RepositoryError::CorruptState),
    }
}

pub(super) fn parse_rights(value: i64) -> Result<Rights, RepositoryError> {
    Rights::from_bits(u32::try_from(value).map_err(|_| RepositoryError::CorruptState)?)
        .map_err(|_| RepositoryError::CorruptState)
}

pub(super) fn positive(value: i64) -> Result<u64, RepositoryError> {
    let value = u64::try_from(value).map_err(|_| RepositoryError::CorruptState)?;
    if value == 0 {
        Err(RepositoryError::CorruptState)
    } else {
        Ok(value)
    }
}

pub(super) fn nonnegative(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value).map_err(|_| RepositoryError::CorruptState)
}

macro_rules! parse_id {
    ($name:ident, $type:ty) => {
        pub(super) fn $name(value: &[u8]) -> Result<$type, RepositoryError> {
            <$type>::from_bytes(
                value
                    .try_into()
                    .map_err(|_| RepositoryError::CorruptState)?,
            )
            .map_err(|_| RepositoryError::CorruptState)
        }
    };
}

parse_id!(parse_mesh, MeshId);
parse_id!(parse_principal, PrincipalId);
parse_id!(parse_relationship, FederationRelationshipId);
parse_id!(parse_grant, FederationGrantId);
parse_id!(parse_operation, OperationId);
parse_id!(parse_volume, VolumeId);
parse_id!(parse_object, ObjectId);

pub(super) fn parse_digest(value: &[u8]) -> Result<[u8; 32], RepositoryError> {
    value.try_into().map_err(|_| RepositoryError::CorruptState)
}

pub(super) fn parse_signature(value: &[u8]) -> Result<[u8; 64], RepositoryError> {
    value.try_into().map_err(|_| RepositoryError::CorruptState)
}
