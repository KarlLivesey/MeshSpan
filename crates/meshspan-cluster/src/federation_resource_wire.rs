// SPDX-License-Identifier: GPL-2.0-only

//! Canonical private-wire encoding for one typed federation resource scope.

use meshspan_domain::{FederationResourceScope, MeshId, ObjectId, VolumeId};
use meshspan_protocol::v1::VersionedPayload;
use thiserror::Error;

const FORMAT_VERSION: u32 = 1;
const DOMAIN: &[u8] = b"meshspan.federation.resource-scope\0";
const SIMPLE_LENGTH: usize = DOMAIN.len() + 1 + 16 + 16;
const OBJECT_LENGTH: usize = SIMPLE_LENGTH + 16;

/// Encodes an exact owner-qualified resource without using text or platform paths.
#[must_use]
pub fn version_federation_resource_scope(resource: FederationResourceScope) -> VersionedPayload {
    let mut bytes = Vec::with_capacity(OBJECT_LENGTH);
    bytes.extend_from_slice(DOMAIN);
    match resource {
        FederationResourceScope::Volume {
            owner_mesh_id,
            volume_id,
        } => {
            bytes.push(1);
            bytes.extend_from_slice(&owner_mesh_id.as_bytes());
            bytes.extend_from_slice(&volume_id.as_bytes());
        }
        FederationResourceScope::Subtree {
            owner_mesh_id,
            volume_id,
            root_object_id,
        } => {
            bytes.push(2);
            bytes.extend_from_slice(&owner_mesh_id.as_bytes());
            bytes.extend_from_slice(&volume_id.as_bytes());
            bytes.extend_from_slice(&root_object_id.as_bytes());
        }
        FederationResourceScope::File {
            owner_mesh_id,
            volume_id,
            object_id,
        } => {
            bytes.push(3);
            bytes.extend_from_slice(&owner_mesh_id.as_bytes());
            bytes.extend_from_slice(&volume_id.as_bytes());
            bytes.extend_from_slice(&object_id.as_bytes());
        }
        FederationResourceScope::StorageCapacity { provider_mesh_id } => {
            bytes.push(4);
            bytes.extend_from_slice(&provider_mesh_id.as_bytes());
        }
    }
    VersionedPayload {
        format_version: FORMAT_VERSION,
        canonical_bytes: bytes,
    }
}

pub(crate) fn decode_federation_resource_scope(
    payload: &VersionedPayload,
) -> Result<FederationResourceScope, FederationResourceWireError> {
    if payload.format_version != FORMAT_VERSION || !payload.canonical_bytes.starts_with(DOMAIN) {
        return Err(FederationResourceWireError::Invalid);
    }
    let encoded = &payload.canonical_bytes[DOMAIN.len()..];
    let (&kind, identifiers) = encoded
        .split_first()
        .ok_or(FederationResourceWireError::Invalid)?;
    match (kind, identifiers.len()) {
        (1, length) if payload.canonical_bytes.len() == SIMPLE_LENGTH && length == 32 => {
            Ok(FederationResourceScope::Volume {
                owner_mesh_id: mesh(&identifiers[..16])?,
                volume_id: volume(&identifiers[16..])?,
            })
        }
        (2, length) if payload.canonical_bytes.len() == OBJECT_LENGTH && length == 48 => {
            Ok(FederationResourceScope::Subtree {
                owner_mesh_id: mesh(&identifiers[..16])?,
                volume_id: volume(&identifiers[16..32])?,
                root_object_id: object(&identifiers[32..])?,
            })
        }
        (3, length) if payload.canonical_bytes.len() == OBJECT_LENGTH && length == 48 => {
            Ok(FederationResourceScope::File {
                owner_mesh_id: mesh(&identifiers[..16])?,
                volume_id: volume(&identifiers[16..32])?,
                object_id: object(&identifiers[32..])?,
            })
        }
        (4, 16) => Ok(FederationResourceScope::StorageCapacity {
            provider_mesh_id: mesh(identifiers)?,
        }),
        _ => Err(FederationResourceWireError::Invalid),
    }
}

fn mesh(bytes: &[u8]) -> Result<MeshId, FederationResourceWireError> {
    MeshId::from_bytes(exact(bytes)?).map_err(|_| FederationResourceWireError::Invalid)
}

fn volume(bytes: &[u8]) -> Result<VolumeId, FederationResourceWireError> {
    VolumeId::from_bytes(exact(bytes)?).map_err(|_| FederationResourceWireError::Invalid)
}

fn object(bytes: &[u8]) -> Result<ObjectId, FederationResourceWireError> {
    ObjectId::from_bytes(exact(bytes)?).map_err(|_| FederationResourceWireError::Invalid)
}

fn exact(bytes: &[u8]) -> Result<[u8; 16], FederationResourceWireError> {
    bytes
        .try_into()
        .map_err(|_| FederationResourceWireError::Invalid)
}

/// A resource payload was not the one exact supported canonical form.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum FederationResourceWireError {
    /// Version, domain, type, length or stable identifier was invalid.
    #[error("federation resource scope is invalid")]
    Invalid,
}

#[cfg(test)]
mod tests {
    use meshspan_domain::{FederationResourceScope, MeshId, ObjectId, VolumeId};

    use super::{decode_federation_resource_scope, version_federation_resource_scope};

    #[test]
    fn every_scope_round_trips_and_trailing_or_unknown_bytes_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let mesh = MeshId::from_bytes([1; 16])?;
        let volume = VolumeId::from_bytes([2; 16])?;
        let object = ObjectId::from_bytes([3; 16])?;
        let scopes = [
            FederationResourceScope::Volume {
                owner_mesh_id: mesh,
                volume_id: volume,
            },
            FederationResourceScope::Subtree {
                owner_mesh_id: mesh,
                volume_id: volume,
                root_object_id: object,
            },
            FederationResourceScope::File {
                owner_mesh_id: mesh,
                volume_id: volume,
                object_id: object,
            },
            FederationResourceScope::StorageCapacity {
                provider_mesh_id: mesh,
            },
        ];
        for scope in scopes {
            let payload = version_federation_resource_scope(scope);
            assert_eq!(decode_federation_resource_scope(&payload), Ok(scope));
            let mut trailing = payload.clone();
            trailing.canonical_bytes.push(0);
            assert!(decode_federation_resource_scope(&trailing).is_err());
            let mut unknown_version = payload;
            unknown_version.format_version = 2;
            assert!(decode_federation_resource_scope(&unknown_version).is_err());
        }
        Ok(())
    }
}
