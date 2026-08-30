// SPDX-License-Identifier: GPL-2.0-only

//! Exact fixed-width encoding for provider-issued cross-swarm shard permits.

use meshspan_contracts::FederatedShardPermit;
use meshspan_domain::{
    FederationGrantId, FederationRelationshipId, FederationStorageAction,
    FederationStorageAllocationId, MeshId, NodeId, OperationId, Revision, TargetId, UnixMicros,
};

use super::{CapabilityCodecError, Reader, push_shard};

const FEDERATED_SHARD_PERMIT_BYTES: usize = 359;

/// Encodes one exact provider-issued federated shard permit.
#[must_use]
pub fn encode_federated_shard_permit(permit: FederatedShardPermit) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(FEDERATED_SHARD_PERMIT_BYTES);
    bytes.extend_from_slice(&permit.operation_id.as_bytes());
    bytes.extend_from_slice(&permit.relationship_id.as_bytes());
    bytes.extend_from_slice(&permit.remote_mesh_id.as_bytes());
    bytes.extend_from_slice(&permit.provider_mesh_id.as_bytes());
    bytes.extend_from_slice(&permit.allocation_id.as_bytes());
    bytes.extend_from_slice(&permit.grant_id.as_bytes());
    bytes.extend_from_slice(&permit.provider_node_id.as_bytes());
    bytes.extend_from_slice(&permit.target_id.as_bytes());
    bytes.extend_from_slice(&permit.target_generation.to_be_bytes());
    push_shard(&mut bytes, permit.shard);
    bytes.push(permit.action.code());
    bytes.extend_from_slice(&permit.maximum_bytes.to_be_bytes());
    bytes.extend_from_slice(&permit.relationship_authority_epoch.to_be_bytes());
    bytes.extend_from_slice(&permit.grant_revision.get().to_be_bytes());
    bytes.extend_from_slice(&permit.allocation_revision.get().to_be_bytes());
    bytes.extend_from_slice(&permit.issued_at.get().to_be_bytes());
    bytes.extend_from_slice(&permit.expires_at.get().to_be_bytes());
    bytes.extend_from_slice(&permit.capability_nonce);
    bytes.extend_from_slice(&permit.scope_digest);
    bytes.extend_from_slice(&permit.request_digest);
    bytes.extend_from_slice(&permit.permit_digest);
    bytes
}

/// Decodes and independently validates one exact federated shard permit.
///
/// # Errors
///
/// Rejects every truncated, excessive, nil, zero, reversed-time or unknown-action encoding.
pub fn decode_federated_shard_permit(
    bytes: &[u8],
) -> Result<FederatedShardPermit, CapabilityCodecError> {
    if bytes.len() != FEDERATED_SHARD_PERMIT_BYTES {
        return Err(CapabilityCodecError::Invalid);
    }
    let mut reader = Reader::new(bytes);
    let permit = FederatedShardPermit {
        operation_id: OperationId::from_bytes(reader.array()?)
            .map_err(|_| CapabilityCodecError::Invalid)?,
        relationship_id: FederationRelationshipId::from_bytes(reader.array()?)
            .map_err(|_| CapabilityCodecError::Invalid)?,
        remote_mesh_id: MeshId::from_bytes(reader.array()?)
            .map_err(|_| CapabilityCodecError::Invalid)?,
        provider_mesh_id: MeshId::from_bytes(reader.array()?)
            .map_err(|_| CapabilityCodecError::Invalid)?,
        allocation_id: FederationStorageAllocationId::from_bytes(reader.array()?)
            .map_err(|_| CapabilityCodecError::Invalid)?,
        grant_id: FederationGrantId::from_bytes(reader.array()?)
            .map_err(|_| CapabilityCodecError::Invalid)?,
        provider_node_id: NodeId::from_bytes(reader.array()?)
            .map_err(|_| CapabilityCodecError::Invalid)?,
        target_id: TargetId::from_bytes(reader.array()?)
            .map_err(|_| CapabilityCodecError::Invalid)?,
        target_generation: reader.u64()?,
        shard: reader.shard()?,
        action: FederationStorageAction::from_code(reader.u8()?)
            .map_err(|_| CapabilityCodecError::Invalid)?,
        maximum_bytes: reader.u64()?,
        relationship_authority_epoch: reader.u64()?,
        grant_revision: Revision::new(reader.u64()?),
        allocation_revision: Revision::new(reader.u64()?),
        issued_at: UnixMicros::new(reader.i64()?),
        expires_at: UnixMicros::new(reader.i64()?),
        capability_nonce: reader.array()?,
        scope_digest: reader.array()?,
        request_digest: reader.array()?,
        permit_digest: reader.array()?,
    };
    reader.finish()?;
    validate(&permit)?;
    Ok(permit)
}

fn validate(permit: &FederatedShardPermit) -> Result<(), CapabilityCodecError> {
    let valid = permit.remote_mesh_id != permit.provider_mesh_id
        && permit.target_generation > 0
        && permit.maximum_bytes > 0
        && permit.relationship_authority_epoch > 0
        && permit.grant_revision != Revision::ZERO
        && permit.allocation_revision != Revision::ZERO
        && permit.issued_at.get() > 0
        && permit.expires_at > permit.issued_at
        && permit.capability_nonce != [0; 32]
        && permit.scope_digest != [0; 32]
        && permit.request_digest != [0; 32]
        && permit.permit_digest != [0; 32];
    if valid {
        Ok(())
    } else {
        Err(CapabilityCodecError::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use meshspan_contracts::FederatedShardPermit;
    use meshspan_domain::{
        FederationGrantId, FederationRelationshipId, FederationStorageAction,
        FederationStorageAllocationId, MeshId, NodeId, OperationId, Revision, TargetId, UnixMicros,
    };

    use super::{decode_federated_shard_permit, encode_federated_shard_permit};
    use crate::CapabilityCodecError;

    const ACTION_OFFSET: usize = (16 * 8) + 8 + 32 + 8 + 2 + 4;

    #[test]
    fn exact_encoding_round_trips_and_rejects_every_wrong_length()
    -> Result<(), Box<dyn std::error::Error>> {
        let permit = permit()?;
        let encoded = encode_federated_shard_permit(permit);
        assert_eq!(decode_federated_shard_permit(&encoded)?, permit);
        for length in 0..encoded.len() {
            assert!(decode_federated_shard_permit(&encoded[..length]).is_err());
        }
        let mut excessive = encoded;
        excessive.push(0);
        assert!(decode_federated_shard_permit(&excessive).is_err());
        Ok(())
    }

    #[test]
    fn structural_substitutions_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let permit = permit()?;
        for invalid in [
            FederatedShardPermit {
                target_generation: 0,
                ..permit
            },
            FederatedShardPermit {
                maximum_bytes: 0,
                ..permit
            },
            FederatedShardPermit {
                relationship_authority_epoch: 0,
                ..permit
            },
            FederatedShardPermit {
                grant_revision: Revision::ZERO,
                ..permit
            },
            FederatedShardPermit {
                allocation_revision: Revision::ZERO,
                ..permit
            },
            FederatedShardPermit {
                issued_at: UnixMicros::new(0),
                ..permit
            },
            FederatedShardPermit {
                expires_at: permit.issued_at,
                ..permit
            },
            FederatedShardPermit {
                capability_nonce: [0; 32],
                ..permit
            },
            FederatedShardPermit {
                scope_digest: [0; 32],
                ..permit
            },
            FederatedShardPermit {
                request_digest: [0; 32],
                ..permit
            },
            FederatedShardPermit {
                permit_digest: [0; 32],
                ..permit
            },
            FederatedShardPermit {
                provider_mesh_id: permit.remote_mesh_id,
                ..permit
            },
        ] {
            assert_eq!(
                decode_federated_shard_permit(&encode_federated_shard_permit(invalid)),
                Err(CapabilityCodecError::Invalid)
            );
        }
        let mut unknown_action = encode_federated_shard_permit(permit);
        unknown_action[ACTION_OFFSET] = u8::MAX;
        assert_eq!(
            decode_federated_shard_permit(&unknown_action),
            Err(CapabilityCodecError::Invalid)
        );
        Ok(())
    }

    fn permit() -> Result<FederatedShardPermit, Box<dyn std::error::Error>> {
        Ok(FederatedShardPermit {
            operation_id: OperationId::from_bytes([1; 16])?,
            relationship_id: FederationRelationshipId::from_bytes([2; 16])?,
            remote_mesh_id: MeshId::from_bytes([3; 16])?,
            provider_mesh_id: MeshId::from_bytes([4; 16])?,
            allocation_id: FederationStorageAllocationId::from_bytes([5; 16])?,
            grant_id: FederationGrantId::from_bytes([6; 16])?,
            provider_node_id: NodeId::from_bytes([7; 16])?,
            target_id: TargetId::from_bytes([8; 16])?,
            target_generation: 9,
            shard: meshspan_contracts::ShardIdentity {
                manifest_digest: [10; 32],
                stripe_index: 11,
                shard_index: 12,
                generation: 13,
            },
            action: FederationStorageAction::Put,
            maximum_bytes: 14,
            relationship_authority_epoch: 15,
            grant_revision: Revision::new(16),
            allocation_revision: Revision::new(17),
            issued_at: UnixMicros::new(18),
            expires_at: UnixMicros::new(19),
            capability_nonce: [20; 32],
            scope_digest: [21; 32],
            request_digest: [22; 32],
            permit_digest: [23; 32],
        })
    }
}
