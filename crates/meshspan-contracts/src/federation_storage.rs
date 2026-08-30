// SPDX-License-Identifier: GPL-2.0-only

//! Provider-issued authority for one exact cross-swarm shard operation.

use meshspan_domain::{
    FederationGrantId, FederationRelationshipId, FederationStorageAction,
    FederationStorageAllocationId, MeshId, NodeId, OperationId, Revision, TargetId, UnixMicros,
};

use crate::{ContractError, ShardIdentity};

const PERMIT_DOMAIN: &[u8] = b"meshspan.federation.shard-permit.v1";

/// Secret 256-bit key used only for provider-side federated shard permits.
///
/// The type deliberately omits `Clone`, `Copy` and `Debug`; capability-signing material must not
/// accidentally enter logs or ordinary serialisation.
pub struct FederatedStoragePermitMacKey([u8; 32]);

impl FederatedStoragePermitMacKey {
    /// Accepts exact key bytes from the provider swarm's secret-distribution boundary.
    ///
    /// # Errors
    ///
    /// Rejects the all-zero sentinel, which is never valid key material.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, ContractError> {
        if bytes == [0; 32] {
            Err(ContractError::InvalidInput)
        } else {
            Ok(Self(bytes))
        }
    }
}

/// Opaque, short-lived provider authority for one exact remote shard lifecycle action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederatedShardPermit {
    /// Idempotent operation identity shared by exact retries.
    pub operation_id: OperationId,
    /// Exact bilateral relationship carrying the request.
    pub relationship_id: FederationRelationshipId,
    /// Certificate-authenticated swarm allowed to present the permit.
    pub remote_mesh_id: MeshId,
    /// Swarm which issued and may verify the permit.
    pub provider_mesh_id: MeshId,
    /// Disjoint replicated quota allocation consumed by capacity-changing actions.
    pub allocation_id: FederationStorageAllocationId,
    /// Exact effective bilateral storage grant.
    pub grant_id: FederationGrantId,
    /// Sole provider node allowed to execute the operation.
    pub provider_node_id: NodeId,
    /// Exact provider target.
    pub target_id: TargetId,
    /// Exact target incarnation fence.
    pub target_generation: u64,
    /// Exact immutable shard generation.
    pub shard: ShardIdentity,
    /// Closed lifecycle action.
    pub action: FederationStorageAction,
    /// Maximum bytes the operation may transfer or affect.
    pub maximum_bytes: u64,
    /// Relationship authority epoch fencing older capabilities.
    pub relationship_authority_epoch: u64,
    /// Exact effective grant revision used at issuance.
    pub grant_revision: Revision,
    /// Exact allocation revision used at issuance.
    pub allocation_revision: Revision,
    /// Quorum-derived issuance instant.
    pub issued_at: UnixMicros,
    /// Exclusive expiry.
    pub expires_at: UnixMicros,
    /// Fresh capability nonce preventing cross-operation substitution.
    pub capability_nonce: [u8; 32],
    /// Digest binding the opaque logical scope without exposing namespace metadata.
    pub scope_digest: [u8; 32],
    /// Digest of the complete authenticated capability request.
    pub request_digest: [u8; 32],
    /// Domain-separated keyed digest over every preceding field.
    pub permit_digest: [u8; 32],
}

/// Calculates the provider-only keyed digest for one exact federated shard permit.
///
/// The existing `permit_digest` is excluded so callers can replace it with this result.
#[must_use]
pub fn federated_shard_permit_mac(
    key: &FederatedStoragePermitMacKey,
    permit: &FederatedShardPermit,
) -> [u8; 32] {
    let mut mac = blake3::Hasher::new_keyed(&key.0);
    mac.update(PERMIT_DOMAIN);
    mac.update(&permit.operation_id.as_bytes());
    mac.update(&permit.relationship_id.as_bytes());
    mac.update(&permit.remote_mesh_id.as_bytes());
    mac.update(&permit.provider_mesh_id.as_bytes());
    mac.update(&permit.allocation_id.as_bytes());
    mac.update(&permit.grant_id.as_bytes());
    mac.update(&permit.provider_node_id.as_bytes());
    mac.update(&permit.target_id.as_bytes());
    mac.update(&permit.target_generation.to_be_bytes());
    mac.update(&permit.shard.manifest_digest);
    mac.update(&permit.shard.stripe_index.to_be_bytes());
    mac.update(&permit.shard.shard_index.to_be_bytes());
    mac.update(&permit.shard.generation.to_be_bytes());
    mac.update(&[permit.action.code()]);
    mac.update(&permit.maximum_bytes.to_be_bytes());
    mac.update(&permit.relationship_authority_epoch.to_be_bytes());
    mac.update(&permit.grant_revision.get().to_be_bytes());
    mac.update(&permit.allocation_revision.get().to_be_bytes());
    mac.update(&permit.issued_at.get().to_be_bytes());
    mac.update(&permit.expires_at.get().to_be_bytes());
    mac.update(&permit.capability_nonce);
    mac.update(&permit.scope_digest);
    mac.update(&permit.request_digest);
    mac.finalize().into()
}

/// Verifies the federated permit digest without data-dependent byte comparison.
#[must_use]
pub fn verify_federated_shard_permit_mac(
    key: &FederatedStoragePermitMacKey,
    permit: &FederatedShardPermit,
) -> bool {
    blake3::Hash::from_bytes(federated_shard_permit_mac(key, permit))
        == blake3::Hash::from_bytes(permit.permit_digest)
}

#[cfg(test)]
mod tests {
    use meshspan_domain::{
        FederationGrantId, FederationRelationshipId, FederationStorageAction,
        FederationStorageAllocationId, MeshId, NodeId, OperationId, Revision, TargetId, UnixMicros,
    };

    use super::{
        FederatedShardPermit, FederatedStoragePermitMacKey, federated_shard_permit_mac,
        verify_federated_shard_permit_mac,
    };
    use crate::ShardIdentity;

    #[test]
    fn digest_binds_every_authority_dimension() -> Result<(), Box<dyn std::error::Error>> {
        let key = FederatedStoragePermitMacKey::from_bytes([1; 32])?;
        let permit = permit()?;
        let digest = federated_shard_permit_mac(&key, &permit);
        let authorised = FederatedShardPermit {
            permit_digest: digest,
            ..permit
        };
        assert!(verify_federated_shard_permit_mac(&key, &authorised));
        reject_every_substitution(&key, &authorised)?;
        let other_key = FederatedStoragePermitMacKey::from_bytes([2; 32])?;
        assert!(!verify_federated_shard_permit_mac(&other_key, &authorised));
        Ok(())
    }

    #[test]
    fn secret_key_rejects_zero_sentinel() {
        assert!(FederatedStoragePermitMacKey::from_bytes([0; 32]).is_err());
    }

    fn reject_every_substitution(
        key: &FederatedStoragePermitMacKey,
        permit: &FederatedShardPermit,
    ) -> Result<(), Box<dyn std::error::Error>> {
        reject_identity_substitutions(key, permit)?;
        reject_authority_substitutions(key, permit);
        Ok(())
    }

    fn reject_identity_substitutions(
        key: &FederatedStoragePermitMacKey,
        permit: &FederatedShardPermit,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let permit = *permit;
        let substitutions = [
            FederatedShardPermit {
                operation_id: OperationId::from_bytes([23; 16])?,
                ..permit
            },
            FederatedShardPermit {
                relationship_id: FederationRelationshipId::from_bytes([24; 16])?,
                ..permit
            },
            FederatedShardPermit {
                remote_mesh_id: MeshId::from_bytes([25; 16])?,
                ..permit
            },
            FederatedShardPermit {
                provider_mesh_id: MeshId::from_bytes([26; 16])?,
                ..permit
            },
            FederatedShardPermit {
                allocation_id: FederationStorageAllocationId::from_bytes([27; 16])?,
                ..permit
            },
            FederatedShardPermit {
                grant_id: FederationGrantId::from_bytes([28; 16])?,
                ..permit
            },
            FederatedShardPermit {
                provider_node_id: NodeId::from_bytes([29; 16])?,
                ..permit
            },
            FederatedShardPermit {
                target_id: TargetId::from_bytes([30; 16])?,
                ..permit
            },
            FederatedShardPermit {
                target_generation: 2,
                ..permit
            },
            FederatedShardPermit {
                shard: ShardIdentity {
                    manifest_digest: [31; 32],
                    ..permit.shard
                },
                ..permit
            },
            FederatedShardPermit {
                shard: ShardIdentity {
                    stripe_index: 32,
                    ..permit.shard
                },
                ..permit
            },
            FederatedShardPermit {
                shard: ShardIdentity {
                    shard_index: 33,
                    ..permit.shard
                },
                ..permit
            },
            FederatedShardPermit {
                shard: ShardIdentity {
                    generation: 34,
                    ..permit.shard
                },
                ..permit
            },
        ];
        assert_rejected(key, &substitutions);
        Ok(())
    }

    fn reject_authority_substitutions(
        key: &FederatedStoragePermitMacKey,
        permit: &FederatedShardPermit,
    ) {
        let permit = *permit;
        let substitutions = [
            FederatedShardPermit {
                action: FederationStorageAction::Repair,
                ..permit
            },
            FederatedShardPermit {
                maximum_bytes: 2,
                ..permit
            },
            FederatedShardPermit {
                relationship_authority_epoch: 2,
                ..permit
            },
            FederatedShardPermit {
                grant_revision: Revision::new(35),
                ..permit
            },
            FederatedShardPermit {
                allocation_revision: Revision::new(36),
                ..permit
            },
            FederatedShardPermit {
                issued_at: UnixMicros::new(18),
                ..permit
            },
            FederatedShardPermit {
                expires_at: UnixMicros::new(31),
                ..permit
            },
            FederatedShardPermit {
                capability_nonce: [37; 32],
                ..permit
            },
            FederatedShardPermit {
                scope_digest: [38; 32],
                ..permit
            },
            FederatedShardPermit {
                request_digest: [39; 32],
                ..permit
            },
            FederatedShardPermit {
                permit_digest: [40; 32],
                ..permit
            },
        ];
        assert_rejected(key, &substitutions);
    }

    fn assert_rejected(key: &FederatedStoragePermitMacKey, substitutions: &[FederatedShardPermit]) {
        assert!(
            substitutions
                .iter()
                .all(|value| !verify_federated_shard_permit_mac(key, value))
        );
    }

    fn permit() -> Result<FederatedShardPermit, Box<dyn std::error::Error>> {
        Ok(FederatedShardPermit {
            operation_id: OperationId::from_bytes([5; 16])?,
            relationship_id: FederationRelationshipId::from_bytes([6; 16])?,
            remote_mesh_id: MeshId::from_bytes([7; 16])?,
            provider_mesh_id: MeshId::from_bytes([8; 16])?,
            allocation_id: FederationStorageAllocationId::from_bytes([9; 16])?,
            grant_id: FederationGrantId::from_bytes([10; 16])?,
            provider_node_id: NodeId::from_bytes([11; 16])?,
            target_id: TargetId::from_bytes([12; 16])?,
            target_generation: 1,
            shard: ShardIdentity {
                manifest_digest: [13; 32],
                stripe_index: 14,
                shard_index: 15,
                generation: 16,
            },
            action: FederationStorageAction::Put,
            maximum_bytes: 1,
            relationship_authority_epoch: 1,
            grant_revision: Revision::new(17),
            allocation_revision: Revision::new(18),
            issued_at: UnixMicros::new(19),
            expires_at: UnixMicros::new(30),
            capability_nonce: [20; 32],
            scope_digest: [21; 32],
            request_digest: [22; 32],
            permit_digest: [0; 32],
        })
    }
}
