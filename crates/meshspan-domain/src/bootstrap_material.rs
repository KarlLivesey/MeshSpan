// SPDX-License-Identifier: GPL-2.0-only

//! Restart-stable, domain-separated identities for one first-appliance bootstrap.

use thiserror::Error;

use crate::secret_text::derive;
use crate::{
    ApiKeyBundle, ApiKeyBundleError, AuditEventId, AuthenticationMethodId, ClaimBundle, HostId,
    MeshId, NodeId, OperationId, PartitionId, PrincipalId, QuorumPlanId, RoleId,
};

/// Complete deterministic identity and secret plan for one claimed first-mesh operation.
///
/// The type deliberately implements neither `Debug` nor `Clone` because it owns the API key.
pub struct InitialBootstrapMaterial {
    /// Created mesh identity.
    pub mesh_id: MeshId,
    /// First administrator principal identity.
    pub administrator_id: PrincipalId,
    /// Built-in administrator role identity.
    pub administrator_role_id: RoleId,
    /// First physical host identity.
    pub host_id: HostId,
    /// First daemon-node identity.
    pub node_id: NodeId,
    /// Root metadata partition identity.
    pub partition_id: PartitionId,
    /// Initial single-voter quorum-plan identity.
    pub quorum_plan_id: QuorumPlanId,
    /// Initial authentication-method identity.
    pub authentication_method_id: AuthenticationMethodId,
    /// Bootstrap audit-event identity.
    pub audit_event_id: AuditEventId,
    /// Initial administrator API key, exposed only at the successful response boundary.
    pub api_key: ApiKeyBundle,
}

impl InitialBootstrapMaterial {
    /// Derives the same independent values for every exact retry of one claimed operation.
    ///
    /// # Errors
    ///
    /// Rejects any cryptographically negligible nil derivation rather than substituting a value.
    pub fn derive(
        claim: &ClaimBundle,
        operation_id: OperationId,
    ) -> Result<Self, InitialBootstrapMaterialError> {
        Ok(Self {
            mesh_id: MeshId::from_bytes(identifier(
                b"meshspan.setup.mesh-id.v1",
                claim,
                operation_id,
            ))?,
            administrator_id: PrincipalId::from_bytes(identifier(
                b"meshspan.setup.administrator-id.v1",
                claim,
                operation_id,
            ))?,
            administrator_role_id: RoleId::from_bytes(identifier(
                b"meshspan.setup.administrator-role-id.v1",
                claim,
                operation_id,
            ))?,
            host_id: HostId::from_bytes(identifier(
                b"meshspan.setup.host-id.v1",
                claim,
                operation_id,
            ))?,
            node_id: NodeId::from_bytes(identifier(
                b"meshspan.setup.node-id.v1",
                claim,
                operation_id,
            ))?,
            partition_id: PartitionId::from_bytes(identifier(
                b"meshspan.setup.partition-id.v1",
                claim,
                operation_id,
            ))?,
            quorum_plan_id: QuorumPlanId::from_bytes(identifier(
                b"meshspan.setup.quorum-plan-id.v1",
                claim,
                operation_id,
            ))?,
            authentication_method_id: AuthenticationMethodId::from_bytes(identifier(
                b"meshspan.setup.authentication-method-id.v1",
                claim,
                operation_id,
            ))?,
            audit_event_id: AuditEventId::from_bytes(identifier(
                b"meshspan.setup.audit-event-id.v1",
                claim,
                operation_id,
            ))?,
            api_key: ApiKeyBundle::derive_initial(claim, operation_id)?,
        })
    }
}

/// Failure to derive structurally valid initial bootstrap material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum InitialBootstrapMaterialError {
    /// A derived identifier was nil.
    #[error("derived bootstrap identifier is invalid")]
    Identifier,
    /// The derived initial API key was invalid.
    #[error("derived bootstrap API key is invalid")]
    ApiKey,
}

impl From<crate::IdentifierError> for InitialBootstrapMaterialError {
    fn from(_: crate::IdentifierError) -> Self {
        Self::Identifier
    }
}

impl From<ApiKeyBundleError> for InitialBootstrapMaterialError {
    fn from(_: ApiKeyBundleError) -> Self {
        Self::ApiKey
    }
}

fn identifier(domain: &[u8], claim: &ClaimBundle, operation_id: OperationId) -> [u8; 16] {
    let digest = derive(domain, claim.secret_bytes(), operation_id);
    let mut identifier = [0_u8; 16];
    identifier.copy_from_slice(&digest[..16]);
    identifier[6] = (identifier[6] & 0x0f) | 0x40;
    identifier[8] = (identifier[8] & 0x3f) | 0x80;
    identifier
}

#[cfg(test)]
mod tests {
    use super::InitialBootstrapMaterial;
    use crate::{ClaimBundle, EntropyError, OperationId, RandomSource};

    #[test]
    fn exact_retry_is_stable_and_every_identity_is_distinct()
    -> Result<(), Box<dyn std::error::Error>> {
        let claim = ClaimBundle::generate(&mut SequentialRandom(1))?;
        let operation = OperationId::from_bytes([99; 16])?;
        let first = InitialBootstrapMaterial::derive(&claim, operation)?;
        let replay = InitialBootstrapMaterial::derive(&claim, operation)?;
        assert_eq!(first.mesh_id, replay.mesh_id);
        assert_eq!(first.node_id, replay.node_id);
        assert_eq!(
            first.api_key.expose_encoded(),
            replay.api_key.expose_encoded()
        );
        let identities = [
            first.mesh_id.as_bytes(),
            first.administrator_id.as_bytes(),
            first.administrator_role_id.as_bytes(),
            first.host_id.as_bytes(),
            first.node_id.as_bytes(),
            first.partition_id.as_bytes(),
            first.quorum_plan_id.as_bytes(),
            first.authentication_method_id.as_bytes(),
            first.audit_event_id.as_bytes(),
            first.api_key.key_id().as_bytes(),
        ];
        for (index, identity) in identities.iter().enumerate() {
            assert!(!identities[..index].contains(identity));
            assert_eq!(identity[6] >> 4, 4);
            assert_eq!(identity[8] >> 6, 2);
        }
        Ok(())
    }

    struct SequentialRandom(u8);

    impl RandomSource for SequentialRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
            for byte in destination {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }
}
