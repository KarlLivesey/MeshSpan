// SPDX-License-Identifier: GPL-2.0-only

//! Restart-stable, domain-separated identities for one first-appliance bootstrap.

use sha2::{Digest, Sha256};
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
    /// Derives the first node identity from its locally generated public key.
    ///
    /// The node-local database and identity key lifecycle begin before a browser or headless client
    /// chooses its idempotency operation or claim rotation. Binding the node solely to its public
    /// key therefore keeps that identity stable across setup retries, claim rotation and restarts.
    ///
    /// # Errors
    ///
    /// Rejects the cryptographically negligible nil derivation.
    pub fn node_id(
        public_key_fingerprint: [u8; 32],
    ) -> Result<NodeId, InitialBootstrapMaterialError> {
        if public_key_fingerprint == [0; 32] {
            return Err(InitialBootstrapMaterialError::Identifier);
        }
        let mut digest = Sha256::new();
        digest.update(b"meshspan.setup.node-id.v1");
        digest.update(public_key_fingerprint);
        NodeId::from_bytes(uuid_identifier(digest.finalize().into())).map_err(Into::into)
    }

    /// Derives the first root-partition identity from the stable first node.
    ///
    /// This identity must exist before a create-mesh request arrives and remain discoverable after
    /// the one-time claim has been consumed.
    ///
    /// # Errors
    ///
    /// Rejects the cryptographically negligible nil derivation.
    pub fn root_partition_id(
        node_id: NodeId,
    ) -> Result<PartitionId, InitialBootstrapMaterialError> {
        PartitionId::from_bytes(node_bound_identifier(
            b"meshspan.setup.partition-id.v2",
            node_id,
        ))
        .map_err(Into::into)
    }

    /// Derives the first single-voter plan identity from the stable first node.
    ///
    /// # Errors
    ///
    /// Rejects the cryptographically negligible nil derivation.
    pub fn initial_quorum_plan_id(
        node_id: NodeId,
    ) -> Result<QuorumPlanId, InitialBootstrapMaterialError> {
        QuorumPlanId::from_bytes(node_bound_identifier(
            b"meshspan.setup.quorum-plan-id.v2",
            node_id,
        ))
        .map_err(Into::into)
    }

    /// Derives the same independent values for every exact retry of one claimed operation.
    ///
    /// # Errors
    ///
    /// Rejects any cryptographically negligible nil derivation rather than substituting a value.
    pub fn derive(
        claim: &ClaimBundle,
        operation_id: OperationId,
        node_id: NodeId,
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
            node_id,
            partition_id: Self::root_partition_id(node_id)?,
            quorum_plan_id: Self::initial_quorum_plan_id(node_id)?,
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
    uuid_identifier(digest)
}

fn node_bound_identifier(domain: &[u8], node_id: NodeId) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(node_id.as_bytes());
    uuid_identifier(digest.finalize().into())
}

fn uuid_identifier(digest: [u8; 32]) -> [u8; 16] {
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
        let node_id = InitialBootstrapMaterial::node_id([77; 32])?;
        let first = InitialBootstrapMaterial::derive(&claim, operation, node_id)?;
        let replay = InitialBootstrapMaterial::derive(&claim, operation, node_id)?;
        assert_eq!(first.mesh_id, replay.mesh_id);
        assert_eq!(first.node_id, replay.node_id);
        let another_operation =
            InitialBootstrapMaterial::derive(&claim, OperationId::from_bytes([100; 16])?, node_id)?;
        assert_eq!(first.node_id, another_operation.node_id);
        assert_eq!(first.partition_id, another_operation.partition_id);
        assert_eq!(first.quorum_plan_id, another_operation.quorum_plan_id);
        assert_ne!(first.mesh_id, another_operation.mesh_id);
        assert_ne!(InitialBootstrapMaterial::node_id([78; 32])?, node_id);
        assert!(InitialBootstrapMaterial::node_id([0; 32]).is_err());
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
