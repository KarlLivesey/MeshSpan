// SPDX-License-Identifier: GPL-2.0-only

//! Restart-stable, domain-separated identities for one first-appliance bootstrap.

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::secret_text::derive;
use crate::{
    ApiKeyBundle, ApiKeyBundleError, AuditEventId, AuthenticationMethodId, BranchId, ClaimBundle,
    EntropyError, HostId, MeshId, NodeId, OperationId, PartitionId, PrincipalId, QuorumPlanId,
    RandomSource, RoleId,
};

type HmacSha256 = Hmac<Sha256>;

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
    /// Domain-separated recovery-code seed exposed only to the recovery-bundle composer.
    recovery_bundle_code_seed: Zeroizing<[u8; 32]>,
    /// Domain-separated storage-permit key retained only for protected setup composition.
    storage_permit_key: Zeroizing<[u8; 32]>,
    /// Domain-separated exact-retry entropy for the initial encrypted permit envelope.
    storage_permit_envelope_seed: Zeroizing<[u8; 32]>,
    /// Domain-separated gateway-only authentication root retained for protected setup composition.
    authentication_root_key: Zeroizing<[u8; 32]>,
    /// Domain-separated exact-retry entropy for the initial authentication-root envelope.
    authentication_root_envelope_seed: Zeroizing<[u8; 32]>,
    /// Domain-separated P-256 seed for the initial online node-certificate authority.
    online_authority_key_seed: Zeroizing<[u8; 32]>,
    /// Domain-separated exact-retry entropy for the online-authority key envelope.
    online_authority_envelope_seed: Zeroizing<[u8; 32]>,
}

/// Restart-stable secret and cryptographic stream for the initial storage-permit envelope.
///
/// Exact setup retries must submit byte-identical authoritative commands. This value derives both
/// independently from the high-entropy one-time claim and is only valid for this one envelope. It
/// deliberately implements neither `Clone` nor `Debug`.
pub struct InitialStoragePermitMaterial {
    key: Zeroizing<[u8; 32]>,
    entropy_key: Zeroizing<[u8; 32]>,
    counter: u64,
}

/// Restart-stable secret and cryptographic stream for the initial authentication-root envelope.
///
/// The root is encrypted independently from storage authority so storage-only nodes never receive
/// credential-derivation material. This value deliberately implements neither `Clone` nor `Debug`.
pub struct InitialAuthenticationRootMaterial {
    key: Zeroizing<[u8; 32]>,
    entropy_key: Zeroizing<[u8; 32]>,
    counter: u64,
}

/// Restart-stable online-authority seed and envelope stream for first-mesh bootstrap.
///
/// The seed recreates the exact root-signed online CA generation while the independent stream
/// encrypts its private key to the initial voter and offline recovery identity.
pub struct InitialOnlineAuthorityMaterial {
    key_seed: Zeroizing<[u8; 32]>,
    entropy_key: Zeroizing<[u8; 32]>,
    counter: u64,
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

    /// Derives the restart-stable local namespace branch owned by one daemon node.
    ///
    /// Every daemon process serialises its own disconnected-write branch. Binding that branch to
    /// the node identity keeps it stable across restart while preventing two nodes from silently
    /// publishing through the same branch.
    ///
    /// # Errors
    ///
    /// Rejects the cryptographically negligible nil derivation.
    pub fn local_branch_id(node_id: NodeId) -> Result<BranchId, InitialBootstrapMaterialError> {
        BranchId::from_bytes(node_bound_identifier(
            b"meshspan.setup.local-branch-id.v1",
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
        let recovery_bundle_code_seed = derive(
            b"meshspan.setup.recovery-bundle-code.v1",
            claim.secret_bytes(),
            operation_id,
        );
        if recovery_bundle_code_seed == [0; 32] {
            return Err(InitialBootstrapMaterialError::RecoveryCode);
        }
        let storage_permit_key = derive(
            b"meshspan.setup.storage-permit-key.v1",
            claim.secret_bytes(),
            operation_id,
        );
        let storage_permit_envelope_seed = derive(
            b"meshspan.setup.storage-permit-envelope.v1",
            claim.secret_bytes(),
            operation_id,
        );
        if storage_permit_key == [0; 32] || storage_permit_envelope_seed == [0; 32] {
            return Err(InitialBootstrapMaterialError::StoragePermit);
        }
        let authentication_root_key = derive(
            b"meshspan.setup.authentication-root-key.v1",
            claim.secret_bytes(),
            operation_id,
        );
        let authentication_root_envelope_seed = derive(
            b"meshspan.setup.authentication-root-envelope.v1",
            claim.secret_bytes(),
            operation_id,
        );
        if authentication_root_key == [0; 32] || authentication_root_envelope_seed == [0; 32] {
            return Err(InitialBootstrapMaterialError::AuthenticationRoot);
        }
        let online_authority_key_seed = derive(
            b"meshspan.setup.online-authority-key.v1",
            claim.secret_bytes(),
            operation_id,
        );
        let online_authority_envelope_seed = derive(
            b"meshspan.setup.online-authority-envelope.v1",
            claim.secret_bytes(),
            operation_id,
        );
        if online_authority_key_seed == [0; 32] || online_authority_envelope_seed == [0; 32] {
            return Err(InitialBootstrapMaterialError::OnlineAuthority);
        }
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
            recovery_bundle_code_seed: Zeroizing::new(recovery_bundle_code_seed),
            storage_permit_key: Zeroizing::new(storage_permit_key),
            storage_permit_envelope_seed: Zeroizing::new(storage_permit_envelope_seed),
            authentication_root_key: Zeroizing::new(authentication_root_key),
            authentication_root_envelope_seed: Zeroizing::new(authentication_root_envelope_seed),
            online_authority_key_seed: Zeroizing::new(online_authority_key_seed),
            online_authority_envelope_seed: Zeroizing::new(online_authority_envelope_seed),
        })
    }

    /// Copies the restart-stable high-entropy recovery-code seed to its protected composer.
    #[must_use]
    pub fn recovery_bundle_code_seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.recovery_bundle_code_seed)
    }

    /// Returns a fresh exact-retry stream and the initial mesh storage-permit key.
    #[must_use]
    pub fn storage_permit_material(&self) -> InitialStoragePermitMaterial {
        InitialStoragePermitMaterial {
            key: Zeroizing::new(*self.storage_permit_key),
            entropy_key: Zeroizing::new(*self.storage_permit_envelope_seed),
            counter: 0,
        }
    }

    /// Returns a fresh exact-retry stream and the initial gateway authentication root.
    #[must_use]
    pub fn authentication_root_material(&self) -> InitialAuthenticationRootMaterial {
        InitialAuthenticationRootMaterial {
            key: Zeroizing::new(*self.authentication_root_key),
            entropy_key: Zeroizing::new(*self.authentication_root_envelope_seed),
            counter: 0,
        }
    }

    /// Returns a fresh exact-retry seed and stream for the initial online node authority.
    #[must_use]
    pub fn online_authority_material(&self) -> InitialOnlineAuthorityMaterial {
        InitialOnlineAuthorityMaterial {
            key_seed: Zeroizing::new(*self.online_authority_key_seed),
            entropy_key: Zeroizing::new(*self.online_authority_envelope_seed),
            counter: 0,
        }
    }
}

impl InitialStoragePermitMaterial {
    /// Copies the permit key into the protected envelope composer.
    #[must_use]
    pub fn key(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.key)
    }
}

impl RandomSource for InitialStoragePermitMaterial {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        fill_deterministic_stream(
            &self.entropy_key,
            &mut self.counter,
            b"meshspan.setup.storage-permit-envelope-block.v1",
            destination,
        )
    }
}

impl InitialAuthenticationRootMaterial {
    /// Copies the authentication root into the protected envelope composer.
    #[must_use]
    pub fn key(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.key)
    }
}

impl RandomSource for InitialAuthenticationRootMaterial {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        fill_deterministic_stream(
            &self.entropy_key,
            &mut self.counter,
            b"meshspan.setup.authentication-root-envelope-block.v1",
            destination,
        )
    }
}

impl InitialOnlineAuthorityMaterial {
    /// Copies the deterministic P-256 key seed into the certificate composer.
    #[must_use]
    pub fn key_seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.key_seed)
    }
}

impl RandomSource for InitialOnlineAuthorityMaterial {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        fill_deterministic_stream(
            &self.entropy_key,
            &mut self.counter,
            b"meshspan.setup.online-authority-envelope-block.v1",
            destination,
        )
    }
}

fn fill_deterministic_stream(
    entropy_key: &[u8; 32],
    counter: &mut u64,
    domain: &[u8],
    destination: &mut [u8],
) -> Result<(), EntropyError> {
    for chunk in destination.chunks_mut(32) {
        *counter = counter.checked_add(1).ok_or(EntropyError)?;
        let mut mac = HmacSha256::new_from_slice(entropy_key).map_err(|_| EntropyError)?;
        mac.update(domain);
        mac.update(&counter.to_be_bytes());
        let block = mac.finalize().into_bytes();
        chunk.copy_from_slice(&block[..chunk.len()]);
    }
    Ok(())
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
    /// The derived offline recovery code was structurally invalid.
    #[error("derived bootstrap recovery code is invalid")]
    RecoveryCode,
    /// The derived initial permit key or envelope stream was invalid.
    #[error("derived bootstrap storage permit material is invalid")]
    StoragePermit,
    /// The derived authentication root or envelope stream was invalid.
    #[error("derived bootstrap authentication-root material is invalid")]
    AuthenticationRoot,
    /// The derived online-authority key seed or envelope stream was invalid.
    #[error("derived bootstrap online-authority material is invalid")]
    OnlineAuthority,
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
    fn exact_retry_preserves_identifiers_and_separates_new_meshes()
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
        assert_eq!(
            InitialBootstrapMaterial::local_branch_id(first.node_id)?,
            InitialBootstrapMaterial::local_branch_id(another_operation.node_id)?
        );
        assert_ne!(
            InitialBootstrapMaterial::local_branch_id(first.node_id)?,
            InitialBootstrapMaterial::local_branch_id(InitialBootstrapMaterial::node_id(
                [78; 32]
            )?)?
        );
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

    #[test]
    fn exact_retry_preserves_and_separates_each_secret_stream()
    -> Result<(), Box<dyn std::error::Error>> {
        let claim = ClaimBundle::generate(&mut SequentialRandom(1))?;
        let operation = OperationId::from_bytes([99; 16])?;
        let node_id = InitialBootstrapMaterial::node_id([77; 32])?;
        let first = InitialBootstrapMaterial::derive(&claim, operation, node_id)?;
        let replay = InitialBootstrapMaterial::derive(&claim, operation, node_id)?;
        let mut first_permit = first.storage_permit_material();
        let mut replay_permit = replay.storage_permit_material();
        assert_eq!(first_permit.key().as_ref(), replay_permit.key().as_ref());
        let mut first_entropy = [0_u8; 97];
        let mut replay_entropy = [0_u8; 97];
        first_permit.fill_bytes(&mut first_entropy)?;
        replay_permit.fill_bytes(&mut replay_entropy)?;
        assert_eq!(first_entropy, replay_entropy);
        assert_ne!(first_permit.key().as_ref(), &first_entropy[..32]);
        let mut first_authentication = first.authentication_root_material();
        let mut replay_authentication = replay.authentication_root_material();
        assert_eq!(
            first_authentication.key().as_ref(),
            replay_authentication.key().as_ref()
        );
        assert_ne!(
            first_authentication.key().as_ref(),
            first_permit.key().as_ref()
        );
        let mut first_authentication_entropy = [0_u8; 97];
        let mut replay_authentication_entropy = [0_u8; 97];
        first_authentication.fill_bytes(&mut first_authentication_entropy)?;
        replay_authentication.fill_bytes(&mut replay_authentication_entropy)?;
        assert_eq!(first_authentication_entropy, replay_authentication_entropy);
        assert_ne!(first_authentication_entropy, first_entropy);
        let mut first_online = first.online_authority_material();
        let mut replay_online = replay.online_authority_material();
        assert_eq!(first_online.key_seed(), replay_online.key_seed());
        assert_ne!(first_online.key_seed(), first_authentication.key());
        let mut first_online_entropy = [0_u8; 97];
        let mut replay_online_entropy = [0_u8; 97];
        first_online.fill_bytes(&mut first_online_entropy)?;
        replay_online.fill_bytes(&mut replay_online_entropy)?;
        assert_eq!(first_online_entropy, replay_online_entropy);
        assert_ne!(first_online_entropy, first_authentication_entropy);
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
