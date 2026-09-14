// SPDX-License-Identifier: GPL-2.0-only

//! Explicit catastrophic-recovery authority, separate from an ordinary quorum transition.

use std::collections::{BTreeMap, BTreeSet};

use meshspan_certificates::NodePublicIdentity;
use meshspan_consensus::ActiveQuorumPlan;
use meshspan_domain::{HostId, MeshId, NodeId, OperationId, PartitionId};
use meshspan_secret_envelope::WrappingPublicKey;
use sha2::{Digest as _, Sha256};

use crate::{JoinRoles, MetadataCommandCodecError, RecordName, RecoverySecretInventory};

/// Exact public identity and role selection for one replacement node.
/// Private identity/wrapping keys stay on that node; this record is not proof of
/// possession, reachability, installed state or permission to serve.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryReplacementNode {
    /// Node identity selected by the offline authority.
    pub node_id: NodeId,
    /// Shared host identity, distinct from a process/node identity.
    pub host_id: HostId,
    /// Exact host display name to retain or create.
    pub host_name: RecordName,
    /// Exact node display name to retain or create.
    pub node_name: RecordName,
    /// New positive process incarnation, checked against source metadata during admission.
    pub incarnation: u64,
    /// Explicit replacement role ceiling.
    pub roles: JoinRoles,
    /// Canonical uncompressed P-256 identity whose private key remains node-local.
    pub identity_public_key: [u8; 65],
    /// Node-owned public wrapping recipient; never the offline recovery recipient.
    pub wrapping_public_key: WrappingPublicKey,
    /// Exact private QUIC endpoint, requiring a later authenticated reachability probe.
    pub private_endpoint: String,
}

/// Canonical public replacement plan bound by the offline recovery authorisation.
/// Storage/content inventory is separately bound by that authorisation. Validating
/// this plan never resets consensus or confirms installed keys on replacement nodes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryReplacementPlan {
    /// Intrinsic mesh whose identity is preserved.
    pub mesh_id: MeshId,
    /// Recovered metadata partition.
    pub partition_id: PartitionId,
    /// Exact recovery operation, preventing cross-recovery reuse.
    pub recovery_id: OperationId,
    /// Explicit successor recovery authority epoch.
    pub recovery_epoch: u64,
    /// Complete prepared secret-set commitment, including fresh control keys.
    pub secrets: RecoverySecretInventory,
    /// Stable, independently re-proved replacement election/write/read quorum plan.
    pub quorum: ActiveQuorumPlan,
    /// Strictly node-ID-ordered replacement nodes. Further nodes may join normally later.
    pub nodes: Vec<RecoveryReplacementNode>,
}

impl RecoveryReplacementPlan {
    /// Encodes the exact bounded public manifest, validating every node and quorum relation.
    /// # Errors
    /// Rejects malformed identities, duplicate endpoints/keys, unsupported phases or bounds.
    pub fn encode(&self) -> Result<Vec<u8>, MetadataCommandCodecError> {
        crate::command_codec::recovery_plan::encode(self)
    }

    /// Decodes untrusted bytes, recompiles quorum proofs and rejects noncanonical input.
    /// # Errors
    /// Rejects framing, bounds, identities, collection order and unsafe quorum specifications.
    pub fn decode(bytes: &[u8]) -> Result<Self, MetadataCommandCodecError> {
        crate::command_codec::recovery_plan::decode(bytes)
    }

    /// Returns the domain-separated digest stored in the root-signed recovery claims.
    /// # Errors
    /// Rejects an invalid replacement plan rather than hashing unchecked claims.
    pub fn digest(&self) -> Result<[u8; 32], MetadataCommandCodecError> {
        let mut digest = Sha256::new();
        digest.update(b"MeshSpan recovery replacement plan v1\0");
        digest.update(self.encode()?);
        Ok(digest.finalize().into())
    }

    pub(crate) fn validate(&self) -> Result<(), MetadataCommandCodecError> {
        if self.recovery_epoch == 0
            || self.recovery_epoch > i64::MAX.unsigned_abs()
            || self.secrets.generation_count == 0
            || self.secrets.generation_count > i64::MAX.unsigned_abs()
            || self.secrets.digest == [0; 32]
            || self.nodes.is_empty()
            || self.nodes.len() > 1024
            || !matches!(self.quorum, ActiveQuorumPlan::Stable(_))
            || self.quorum.membership_epoch() == 0
            || self.quorum.membership_epoch() > i64::MAX.unsigned_abs()
        {
            return Err(MetadataCommandCodecError::Invalid);
        }
        let mut previous = None;
        let mut identities = BTreeSet::new();
        let mut wrapping_keys = BTreeSet::new();
        let mut endpoints = BTreeSet::new();
        let mut hosts = BTreeMap::new();
        let mut host_names = BTreeMap::new();
        let mut node_names = BTreeSet::new();
        for node in &self.nodes {
            validate_node(node)?;
            if previous.is_some_and(|id| id >= node.node_id)
                || !identities.insert(node.identity_public_key)
                || !wrapping_keys.insert(node.wrapping_public_key)
                || !endpoints.insert(&node.private_endpoint)
                || !node_names.insert(node.node_name.canonical())
                || host_names
                    .insert(node.host_name.canonical(), node.host_id)
                    .is_some_and(|id| id != node.host_id)
                || hosts
                    .insert(node.host_id, &node.host_name)
                    .is_some_and(|name| name != &node.host_name)
            {
                return Err(MetadataCommandCodecError::Invalid);
            }
            previous = Some(node.node_id);
        }
        if !self
            .nodes
            .iter()
            .any(|node| node.roles.bits() & JoinRoles::GATEWAY != 0)
            || self.quorum.members().iter().any(|member| {
                !self
                    .nodes
                    .iter()
                    .any(|node| node.node_id == *member && node.roles.metadata_eligible())
            })
        {
            return Err(MetadataCommandCodecError::Invalid);
        }
        Ok(())
    }
}

fn validate_node(node: &RecoveryReplacementNode) -> Result<(), MetadataCommandCodecError> {
    if node.incarnation == 0
        || node.incarnation > i64::MAX.unsigned_abs()
        || !crate::repository::valid_private_endpoint(&node.private_endpoint)
    {
        return Err(MetadataCommandCodecError::Invalid);
    }
    NodePublicIdentity::from_sec1(&node.identity_public_key)
        .map_err(|_| MetadataCommandCodecError::Invalid)?;
    Ok(())
}
