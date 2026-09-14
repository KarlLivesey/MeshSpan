// SPDX-License-Identifier: GPL-2.0-only

//! Convert bounded operator intent into existing domain identities and proved quorum rules.

use meshspan_api_contract::{
    RecoveryNodeRole, RecoveryNodeSelection, RecoveryPreparationSelection, RecoveryQuorumSelection,
};
use meshspan_certificates::NodePublicIdentity;
use meshspan_consensus::{ActiveQuorumPlan, compile_plan, flat_plan};
use meshspan_domain::{HostId, NodeId, OperationId, QuorumPlanId, uuid_v8};
use meshspan_metadata::{AuthoritativeRepository, JoinRoles, RecordName, RecoveryReplacementNode};
use meshspan_secret_envelope::WrappingPublicKey;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;

use super::RecoveryPreparationError as Error;

pub(super) struct Selection {
    pub(super) recovery_id: OperationId,
    pub(super) nodes: Vec<RecoveryReplacementNode>,
    pub(super) quorum: ActiveQuorumPlan,
}

impl Selection {
    pub(super) fn convert(
        value: RecoveryPreparationSelection,
        source: &AuthoritativeRepository,
    ) -> Result<Self, Error> {
        let recovery_id = OperationId::from_bytes(identifier(value.recovery_id.as_str())?)
            .map_err(|_| Error::Input)?;
        let mut nodes = value
            .nodes
            .into_iter()
            .map(convert_node)
            .collect::<Result<Vec<_>, _>>()?;
        nodes.sort_by_key(|node| node.node_id);
        let epoch = source
            .load_active_consensus_quorum_plan()
            .map_err(|_| Error::Quorum)?
            .ok_or(Error::Authority)?
            .membership_epoch()
            .checked_add(1)
            .ok_or(Error::Input)?;
        let quorum = match value.quorum {
            RecoveryQuorumSelection::Automatic => automatic_quorum(recovery_id, epoch, &nodes)?,
            RecoveryQuorumSelection::Compiled { specification } => {
                ActiveQuorumPlan::decode(&hex(&specification)?).map_err(|_| Error::Input)?
            }
        };
        if quorum.membership_epoch() != epoch || !matches!(quorum, ActiveQuorumPlan::Stable(_)) {
            return Err(Error::Input);
        }
        Ok(Self {
            recovery_id,
            nodes,
            quorum,
        })
    }

    pub(super) fn gateway_keys(&self) -> Vec<WrappingPublicKey> {
        self.nodes
            .iter()
            .filter(|node| node.roles.bits() & JoinRoles::GATEWAY != 0)
            .map(|node| node.wrapping_public_key)
            .collect()
    }

    pub(super) fn storage_keys(&self) -> Vec<WrappingPublicKey> {
        self.nodes
            .iter()
            .filter(|node| node.roles.bits() & JoinRoles::STORAGE != 0)
            .map(|node| node.wrapping_public_key)
            .collect()
    }
}

fn automatic_quorum(
    id: OperationId,
    epoch: u64,
    nodes: &[RecoveryReplacementNode],
) -> Result<ActiveQuorumPlan, Error> {
    let mut digest = Sha256::new();
    digest.update(b"MeshSpan recovery quorum selection v1\0");
    digest.update(id.as_bytes());
    let digest = digest.finalize();
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest[..16]);
    let plan_id = QuorumPlanId::from_bytes(uuid_v8(bytes)).map_err(|_| Error::Input)?;
    let voters = nodes
        .iter()
        .filter(|node| node.roles.metadata_eligible())
        .map(|node| node.node_id)
        .collect();
    Ok(ActiveQuorumPlan::Stable(Box::new(
        compile_plan(flat_plan(plan_id, epoch, voters, BTreeSet::new()).map_err(|_| Error::Input)?)
            .map_err(|_| Error::Input)?,
    )))
}

fn convert_node(value: RecoveryNodeSelection) -> Result<RecoveryReplacementNode, Error> {
    let identity_public_key: [u8; 65] = hex(&value.identity_public_key)?
        .try_into()
        .map_err(|_| Error::Input)?;
    NodePublicIdentity::from_sec1(&identity_public_key).map_err(|_| Error::Input)?;
    let mut roles = 0;
    for role in value.roles {
        let bit = match role {
            RecoveryNodeRole::Storage => JoinRoles::STORAGE,
            RecoveryNodeRole::Gateway => JoinRoles::GATEWAY,
            RecoveryNodeRole::Metadata => JoinRoles::METADATA_ELIGIBLE,
        };
        if roles & bit != 0 {
            return Err(Error::Input);
        }
        roles |= bit;
    }
    Ok(RecoveryReplacementNode {
        node_id: NodeId::from_bytes(identifier(&value.node_id)?).map_err(|_| Error::Input)?,
        host_id: HostId::from_bytes(identifier(&value.host_id)?).map_err(|_| Error::Input)?,
        host_name: RecordName::new(&value.host_name).map_err(|_| Error::Input)?,
        node_name: RecordName::new(&value.node_name).map_err(|_| Error::Input)?,
        incarnation: value.incarnation.parse().map_err(|_| Error::Input)?,
        roles: JoinRoles::new(roles).map_err(|_| Error::Input)?,
        identity_public_key,
        wrapping_public_key: WrappingPublicKey::from_bytes(
            hex(&value.wrapping_public_key)?
                .try_into()
                .map_err(|_| Error::Input)?,
        )
        .map_err(|_| Error::Input)?,
        private_endpoint: value.private_endpoint,
    })
}

fn identifier(value: &str) -> Result<[u8; 16], Error> {
    crate::create_mesh_setup::parse_uuid(value).map_err(|_| Error::Input)
}

fn hex(value: &str) -> Result<Vec<u8>, Error> {
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::Input);
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).map_err(|_| Error::Input)?, 16)
                .map_err(|_| Error::Input)
        })
        .collect()
}
