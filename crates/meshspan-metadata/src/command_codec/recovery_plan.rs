// SPDX-License-Identifier: GPL-2.0-only

//! Canonical replacement-manifest bytes reuse the existing independently proved quorum codec.

use meshspan_consensus::ActiveQuorumPlan;
use meshspan_domain::{HostId, MeshId, NodeId, OperationId, PartitionId};
use meshspan_secret_envelope::WrappingPublicKey;

use super::{MetadataCommandCodecError, decoder::Decoder, encoder::Encoder};
use crate::{
    JoinRoles, RecordName, RecoveryReplacementNode, RecoveryReplacementPlan,
    RecoverySecretInventory,
};

const MAGIC: [u8; 7] = *b"MSRPLN\x01";
const MAXIMUM_BYTES: usize = 2 * 1024 * 1024;

pub(crate) fn encode(plan: &RecoveryReplacementPlan) -> Result<Vec<u8>, MetadataCommandCodecError> {
    plan.validate()?;
    let mut encoder = Encoder::new(MAXIMUM_BYTES);
    encoder.fixed(&MAGIC)?;
    encoder.identifier(plan.mesh_id.as_bytes())?;
    encoder.identifier(plan.partition_id.as_bytes())?;
    encoder.identifier(plan.recovery_id.as_bytes())?;
    encoder.u64(plan.recovery_epoch)?;
    encoder.u64(plan.secrets.generation_count)?;
    encoder.fixed(&plan.secrets.digest)?;
    encoder.bytes(
        &plan
            .quorum
            .encode()
            .map_err(|_| MetadataCommandCodecError::Invalid)?,
        65536,
    )?;
    encoder
        .u16(u16::try_from(plan.nodes.len()).map_err(|_| MetadataCommandCodecError::Invalid)?)?;
    for node in &plan.nodes {
        encode_node(&mut encoder, node)?;
    }
    Ok(encoder.finish())
}

pub(crate) fn decode(bytes: &[u8]) -> Result<RecoveryReplacementPlan, MetadataCommandCodecError> {
    if bytes.len() > MAXIMUM_BYTES {
        return Err(MetadataCommandCodecError::CapacityExceeded);
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.fixed::<7>()? != MAGIC {
        return Err(MetadataCommandCodecError::Invalid);
    }
    let mut plan = RecoveryReplacementPlan {
        mesh_id: MeshId::from_bytes(decoder.identifier()?)
            .map_err(|_| MetadataCommandCodecError::Invalid)?,
        partition_id: PartitionId::from_bytes(decoder.identifier()?)
            .map_err(|_| MetadataCommandCodecError::Invalid)?,
        recovery_id: OperationId::from_bytes(decoder.identifier()?)
            .map_err(|_| MetadataCommandCodecError::Invalid)?,
        recovery_epoch: decoder.u64()?,
        secrets: RecoverySecretInventory {
            generation_count: decoder.u64()?,
            digest: decoder.fixed()?,
        },
        quorum: ActiveQuorumPlan::decode(&decoder.bytes(65536)?)
            .map_err(|_| MetadataCommandCodecError::Invalid)?,
        nodes: Vec::new(),
    };
    let count = usize::from(decoder.u16()?);
    if count == 0 || count > 1024 {
        return Err(MetadataCommandCodecError::Invalid);
    }
    for _ in 0..count {
        plan.nodes.push(decode_node(&mut decoder)?);
    }
    decoder.finish()?;
    plan.validate()?;
    if encode(&plan)? != bytes {
        return Err(MetadataCommandCodecError::Invalid);
    }
    Ok(plan)
}

fn encode_node(
    encoder: &mut Encoder,
    node: &RecoveryReplacementNode,
) -> Result<(), MetadataCommandCodecError> {
    encoder.identifier(node.node_id.as_bytes())?;
    encoder.identifier(node.host_id.as_bytes())?;
    encoder.text(node.host_name.display(), 256)?;
    encoder.text(node.node_name.display(), 256)?;
    encoder.u64(node.incarnation)?;
    encoder.u8(node.roles.bits())?;
    encoder.fixed(&node.identity_public_key)?;
    encoder.fixed(&node.wrapping_public_key.as_bytes())?;
    encoder.text(&node.private_endpoint, 512)
}

fn decode_node(
    decoder: &mut Decoder<'_>,
) -> Result<RecoveryReplacementNode, MetadataCommandCodecError> {
    Ok(RecoveryReplacementNode {
        node_id: NodeId::from_bytes(decoder.identifier()?)
            .map_err(|_| MetadataCommandCodecError::Invalid)?,
        host_id: HostId::from_bytes(decoder.identifier()?)
            .map_err(|_| MetadataCommandCodecError::Invalid)?,
        host_name: RecordName::new(&decoder.text(256)?)
            .map_err(|_| MetadataCommandCodecError::Invalid)?,
        node_name: RecordName::new(&decoder.text(256)?)
            .map_err(|_| MetadataCommandCodecError::Invalid)?,
        incarnation: decoder.u64()?,
        roles: JoinRoles::new(decoder.u8()?).map_err(|_| MetadataCommandCodecError::Invalid)?,
        identity_public_key: decoder.fixed()?,
        wrapping_public_key: WrappingPublicKey::from_bytes(decoder.fixed()?)
            .map_err(|_| MetadataCommandCodecError::Invalid)?,
        private_endpoint: decoder.text(512)?,
    })
}
