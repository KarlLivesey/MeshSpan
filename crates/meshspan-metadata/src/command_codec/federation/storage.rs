// SPDX-License-Identifier: GPL-2.0-only

//! Disjoint provider allocations: quota authority remains local to the owning swarm.

use super::{Decoder, Encoder, MetadataCommandCodecError};
use crate::{
    AuthoritativeCommand, IssueFederationStorageAllocation, RevokeFederationStorageAllocation,
};
use meshspan_domain::{
    FederationGrantId, FederationStorageAllocation, FederationStorageAllocationId, NodeId,
    Revision, TargetId, UnixMicros,
};

const ISSUE: u16 = 101;
const REVOKE: u16 = 102;
const SEAL: u16 = 122;

pub(super) fn is_kind(kind: u16) -> bool {
    (ISSUE..=REVOKE).contains(&kind) || kind == SEAL
}

pub(super) fn encode(
    encoder: &mut Encoder,
    command: &AuthoritativeCommand,
) -> Result<bool, MetadataCommandCodecError> {
    match command {
        AuthoritativeCommand::RecordFederationStorageSeal(value) => {
            encoder.u16(SEAL)?;
            encoder.identifier(value.provider_mesh_id.as_bytes())?;
            encoder.identifier(value.seal.allocation_id.as_bytes())?;
            encoder.identifier(value.seal.provider_node_id.as_bytes())?;
            encoder.identifier(value.seal.target_id.as_bytes())?;
            encoder.u64(value.seal.target_generation)?;
            encoder.u64(value.seal.ceiling_bytes)?;
            encoder.u64(value.seal.sequence)?;
            encoder.i64(value.seal.sealed_at.get())?;
            encoder.u64(value.node_incarnation)?;
            encoder.u64(value.key_generation)?;
            encoder.fixed(&value.signature)?;
        }
        AuthoritativeCommand::IssueFederationStorageAllocation(value) => {
            let allocation = value.allocation;
            encoder.u16(ISSUE)?;
            encoder.identifier(allocation.allocation_id().as_bytes())?;
            encoder.identifier(allocation.grant_id().as_bytes())?;
            encoder.identifier(allocation.provider_node_id().as_bytes())?;
            encoder.identifier(allocation.target_id().as_bytes())?;
            encoder.u64(allocation.target_generation())?;
            encoder.u64(allocation.maximum_bytes())?;
            encoder.i64(allocation.valid_from().get())?;
            encoder.i64(allocation.valid_until().get())?;
            encoder.u64(value.expected_grant_revision.get())?;
        }
        AuthoritativeCommand::RevokeFederationStorageAllocation(value) => {
            encoder.u16(REVOKE)?;
            encoder.identifier(value.allocation_id.as_bytes())?;
            encoder.u64(value.expected_allocation_revision.get())?;
            encoder.text(&value.reason, 512)?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

pub(super) fn decode(
    kind: u16,
    decoder: &mut Decoder<'_>,
) -> Result<AuthoritativeCommand, MetadataCommandCodecError> {
    Ok(match kind {
        SEAL => {
            AuthoritativeCommand::RecordFederationStorageSeal(crate::RecordFederationStorageSeal {
                provider_mesh_id: meshspan_domain::MeshId::from_bytes(decoder.identifier()?)?,
                seal: crate::FederationStorageCapacitySeal {
                    allocation_id: FederationStorageAllocationId::from_bytes(
                        decoder.identifier()?,
                    )?,
                    provider_node_id: NodeId::from_bytes(decoder.identifier()?)?,
                    target_id: TargetId::from_bytes(decoder.identifier()?)?,
                    target_generation: decoder.u64()?,
                    ceiling_bytes: decoder.u64()?,
                    sequence: decoder.u64()?,
                    sealed_at: UnixMicros::new(decoder.i64()?),
                },
                node_incarnation: decoder.u64()?,
                key_generation: decoder.u64()?,
                signature: decoder.fixed()?,
            })
        }
        ISSUE => {
            let allocation = FederationStorageAllocation::new(
                FederationStorageAllocationId::from_bytes(decoder.identifier()?)?,
                FederationGrantId::from_bytes(decoder.identifier()?)?,
                NodeId::from_bytes(decoder.identifier()?)?,
                TargetId::from_bytes(decoder.identifier()?)?,
                decoder.u64()?,
                decoder.u64()?,
                UnixMicros::new(decoder.i64()?),
                UnixMicros::new(decoder.i64()?),
            )
            .map_err(|_| MetadataCommandCodecError::Invalid)?;
            AuthoritativeCommand::IssueFederationStorageAllocation(
                IssueFederationStorageAllocation {
                    allocation,
                    expected_grant_revision: Revision::new(decoder.u64()?),
                },
            )
        }
        REVOKE => AuthoritativeCommand::RevokeFederationStorageAllocation(
            RevokeFederationStorageAllocation {
                allocation_id: FederationStorageAllocationId::from_bytes(decoder.identifier()?)?,
                expected_allocation_revision: Revision::new(decoder.u64()?),
                reason: decoder.text(512)?,
            },
        ),
        _ => return Err(MetadataCommandCodecError::Unsupported),
    })
}
