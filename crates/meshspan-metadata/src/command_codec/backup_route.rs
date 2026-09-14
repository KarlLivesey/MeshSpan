// SPDX-License-Identifier: GPL-2.0-only

//! Closed canonical encoding shared by consensus and its immutable routing projection.

use super::{MetadataCommandCodecError as Error, decoder::Decoder, encoder::Encoder};
use crate::{BindFederatedBackupRoute, MetadataBackupRunClaim};
use meshspan_contracts::{
    BackupObjectIdentity, FederatedBackupScope, federated_provider_backup_identity,
};
use meshspan_domain::{
    BackupDestinationId, BackupId, FederationGrantId, FederationRelationshipId,
    FederationStorageAllocationId, MeshId, NodeId, Revision, TargetId,
};

pub(super) const LEGACY_KIND: u16 = 120;
pub(super) const KIND: u16 = 121;
pub(crate) const MAXIMUM_BYTES: usize = 320;

pub(super) fn encode(encoder: &mut Encoder, value: &BindFederatedBackupRoute) -> Result<(), Error> {
    validate(value)?;
    let object = value.object;
    let scope = value.scope;
    for id in [
        object.backup_id.as_bytes(),
        object.destination_id.as_bytes(),
        scope.relationship_id.as_bytes(),
        scope.remote_mesh_id.as_bytes(),
        scope.provider_mesh_id.as_bytes(),
        scope.allocation_id.as_bytes(),
        scope.grant_id.as_bytes(),
        scope.namespace_grant_id.as_bytes(),
        scope.provider_node_id.as_bytes(),
        scope.target_id.as_bytes(),
    ] {
        encoder.identifier(id)?;
    }
    for number in [
        object.provider_generation,
        object.byte_length,
        scope.target_generation,
        scope.relationship_authority_epoch,
        scope.grant_revision.get(),
        scope.allocation_revision.get(),
    ] {
        encoder.u64(number)?;
    }
    encoder.fixed(&object.digest)?;
    encoder.identifier(value.claim.worker_node_id.as_bytes())?;
    for number in [
        value.claim.worker_incarnation,
        value.claim.claim_generation,
        value.claim.fence,
        value.expected_destination_revision.get(),
    ] {
        encoder.u64(number)?;
    }
    Ok(())
}

pub(super) fn decode(
    decoder: &mut Decoder<'_>,
    version: u8,
) -> Result<BindFederatedBackupRoute, Error> {
    if !matches!(version, 1 | 2) {
        return Err(Error::Invalid);
    }
    let backup_id = BackupId::from_bytes(decoder.identifier()?).map_err(|_| Error::Invalid)?;
    let destination_id =
        BackupDestinationId::from_bytes(decoder.identifier()?).map_err(|_| Error::Invalid)?;
    let relationship_id =
        FederationRelationshipId::from_bytes(decoder.identifier()?).map_err(|_| Error::Invalid)?;
    let remote_mesh_id = MeshId::from_bytes(decoder.identifier()?).map_err(|_| Error::Invalid)?;
    let provider_mesh_id = MeshId::from_bytes(decoder.identifier()?).map_err(|_| Error::Invalid)?;
    let allocation_id = FederationStorageAllocationId::from_bytes(decoder.identifier()?)
        .map_err(|_| Error::Invalid)?;
    let grant_id =
        FederationGrantId::from_bytes(decoder.identifier()?).map_err(|_| Error::Invalid)?;
    // Version 1 predates renewable authority; its sole grant also names the physical origin.
    let namespace_grant_id = if version == 1 {
        grant_id
    } else {
        FederationGrantId::from_bytes(decoder.identifier()?).map_err(|_| Error::Invalid)?
    };
    let provider_node_id = NodeId::from_bytes(decoder.identifier()?).map_err(|_| Error::Invalid)?;
    let target_id = TargetId::from_bytes(decoder.identifier()?).map_err(|_| Error::Invalid)?;
    let provider_generation = decoder.u64()?;
    let byte_length = decoder.u64()?;
    let scope = FederatedBackupScope {
        relationship_id,
        remote_mesh_id,
        provider_mesh_id,
        allocation_id,
        grant_id,
        namespace_grant_id,
        provider_node_id,
        target_id,
        target_generation: decoder.u64()?,
        relationship_authority_epoch: decoder.u64()?,
        grant_revision: Revision::new(decoder.u64()?),
        allocation_revision: Revision::new(decoder.u64()?),
    };
    let digest = decoder.fixed()?;
    let value = BindFederatedBackupRoute {
        object: BackupObjectIdentity {
            backup_id,
            destination_id,
            provider_generation,
            byte_length,
            digest,
        },
        scope,
        claim: MetadataBackupRunClaim {
            worker_node_id: NodeId::from_bytes(decoder.identifier()?)
                .map_err(|_| Error::Invalid)?,
            worker_incarnation: decoder.u64()?,
            claim_generation: decoder.u64()?,
            fence: decoder.u64()?,
        },
        expected_destination_revision: Revision::new(decoder.u64()?),
    };
    validate(&value)?;
    Ok(value)
}

pub(crate) fn record(value: &BindFederatedBackupRoute) -> Result<Vec<u8>, Error> {
    let mut encoder = Encoder::new(MAXIMUM_BYTES);
    encoder.u8(2)?;
    encode(&mut encoder, value)?;
    Ok(encoder.finish())
}

pub(crate) fn parse(bytes: &[u8]) -> Result<BindFederatedBackupRoute, Error> {
    if bytes.len() > MAXIMUM_BYTES {
        return Err(Error::Invalid);
    }
    let mut decoder = Decoder::new(bytes);
    let version = decoder.u8()?;
    let value = decode(&mut decoder, version)?;
    decoder.finish()?;
    Ok(value)
}

fn validate(value: &BindFederatedBackupRoute) -> Result<(), Error> {
    federated_provider_backup_identity(value.scope, value.object).map_err(|_| Error::Invalid)?;
    if [
        value.object.provider_generation,
        value.object.byte_length,
        value.scope.target_generation,
        value.scope.relationship_authority_epoch,
        value.scope.grant_revision.get(),
        value.scope.allocation_revision.get(),
        value.claim.worker_incarnation,
        value.claim.claim_generation,
        value.claim.fence,
        value.expected_destination_revision.get(),
    ]
    .into_iter()
    .any(|number| number == 0 || number > i64::MAX.unsigned_abs())
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
