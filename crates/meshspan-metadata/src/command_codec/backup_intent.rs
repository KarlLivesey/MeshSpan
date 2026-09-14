// SPDX-License-Identifier: GPL-2.0-only

//! Canonical exact upload intent shared by consensus and its retained projection.

use super::{Decoder, Encoder, MetadataCommandCodecError as Error};
use crate::{BindBackupPublicationIntent, MetadataBackupRunClaim};
use meshspan_contracts::BackupObjectIdentity;
use meshspan_domain::{BackupDestinationId, BackupId, NodeId, OperationId, Revision};

pub(super) const KIND: u16 = 125;

pub(super) fn encode(
    encoder: &mut Encoder,
    value: &BindBackupPublicationIntent,
) -> Result<(), Error> {
    validate(value)?;
    encoder.identifier(value.object.backup_id.as_bytes())?;
    encoder.identifier(value.object.destination_id.as_bytes())?;
    encoder.u64(value.object.provider_generation)?;
    encoder.u64(value.object.byte_length)?;
    encoder.fixed(&value.object.digest)?;
    encoder.identifier(value.store_operation_id.as_bytes())?;
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

pub(super) fn decode(decoder: &mut Decoder<'_>) -> Result<BindBackupPublicationIntent, Error> {
    let value = BindBackupPublicationIntent {
        object: BackupObjectIdentity {
            backup_id: BackupId::from_bytes(decoder.identifier()?)?,
            destination_id: BackupDestinationId::from_bytes(decoder.identifier()?)?,
            provider_generation: decoder.u64()?,
            byte_length: decoder.u64()?,
            digest: decoder.fixed()?,
        },
        store_operation_id: OperationId::from_bytes(decoder.identifier()?)?,
        claim: MetadataBackupRunClaim {
            worker_node_id: NodeId::from_bytes(decoder.identifier()?)?,
            worker_incarnation: decoder.u64()?,
            claim_generation: decoder.u64()?,
            fence: decoder.u64()?,
        },
        expected_destination_revision: Revision::new(decoder.u64()?),
    };
    validate(&value)?;
    Ok(value)
}

fn validate(value: &BindBackupPublicationIntent) -> Result<(), Error> {
    if value.object.digest == [0; 32]
        || [
            value.object.provider_generation,
            value.object.byte_length,
            value.claim.worker_incarnation,
            value.claim.claim_generation,
            value.claim.fence,
            value.expected_destination_revision.get(),
        ]
        .into_iter()
        .any(|number| number == 0 || number > i64::MAX as u64)
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
