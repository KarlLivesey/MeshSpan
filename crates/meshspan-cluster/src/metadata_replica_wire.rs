// SPDX-License-Identifier: GPL-2.0-only

//! Conversions keep private protobuf framing separate from the passive metadata application model.

use meshspan_consensus::LogPosition;
use meshspan_domain::PartitionId;
use meshspan_protocol::{decode_metadata_replica_body, encode_metadata_replica_body, v1};

use crate::{MetadataReplicaCursor, MetadataReplicaPage, MetadataReplicaTransferError};

pub(crate) fn wire_cursor(cursor: MetadataReplicaCursor) -> v1::MetadataReplicaCursor {
    v1::MetadataReplicaCursor {
        partition_id: cursor.partition_id.as_bytes().to_vec(),
        membership_epoch: cursor.membership_epoch,
        plan_digest: cursor.plan_digest.to_vec(),
        applied: Some(v1::LogPosition {
            term: cursor.applied.term,
            index: cursor.applied.index,
        }),
        applied_digest: cursor.applied_digest.to_vec(),
    }
}

pub(crate) fn core_cursor(
    value: Option<&v1::MetadataReplicaCursor>,
) -> Result<MetadataReplicaCursor, MetadataReplicaTransferError> {
    let value = value.ok_or(MetadataReplicaTransferError::Rejected)?;
    let applied = value
        .applied
        .as_ref()
        .ok_or(MetadataReplicaTransferError::Rejected)?;
    Ok(MetadataReplicaCursor {
        partition_id: PartitionId::from_bytes(
            value
                .partition_id
                .as_slice()
                .try_into()
                .map_err(|_| MetadataReplicaTransferError::Rejected)?,
        )
        .map_err(|_| MetadataReplicaTransferError::Rejected)?,
        membership_epoch: value.membership_epoch,
        plan_digest: value
            .plan_digest
            .as_slice()
            .try_into()
            .map_err(|_| MetadataReplicaTransferError::Rejected)?,
        applied: LogPosition {
            term: applied.term,
            index: applied.index,
        },
        applied_digest: value
            .applied_digest
            .as_slice()
            .try_into()
            .map_err(|_| MetadataReplicaTransferError::Rejected)?,
    })
}

pub(crate) fn encode_page(
    page: &MetadataReplicaPage,
) -> Result<Vec<u8>, MetadataReplicaTransferError> {
    encode_metadata_replica_body(&v1::MetadataReplicaBody {
        format_version: 1,
        after: Some(wire_cursor(page.after)),
        entries: page.entries.iter().map(crate::wire::wire_entry).collect(),
    })
    .map_err(Into::into)
}

pub(crate) fn decode_page(
    bytes: &[u8],
) -> Result<MetadataReplicaPage, MetadataReplicaTransferError> {
    let body = decode_metadata_replica_body(bytes)?;
    Ok(MetadataReplicaPage {
        after: core_cursor(body.after.as_ref())?,
        entries: body
            .entries
            .iter()
            .map(crate::wire::core_entry)
            .collect::<Result<_, _>>()
            .map_err(|_| MetadataReplicaTransferError::Rejected)?,
    })
}
