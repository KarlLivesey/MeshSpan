// SPDX-License-Identifier: GPL-2.0-only

//! Canonical same-swarm transfer record for one protected stripe and its durable receipts.

use meshspan_contracts::{
    BoundedBytes, CodingLayout, ShardAcknowledgement, ShardIdentity, ShardReceipt,
    VersionedPayload as ContractPayload,
};
use meshspan_domain::{OperationId, Revision, TargetId};
use meshspan_filesystem::{
    CommittedProtectedStripe, ContentPublicationRequest, ManifestPublication, PreparedContentChunk,
    PreparedProtectedShard, PreparedProtectedStripe,
};
use meshspan_protocol::v1::VersionedPayload;

use crate::NativeGatewayWireError;

const FORMAT_VERSION: u32 = 1;
const DOMAIN: &[u8] = b"meshspan.native.protected-stripe.v1\0";
const MAXIMUM_BYTES: usize = 16 * 1_024;
const MAXIMUM_POLICY_BYTES: usize = 4_096;
const MAXIMUM_SHARDS: usize = 24;

/// Encodes one exact protected plan and which of its receipts were durable at publication.
#[must_use]
pub fn version_native_protected_stripe(value: &CommittedProtectedStripe) -> VersionedPayload {
    let stripe = &value.stripe;
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&stripe.chunk().chunk_index.to_be_bytes());
    bytes.extend_from_slice(&stripe.coding_layout().data_slices().to_be_bytes());
    bytes.extend_from_slice(&stripe.coding_layout().recovery_slices().to_be_bytes());
    bytes.extend_from_slice(&stripe.coding_layout().slice_bytes().to_be_bytes());
    bytes.extend_from_slice(&stripe.topology_revision().get().to_be_bytes());
    bytes.extend_from_slice(&stripe.capacity_revision().get().to_be_bytes());
    bytes.extend_from_slice(&stripe.policy_evidence().format_version.to_be_bytes());
    bytes.extend_from_slice(
        &u32::try_from(stripe.policy_evidence().bytes.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    bytes.extend_from_slice(stripe.policy_evidence().bytes.as_slice());
    bytes.extend_from_slice(
        &u16::try_from(stripe.shards().len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    for shard in stripe.shards() {
        encode_shard(&mut bytes, *shard, receipt_present(value, *shard));
    }
    VersionedPayload {
        format_version: FORMAT_VERSION,
        canonical_bytes: bytes,
    }
}

/// Decodes an authenticated but untrusted protected stripe transfer.
///
/// # Errors
///
/// Rejects excess, truncation, unknown roles, changed layout identity and fabricated receipts.
pub fn decode_native_protected_stripe(
    payload: &VersionedPayload,
    request: ContentPublicationRequest,
    chunk: PreparedContentChunk,
    manifest: ManifestPublication,
) -> Result<CommittedProtectedStripe, NativeGatewayWireError> {
    let mut reader = Reader::new(payload)?;
    if reader.u64()? != chunk.chunk_index {
        return Err(NativeGatewayWireError::Invalid);
    }
    let layout = CodingLayout::new(reader.u16()?, reader.u16()?, reader.u32()?)
        .map_err(|_| NativeGatewayWireError::Invalid)?;
    let topology_revision = Revision::new(reader.u64()?);
    let capacity_revision = Revision::new(reader.u64()?);
    let policy_version = reader.u32()?;
    let policy_length =
        usize::try_from(reader.u32()?).map_err(|_| NativeGatewayWireError::Invalid)?;
    let policy = ContractPayload {
        format_version: policy_version,
        bytes: BoundedBytes::copy_from(reader.bytes(policy_length)?, MAXIMUM_POLICY_BYTES)
            .map_err(|_| NativeGatewayWireError::Invalid)?,
    };
    let shard_count = usize::from(reader.u16()?);
    if shard_count == 0 || shard_count > MAXIMUM_SHARDS {
        return Err(NativeGatewayWireError::Invalid);
    }
    let mut shards = Vec::with_capacity(shard_count);
    let mut receipt_flags = Vec::with_capacity(shard_count);
    for _ in 0..shard_count {
        let (shard, receipt) = reader.shard()?;
        shards.push(shard);
        receipt_flags.push(receipt);
    }
    reader.finish()?;
    let expected_layout_digest = chunk.storage_layout_digest;
    let mut unbound = chunk;
    unbound.storage_layout_digest = [0; 32];
    let stripe = PreparedProtectedStripe::from_untrusted(
        request,
        unbound,
        layout,
        topology_revision,
        capacity_revision,
        policy,
        shards,
    )
    .map_err(|_| NativeGatewayWireError::Invalid)?;
    if stripe.chunk().storage_layout_digest != expected_layout_digest
        || manifest.manifest_id != request.manifest_id
        || manifest.root_digest == [0; 32]
    {
        return Err(NativeGatewayWireError::Invalid);
    }
    let receipts = stripe
        .shards()
        .iter()
        .zip(receipt_flags)
        .filter_map(|(shard, present)| {
            present.then_some(receipt(manifest, chunk.chunk_index, *shard))
        })
        .collect::<Vec<_>>();
    Ok(CommittedProtectedStripe {
        stripe,
        receipts: meshspan_contracts::BoundedItems::new(receipts, MAXIMUM_SHARDS)
            .map_err(|_| NativeGatewayWireError::Invalid)?,
    })
}

fn receipt_present(value: &CommittedProtectedStripe, shard: PreparedProtectedShard) -> bool {
    value.receipts.as_slice().iter().any(|receipt| {
        receipt.operation_id == shard.provider_operation_id
            && receipt.shard.shard_index == shard.shard_index
            && receipt.shard.generation == shard.shard_generation
            && receipt.length == shard.expected_length
            && receipt.digest == shard.expected_digest
            && receipt.target_id == shard.target_id
            && receipt.target_generation == shard.target_generation
    })
}

fn encode_shard(bytes: &mut Vec<u8>, shard: PreparedProtectedShard, receipt: bool) {
    bytes.extend_from_slice(&shard.shard_index.to_be_bytes());
    bytes.extend_from_slice(&shard.shard_generation.to_be_bytes());
    bytes.extend_from_slice(&shard.provider_operation_id.as_bytes());
    bytes.extend_from_slice(&shard.expected_length.to_be_bytes());
    bytes.extend_from_slice(&shard.expected_digest);
    bytes.extend_from_slice(&shard.target_id.as_bytes());
    bytes.extend_from_slice(&shard.target_generation.to_be_bytes());
    bytes.push(match shard.acknowledgement {
        ShardAcknowledgement::Required => 1,
        ShardAcknowledgement::Eventual => 2,
    });
    bytes.push(u8::from(receipt));
}

const fn receipt(
    manifest: ManifestPublication,
    chunk_index: u64,
    shard: PreparedProtectedShard,
) -> ShardReceipt {
    ShardReceipt {
        operation_id: shard.provider_operation_id,
        shard: ShardIdentity {
            manifest_digest: manifest.root_digest,
            stripe_index: chunk_index,
            shard_index: shard.shard_index,
            generation: shard.shard_generation,
        },
        length: shard.expected_length,
        digest: shard.expected_digest,
        target_id: shard.target_id,
        target_generation: shard.target_generation,
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(payload: &'a VersionedPayload) -> Result<Self, NativeGatewayWireError> {
        if payload.format_version != FORMAT_VERSION
            || payload.canonical_bytes.len() > MAXIMUM_BYTES
            || !payload.canonical_bytes.starts_with(DOMAIN)
        {
            return Err(NativeGatewayWireError::Invalid);
        }
        Ok(Self {
            bytes: &payload.canonical_bytes[DOMAIN.len()..],
            offset: 0,
        })
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], NativeGatewayWireError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(NativeGatewayWireError::Invalid)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(NativeGatewayWireError::Invalid)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], NativeGatewayWireError> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| NativeGatewayWireError::Invalid)
    }

    fn u16(&mut self) -> Result<u16, NativeGatewayWireError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, NativeGatewayWireError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, NativeGatewayWireError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn shard(&mut self) -> Result<(PreparedProtectedShard, bool), NativeGatewayWireError> {
        let shard_index = self.u16()?;
        let shard_generation = self.u32()?;
        let provider_operation_id =
            OperationId::from_bytes(self.array()?).map_err(|_| NativeGatewayWireError::Invalid)?;
        let expected_length = self.u64()?;
        let expected_digest = self.array()?;
        let target_id =
            TargetId::from_bytes(self.array()?).map_err(|_| NativeGatewayWireError::Invalid)?;
        let target_generation = self.u64()?;
        let acknowledgement = match self.array::<1>()?[0] {
            1 => ShardAcknowledgement::Required,
            2 => ShardAcknowledgement::Eventual,
            _ => return Err(NativeGatewayWireError::Invalid),
        };
        let receipt = match self.array::<1>()?[0] {
            0 => false,
            1 => true,
            _ => return Err(NativeGatewayWireError::Invalid),
        };
        Ok((
            PreparedProtectedShard {
                shard_index,
                shard_generation,
                provider_operation_id,
                expected_length,
                expected_digest,
                target_id,
                target_generation,
                acknowledgement,
            },
            receipt,
        ))
    }

    fn finish(self) -> Result<(), NativeGatewayWireError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(NativeGatewayWireError::Invalid)
        }
    }
}
