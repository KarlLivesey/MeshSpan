// SPDX-License-Identifier: GPL-2.0-only

//! Durable erasure-coded stripe geometry, placement and provider acknowledgements.

use std::collections::BTreeSet;

use meshspan_contracts::{
    BoundedItems, CodingLayout, ShardAcknowledgement, ShardReceipt, VersionedPayload,
};
use meshspan_domain::{OperationId, Revision, TargetId, UnixMicros};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use super::repository::{
    copy_array, decode_target, from_sql, layout_is_sealed, load_prepared_manifest, to_i64,
    validate_chunk, validate_exact_request, validate_live_request,
};
use super::{
    ContentCatalogError, ContentPublicationRequest, DurableContentCatalog, MAXIMUM_PAGE_ITEMS,
    PreparedContentChunk,
};

const LAYOUT_DOMAIN: &[u8] = b"meshspan.content.protected-stripe-layout.v1\0";
const MAXIMUM_POLICY_BYTES: usize = 4_096;
const MAXIMUM_STRIPE_SHARDS: usize = 24;

/// One exact erasure-coded shard destination prepared before provider IO.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedProtectedShard {
    /// Stable zero-based position within the coded stripe.
    pub shard_index: u16,
    /// Generation of these shard bytes within the logical stripe.
    pub shard_generation: u32,
    /// Idempotent provider write identity.
    pub provider_operation_id: OperationId,
    /// Exact full encoded length.
    pub expected_length: u64,
    /// BLAKE3 identity checked before and after provider IO.
    pub expected_digest: [u8; 32],
    /// Exact planned storage target.
    pub target_id: TargetId,
    /// Target incarnation fence observed by placement.
    pub target_generation: u64,
    /// Whether this receipt gates acknowledgement of the logical write.
    pub acknowledgement: ShardAcknowledgement,
}

/// One immutable, revision-bound protected stripe plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedProtectedStripe {
    chunk: PreparedContentChunk,
    coding_layout: CodingLayout,
    topology_revision: Revision,
    capacity_revision: Revision,
    policy_evidence: VersionedPayload,
    shards: BoundedItems<PreparedProtectedShard>,
}

/// One committed protected stripe plus the exact durable receipts currently held for it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedProtectedStripe {
    /// Immutable coding and placement record.
    pub stripe: PreparedProtectedStripe,
    /// Durable receipts for every required shard and any completed eventual shard.
    pub receipts: BoundedItems<ShardReceipt>,
}

impl PreparedProtectedStripe {
    /// Validates untrusted placement output and binds it into the chunk manifest identity.
    ///
    /// # Errors
    ///
    /// Rejects any malformed geometry, revision, policy, shard ordering or target fence.
    pub fn from_untrusted(
        request: ContentPublicationRequest,
        mut chunk: PreparedContentChunk,
        coding_layout: CodingLayout,
        topology_revision: Revision,
        capacity_revision: Revision,
        policy_evidence: VersionedPayload,
        shards: Vec<PreparedProtectedShard>,
    ) -> Result<Self, ContentCatalogError> {
        if request.format_version != 2
            || chunk.storage_layout_digest != [0; 32]
            || topology_revision == Revision::ZERO
            || capacity_revision == Revision::ZERO
            || policy_evidence.format_version == 0
            || policy_evidence.bytes.is_empty()
            || policy_evidence.bytes.len() > MAXIMUM_POLICY_BYTES
            || shards.len() != usize::from(coding_layout.total_slices())
            || u64::from(coding_layout.data_slices())
                .checked_mul(u64::from(coding_layout.slice_bytes()))
                .is_none_or(|capacity| chunk.ciphertext_length > capacity)
        {
            return Err(ContentCatalogError::InvalidInput);
        }
        validate_shards(coding_layout, &shards)?;
        let bounded = BoundedItems::new(shards, MAXIMUM_STRIPE_SHARDS)
            .map_err(|_| ContentCatalogError::InvalidInput)?;
        chunk.storage_layout_digest = layout_digest(
            request,
            chunk,
            coding_layout,
            topology_revision,
            capacity_revision,
            &policy_evidence,
            bounded.as_slice(),
        );
        Ok(Self {
            chunk,
            coding_layout,
            topology_revision,
            capacity_revision,
            policy_evidence,
            shards: bounded,
        })
    }

    /// Manifest-bound encrypted chunk identity.
    #[must_use]
    pub const fn chunk(&self) -> PreparedContentChunk {
        self.chunk
    }

    /// Exact immutable coding geometry.
    #[must_use]
    pub const fn coding_layout(&self) -> CodingLayout {
        self.coding_layout
    }

    /// Topology revision used to prove the placement.
    #[must_use]
    pub const fn topology_revision(&self) -> Revision {
        self.topology_revision
    }

    /// Capacity observation revision used to admit the placement.
    #[must_use]
    pub const fn capacity_revision(&self) -> Revision {
        self.capacity_revision
    }

    /// Versioned acknowledgement and locality policy evidence.
    #[must_use]
    pub const fn policy_evidence(&self) -> &VersionedPayload {
        &self.policy_evidence
    }

    /// Exact ordered shard identities and destinations.
    #[must_use]
    pub fn shards(&self) -> &[PreparedProtectedShard] {
        self.shards.as_slice()
    }

    fn from_stored(
        request: ContentPublicationRequest,
        chunk: PreparedContentChunk,
        coding_layout: CodingLayout,
        topology_revision: Revision,
        capacity_revision: Revision,
        policy_evidence: VersionedPayload,
        shards: Vec<PreparedProtectedShard>,
    ) -> Result<Self, ContentCatalogError> {
        if chunk.storage_layout_digest == [0; 32] {
            return Err(ContentCatalogError::Corrupt);
        }
        let expected_digest = chunk.storage_layout_digest;
        let mut unbound = chunk;
        unbound.storage_layout_digest = [0; 32];
        let loaded = Self::from_untrusted(
            request,
            unbound,
            coding_layout,
            topology_revision,
            capacity_revision,
            policy_evidence,
            shards,
        )
        .map_err(|_| ContentCatalogError::Corrupt)?;
        if loaded.chunk.storage_layout_digest == expected_digest {
            Ok(loaded)
        } else {
            Err(ContentCatalogError::Corrupt)
        }
    }
}

/// Stable keyset position for one protected shard page.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProtectedShardCursor {
    /// Logical chunk/stripe index.
    pub chunk_index: u64,
    /// Shard index within that stripe.
    pub shard_index: u16,
}

/// One bounded page of protected shard writes lacking durable receipts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingProtectedShardPage {
    /// Pending writes in stable stripe then shard order.
    pub shards: BoundedItems<(ProtectedShardCursor, PreparedProtectedShard)>,
    /// Last returned key when another page exists.
    pub next: Option<ProtectedShardCursor>,
}

impl DurableContentCatalog {
    /// Loads one committed protected stripe and reconstitutes its exact recorded receipts.
    ///
    /// # Errors
    ///
    /// Rejects an uncommitted/wrong-format manifest, unknown stripe or inconsistent receipt row.
    pub fn committed_protected_stripe(
        &self,
        content: crate::PublishedContentReference,
        chunk_index: u64,
    ) -> Result<CommittedProtectedStripe, ContentCatalogError> {
        let committed = self.committed_layout(content)?;
        if committed.request.format_version != 2 {
            return Err(ContentCatalogError::InvalidInput);
        }
        let stripe = load_protected_stripe(&self.connection, committed.request, chunk_index)?;
        let mut statement = self.connection.prepare(
            "SELECT shard_index FROM content_stripe_shards
             WHERE operation_id = ?1 AND chunk_index = ?2 AND receipt_recorded_at IS NOT NULL
             ORDER BY shard_index LIMIT ?3",
        )?;
        let indices = statement
            .query_map(
                params![
                    committed.request.operation_id.as_bytes().as_slice(),
                    to_i64(chunk_index)?,
                    i64::try_from(MAXIMUM_STRIPE_SHARDS + 1)
                        .map_err(|_| ContentCatalogError::Corrupt)?,
                ],
                |row| {
                    u16::try_from(row.get::<_, i64>(0)?).map_err(|_| rusqlite::Error::InvalidQuery)
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;
        let receipts = indices
            .into_iter()
            .map(|index| {
                let shard = stripe
                    .shards()
                    .get(usize::from(index))
                    .copied()
                    .filter(|shard| shard.shard_index == index)
                    .ok_or(ContentCatalogError::Corrupt)?;
                Ok::<ShardReceipt, ContentCatalogError>(ShardReceipt {
                    operation_id: shard.provider_operation_id,
                    shard: meshspan_contracts::ShardIdentity {
                        manifest_digest: content.manifest.root_digest,
                        stripe_index: chunk_index,
                        shard_index: index,
                        generation: shard.shard_generation,
                    },
                    length: shard.expected_length,
                    digest: shard.expected_digest,
                    target_id: shard.target_id,
                    target_generation: shard.target_generation,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(CommittedProtectedStripe {
            stripe,
            receipts: BoundedItems::new(receipts, MAXIMUM_STRIPE_SHARDS)
                .map_err(|_| ContentCatalogError::Corrupt)?,
        })
    }

    /// Installs source-authenticated protected plans beside already imported chunk identities.
    ///
    /// # Errors
    ///
    /// Rejects missing/different chunks, duplicate layouts, malformed placement or excess pages.
    pub fn append_protected_layout_import_page(
        &mut self,
        request: ContentPublicationRequest,
        stripes: &[PreparedProtectedStripe],
    ) -> Result<(), ContentCatalogError> {
        validate_live_request(request)?;
        validate_exact_request(&self.connection, request)?;
        if request.format_version != 2 || stripes.is_empty() || stripes.len() > MAXIMUM_PAGE_ITEMS {
            return Err(ContentCatalogError::InvalidInput);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for stripe in stripes {
            let stored = super::repository::load_chunk(
                &transaction,
                request.operation_id,
                stripe.chunk().chunk_index,
            )?;
            if stored != stripe.chunk()
                || recompute_digest(request, stripe) != stripe.chunk().storage_layout_digest
            {
                return Err(ContentCatalogError::Conflict);
            }
            let exists: bool = transaction.query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM content_stripe_layouts
                    WHERE operation_id = ?1 AND chunk_index = ?2
                 )",
                params![
                    request.operation_id.as_bytes().as_slice(),
                    to_i64(stripe.chunk().chunk_index)?,
                ],
                |row| row.get(0),
            )?;
            if exists {
                if load_protected_stripe(&transaction, request, stripe.chunk().chunk_index)?
                    == *stripe
                {
                    continue;
                }
                return Err(ContentCatalogError::Conflict);
            }
            insert_stripe_layout(&transaction, request.operation_id, stripe)?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Appends contiguous protected stripes and all planned shard writes atomically.
    ///
    /// # Errors
    ///
    /// Rejects gaps, changed plans, malformed evidence, sealed layouts and excessive pages.
    pub fn append_protected_stripes(
        &mut self,
        request: ContentPublicationRequest,
        stripes: &[PreparedProtectedStripe],
    ) -> Result<(), ContentCatalogError> {
        validate_live_request(request)?;
        validate_exact_request(&self.connection, request)?;
        if request.format_version != 2
            || stripes.is_empty()
            || stripes.len() > MAXIMUM_PAGE_ITEMS
            || layout_is_sealed(&self.connection, request.operation_id)?
        {
            return Err(ContentCatalogError::InvalidInput);
        }
        let expected: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM content_chunks WHERE operation_id = ?1",
            [request.operation_id.as_bytes().as_slice()],
            |row| row.get(0),
        )?;
        let expected = from_sql(expected)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for (offset, stripe) in stripes.iter().enumerate() {
            let index = expected
                .checked_add(u64::try_from(offset).map_err(|_| ContentCatalogError::InvalidInput)?)
                .ok_or(ContentCatalogError::InvalidInput)?;
            validate_chunk(stripe.chunk, index, request.format_version)?;
            if recompute_digest(request, stripe) != stripe.chunk.storage_layout_digest {
                return Err(ContentCatalogError::Conflict);
            }
            insert_stripe(&transaction, request.operation_id, stripe)?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Returns a bounded keyset page of protected shard writes still awaiting receipts.
    ///
    /// # Errors
    ///
    /// Rejects malformed bounds, conflicting operations and corrupt durable rows.
    pub fn pending_protected_shards(
        &self,
        request: ContentPublicationRequest,
        after: Option<ProtectedShardCursor>,
        limit: usize,
    ) -> Result<PendingProtectedShardPage, ContentCatalogError> {
        validate_exact_request(&self.connection, request)?;
        if request.format_version != 2 || limit == 0 || limit > MAXIMUM_PAGE_ITEMS {
            return Err(ContentCatalogError::InvalidInput);
        }
        let (after_chunk, after_shard) = after.map_or((-1, -1), |cursor| {
            (
                i64::try_from(cursor.chunk_index).unwrap_or(i64::MAX),
                i64::from(cursor.shard_index),
            )
        });
        let mut statement = self.connection.prepare(
            "SELECT chunk_index, shard_index, shard_generation, provider_operation_id,
                    expected_length, expected_digest, target_id, target_generation,
                    required_for_commit
             FROM content_stripe_shards
             WHERE operation_id = ?1 AND receipt_recorded_at IS NULL
               AND (chunk_index > ?2 OR (chunk_index = ?2 AND shard_index > ?3))
             ORDER BY chunk_index, shard_index LIMIT ?4",
        )?;
        let rows = statement.query_map(
            params![
                request.operation_id.as_bytes().as_slice(),
                after_chunk,
                after_shard,
                i64::try_from(limit.saturating_add(1))
                    .map_err(|_| ContentCatalogError::InvalidInput)?,
            ],
            decode_pending_shard,
        )?;
        let mut shards = rows.collect::<Result<Vec<_>, _>>()?;
        let next = if shards.len() > limit {
            shards.pop();
            shards.last().map(|(cursor, _)| *cursor)
        } else {
            None
        };
        Ok(PendingProtectedShardPage {
            shards: BoundedItems::new(shards, limit).map_err(|_| ContentCatalogError::Corrupt)?,
            next,
        })
    }

    /// Loads and independently revalidates one complete protected stripe plan.
    ///
    /// # Errors
    ///
    /// Rejects an unknown stripe and any malformed, incomplete or substituted durable field.
    pub fn protected_stripe(
        &self,
        request: ContentPublicationRequest,
        chunk_index: u64,
    ) -> Result<PreparedProtectedStripe, ContentCatalogError> {
        validate_exact_request(&self.connection, request)?;
        if request.format_version != 2 {
            return Err(ContentCatalogError::InvalidInput);
        }
        load_protected_stripe(&self.connection, request, chunk_index)
    }

    /// Records one exact durable receipt for a protected shard.
    ///
    /// # Errors
    ///
    /// Rejects unsealed layouts, any receipt substitution and conflicting replay.
    pub fn record_protected_receipt(
        &mut self,
        request: ContentPublicationRequest,
        receipt: ShardReceipt,
        recorded_at: UnixMicros,
    ) -> Result<(), ContentCatalogError> {
        if request.format_version != 2 {
            return Err(ContentCatalogError::InvalidInput);
        }
        let manifest = load_prepared_manifest(&self.connection, request)?
            .ok_or(ContentCatalogError::InvalidInput)?;
        let cursor = ProtectedShardCursor {
            chunk_index: receipt.shard.stripe_index,
            shard_index: receipt.shard.shard_index,
        };
        let expected = load_protected_shard(&self.connection, request.operation_id, cursor)?;
        if receipt.shard.manifest_digest != manifest.root_digest
            || !receipt_matches(receipt, expected)
        {
            return Err(ContentCatalogError::InvalidInput);
        }
        let existing: Option<i64> = self
            .connection
            .query_row(
                "SELECT receipt_recorded_at FROM content_stripe_shards
                 WHERE operation_id = ?1 AND chunk_index = ?2 AND shard_index = ?3",
                params![
                    request.operation_id.as_bytes().as_slice(),
                    to_i64(cursor.chunk_index)?,
                    i64::from(cursor.shard_index),
                ],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        if existing.is_some() {
            return Ok(());
        }
        let updated = self.connection.execute(
            "UPDATE content_stripe_shards SET receipt_recorded_at = ?1
             WHERE operation_id = ?2 AND chunk_index = ?3 AND shard_index = ?4
               AND receipt_recorded_at IS NULL",
            params![
                recorded_at.get(),
                request.operation_id.as_bytes().as_slice(),
                to_i64(cursor.chunk_index)?,
                i64::from(cursor.shard_index),
            ],
        )?;
        if updated == 1 {
            Ok(())
        } else {
            Err(ContentCatalogError::Conflict)
        }
    }
}

fn validate_shards(
    layout: CodingLayout,
    shards: &[PreparedProtectedShard],
) -> Result<(), ContentCatalogError> {
    if shards
        .iter()
        .filter(|shard| shard.acknowledgement == ShardAcknowledgement::Required)
        .count()
        < usize::from(layout.data_slices())
    {
        return Err(ContentCatalogError::InvalidInput);
    }
    let mut operations = BTreeSet::new();
    let mut targets = BTreeSet::new();
    for (index, shard) in shards.iter().enumerate() {
        if usize::from(shard.shard_index) != index
            || shard.shard_generation == 0
            || shard.expected_length != u64::from(layout.slice_bytes())
            || shard.target_generation == 0
            || !operations.insert(shard.provider_operation_id)
            || !targets.insert(shard.target_id)
        {
            return Err(ContentCatalogError::InvalidInput);
        }
    }
    Ok(())
}

fn recompute_digest(
    request: ContentPublicationRequest,
    stripe: &PreparedProtectedStripe,
) -> [u8; 32] {
    layout_digest(
        request,
        stripe.chunk,
        stripe.coding_layout,
        stripe.topology_revision,
        stripe.capacity_revision,
        &stripe.policy_evidence,
        stripe.shards.as_slice(),
    )
}

fn layout_digest(
    request: ContentPublicationRequest,
    chunk: PreparedContentChunk,
    layout: CodingLayout,
    topology_revision: Revision,
    capacity_revision: Revision,
    policy: &VersionedPayload,
    shards: &[PreparedProtectedShard],
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(LAYOUT_DOMAIN);
    digest.update(&request.operation_id.as_bytes());
    digest.update(&request.manifest_id.as_bytes());
    digest.update(&chunk.chunk_index.to_be_bytes());
    digest.update(&chunk.ciphertext_length.to_be_bytes());
    digest.update(&chunk.ciphertext_digest);
    digest.update(&layout.data_slices().to_be_bytes());
    digest.update(&layout.recovery_slices().to_be_bytes());
    digest.update(&layout.slice_bytes().to_be_bytes());
    digest.update(&topology_revision.get().to_be_bytes());
    digest.update(&capacity_revision.get().to_be_bytes());
    digest.update(&policy.format_version.to_be_bytes());
    digest.update(policy.bytes.as_slice());
    for shard in shards {
        digest.update(&shard.shard_index.to_be_bytes());
        digest.update(&shard.shard_generation.to_be_bytes());
        digest.update(&shard.provider_operation_id.as_bytes());
        digest.update(&shard.expected_length.to_be_bytes());
        digest.update(&shard.expected_digest);
        digest.update(&shard.target_id.as_bytes());
        digest.update(&shard.target_generation.to_be_bytes());
        digest.update(&[match shard.acknowledgement {
            ShardAcknowledgement::Required => 1,
            ShardAcknowledgement::Eventual => 0,
        }]);
    }
    digest.finalize().into()
}

fn insert_stripe(
    transaction: &rusqlite::Transaction<'_>,
    operation_id: OperationId,
    stripe: &PreparedProtectedStripe,
) -> Result<(), ContentCatalogError> {
    transaction.execute(
        "INSERT INTO content_chunks(
            operation_id, chunk_index, plaintext_length, plaintext_digest,
            ciphertext_length, ciphertext_digest, storage_layout_digest,
            provider_operation_id
         ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![
            operation_id.as_bytes().as_slice(),
            to_i64(stripe.chunk.chunk_index)?,
            to_i64(stripe.chunk.plaintext_length)?,
            stripe.chunk.plaintext_digest.as_slice(),
            to_i64(stripe.chunk.ciphertext_length)?,
            stripe.chunk.ciphertext_digest.as_slice(),
            stripe.chunk.storage_layout_digest.as_slice(),
            stripe.chunk.provider_operation_id.as_bytes().as_slice(),
        ],
    )?;
    insert_stripe_layout(transaction, operation_id, stripe)
}

fn insert_stripe_layout(
    transaction: &rusqlite::Transaction<'_>,
    operation_id: OperationId,
    stripe: &PreparedProtectedStripe,
) -> Result<(), ContentCatalogError> {
    transaction.execute(
        "INSERT INTO content_stripe_layouts(
            operation_id, chunk_index, data_slices, recovery_slices, slice_bytes,
            topology_revision, capacity_revision, policy_format_version, policy_evidence,
            layout_digest
         ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        params![
            operation_id.as_bytes().as_slice(),
            to_i64(stripe.chunk.chunk_index)?,
            i64::from(stripe.coding_layout.data_slices()),
            i64::from(stripe.coding_layout.recovery_slices()),
            i64::from(stripe.coding_layout.slice_bytes()),
            to_i64(stripe.topology_revision.get())?,
            to_i64(stripe.capacity_revision.get())?,
            i64::from(stripe.policy_evidence.format_version),
            stripe.policy_evidence.bytes.as_slice(),
            stripe.chunk.storage_layout_digest.as_slice(),
        ],
    )?;
    for shard in stripe.shards.as_slice() {
        transaction.execute(
            "INSERT INTO content_stripe_shards(
                operation_id, chunk_index, shard_index, shard_generation,
                provider_operation_id, expected_length, expected_digest, target_id,
                target_generation, required_for_commit
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                operation_id.as_bytes().as_slice(),
                to_i64(stripe.chunk.chunk_index)?,
                i64::from(shard.shard_index),
                i64::from(shard.shard_generation),
                shard.provider_operation_id.as_bytes().as_slice(),
                to_i64(shard.expected_length)?,
                shard.expected_digest.as_slice(),
                shard.target_id.as_bytes().as_slice(),
                to_i64(shard.target_generation)?,
                match shard.acknowledgement {
                    ShardAcknowledgement::Required => 1,
                    ShardAcknowledgement::Eventual => 0,
                },
            ],
        )?;
    }
    Ok(())
}

fn decode_pending_shard(
    row: &rusqlite::Row<'_>,
) -> Result<(ProtectedShardCursor, PreparedProtectedShard), rusqlite::Error> {
    Ok((
        ProtectedShardCursor {
            chunk_index: from_sql(row.get(0)?)?,
            shard_index: u16::try_from(row.get::<_, i64>(1)?)
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
        },
        PreparedProtectedShard {
            shard_index: u16::try_from(row.get::<_, i64>(1)?)
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
            shard_generation: u32::try_from(row.get::<_, i64>(2)?)
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
            provider_operation_id: OperationId::from_bytes(copy_array(&row.get::<_, Vec<u8>>(3)?)?)
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
            expected_length: from_sql(row.get(4)?)?,
            expected_digest: copy_array(&row.get::<_, Vec<u8>>(5)?)?,
            target_id: decode_target(&row.get::<_, Vec<u8>>(6)?)?,
            target_generation: from_sql(row.get(7)?)?,
            acknowledgement: if row.get::<_, bool>(8)? {
                ShardAcknowledgement::Required
            } else {
                ShardAcknowledgement::Eventual
            },
        },
    ))
}

fn load_protected_shard(
    connection: &rusqlite::Connection,
    operation_id: OperationId,
    cursor: ProtectedShardCursor,
) -> Result<PreparedProtectedShard, ContentCatalogError> {
    connection
        .query_row(
            "SELECT chunk_index, shard_index, shard_generation, provider_operation_id,
                    expected_length, expected_digest, target_id, target_generation,
                    required_for_commit
             FROM content_stripe_shards
             WHERE operation_id = ?1 AND chunk_index = ?2 AND shard_index = ?3",
            params![
                operation_id.as_bytes().as_slice(),
                to_i64(cursor.chunk_index)?,
                i64::from(cursor.shard_index),
            ],
            |row| decode_pending_shard(row).map(|(_, shard)| shard),
        )
        .optional()?
        .ok_or(ContentCatalogError::InvalidInput)
}

fn load_protected_stripe(
    connection: &rusqlite::Connection,
    request: ContentPublicationRequest,
    chunk_index: u64,
) -> Result<PreparedProtectedStripe, ContentCatalogError> {
    let chunk = super::repository::load_chunk(connection, request.operation_id, chunk_index)?;
    let stored = connection
        .query_row(
            "SELECT data_slices, recovery_slices, slice_bytes, topology_revision,
                    capacity_revision, policy_format_version, policy_evidence, layout_digest
             FROM content_stripe_layouts WHERE operation_id = ?1 AND chunk_index = ?2",
            params![
                request.operation_id.as_bytes().as_slice(),
                to_i64(chunk_index)?,
            ],
            |row| {
                Ok((
                    u16::try_from(row.get::<_, i64>(0)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    u16::try_from(row.get::<_, i64>(1)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    u32::try_from(row.get::<_, i64>(2)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    Revision::new(from_sql(row.get(3)?)?),
                    Revision::new(from_sql(row.get(4)?)?),
                    u32::try_from(row.get::<_, i64>(5)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    row.get::<_, Vec<u8>>(6)?,
                    copy_array::<32>(&row.get::<_, Vec<u8>>(7)?)?,
                ))
            },
        )
        .optional()?
        .ok_or(ContentCatalogError::InvalidInput)?;
    if stored.7 != chunk.storage_layout_digest {
        return Err(ContentCatalogError::Corrupt);
    }
    let layout = CodingLayout::new(stored.0, stored.1, stored.2)
        .map_err(|_| ContentCatalogError::Corrupt)?;
    let policy_evidence = VersionedPayload {
        format_version: stored.5,
        bytes: meshspan_contracts::BoundedBytes::from_vec(stored.6, MAXIMUM_POLICY_BYTES)
            .map_err(|_| ContentCatalogError::Corrupt)?,
    };
    let mut statement = connection.prepare(
        "SELECT chunk_index, shard_index, shard_generation, provider_operation_id,
                expected_length, expected_digest, target_id, target_generation,
                required_for_commit
         FROM content_stripe_shards WHERE operation_id = ?1 AND chunk_index = ?2
         ORDER BY shard_index LIMIT ?3",
    )?;
    let shards = statement
        .query_map(
            params![
                request.operation_id.as_bytes().as_slice(),
                to_i64(chunk_index)?,
                i64::try_from(MAXIMUM_STRIPE_SHARDS + 1)
                    .map_err(|_| ContentCatalogError::Corrupt)?,
            ],
            |row| decode_pending_shard(row).map(|(_, shard)| shard),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    PreparedProtectedStripe::from_stored(
        request,
        chunk,
        layout,
        stored.3,
        stored.4,
        policy_evidence,
        shards,
    )
}

fn receipt_matches(receipt: ShardReceipt, expected: PreparedProtectedShard) -> bool {
    receipt.operation_id == expected.provider_operation_id
        && receipt.shard.shard_index == expected.shard_index
        && receipt.shard.generation == expected.shard_generation
        && receipt.length == expected.expected_length
        && receipt.digest == expected.expected_digest
        && receipt.target_id == expected.target_id
        && receipt.target_generation == expected.target_generation
}
