// SPDX-License-Identifier: GPL-2.0-only

//! Durable erasure-coded stripe geometry, placement and provider acknowledgements.

use std::collections::BTreeSet;

use meshspan_contracts::{
    BoundedItems, CodingLayout, ShardAcknowledgement, ShardReceipt, VersionedPayload,
};
use meshspan_domain::{DurabilityScope, OperationId, Revision, TargetId, UnixMicros};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use super::repository::{
    copy_array, decode_target, from_sql, layout_is_sealed, load_prepared_manifest, to_i64,
    validate_chunk, validate_exact_request, validate_live_request,
};
use super::{
    ContentCatalogError, ContentPublicationRequest, DurableContentCatalog, MAXIMUM_PAGE_ITEMS,
    ManifestPublication, PreparedContentChunk,
};
use crate::{
    ContentAcknowledgementClass, ContentAcknowledgementEvidence, ContentAcknowledgementOutcome,
    ContentAcknowledgementPolicy, ContentStrongFallback,
};

mod repair;
mod target_inventory;

pub use repair::{ShardRepairCandidate, ShardRepairTransition};
pub use target_inventory::{TargetShardCursor, TargetShardPage, TargetShardRoute};

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
    /// Whether this receipt gates an explicitly permitted eventual fallback.
    pub eventual_fallback: ShardAcknowledgement,
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
    /// Returns one bounded keyset page of exact current shard routes on a target generation.
    ///
    /// Original placement rows shadowed by a committed repair are excluded. Every returned route
    /// is independently resolved through the same manifest and route checks used by scrub repair.
    ///
    /// # Errors
    ///
    /// Rejects invalid bounds and any malformed, incomplete or contradictory catalogue state.
    pub fn current_target_shards(
        &self,
        target_id: TargetId,
        target_generation: u64,
        after: Option<TargetShardCursor>,
        limit: usize,
    ) -> Result<TargetShardPage, ContentCatalogError> {
        target_inventory::page(&self.connection, target_id, target_generation, after, limit)
    }

    /// Resolves one exact currently active shard route named by provider scrub evidence.
    ///
    /// # Errors
    ///
    /// Rejects malformed evidence and fails closed when committed manifest, layout or repair
    /// projection state contradicts itself.
    pub fn shard_repair_candidate(
        &self,
        target_id: TargetId,
        target_generation: u64,
        shard: meshspan_contracts::ShardIdentity,
    ) -> Result<Option<ShardRepairCandidate>, ContentCatalogError> {
        repair::candidate(&self.connection, target_id, target_generation, shard)
    }

    /// Fixes the acknowledgement meaning before any protected stripe plan is persisted.
    ///
    /// # Errors
    ///
    /// Rejects a changed class/scope after layout preparation, a committed publication or an
    /// invalid non-local/non-cell content scope.
    pub fn configure_protected_acknowledgement(
        &mut self,
        request: ContentPublicationRequest,
        policy: ContentAcknowledgementPolicy,
        scope: DurabilityScope,
    ) -> Result<(), ContentCatalogError> {
        validate_live_request(request)?;
        validate_exact_request(&self.connection, request)?;
        if request.format_version != 2 || scope == DurabilityScope::GloballyConverged {
            return Err(ContentCatalogError::InvalidInput);
        }
        let strong_deadline = acknowledgement_deadline(request, policy)?;
        let encoded = (
            encode_class(policy.class),
            encode_scope(scope),
            strong_deadline.map(UnixMicros::get),
            encode_fallback(policy.fallback),
        );
        let stored = self.connection.query_row(
            "SELECT acknowledgement_class, acknowledgement_scope, strong_deadline_at,
                    strong_fallback_mode, state,
                    EXISTS(SELECT 1 FROM content_stripe_layouts
                           WHERE operation_id = content_publications.operation_id)
             FROM content_publications WHERE operation_id = ?1",
            [request.operation_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, bool>(5)?,
                ))
            },
        )?;
        if (stored.4 == 2 || stored.5) && (stored.0, stored.1, stored.2, stored.3) != encoded {
            return Err(ContentCatalogError::Conflict);
        }
        if (stored.0, stored.1, stored.2, stored.3) == encoded {
            return Ok(());
        }
        let updated = self.connection.execute(
            "UPDATE content_publications
             SET acknowledgement_class = ?1, acknowledgement_scope = ?2,
                 strong_deadline_at = ?3, strong_fallback_mode = ?4
             WHERE operation_id = ?5 AND state = 1
               AND NOT EXISTS(SELECT 1 FROM content_stripe_layouts
                              WHERE operation_id = content_publications.operation_id)",
            params![
                encoded.0,
                encoded.1,
                encoded.2,
                encoded.3,
                request.operation_id.as_bytes().as_slice(),
            ],
        )?;
        if updated == 1 {
            Ok(())
        } else {
            Err(ContentCatalogError::Conflict)
        }
    }

    /// Reconstructs immutable acknowledgement evidence from one committed protected layout.
    ///
    /// # Errors
    ///
    /// Rejects an uncommitted/wrong-format publication or malformed/missing required receipts.
    pub fn protected_acknowledgement_evidence(
        &self,
        request: ContentPublicationRequest,
    ) -> Result<ContentAcknowledgementEvidence, ContentCatalogError> {
        validate_exact_request(&self.connection, request)?;
        if request.format_version != 2 {
            return Err(ContentCatalogError::InvalidInput);
        }
        let header = self.connection.query_row(
            "SELECT state, acknowledgement_class, acknowledgement_scope,
                    acknowledgement_outcome, strong_deadline_at, strong_fallback_mode, root_digest
             FROM content_publications WHERE operation_id = ?1",
            [request.operation_id.as_bytes().as_slice()],
            |row| {
                Ok(AcknowledgementHeader {
                    state: row.get(0)?,
                    configured_class: row.get(1)?,
                    scope: row.get(2)?,
                    outcome: row.get(3)?,
                    strong_deadline: row.get(4)?,
                    fallback: row.get(5)?,
                    root_digest: row.get(6)?,
                })
            },
        )?;
        if header.state != 2 {
            return Err(ContentCatalogError::Incomplete);
        }
        acknowledgement_evidence(&self.connection, request.operation_id, &header)
    }

    pub(crate) fn strong_fallback_for_attempt(
        &self,
        request: ContentPublicationRequest,
    ) -> Result<Option<ContentStrongFallback>, ContentCatalogError> {
        validate_exact_request(&self.connection, request)?;
        let stored = self.connection.query_row(
            "SELECT acknowledgement_class, strong_deadline_at, strong_fallback_mode, state
             FROM content_publications WHERE operation_id = ?1",
            [request.operation_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )?;
        if stored.3 == 2 || decode_class(stored.0)? == ContentAcknowledgementClass::Eventual {
            return Ok(None);
        }
        let deadline = stored
            .1
            .map(UnixMicros::new)
            .ok_or(ContentCatalogError::Corrupt)?;
        if request.observed_at < deadline {
            Ok(Some(ContentStrongFallback::RemainPending))
        } else {
            Ok(Some(decode_fallback(stored.2)?))
        }
    }

    pub(crate) fn finish_eventual_fallback(
        &mut self,
        request: ContentPublicationRequest,
    ) -> Result<ManifestPublication, ContentCatalogError> {
        if self.strong_fallback_for_attempt(request)? != Some(ContentStrongFallback::Eventual) {
            return Err(ContentCatalogError::InvalidInput);
        }
        self.finish_with_outcome(
            request,
            request.observed_at,
            ContentAcknowledgementOutcome::EventualFallback,
        )
    }

    /// Installs one already-authoritative shard-location transition into the local read route.
    ///
    /// The immutable manifest and coding layout are never changed. Exact replay is a no-op;
    /// stale, skipped or substituted location generations fail closed.
    ///
    /// # Errors
    ///
    /// Rejects unknown content, non-protected layouts, incomplete source shards, broken
    /// generation continuity and any receipt which changes the immutable shard bytes.
    pub fn install_shard_repair(
        &mut self,
        content: crate::PublishedContentReference,
        transition: &ShardRepairTransition,
    ) -> Result<(), ContentCatalogError> {
        let committed = self.committed_layout(content)?;
        if committed.request.format_version != 2 {
            return Err(ContentCatalogError::InvalidInput);
        }
        repair::install(&mut self.connection, committed.request, content, transition)
    }

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
        self.active_protected_stripe(committed.request, content, chunk_index)
    }

    pub(crate) fn active_protected_stripe(
        &self,
        request: ContentPublicationRequest,
        content: crate::PublishedContentReference,
        chunk_index: u64,
    ) -> Result<CommittedProtectedStripe, ContentCatalogError> {
        if request.format_version != 2 || request.operation_id != content.publication_operation_id {
            return Err(ContentCatalogError::InvalidInput);
        }
        let stripe = load_protected_stripe(&self.connection, request, chunk_index)?;
        let mut statement = self.connection.prepare(
            "SELECT shard_index FROM content_stripe_shards
             WHERE operation_id = ?1 AND chunk_index = ?2 AND receipt_recorded_at IS NOT NULL
             ORDER BY shard_index LIMIT ?3",
        )?;
        let indices = statement
            .query_map(
                params![
                    request.operation_id.as_bytes().as_slice(),
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
                let original = ShardReceipt {
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
                };
                repair::current_receipt(&self.connection, request.operation_id, original)
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
                    required_for_commit, eventual_fallback_required
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

struct AcknowledgementHeader {
    state: i64,
    configured_class: i64,
    scope: i64,
    outcome: i64,
    strong_deadline: Option<i64>,
    fallback: i64,
    root_digest: Vec<u8>,
}

fn acknowledgement_evidence(
    connection: &rusqlite::Connection,
    operation_id: OperationId,
    header: &AcknowledgementHeader,
) -> Result<ContentAcknowledgementEvidence, ContentCatalogError> {
    let configured_class = decode_class(header.configured_class)?;
    let scope = decode_scope(header.scope)?;
    let outcome = decode_outcome(header.outcome)?;
    let strong_deadline = header.strong_deadline.map(UnixMicros::new);
    let fallback = decode_fallback(header.fallback)?;
    let root_digest = copy_array(&header.root_digest)?;
    let policy_evidence_digest = policy_evidence_digest(
        connection,
        operation_id,
        configured_class,
        scope,
        outcome,
        strong_deadline,
        fallback,
    )?;
    let shard_evidence = shard_evidence(connection, operation_id, root_digest, outcome)?;
    let fallback_applied = outcome == ContentAcknowledgementOutcome::EventualFallback;
    Ok(ContentAcknowledgementEvidence {
        configured_class,
        acknowledged_class: if fallback_applied {
            ContentAcknowledgementClass::Eventual
        } else {
            configured_class
        },
        fallback_applied,
        content_scope: scope,
        required_shard_receipts: shard_evidence.required,
        eventual_shard_receipts: shard_evidence.eventual,
        pending_eventual_shards: shard_evidence.pending,
        policy_evidence_digest,
        achieved_protection_digest: shard_evidence.achieved_digest,
        pending_debt_digest: shard_evidence.debt_digest,
    })
}

fn policy_evidence_digest(
    connection: &rusqlite::Connection,
    operation_id: OperationId,
    class: ContentAcknowledgementClass,
    scope: DurabilityScope,
    outcome: ContentAcknowledgementOutcome,
    strong_deadline: Option<UnixMicros>,
    fallback: ContentStrongFallback,
) -> Result<[u8; 32], ContentCatalogError> {
    let mut policy = blake3::Hasher::new();
    policy.update(b"meshspan.content-acknowledgement-policy.v1\0");
    policy.update(&operation_id.as_bytes());
    policy.update(&[
        class_tag(class),
        scope_tag(scope),
        outcome_tag(outcome),
        fallback_tag(fallback),
    ]);
    policy.update(&strong_deadline.map_or(0, UnixMicros::get).to_be_bytes());
    let mut layouts = connection.prepare(
        "SELECT chunk_index, topology_revision, capacity_revision, policy_format_version,
                policy_evidence, layout_digest
         FROM content_stripe_layouts WHERE operation_id = ?1 ORDER BY chunk_index",
    )?;
    let rows = layouts.query_map([operation_id.as_bytes().as_slice()], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, Vec<u8>>(4)?,
            row.get::<_, Vec<u8>>(5)?,
        ))
    })?;
    for row in rows {
        let row = row?;
        policy.update(&from_sql(row.0)?.to_be_bytes());
        policy.update(&from_sql(row.1)?.to_be_bytes());
        policy.update(&from_sql(row.2)?.to_be_bytes());
        policy.update(
            &u32::try_from(row.3)
                .map_err(|_| ContentCatalogError::Corrupt)?
                .to_be_bytes(),
        );
        if row.4.is_empty() || row.4.len() > MAXIMUM_POLICY_BYTES {
            return Err(ContentCatalogError::Corrupt);
        }
        policy.update(&row.4);
        policy.update(&copy_array::<32>(&row.5)?);
    }
    Ok(policy.finalize().into())
}

struct ShardEvidence {
    required: u64,
    eventual: u64,
    pending: u64,
    achieved_digest: [u8; 32],
    debt_digest: [u8; 32],
}

fn shard_evidence(
    connection: &rusqlite::Connection,
    operation_id: OperationId,
    root_digest: [u8; 32],
    outcome: ContentAcknowledgementOutcome,
) -> Result<ShardEvidence, ContentCatalogError> {
    let mut achieved = blake3::Hasher::new();
    achieved.update(b"meshspan.content-acknowledgement-achieved.v1\0");
    achieved.update(&operation_id.as_bytes());
    achieved.update(&root_digest);
    let mut debt = blake3::Hasher::new();
    debt.update(b"meshspan.content-acknowledgement-debt.v1\0");
    debt.update(&operation_id.as_bytes());
    debt.update(&root_digest);
    let mut required_shard_receipts = 0_u64;
    let mut eventual_shard_receipts = 0_u64;
    let mut pending_eventual_shards = 0_u64;
    let mut shards = connection.prepare(
        "SELECT chunk_index, shard_index, provider_operation_id, expected_length,
                expected_digest, target_id, target_generation, required_for_commit,
                eventual_fallback_required, receipt_recorded_at
         FROM content_stripe_shards WHERE operation_id = ?1
         ORDER BY chunk_index, shard_index",
    )?;
    let rows = shards.query_map([operation_id.as_bytes().as_slice()], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, Vec<u8>>(4)?,
            row.get::<_, Vec<u8>>(5)?,
            row.get::<_, i64>(6)?,
            row.get::<_, bool>(7)?,
            row.get::<_, bool>(8)?,
            row.get::<_, Option<i64>>(9)?,
        ))
    })?;
    for row in rows {
        let row = row?;
        let mut canonical = Vec::with_capacity(98);
        canonical.extend_from_slice(&from_sql(row.0)?.to_be_bytes());
        canonical.extend_from_slice(
            &u16::try_from(row.1)
                .map_err(|_| ContentCatalogError::Corrupt)?
                .to_be_bytes(),
        );
        canonical.extend_from_slice(&copy_array::<16>(&row.2)?);
        canonical.extend_from_slice(&from_sql(row.3)?.to_be_bytes());
        canonical.extend_from_slice(&copy_array::<32>(&row.4)?);
        canonical.extend_from_slice(&copy_array::<16>(&row.5)?);
        canonical.extend_from_slice(&from_sql(row.6)?.to_be_bytes());
        canonical.push(u8::from(row.7));
        canonical.push(u8::from(row.8));
        let required = match outcome {
            ContentAcknowledgementOutcome::PolicyCommitted => row.7,
            ContentAcknowledgementOutcome::EventualFallback => row.8,
        };
        match (required, row.9) {
            (true, Some(recorded_at)) => {
                required_shard_receipts = required_shard_receipts
                    .checked_add(1)
                    .ok_or(ContentCatalogError::Corrupt)?;
                achieved.update(&canonical);
                achieved.update(&recorded_at.to_be_bytes());
            }
            (true, None) => return Err(ContentCatalogError::Corrupt),
            (false, Some(recorded_at)) => {
                eventual_shard_receipts = eventual_shard_receipts
                    .checked_add(1)
                    .ok_or(ContentCatalogError::Corrupt)?;
                achieved.update(&canonical);
                achieved.update(&recorded_at.to_be_bytes());
            }
            (false, None) => {
                pending_eventual_shards = pending_eventual_shards
                    .checked_add(1)
                    .ok_or(ContentCatalogError::Corrupt)?;
                debt.update(&canonical);
            }
        }
    }
    Ok(ShardEvidence {
        required: required_shard_receipts,
        eventual: eventual_shard_receipts,
        pending: pending_eventual_shards,
        achieved_digest: achieved.finalize().into(),
        debt_digest: debt.finalize().into(),
    })
}

const fn class_tag(class: ContentAcknowledgementClass) -> u8 {
    match class {
        ContentAcknowledgementClass::Eventual => 1,
        ContentAcknowledgementClass::Strong => 2,
    }
}

const fn encode_class(class: ContentAcknowledgementClass) -> i64 {
    class_tag(class) as i64
}

fn decode_class(value: i64) -> Result<ContentAcknowledgementClass, ContentCatalogError> {
    match value {
        1 => Ok(ContentAcknowledgementClass::Eventual),
        2 => Ok(ContentAcknowledgementClass::Strong),
        _ => Err(ContentCatalogError::Corrupt),
    }
}

fn acknowledgement_deadline(
    request: ContentPublicationRequest,
    policy: ContentAcknowledgementPolicy,
) -> Result<Option<UnixMicros>, ContentCatalogError> {
    match policy.class {
        ContentAcknowledgementClass::Eventual => {
            if policy.strong_wait.is_some()
                || policy.fallback != ContentStrongFallback::RemainPending
            {
                Err(ContentCatalogError::InvalidInput)
            } else {
                Ok(None)
            }
        }
        ContentAcknowledgementClass::Strong => {
            let policy_deadline = policy
                .strong_wait
                .map(|wait| {
                    request
                        .observed_at
                        .checked_add(wait)
                        .ok_or(ContentCatalogError::InvalidInput)
                })
                .transpose()?;
            Ok(Some(policy_deadline.map_or(request.deadline, |deadline| {
                deadline.min(request.deadline)
            })))
        }
    }
}

const fn fallback_tag(fallback: ContentStrongFallback) -> u8 {
    match fallback {
        ContentStrongFallback::RemainPending => 1,
        ContentStrongFallback::FailAtDeadline => 2,
        ContentStrongFallback::Eventual => 3,
    }
}

const fn encode_fallback(fallback: ContentStrongFallback) -> i64 {
    fallback_tag(fallback) as i64
}

fn decode_fallback(value: i64) -> Result<ContentStrongFallback, ContentCatalogError> {
    match value {
        1 => Ok(ContentStrongFallback::RemainPending),
        2 => Ok(ContentStrongFallback::FailAtDeadline),
        3 => Ok(ContentStrongFallback::Eventual),
        _ => Err(ContentCatalogError::Corrupt),
    }
}

const fn outcome_tag(outcome: ContentAcknowledgementOutcome) -> u8 {
    match outcome {
        ContentAcknowledgementOutcome::PolicyCommitted => 1,
        ContentAcknowledgementOutcome::EventualFallback => 2,
    }
}

fn decode_outcome(value: i64) -> Result<ContentAcknowledgementOutcome, ContentCatalogError> {
    match value {
        1 => Ok(ContentAcknowledgementOutcome::PolicyCommitted),
        2 => Ok(ContentAcknowledgementOutcome::EventualFallback),
        _ => Err(ContentCatalogError::Corrupt),
    }
}

const fn encode_scope(scope: DurabilityScope) -> i64 {
    scope_tag(scope) as i64
}

const fn scope_tag(scope: DurabilityScope) -> u8 {
    match scope {
        DurabilityScope::NodeLocal => 1,
        DurabilityScope::CellReplicated => 2,
        DurabilityScope::GloballyConverged => 3,
    }
}

fn decode_scope(value: i64) -> Result<DurabilityScope, ContentCatalogError> {
    match value {
        1 => Ok(DurabilityScope::NodeLocal),
        2 => Ok(DurabilityScope::CellReplicated),
        _ => Err(ContentCatalogError::Corrupt),
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
        || shards
            .iter()
            .filter(|shard| shard.eventual_fallback == ShardAcknowledgement::Required)
            .count()
            < usize::from(layout.data_slices())
        || shards.iter().any(|shard| {
            shard.eventual_fallback == ShardAcknowledgement::Required
                && shard.acknowledgement != ShardAcknowledgement::Required
        })
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
        digest.update(&[match shard.eventual_fallback {
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
                target_generation, required_for_commit, eventual_fallback_required
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
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
                match shard.eventual_fallback {
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
            eventual_fallback: if row.get::<_, bool>(9)? {
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
                    required_for_commit, eventual_fallback_required
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
                required_for_commit, eventual_fallback_required
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
