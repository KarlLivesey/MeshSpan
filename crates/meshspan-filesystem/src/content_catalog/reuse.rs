// SPDX-License-Identifier: GPL-2.0-only

//! Exact upload-to-layout bindings; no ciphertext, keys or file rights are copied.

use meshspan_domain::{DurabilityScope, OperationId};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use super::repository::{copy_array, load_request, to_i64, validate_exact_request};
use super::{ContentCatalogError, DurableContentCatalog};
use crate::{
    ContentAcknowledgementClass, ContentAcknowledgementEvidence, ContentPublicationRequest,
    PublishedContentReference, VerifiedContentReuse,
};

impl DurableContentCatalog {
    pub(crate) fn record_content_reuse(
        &mut self,
        reuse: &VerifiedContentReuse,
    ) -> Result<(), ContentCatalogError> {
        validate_exact_request(&self.connection, reuse.request)?;
        if let Some(stored) = self.content_reuse(reuse.request)? {
            return if stored.content == reuse.content && stored.evidence == reuse.evidence {
                Ok(())
            } else {
                Err(ContentCatalogError::Conflict)
            };
        }
        let committed = self.committed_layout(reuse.content)?;
        if committed.request.volume_id != reuse.request.volume_id
            || committed.layout.manifest.logical_length != reuse.request.logical_length
            || reuse.evidence.configured_class != reuse.evidence.acknowledged_class
            || reuse.evidence.fallback_applied
            || reuse.evidence.pending_eventual_shards != 0
            || reuse.evidence.eventual_shard_receipts != 0
            || reuse.evidence.required_shard_receipts == 0
        {
            return Err(ContentCatalogError::InvalidInput);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let unused: bool = transaction.query_row(
            "SELECT state = 1 AND root_digest IS NULL AND NOT EXISTS(
                SELECT 1 FROM content_chunks WHERE operation_id = ?1)
             FROM content_publications WHERE operation_id = ?1",
            [reuse.request.operation_id.as_bytes().as_slice()],
            |row| row.get(0),
        )?;
        if !unused {
            return Err(ContentCatalogError::Conflict);
        }
        transaction.execute(
            "INSERT INTO content_reuse(operation_id, source_operation_id, manifest_root_digest,
                acknowledgement_class, acknowledgement_scope, verified_receipts,
                policy_digest, achieved_digest, debt_digest) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![reuse.request.operation_id.as_bytes().as_slice(),
                reuse.content.publication_operation_id.as_bytes().as_slice(),
                reuse.content.manifest.root_digest.as_slice(),
                class_tag(reuse.evidence.configured_class), scope_tag(reuse.evidence.content_scope),
                to_i64(reuse.evidence.required_shard_receipts)?,
                reuse.evidence.policy_evidence_digest.as_slice(),
                reuse.evidence.achieved_protection_digest.as_slice(),
                reuse.evidence.pending_debt_digest.as_slice()],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn content_reuse(
        &self,
        request: ContentPublicationRequest,
    ) -> Result<Option<VerifiedContentReuse>, ContentCatalogError> {
        validate_exact_request(&self.connection, request)?;
        let row = self.connection.query_row(
            "SELECT source_operation_id, manifest_root_digest, acknowledgement_class,
                acknowledgement_scope, verified_receipts, policy_digest, achieved_digest, debt_digest
             FROM content_reuse WHERE operation_id = ?1",
            [request.operation_id.as_bytes().as_slice()],
            |row| Ok(ReuseRow {
                operation: row.get(0)?, root: row.get(1)?, class: row.get(2)?, scope: row.get(3)?,
                receipts: row.get(4)?, policy: row.get(5)?, achieved: row.get(6)?, debt: row.get(7)?,
            }),
        ).optional()?;
        row.map(|row| self.decode_reuse(request, &row)).transpose()
    }

    pub(super) fn reused_reference(
        &self,
        content: PublishedContentReference,
    ) -> Result<PublishedContentReference, ContentCatalogError> {
        let request = load_request(&self.connection, content.publication_operation_id)?
            .ok_or(ContentCatalogError::Incomplete)?;
        match self.content_reuse(request)? {
            Some(reuse) if reuse.content.manifest == content.manifest => Ok(reuse.content),
            Some(_) => Err(ContentCatalogError::Conflict),
            None => Ok(content),
        }
    }

    fn decode_reuse(
        &self,
        request: ContentPublicationRequest,
        row: &ReuseRow,
    ) -> Result<VerifiedContentReuse, ContentCatalogError> {
        let operation = OperationId::from_bytes(copy_array(&row.operation)?)
            .map_err(|_| ContentCatalogError::Corrupt)?;
        let source =
            load_request(&self.connection, operation)?.ok_or(ContentCatalogError::Corrupt)?;
        // Sources are original committed layouts, never alias chains.
        let content = self
            .committed_content_by_manifest(source.manifest_id)?
            .ok_or(ContentCatalogError::Corrupt)?;
        if content.publication_operation_id != operation
            || operation == request.operation_id
            || source.volume_id != request.volume_id
            || source.format_version != request.format_version
            || content.manifest.logical_length != request.logical_length
            || content.manifest.root_digest != copy_array::<32>(&row.root)?
            || row.receipts <= 0
        {
            return Err(ContentCatalogError::Corrupt);
        }
        let class = match row.class {
            1 => ContentAcknowledgementClass::Eventual,
            2 => ContentAcknowledgementClass::Strong,
            _ => return Err(ContentCatalogError::Corrupt),
        };
        let scope = match row.scope {
            1 => DurabilityScope::NodeLocal,
            2 => DurabilityScope::CellReplicated,
            3 => DurabilityScope::GloballyConverged,
            _ => return Err(ContentCatalogError::Corrupt),
        };
        Ok(VerifiedContentReuse {
            request,
            content,
            evidence: ContentAcknowledgementEvidence {
                configured_class: class,
                acknowledged_class: class,
                fallback_applied: false,
                content_scope: scope,
                required_shard_receipts: u64::try_from(row.receipts)
                    .map_err(|_| ContentCatalogError::Corrupt)?,
                eventual_shard_receipts: 0,
                pending_eventual_shards: 0,
                policy_evidence_digest: copy_array(&row.policy)?,
                achieved_protection_digest: copy_array(&row.achieved)?,
                pending_debt_digest: copy_array(&row.debt)?,
            },
        })
    }
}

struct ReuseRow {
    operation: Vec<u8>,
    root: Vec<u8>,
    class: i64,
    scope: i64,
    receipts: i64,
    policy: Vec<u8>,
    achieved: Vec<u8>,
    debt: Vec<u8>,
}

const fn class_tag(class: ContentAcknowledgementClass) -> i64 {
    match class {
        ContentAcknowledgementClass::Eventual => 1,
        ContentAcknowledgementClass::Strong => 2,
    }
}

const fn scope_tag(scope: DurabilityScope) -> i64 {
    match scope {
        DurabilityScope::NodeLocal => 1,
        DurabilityScope::CellReplicated => 2,
        DurabilityScope::GloballyConverged => 3,
    }
}
