// SPDX-License-Identifier: GPL-2.0-only

//! Atomic node-attested receipt streams. Archive comparison belongs to the recovery coordinator.

use crate::{AuthoritativeRepository, RecoveryShardRestoration, RepositoryError as Error};
use meshspan_certificates::NodePublicIdentity;
use meshspan_contracts::{ShardReceipt, decode_shard_receipt_v1, encode_shard_receipt_v1};
use meshspan_domain::{TargetId, UnixMicros};
use meshspan_recovery_bundle::RecoveredAuthority;
use rusqlite::{Connection, OptionalExtension as _, Transaction, TransactionBehavior, params};
use sha2::{Digest as _, Sha256};

/// A complete durably collected node claim. Neither serving authority nor an availability probe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryRestorationReceipt {
    /// Exact source, selected destination and complete receipt-stream commitment.
    pub restoration: RecoveryShardRestoration,
    /// First coordinator persistence time; replay preserves it.
    pub recorded_at: UnixMicros,
}

impl AuthoritativeRepository {
    /// Streams revalidated collected receipts from one coherent metadata read view.
    /// Each node's complete stream is verified before its first callback. The callback must
    /// independently compare archive identity before using a receipt, perform no network IO,
    /// and discard isolated output if any later collection or callback fails. No live authority
    /// or present availability is established. Memory does not grow with the receipt count.
    /// # Errors
    /// Rejects corrupted or foreign claims, incomplete streams, persistence and callback failure.
    pub fn visit_recovery_restored_shards(
        &self,
        authority: &RecoveredAuthority,
        mut visit: impl FnMut(&RecoveryShardRestoration, ShardReceipt) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let transaction = self.database.connection().unchecked_transaction()?;
        self.prepared_recovery_authorization(authority)?;
        let mut statement = transaction.prepare("SELECT target_id, source_target_id, source_generation, message, signature FROM partition_recovery_restorations ORDER BY target_id, source_target_id, source_generation")?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let message = super::key_journal::bounded_blob(row, 3, 1024)?;
            let signature = super::key_journal::bounded_blob(row, 4, 72)?;
            let claim = RecoveryShardRestoration::decode_message(
                authority.root_certificate_der(),
                &message,
            )?;
            if super::key_journal::bounded_blob(row, 0, 16)? != claim.target.target_id.as_bytes()
                || super::key_journal::bounded_blob(row, 1, 16)?
                    != claim.source_target_id.as_bytes()
                || u64::try_from(row.get::<_, i64>(2)?).map_err(|_| Error::CorruptState)?
                    != claim.source_generation
            {
                return Err(Error::CorruptState);
            }
            self.validate_restoration(authority, (&claim, &signature))?;
            read_stream(&transaction, &claim)?.finish()?;
            visit_stream(&transaction, &claim, &mut visit)?;
        }
        drop(rows);
        drop(statement);
        transaction.commit()?;
        Ok(())
    }

    /// Validates the node signature, selected target, current recovery and original target identity.
    /// Does not validate a receipt stream, compare the archive or mutate metadata.
    /// # Errors
    /// Rejects forged, stale, substituted, uncollected or foreign target claims.
    pub fn verify_recovery_restoration(
        &self,
        authority: &RecoveredAuthority,
        attestation: (&RecoveryShardRestoration, &[u8]),
    ) -> Result<(), Error> {
        let transaction = self.database.connection().unchecked_transaction()?;
        self.validate_restoration(authority, attestation)?;
        transaction.commit()?;
        Ok(())
    }

    fn validate_restoration(
        &self,
        authority: &RecoveredAuthority,
        attestation: (&RecoveryShardRestoration, &[u8]),
    ) -> Result<(), Error> {
        let (claim, signature) = attestation;
        if !(8..=72).contains(&signature.len())
            || self
                .load_recovery_target(authority, claim.target.target_id)?
                .as_ref()
                != Some(&claim.target)
            || self
                .recovery_storage_target_marker(claim.source_target_id, claim.source_generation)?
                .is_none()
        {
            return Err(Error::InvalidCommand);
        }
        let plan = self
            .load_recovery_replacement_plan(authority)?
            .ok_or(Error::InvalidCommand)?;
        let node = plan
            .nodes
            .iter()
            .find(|node| node.node_id == claim.target.node_id)
            .ok_or(Error::InvalidCommand)?;
        NodePublicIdentity::from_sec1(&node.identity_public_key)
            .map_err(|_| Error::InvalidCommand)?
            .verify_enrolment_transcript(&claim.installation_message()?, signature)
            .map_err(|_| Error::InvalidCommand)
    }

    /// Atomically stores an entire signed stream, retaining original time on exact replay.
    /// The coordinator must first compare it with authenticated retained archive layouts.
    /// These immutable rows are collected node claims, never active routes or service admission.
    /// Input is consumed with bounded memory inside a local-only SQLite transaction; no network IO.
    /// # Errors
    /// Rejects invalid authority/target, incomplete or changed streams, conflicting replay,
    /// time before fencing and persistence/input failure. Every partial insertion rolls back.
    pub fn record_recovery_restoration(
        &mut self,
        authority: &RecoveredAuthority,
        attestation: (&RecoveryShardRestoration, &[u8]),
        receipts: impl IntoIterator<Item = Result<ShardReceipt, Error>>,
        now: UnixMicros,
    ) -> Result<RecoveryRestorationReceipt, Error> {
        let (claim, signature) = attestation;
        let transaction =
            Transaction::new_unchecked(self.database.connection(), TransactionBehavior::Immediate)?;
        self.validate_restoration(authority, attestation)?;
        let fence =
            super::credential_fence::read_fence(&transaction)?.ok_or(Error::InvalidCommand)?;
        if now < fence.fenced_at {
            return Err(Error::InvalidCommand);
        }
        let saved = load(
            &transaction,
            claim.target.target_id,
            (claim.source_target_id, claim.source_generation),
        )?;
        let recorded_at = if let Some(saved) = &saved {
            if saved.message != claim.installation_message()? || saved.signature != signature {
                return Err(Error::OperationConflict);
            }
            saved.recorded_at
        } else {
            transaction.execute("INSERT INTO partition_recovery_restorations (target_id, source_target_id, source_generation, message, signature, recorded_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![claim.target.target_id.as_bytes().as_slice(), claim.source_target_id.as_bytes().as_slice(), i64::try_from(claim.source_generation).map_err(|_| Error::InvalidCommand)?, claim.installation_message()?, signature, now.get()])?;
            now
        };
        let mut checked = StreamCheck::new(claim);
        let mut statement = transaction.prepare(if saved.is_some() {
            "SELECT receipt FROM partition_recovery_shards WHERE target_id = ?1 AND source_target_id = ?2 AND source_generation = ?3 AND ordinal = ?4"
        } else {
            "INSERT INTO partition_recovery_shards (target_id, source_target_id, source_generation, ordinal, receipt) VALUES (?1, ?2, ?3, ?4, ?5)"
        })?;
        for receipt in receipts {
            let receipt = receipt?;
            let ordinal = checked.count;
            let encoded = checked.push(receipt)?;
            persist_receipt(&mut statement, claim, ordinal, &encoded, saved.is_some())?;
        }
        drop(statement);
        checked.finish()?;
        let stored = read_stream(&transaction, claim)?;
        stored.finish()?;
        transaction.commit()?;
        Ok(RecoveryRestorationReceipt {
            restoration: claim.clone(),
            recorded_at,
        })
    }

    /// Revalidates the node claim and the complete stored stream after reopening.
    /// This verifies collected evidence, not current disk health or recovered-cluster readiness.
    /// # Errors
    /// Rejects corrupted identity/signature/receipt state and persistence failures.
    pub fn recovery_restoration(
        &self,
        authority: &RecoveredAuthority,
        target: TargetId,
        source: (TargetId, u64),
    ) -> Result<Option<RecoveryRestorationReceipt>, Error> {
        let transaction = self.database.connection().unchecked_transaction()?;
        let Some(saved) = load(self.database.connection(), target, source)? else {
            return Ok(None);
        };
        let claim = RecoveryShardRestoration::decode_message(
            authority.root_certificate_der(),
            &saved.message,
        )?;
        if claim.target.target_id != target
            || (claim.source_target_id, claim.source_generation) != source
        {
            return Err(Error::CorruptState);
        }
        self.validate_restoration(authority, (&claim, &saved.signature))?;
        read_stream(&transaction, &claim)?.finish()?;
        transaction.commit()?;
        Ok(Some(RecoveryRestorationReceipt {
            restoration: claim,
            recorded_at: saved.recorded_at,
        }))
    }
}

struct StoredAttestation {
    message: Vec<u8>,
    signature: Vec<u8>,
    recorded_at: UnixMicros,
}

fn load(
    connection: &Connection,
    target: TargetId,
    source: (TargetId, u64),
) -> Result<Option<StoredAttestation>, Error> {
    Ok(connection.query_row("SELECT message, signature, recorded_at FROM partition_recovery_restorations WHERE target_id = ?1 AND source_target_id = ?2 AND source_generation = ?3",
        params![target.as_bytes().as_slice(), source.0.as_bytes().as_slice(), i64::try_from(source.1).map_err(|_| Error::InvalidCommand)?],
        |row| Ok(StoredAttestation { message: super::key_journal::bounded_blob(row, 0, 1024)?, signature: super::key_journal::bounded_blob(row, 1, 72)?, recorded_at: UnixMicros::new(row.get(2)?) })).optional()?)
}

fn persist_receipt(
    statement: &mut rusqlite::Statement<'_>,
    claim: &RecoveryShardRestoration,
    ordinal: u64,
    bytes: &[u8],
    replay: bool,
) -> Result<(), Error> {
    let target = claim.target.target_id.as_bytes();
    let source = claim.source_target_id.as_bytes();
    let generation = i64::try_from(claim.source_generation).map_err(|_| Error::InvalidCommand)?;
    let ordinal = i64::try_from(ordinal).map_err(|_| Error::InvalidCommand)?;
    let values = params![target.as_slice(), source.as_slice(), generation, ordinal];
    if replay {
        let saved =
            statement.query_row(values, |row| super::key_journal::bounded_blob(row, 0, 126))?;
        if saved != bytes {
            return Err(Error::CorruptState);
        }
    } else {
        statement.execute(params![
            target.as_slice(),
            source.as_slice(),
            generation,
            ordinal,
            bytes
        ])?;
    }
    Ok(())
}

fn read_stream<'a>(
    connection: &Connection,
    claim: &'a RecoveryShardRestoration,
) -> Result<StreamCheck<'a>, Error> {
    let mut statement = connection.prepare("SELECT ordinal, receipt FROM partition_recovery_shards WHERE target_id = ?1 AND source_target_id = ?2 AND source_generation = ?3 ORDER BY ordinal")?;
    let mut rows = statement.query(params![
        claim.target.target_id.as_bytes().as_slice(),
        claim.source_target_id.as_bytes().as_slice(),
        i64::try_from(claim.source_generation).map_err(|_| Error::InvalidCommand)?
    ])?;
    let mut checked = StreamCheck::new(claim);
    while let Some(row) = rows.next()? {
        if u64::try_from(row.get::<_, i64>(0)?).map_err(|_| Error::CorruptState)? != checked.count {
            return Err(Error::CorruptState);
        }
        let bytes = super::key_journal::bounded_blob(row, 1, 126)?;
        checked.push(decode_shard_receipt_v1(&bytes).map_err(|_| Error::CorruptState)?)?;
    }
    Ok(checked)
}

fn visit_stream(
    connection: &Connection,
    claim: &RecoveryShardRestoration,
    visit: &mut impl FnMut(&RecoveryShardRestoration, ShardReceipt) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut statement = connection.prepare("SELECT receipt FROM partition_recovery_shards WHERE target_id = ?1 AND source_target_id = ?2 AND source_generation = ?3 ORDER BY ordinal")?;
    let mut rows = statement.query(params![
        claim.target.target_id.as_bytes().as_slice(),
        claim.source_target_id.as_bytes().as_slice(),
        i64::try_from(claim.source_generation).map_err(|_| Error::InvalidCommand)?
    ])?;
    while let Some(row) = rows.next()? {
        let bytes = super::key_journal::bounded_blob(row, 0, 126)?;
        visit(
            claim,
            decode_shard_receipt_v1(&bytes).map_err(|_| Error::CorruptState)?,
        )?;
    }
    Ok(())
}

struct StreamCheck<'a> {
    claim: &'a RecoveryShardRestoration,
    digest: Sha256,
    count: u64,
    bytes: u64,
}

impl<'a> StreamCheck<'a> {
    fn new(claim: &'a RecoveryShardRestoration) -> Self {
        let mut digest = Sha256::new();
        digest.update(b"MSRRCPT\x01");
        Self {
            claim,
            digest,
            count: 0,
            bytes: 0,
        }
    }
    fn push(&mut self, receipt: ShardReceipt) -> Result<[u8; 126], Error> {
        let bytes = encode_shard_receipt_v1(receipt);
        decode_shard_receipt_v1(&bytes).map_err(|_| Error::InvalidCommand)?;
        if receipt.target_id != self.claim.target.target_id
            || receipt.target_generation != self.claim.target.generation
            || self.count >= self.claim.receipt_count
        {
            return Err(Error::InvalidCommand);
        }
        self.digest.update(126_u16.to_be_bytes());
        self.digest.update(bytes);
        self.count += 1;
        self.bytes = self
            .bytes
            .checked_add(receipt.length)
            .ok_or(Error::InvalidCommand)?;
        Ok(bytes)
    }
    fn finish(self) -> Result<(), Error> {
        if self.count != self.claim.receipt_count
            || self.bytes != self.claim.encrypted_bytes
            || <[u8; 32]>::from(self.digest.finalize()) != self.claim.receipts_digest
        {
            return Err(Error::CorruptState);
        }
        Ok(())
    }
}
