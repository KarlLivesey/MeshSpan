// SPDX-License-Identifier: GPL-2.0-only

//! Permanent local admission fences preceding authoritative quota reassignment.

use meshspan_domain::{FederationStorageAllocationId, NodeId, TargetId, UnixMicros};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use super::{FederationStorageQuotaError as Error, install_or_validate_usage, record::load_usage};
use crate::{FederationStorageAllocationAuthority, LocalDatabase};

/// Provider-local accounting evidence, not a remotely trusted attestation or quota credit.
/// New reservations are permanently stopped; already admitted IO may finish or reconcile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationStorageCapacitySeal {
    /// Immutable allocation whose admission is stopped.
    pub allocation_id: FederationStorageAllocationId,
    /// Sole local ledger owner.
    pub provider_node_id: NodeId,
    /// Storage target bound by the immutable allocation.
    pub target_id: TargetId,
    /// Exact target incarnation; a replacement cannot reuse this evidence.
    pub target_generation: u64,
    /// Upper bound including stored data and every unresolved reservation.
    pub ceiling_bytes: u64,
    /// Local monotonic sequence, advanced only when the ceiling is reduced.
    pub sequence: u64,
    /// Observation time, not a consensus revision or ordering authority.
    pub sealed_at: UnixMicros,
}

impl LocalDatabase {
    /// Reports whether the permanent admission fence exists; sealing revalidates its contents.
    ///
    /// # Errors
    /// Returns database failures instead of treating missing evidence as a confirmed fence.
    pub fn federated_storage_capacity_is_sealed(
        &self,
        allocation: FederationStorageAllocationId,
    ) -> Result<bool, Error> {
        Ok(self.connection().query_row(
            "SELECT EXISTS(SELECT 1 FROM local_federation_storage_seals WHERE allocation_id=?1)",
            [allocation.as_bytes().as_slice()],
            |row| row.get(0),
        )?)
    }

    /// Permanently stops new reservations and snapshots all charges atomically.
    ///
    /// This is a local provider-owner operation. Its result must be authenticated and
    /// committed separately before any other allocation can reuse the unused allowance.
    /// It never deletes bytes, cancels uncertain IO, revokes read authority or itself
    /// credits replicated quota. Repeating it may lower the ceiling after reconciliation.
    ///
    /// # Errors
    /// Rejects wrong-node/expired/stale authority, corrupt accounting or failed durability.
    pub fn seal_federated_storage_capacity(
        &mut self,
        authority: FederationStorageAllocationAuthority,
    ) -> Result<FederationStorageCapacitySeal, Error> {
        let allocation = authority.allocation();
        let now = authority.observed_at();
        if allocation.provider_node_id() != self.node_id()
            || now < authority.valid_from()
            || now >= authority.valid_until()
        {
            return Err(Error::Invalid);
        }
        let tx = self
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        install_or_validate_usage(&tx, authority, now)?;
        let usage = load_usage(&tx, allocation.allocation_id())?.ok_or(Error::CorruptState)?;
        let ceiling = usage
            .committed_bytes
            .checked_add(usage.reserved_bytes)
            .filter(|bytes| *bytes <= allocation.maximum_bytes())
            .ok_or(Error::CorruptState)?;
        let ceiling_sql = number(ceiling)?;
        let previous = tx
            .query_row(
                "SELECT ceiling_bytes, sequence, sealed_at FROM local_federation_storage_seals
             WHERE allocation_id=?1",
                [allocation.allocation_id().as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?;
        let (sequence, sealed_at) = match previous {
            Some((bytes, sequence, instant)) => {
                let bytes = u64::try_from(bytes).map_err(|_| Error::CorruptState)?;
                let sequence = u64::try_from(sequence).map_err(|_| Error::CorruptState)?;
                if bytes < ceiling || sequence == 0 || instant <= 0 {
                    return Err(Error::CorruptState);
                }
                if bytes == ceiling {
                    (sequence, UnixMicros::new(instant))
                } else {
                    (sequence.checked_add(1).ok_or(Error::CorruptState)?, now)
                }
            }
            None => (1, now),
        };
        if previous.is_none() {
            tx.execute(
                "INSERT INTO local_federation_storage_seals
                (allocation_id,ceiling_bytes,sequence,sealed_at) VALUES(?1,?2,?3,?4)",
                params![
                    allocation.allocation_id().as_bytes().as_slice(),
                    number(ceiling)?,
                    number(sequence)?,
                    sealed_at.get()
                ],
            )?;
        } else if previous.is_some_and(|row| row.0 != ceiling_sql) {
            tx.execute(
                "UPDATE local_federation_storage_seals
                SET ceiling_bytes=?2,sequence=?3,sealed_at=?4 WHERE allocation_id=?1",
                params![
                    allocation.allocation_id().as_bytes().as_slice(),
                    number(ceiling)?,
                    number(sequence)?,
                    sealed_at.get()
                ],
            )?;
        }
        tx.commit()?;
        Ok(FederationStorageCapacitySeal {
            allocation_id: allocation.allocation_id(),
            provider_node_id: allocation.provider_node_id(),
            target_id: allocation.target_id(),
            target_generation: allocation.target_generation(),
            ceiling_bytes: ceiling,
            sequence,
            sealed_at,
        })
    }
}

fn number(value: u64) -> Result<i64, Error> {
    i64::try_from(value).map_err(|_| Error::CorruptState)
}
