// SPDX-License-Identifier: GPL-2.0-only

//! Typed checkpoint backfill in the same transaction as schema migration 86.

use meshspan_acme::AcmeOrderMachine;
use rusqlite::{Transaction, params};
use sha2::{Digest as _, Sha256};

use super::MetadataStoreError;

pub(super) fn backfill(transaction: &Transaction<'_>) -> Result<(), MetadataStoreError> {
    let mut after = Vec::<u8>::new();
    loop {
        let mut statement = transaction.prepare(
            "SELECT order_id, checkpoint, checkpoint_digest FROM certificate_order_checkpoints
             WHERE order_id > ?1 ORDER BY order_id LIMIT 32",
        )?;
        let rows = statement
            .query_map([&after], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        if rows.is_empty() {
            return Ok(());
        }
        for (order_id, checkpoint, digest) in rows {
            if order_id.len() != 16 || Sha256::digest(&checkpoint).as_slice() != digest {
                return Err(MetadataStoreError::InvalidMigrationHistory);
            }
            let machine = AcmeOrderMachine::decode_checkpoint(&checkpoint)
                .map_err(|_| MetadataStoreError::InvalidMigrationHistory)?;
            let proof = machine
                .serving_publication()
                .map(meshspan_acme::AcmeChallengePublication::http01_payload)
                .transpose()
                .map_err(|_| MetadataStoreError::InvalidMigrationHistory)?
                .flatten();
            transaction.execute(
                "UPDATE certificate_order_checkpoints SET http01_token = ?1 WHERE order_id = ?2",
                params![
                    proof.as_ref().map(meshspan_acme::Http01Payload::token),
                    &order_id
                ],
            )?;
            after = order_id;
        }
    }
}
