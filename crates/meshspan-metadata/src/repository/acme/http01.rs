// SPDX-License-Identifier: GPL-2.0-only

//! Indexed, revalidated public challenge projection of the authoritative order checkpoint.

use meshspan_acme::{AcmeOrderMachine, Http01Payload};
use meshspan_domain::{CertificateOrderId, UnixMicros};
use rusqlite::{Transaction, params};

use super::{AuthoritativeRepository, RepositoryError};

impl AuthoritativeRepository {
    /// Looks up one published HTTP-01 proof without exposing its enclosing order checkpoint.
    ///
    /// The index is only a candidate locator. The checkpoint digest, configuration binding,
    /// phase, token and original exclusive expiry are revalidated before returning bytes.
    ///
    /// # Errors
    /// Rejects malformed tokens, ambiguous publications and corrupt persisted evidence.
    pub fn public_http01_response(
        &self,
        token: &str,
        now: UnixMicros,
    ) -> Result<Option<(Vec<u8>, UnixMicros)>, RepositoryError> {
        Http01Payload::validate_token(token).map_err(|_| RepositoryError::InvalidCommand)?;
        let transaction = self.database.connection().unchecked_transaction()?;
        let mut statement = transaction.prepare(
            "SELECT order_id FROM certificate_order_checkpoints WHERE http01_token = ?1 LIMIT 2",
        )?;
        let orders = statement
            .query_map([token], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        if orders.len() > 1 {
            return Err(RepositoryError::CorruptState);
        }
        let Some(bytes) = orders.first() else {
            return Ok(None);
        };
        let order_id = CertificateOrderId::from_bytes(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| RepositoryError::CorruptState)?,
        )
        .map_err(|_| RepositoryError::CorruptState)?;
        let record = super::order_checkpoint::load_checkpoint(&transaction, order_id)?
            .ok_or(RepositoryError::CorruptState)?;
        let machine = AcmeOrderMachine::decode_checkpoint(&record.checkpoint)
            .map_err(|_| RepositoryError::CorruptState)?;
        let Some(publication) = machine.serving_publication() else {
            return Ok(None);
        };
        let proof = publication
            .http01_payload()
            .map_err(|_| RepositoryError::CorruptState)?
            .ok_or(RepositoryError::CorruptState)?;
        if proof.token() != token {
            return Err(RepositoryError::CorruptState);
        }
        Ok((now < publication.expires_at())
            .then(|| (proof.key_authorization().to_vec(), publication.expires_at())))
    }
}

pub(super) fn index_checkpoint(
    transaction: &Transaction<'_>,
    order_id: CertificateOrderId,
    checkpoint: &[u8],
) -> Result<(), RepositoryError> {
    let machine = AcmeOrderMachine::decode_checkpoint(checkpoint)
        .map_err(|_| RepositoryError::CorruptState)?;
    let proof = machine
        .serving_publication()
        .map(meshspan_acme::AcmeChallengePublication::http01_payload)
        .transpose()
        .map_err(|_| RepositoryError::CorruptState)?
        .flatten();
    transaction.execute(
        "UPDATE certificate_order_checkpoints SET http01_token = ?1 WHERE order_id = ?2",
        params![
            proof.as_ref().map(Http01Payload::token),
            order_id.as_bytes().as_slice()
        ],
    )?;
    Ok(())
}
