// SPDX-License-Identifier: GPL-2.0-only

//! Publication evidence is immutable; permission to advance it comes from the live claim.

use meshspan_acme::{AcmeOrderMachine, ManualDnsTask, ManualDnsTaskPhase};
use meshspan_contracts::{ContractVersion, RequestContext};
use meshspan_domain::{OperationId, Revision, UnixMicros};
use rusqlite::Transaction;

use crate::{AdvanceManualDnsTask, RepositoryError};

pub(super) struct RetainedPublication {
    pub epoch: u64,
    pub retiring: bool,
}

pub(super) fn retained_publication_epoch(
    transaction: &Transaction<'_>,
    value: &AdvanceManualDnsTask,
) -> Result<Option<RetainedPublication>, RepositoryError> {
    let Some(checkpoint) = super::super::acme::load_checkpoint(transaction, value.order_id)? else {
        return Ok(None);
    };
    let machine = AcmeOrderMachine::decode_checkpoint(&checkpoint.checkpoint)
        .map_err(|_| RepositoryError::CorruptState)?;
    let Some(publication) = machine.publication() else {
        // Original checkpoint formats did not retain publication material. Their existing
        // same-claim transitions remain readable/replayable, but cannot authorise a handoff.
        return Ok(None);
    };
    let revision: i64 = transaction.query_row(
        "SELECT a.revision FROM certificate_orders o
         JOIN acme_configurations a ON a.config_id = o.config_id WHERE o.order_id = ?1",
        [value.order_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    let revision = u64::try_from(revision)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(RepositoryError::CorruptState)?;
    // A local decoding context, not an IO deadline or new authority grant. Use the actual
    // immutable configuration revision to reject a substituted checkpoint binding.
    let request = publication
        .request(RequestContext {
            contract_version: ContractVersion::V1_0,
            operation_id: OperationId::from_bytes(value.order_id.as_bytes())
                .map_err(|_| RepositoryError::CorruptState)?,
            deadline: UnixMicros::new(1),
            expected_revision: Some(Revision::new(revision)),
        })
        .map_err(|_| RepositoryError::InvalidCommand)?;
    let task =
        ManualDnsTask::from_challenge_request(&request, ManualDnsTaskPhase::AwaitingPublication)
            .map_err(|_| RepositoryError::InvalidCommand)?;
    if task.task_digest != value.task_digest
        || task.record_name != value.record_name
        || task.record_value != value.record_value
        || task.expires_at != value.expires_at
    {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(Some(RetainedPublication {
        epoch: task.order_epoch,
        retiring: machine.retirement_reason().is_some(),
    }))
}
