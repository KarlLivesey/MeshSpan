// SPDX-License-Identifier: GPL-2.0-only

use std::sync::OnceLock;

use crate::validation::{CompiledValidator, compile, validate, validator_from};
use crate::{BackupRunStatus, BoundaryError, ListBackupRunsQuery, ListBackupRunsResponse, schema};

static QUERY: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static PAGE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();

/// Validates bounded history queries without assuming a generated caller.
///
/// # Errors
/// Rejects invalid bounds and cursor syntax. The service checks cursor bindings.
pub fn validate_list_backup_runs_query(query: &ListBackupRunsQuery) -> Result<(), BoundaryError> {
    let value = serde_json::to_value(query).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(
        validator_from(
            QUERY.get_or_init(|| compile(&schema::request_schema::<ListBackupRunsQuery>())),
        )?,
        &value,
    )
}

/// Validates history structure, ordering and terminal-state consistency before output.
///
/// # Errors
/// Rejects malformed sequences, contradictory completion, thresholds and continuations.
pub fn encode_list_backup_runs_response(
    response: &ListBackupRunsResponse,
) -> Result<Vec<u8>, BoundaryError> {
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(
        validator_from(
            PAGE.get_or_init(|| compile(&schema::response_schema::<ListBackupRunsResponse>())),
        )?,
        &value,
    )?;
    let mut previous = None;
    for run in &response.runs {
        let sequence = run
            .run_sequence
            .parse::<i64>()
            .map_err(|_| BoundaryError::EncodeMismatch)?;
        run.schedule_sequence
            .parse::<i64>()
            .map_err(|_| BoundaryError::EncodeMismatch)?;
        let terminal = matches!(
            run.state,
            BackupRunStatus::Protected | BackupRunStatus::Incomplete
        );
        if previous.is_some_and(|before| sequence >= before)
            || terminal != run.completed_at_epoch_micros.is_some()
            || run.minimum_independent_copies > run.minimum_verified_copies
        {
            return Err(BoundaryError::EncodeMismatch);
        }
        previous = Some(sequence);
    }
    if response.runs.is_empty() && response.next_page_url.is_some() {
        return Err(BoundaryError::EncodeMismatch);
    }
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}
