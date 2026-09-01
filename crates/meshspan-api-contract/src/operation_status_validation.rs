// SPDX-License-Identifier: GPL-2.0-only

//! Runtime validation for operation-status responses assembled from durable state.

use std::sync::OnceLock;

use crate::validation::{CompiledValidator, compile, validate, validator_from};
use crate::{BoundaryError, OperationState, OperationStatusResponse, schema};

static RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();

/// Validates and encodes one operation-status response.
///
/// # Errors
///
/// Refuses structurally invalid, contradictory or non-canonical outgoing state.
pub fn encode_operation_status_response(
    response: &OperationStatusResponse,
) -> Result<Vec<u8>, BoundaryError> {
    validate_semantics(response)?;
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(
        validator_from(
            RESPONSE.get_or_init(|| compile(&schema::response_schema::<OperationStatusResponse>())),
        )?,
        &value,
    )?;
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}

fn validate_semantics(response: &OperationStatusResponse) -> Result<(), BoundaryError> {
    if response.updated_at_epoch_micros < response.started_at_epoch_micros
        || response
            .progress
            .is_some_and(|progress| progress.completed > progress.total)
    {
        return Err(BoundaryError::EncodeMismatch);
    }
    let terminal = matches!(
        response.state,
        OperationState::Succeeded | OperationState::Failed | OperationState::Cancelled
    );
    if terminal != response.completed_at_epoch_micros.is_some()
        || matches!(response.state, OperationState::Failed) != response.failure.is_some()
        || response.completed_at_epoch_micros.is_some_and(|completed| {
            completed < response.updated_at_epoch_micros
                || completed < response.started_at_epoch_micros
        })
    {
        return Err(BoundaryError::EncodeMismatch);
    }
    Ok(())
}
