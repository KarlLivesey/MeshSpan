// SPDX-License-Identifier: GPL-2.0-only

//! Runtime structural validation for hostile manual DNS task messages.

use std::sync::OnceLock;

use crate::validation::{CompiledValidator, compile, validate, validator_from};
use crate::{BoundaryError, ListManualDnsTasksQuery, ListManualDnsTasksResponse, schema};

static LIST_QUERY: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static LIST_RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();

/// Validates one decoded manual DNS task query.
///
/// # Errors
///
/// Rejects invalid limits and cursor shapes.
pub fn validate_list_manual_dns_tasks_query(
    query: &ListManualDnsTasksQuery,
) -> Result<(), BoundaryError> {
    let value = serde_json::to_value(query).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(query_validator()?, &value)
}

/// Validates and encodes one deadline-ordered manual DNS task page.
///
/// # Errors
///
/// Suppresses malformed, excessive or incorrectly ordered outgoing state.
pub fn encode_list_manual_dns_tasks_response(
    response: &ListManualDnsTasksResponse,
) -> Result<Vec<u8>, BoundaryError> {
    if response
        .tasks
        .windows(2)
        .any(|pair| task_key(&pair[0]) >= task_key(&pair[1]))
    {
        return Err(BoundaryError::EncodeMismatch);
    }
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(response_validator()?, &value)?;
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}

fn task_key(task: &crate::ManualDnsTaskSummary) -> (i64, i64, &str) {
    (
        task.expires_at_epoch_micros,
        task.created_at_epoch_micros,
        task.task_digest.as_str(),
    )
}

fn query_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        LIST_QUERY.get_or_init(|| compile(&schema::request_schema::<ListManualDnsTasksQuery>())),
    )
}

fn response_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        LIST_RESPONSE
            .get_or_init(|| compile(&schema::response_schema::<ListManualDnsTasksResponse>())),
    )
}
