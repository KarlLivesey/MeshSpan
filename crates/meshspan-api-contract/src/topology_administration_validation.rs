// SPDX-License-Identifier: GPL-2.0-only

//! Runtime structural validation for hostile topology administration messages.

use std::sync::OnceLock;

use crate::validation::{CompiledValidator, compile, validate, validator_from};
use crate::{
    BoundaryError, CreateAvailabilityCellRequest, CreateAvailabilityCellResponse,
    CreateFaultGroupRequest, CreateFaultGroupResponse, ListAvailabilityCellsResponse,
    ListFaultGroupMembershipsResponse, ListFaultGroupsResponse, ListTopologyNodesResponse,
    ListTopologyQuery, ListTopologyTargetsResponse, SetAvailabilityCellMembershipResponse,
    SetFaultGroupMembershipRequest, SetFaultGroupMembershipResponse, schema,
};

/// Maximum accepted bytes for one topology mutation.
pub const MAX_TOPOLOGY_MUTATION_BYTES: usize = 16 * 1_024;

static LIST_QUERY: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static CREATE_REQUEST: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static MEMBERSHIP_REQUEST: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static CREATE_CELL_REQUEST: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();

/// Validates one decoded topology-list query.
///
/// # Errors
///
/// Returns a boundary error when the query violates the generated contract.
pub fn validate_list_topology_query(query: &ListTopologyQuery) -> Result<(), BoundaryError> {
    validate_serialized(query, query_validator()?)
}

/// Decodes one bounded fault-group creation request without coercion.
///
/// # Errors
///
/// Returns a boundary error for empty, oversized, malformed or invalid input.
pub fn decode_create_fault_group_request(
    bytes: &[u8],
) -> Result<CreateFaultGroupRequest, BoundaryError> {
    decode_request(bytes, create_request_validator()?)
}

/// Decodes one bounded desired-membership request without coercion.
///
/// # Errors
///
/// Returns a boundary error for empty, oversized, malformed or invalid input.
pub fn decode_set_fault_group_membership_request(
    bytes: &[u8],
) -> Result<SetFaultGroupMembershipRequest, BoundaryError> {
    decode_request(bytes, membership_request_validator()?)
}

/// Decodes one bounded availability-cell creation request without coercion.
///
/// # Errors
///
/// Returns a boundary error for empty, oversized, malformed or invalid input.
pub fn decode_create_availability_cell_request(
    bytes: &[u8],
) -> Result<CreateAvailabilityCellRequest, BoundaryError> {
    decode_request(bytes, create_cell_request_validator()?)
}

/// Validates and encodes one node page.
///
/// # Errors
///
/// Returns a boundary error rather than emitting an invalid response.
pub fn encode_list_topology_nodes_response(
    response: &ListTopologyNodesResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode_response(response)
}

/// Validates and encodes one target page.
///
/// # Errors
///
/// Returns a boundary error rather than emitting an invalid response.
pub fn encode_list_topology_targets_response(
    response: &ListTopologyTargetsResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode_response(response)
}

/// Validates and encodes one fault-group page.
///
/// # Errors
///
/// Returns a boundary error rather than emitting an invalid response.
pub fn encode_list_fault_groups_response(
    response: &ListFaultGroupsResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode_response(response)
}

/// Validates and encodes one fault-group membership page.
///
/// # Errors
///
/// Returns a boundary error rather than emitting an invalid response.
pub fn encode_list_fault_group_memberships_response(
    response: &ListFaultGroupMembershipsResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode_response(response)
}

/// Validates and encodes one created fault group.
///
/// # Errors
///
/// Returns a boundary error rather than emitting an invalid response.
pub fn encode_create_fault_group_response(
    response: &CreateFaultGroupResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode_response(response)
}

/// Validates and encodes one desired-membership result.
///
/// # Errors
///
/// Returns a boundary error rather than emitting an invalid response.
pub fn encode_set_fault_group_membership_response(
    response: &SetFaultGroupMembershipResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode_response(response)
}

/// Validates and encodes one availability-cell page.
///
/// # Errors
///
/// Returns a boundary error rather than emitting an invalid response.
pub fn encode_list_availability_cells_response(
    response: &ListAvailabilityCellsResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode_response(response)
}

/// Validates and encodes one created availability cell.
///
/// # Errors
///
/// Returns a boundary error rather than emitting an invalid response.
pub fn encode_create_availability_cell_response(
    response: &CreateAvailabilityCellResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode_response(response)
}

/// Validates and encodes one desired availability-cell membership.
///
/// # Errors
///
/// Returns a boundary error rather than emitting an invalid response.
pub fn encode_set_availability_cell_membership_response(
    response: &SetAvailabilityCellMembershipResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode_response(response)
}

fn decode_request<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    validator: &CompiledValidator,
) -> Result<T, BoundaryError> {
    if bytes.is_empty() || bytes.len() > MAX_TOPOLOGY_MUTATION_BYTES {
        return Err(BoundaryError::BodyTooLarge {
            limit: MAX_TOPOLOGY_MUTATION_BYTES,
        });
    }
    let value = serde_json::from_slice(bytes).map_err(|_| BoundaryError::MalformedJson)?;
    validate(validator, &value)?;
    serde_json::from_value(value).map_err(|_| BoundaryError::DecodeMismatch)
}

fn encode_response<T: serde::Serialize + schemars::JsonSchema>(
    response: &T,
) -> Result<Vec<u8>, BoundaryError> {
    let validator =
        compile(&schema::response_schema::<T>()).map_err(BoundaryError::InvalidSchema)?;
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(&validator, &value)?;
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}

fn validate_serialized<T: serde::Serialize>(
    value: &T,
    validator: &CompiledValidator,
) -> Result<(), BoundaryError> {
    let value = serde_json::to_value(value).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(validator, &value)
}

fn query_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        LIST_QUERY.get_or_init(|| compile(&schema::request_schema::<ListTopologyQuery>())),
    )
}

fn create_request_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        CREATE_REQUEST
            .get_or_init(|| compile(&schema::request_schema::<CreateFaultGroupRequest>())),
    )
}

fn membership_request_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        MEMBERSHIP_REQUEST
            .get_or_init(|| compile(&schema::request_schema::<SetFaultGroupMembershipRequest>())),
    )
}

fn create_cell_request_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        CREATE_CELL_REQUEST
            .get_or_init(|| compile(&schema::request_schema::<CreateAvailabilityCellRequest>())),
    )
}
