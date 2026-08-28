// SPDX-License-Identifier: GPL-2.0-only

//! Connection and negotiation message validation.

use crate::framing::{WireContractError, WireLimits};
use crate::v1::{
    ComponentSupport, GoAway, NodeHello, NodeRole, NodeWelcome, Ping, Pong, ProtocolError,
};

use super::{valid_count, valid_identifier, valid_text, validate_wire_error};

pub(super) fn hello(value: &NodeHello, limits: WireLimits) -> Result<(), WireContractError> {
    valid_count(value.versions.len(), limits, false)?;
    valid_count(value.roles.len(), limits, false)?;
    valid_count(value.components.len(), limits, false)?;
    valid_count(value.feature_bits.len(), limits, true)?;
    valid_identifier(&value.mesh_id)?;
    valid_identifier(&value.node_id)?;
    validate_roles(&value.roles)?;
    if value.incarnation == 0
        || value.versions.iter().any(|version| version.major == 0)
        || value.maximum_control_bytes == 0
        || value.maximum_data_frame_bytes == 0
        || value.maximum_streams == 0
    {
        return Err(WireContractError::InvalidMessage);
    }
    for component in &value.components {
        validate_component(component, limits)?;
    }
    Ok(())
}

pub(super) fn welcome(value: &NodeWelcome, limits: WireLimits) -> Result<(), WireContractError> {
    let version = value
        .selected_version
        .as_ref()
        .ok_or(WireContractError::InvalidMessage)?;
    valid_identifier(&value.peer_node_id)?;
    valid_count(value.partition_ids.len(), limits, false)?;
    for partition_id in &value.partition_ids {
        valid_identifier(partition_id)?;
    }
    if let Some(leader) = &value.leader_node_id {
        valid_identifier(leader)?;
    }
    if version.major == 0
        || value.peer_incarnation == 0
        || value.routing_epoch == 0
        || value.maximum_control_bytes == 0
        || value.maximum_data_frame_bytes == 0
        || value.maximum_streams == 0
    {
        return Err(WireContractError::InvalidMessage);
    }
    Ok(())
}

pub(super) const fn ping(value: &Ping) -> Result<(), WireContractError> {
    if value.sent_monotonic_micros == 0 {
        Err(WireContractError::InvalidMessage)
    } else {
        Ok(())
    }
}

pub(super) const fn pong(value: &Pong) -> Result<(), WireContractError> {
    if value.received_monotonic_micros == 0 || value.sent_monotonic_micros == 0 {
        Err(WireContractError::InvalidMessage)
    } else {
        Ok(())
    }
}

pub(super) fn go_away(value: &GoAway) -> Result<(), WireContractError> {
    if value.reason_code == 0 || value.retry_after_micros == Some(0) {
        Err(WireContractError::InvalidMessage)
    } else {
        Ok(())
    }
}

pub(super) fn protocol_error(value: &ProtocolError) -> Result<(), WireContractError> {
    valid_identifier(&value.offending_request_id)?;
    validate_wire_error(&crate::v1::WireError {
        code: value.code,
        diagnostic_code: value.diagnostic_code,
        retry_after_micros: None,
    })
}

fn validate_component(
    component: &ComponentSupport,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    valid_text(&component.implementation_id, limits)?;
    valid_count(component.versions.len(), limits, false)?;
    if component.contract_kind == 0
        || component.maximum_control_bytes == 0
        || component.maximum_items == 0
        || component.maximum_concurrency == 0
        || component.versions.iter().any(|version| version.major == 0)
    {
        return Err(WireContractError::InvalidMessage);
    }
    Ok(())
}

fn validate_roles(roles: &[i32]) -> Result<(), WireContractError> {
    if roles
        .iter()
        .any(|role| NodeRole::try_from(*role).map_or(true, |role| role == NodeRole::Unspecified))
    {
        Err(WireContractError::InvalidMessage)
    } else {
        Ok(())
    }
}
