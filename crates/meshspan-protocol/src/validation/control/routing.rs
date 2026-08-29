// SPDX-License-Identifier: GPL-2.0-only

//! Root-owned route records and fenced metadata-scope handoff validation.

use crate::framing::{WireContractError, WireLimits};
use crate::v1::metadata_key_range::Range;
use crate::v1::{
    AbortScopeHandoff, ActivateScope, BeginScopeHandoff, FreezeScope, MetadataKeyRange,
    MetadataOperationFamily, RoutingDelta, ScopeRoute,
};

use super::super::{valid_count, valid_digest, valid_identifier, valid_optional_bytes};

pub(super) fn scope_route(value: &ScopeRoute, limits: WireLimits) -> Result<(), WireContractError> {
    valid_identifier(&value.scope_id)?;
    valid_identifier(&value.partition_id)?;
    valid_identifier(&value.root_partition_id)?;
    valid_identifier(&value.owner_node_id)?;
    nonzero(value.routing_epoch)?;
    nonzero(value.ownership_epoch)?;
    operation_family(value.operation_family)?;
    metadata_key_range(value.key_range.as_ref())?;
    valid_route_signature(&value.signature, limits)
}

pub(super) fn routing_delta(
    value: &RoutingDelta,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    nonzero(value.routing_epoch)?;
    valid_count(value.routes.len(), limits, true)?;
    for route in &value.routes {
        scope_route(route, limits)?;
        if route.routing_epoch != value.routing_epoch {
            return Err(WireContractError::InvalidMessage);
        }
    }
    valid_optional_bytes(&value.next_cursor, limits.maximum_control_bytes())
}

pub(super) fn begin_handoff(value: &BeginScopeHandoff) -> Result<(), WireContractError> {
    scope_transfer(
        &value.scope_id,
        &value.source_partition_id,
        &value.destination_partition_id,
        value.routing_epoch,
    )?;
    valid_identifier(&value.root_partition_id)?;
    operation_family(value.operation_family)?;
    metadata_key_range(value.key_range.as_ref())?;
    valid_nonzero_digest(&value.quorum_plan_digest)?;
    valid_nonzero_digest(&value.load_evidence_digest)?;
    if value.eligible_member_count == 0
        || value.planned_voter_count == 0
        || value.planned_voter_count > 9
        || value.eligible_member_count < value.planned_voter_count
        || value.measured_at_unix_micros <= 0
    {
        Err(WireContractError::InvalidMessage)
    } else {
        Ok(())
    }
}

pub(super) fn freeze_scope(value: &FreezeScope) -> Result<(), WireContractError> {
    scope_transfer(
        &value.scope_id,
        &value.source_partition_id,
        &value.destination_partition_id,
        value.routing_epoch,
    )?;
    nonzero(value.frozen_revision)?;
    valid_digest(&value.snapshot_digest)
}

pub(super) fn activate_scope(value: &ActivateScope) -> Result<(), WireContractError> {
    scope_transfer(
        &value.scope_id,
        &value.source_partition_id,
        &value.destination_partition_id,
        value.routing_epoch,
    )?;
    nonzero(value.frozen_revision)?;
    valid_digest(&value.snapshot_digest)
}

pub(super) fn abort_handoff(value: &AbortScopeHandoff) -> Result<(), WireContractError> {
    scope_transfer(
        &value.scope_id,
        &value.source_partition_id,
        &value.destination_partition_id,
        value.routing_epoch,
    )?;
    nonzero(u64::from(value.reason_code))
}

fn scope_transfer(
    scope_id: &[u8],
    source: &[u8],
    destination: &[u8],
    routing_epoch: u64,
) -> Result<(), WireContractError> {
    valid_identifier(scope_id)?;
    valid_identifier(source)?;
    valid_identifier(destination)?;
    if source == destination {
        return Err(WireContractError::InvalidMessage);
    }
    nonzero(routing_epoch)
}

fn operation_family(value: i32) -> Result<(), WireContractError> {
    let family =
        MetadataOperationFamily::try_from(value).map_err(|_| WireContractError::InvalidMessage)?;
    if family == MetadataOperationFamily::Unspecified {
        Err(WireContractError::InvalidMessage)
    } else {
        Ok(())
    }
}

fn metadata_key_range(value: Option<&MetadataKeyRange>) -> Result<(), WireContractError> {
    match value
        .and_then(|value| value.range.as_ref())
        .ok_or(WireContractError::InvalidMessage)?
    {
        Range::All(true) => Ok(()),
        Range::Bounded(range)
            if range.start_inclusive.len() == 16
                && range.end_exclusive.len() == 16
                && range.start_inclusive < range.end_exclusive =>
        {
            Ok(())
        }
        Range::All(false) | Range::Bounded(_) => Err(WireContractError::InvalidMessage),
    }
}

fn valid_nonzero_digest(value: &[u8]) -> Result<(), WireContractError> {
    valid_digest(value)?;
    if value.iter().any(|byte| *byte != 0) {
        Ok(())
    } else {
        Err(WireContractError::InvalidMessage)
    }
}

fn valid_route_signature(value: &[u8], limits: WireLimits) -> Result<(), WireContractError> {
    if value.len() == 64
        && value.len() <= limits.maximum_control_bytes()
        && value.iter().any(|byte| *byte != 0)
    {
        Ok(())
    } else {
        Err(WireContractError::InvalidMessage)
    }
}

const fn nonzero(value: u64) -> Result<(), WireContractError> {
    if value == 0 {
        Err(WireContractError::InvalidMessage)
    } else {
        Ok(())
    }
}
