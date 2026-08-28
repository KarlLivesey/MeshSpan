// SPDX-License-Identifier: GPL-2.0-only

//! Metadata, routing, presence, branch, work and certificate message validation.

use crate::framing::{WireContractError, WireLimits};
use crate::v1::control_envelope::Message;
use crate::v1::metadata_command::Command;
use crate::v1::metadata_query::Query;
use crate::v1::{
    AbortScopeHandoff, AcknowledgeCertificateInstall, ActivateScope, BeginScopeHandoff,
    BranchInclusionResult, ClaimWork, CompleteWork, ComponentLifecycleState, FetchBranchCommits,
    FetchCertificateEnvelope, FetchIdentityProjection, FetchImmutableObjects, FreezeScope,
    IdentityProjection, InventoryBatch, InventoryBegin, InventoryFinish, MetadataChangeBatch,
    MetadataCommand, MetadataPage, MetadataQuery, MetadataWatch, ProposeBranchInclusion,
    PublishCertificateBundle, PublishComponentObservation, PublishComponentSupport,
    PublishConvergenceReceipt, PublishIsolationDelegation, PublishPresence, PublishTargetStatus,
    QueryConsistency, RenewWork, ReportWorkProgress, RevokeCertificateEnvelope, RoutingDelta,
    ScopeRoute, ScrubObservation, WorkLease,
};

use super::{
    valid_count, valid_digest, valid_digests, valid_identifier, valid_identifiers,
    valid_nonempty_bytes, valid_optional_bytes, valid_page_limit, valid_text,
    validate_operation_result, validate_payload, validate_payloads, validate_shard,
};

pub(super) fn message(value: &Message, limits: WireLimits) -> Result<(), WireContractError> {
    match value {
        Message::MetadataCommand(value) => metadata_command(value, limits),
        Message::MetadataQuery(value) => metadata_query(value, limits),
        Message::MetadataPage(value) => metadata_page(value, limits),
        Message::OperationStatusRequest(value) => valid_identifier(&value.operation_id),
        Message::OperationStatusResponse(value) => {
            validate_operation_result(value.result.as_ref(), limits)
        }
        Message::MetadataWatch(value) => metadata_watch(value, limits),
        Message::MetadataChangeBatch(value) => metadata_changes(value, limits),
        Message::ResolveScopeRoute(value) => valid_identifier(&value.scope_id),
        Message::ScopeRoute(value) => scope_route(value, limits),
        Message::FetchRoutingDelta(value) => {
            valid_optional_bytes(&value.cursor, limits.maximum_control_bytes())?;
            valid_page_limit(value.limit, limits)
        }
        Message::RoutingDelta(value) => routing_delta(value, limits),
        Message::RoutingSnapshotRequired(value) => nonzero(value.current_routing_epoch),
        Message::BeginScopeHandoff(value) => begin_handoff(value),
        Message::FreezeScope(value) => freeze_scope(value),
        Message::ActivateScope(value) => activate_scope(value),
        Message::AbortScopeHandoff(value) => abort_handoff(value),
        Message::FetchIdentityProjection(value) => fetch_identity(value, limits),
        Message::IdentityProjection(value) => identity_projection(value, limits),
        Message::PublishPresence(value) => presence(value, limits),
        Message::PublishComponentSupport(value) => component_support(value, limits),
        Message::PublishComponentObservation(value) => component_observation(value, limits),
        Message::PublishTargetStatus(value) => target_status(value, limits),
        Message::InventoryBegin(value) => inventory_begin(value),
        Message::InventoryBatch(value) => inventory_batch(value, limits),
        Message::InventoryFinish(value) => inventory_finish(value),
        Message::ScrubObservation(value) => scrub_observation(value),
        Message::CompareBranchHeads(value) => {
            valid_identifier(&value.scope_id)?;
            valid_digests(&value.head_digests, limits, false)?;
            valid_digests(&value.causal_frontier, limits, true)
        }
        Message::BranchHeadSummary(value) => {
            valid_identifier(&value.scope_id)?;
            valid_digests(&value.head_digests, limits, false)?;
            valid_digests(&value.missing_commit_digests, limits, true)
        }
        Message::FetchBranchCommits(value) => fetch_branch_commits(value, limits),
        Message::BranchCommitBatch(value) => {
            valid_identifier(&value.scope_id)?;
            validate_payloads(&value.commits, limits, true)?;
            valid_optional_bytes(&value.next_cursor, limits.maximum_control_bytes())
        }
        Message::FetchImmutableObjects(value) => fetch_objects(value, limits),
        Message::ImmutableObjectBatch(value) => {
            validate_payloads(&value.objects, limits, true)?;
            valid_optional_bytes(&value.next_cursor, limits.maximum_control_bytes())
        }
        Message::ProposeBranchInclusion(value) => branch_inclusion(value, limits),
        Message::BranchInclusionResult(value) => branch_result(value, limits),
        Message::FetchMergeCommit(value) => {
            valid_identifier(&value.scope_id)?;
            valid_digest(&value.merge_commit_digest)
        }
        Message::MergeCommitResult(value) => validate_payload(value.merge_commit.as_ref(), limits),
        Message::PublishConvergenceReceipt(value) => convergence_receipt(value, limits),
        Message::PublishIsolationDelegation(value) => publish_delegation(value, limits),
        Message::FetchIsolationDelegation(value) => {
            valid_identifier(&value.delegation_id)?;
            nonzero(value.generation)
        }
        Message::ClaimWork(value) => claim_work(value, limits),
        Message::WorkLease(value) => work_lease(value, limits),
        Message::RenewWork(value) => renew_work(value),
        Message::ReportWorkProgress(value) => report_work(value, limits),
        Message::CompleteWork(value) => complete_work(value, limits),
        Message::PublishCertificateBundle(value) => publish_certificate(value, limits),
        Message::FetchCertificateEnvelope(value) => fetch_certificate(value),
        Message::AcknowledgeCertificateInstall(value) => acknowledge_certificate(value),
        Message::RevokeCertificateEnvelope(value) => revoke_certificate(value),
        _ => Err(WireContractError::InvalidMessage),
    }
}

fn metadata_command(value: &MetadataCommand, limits: WireLimits) -> Result<(), WireContractError> {
    valid_digest(&value.request_digest)?;
    if value.expected_revision == Some(0) {
        return Err(WireContractError::InvalidMessage);
    }
    let Some(
        Command::Topology(payload)
        | Command::IdentityAccess(payload)
        | Command::Namespace(payload)
        | Command::Policy(payload)
        | Command::Lifecycle(payload)
        | Command::ClusterControl(payload),
    ) = value.command.as_ref()
    else {
        return Err(WireContractError::InvalidMessage);
    };
    validate_payload(Some(payload), limits)
}

fn metadata_query(value: &MetadataQuery, limits: WireLimits) -> Result<(), WireContractError> {
    let consistency = QueryConsistency::try_from(value.consistency)
        .map_err(|_| WireContractError::InvalidMessage)?;
    if consistency == QueryConsistency::Unspecified
        || value.at_revision == Some(0)
        || (consistency == QueryConsistency::SnapshotRevision && value.at_revision.is_none())
    {
        return Err(WireContractError::InvalidMessage);
    }
    valid_page_limit(value.limit, limits)?;
    valid_optional_bytes(&value.cursor, limits.maximum_control_bytes())?;
    let Some(
        Query::Topology(payload)
        | Query::IdentityAccess(payload)
        | Query::Namespace(payload)
        | Query::Policy(payload)
        | Query::Lifecycle(payload)
        | Query::ClusterControl(payload),
    ) = value.query.as_ref()
    else {
        return Err(WireContractError::InvalidMessage);
    };
    validate_payload(Some(payload), limits)
}

fn metadata_page(value: &MetadataPage, limits: WireLimits) -> Result<(), WireContractError> {
    nonzero(value.revision)?;
    validate_payloads(&value.records, limits, true)?;
    valid_optional_bytes(&value.next_cursor, limits.maximum_control_bytes())
}

fn metadata_watch(value: &MetadataWatch, limits: WireLimits) -> Result<(), WireContractError> {
    valid_count(value.families.len(), limits, false)?;
    if value.families.contains(&0) {
        return Err(WireContractError::InvalidMessage);
    }
    valid_page_limit(value.maximum_events, limits)
}

fn metadata_changes(
    value: &MetadataChangeBatch,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    if value.first_revision == 0 || value.last_revision < value.first_revision {
        return Err(WireContractError::InvalidMessage);
    }
    validate_payloads(&value.changes, limits, value.snapshot_required)
}

fn scope_route(value: &ScopeRoute, limits: WireLimits) -> Result<(), WireContractError> {
    valid_identifier(&value.scope_id)?;
    valid_identifier(&value.partition_id)?;
    valid_identifier(&value.owner_node_id)?;
    nonzero(value.routing_epoch)?;
    valid_nonempty_bytes(&value.signature, limits.maximum_control_bytes())
}

fn routing_delta(value: &RoutingDelta, limits: WireLimits) -> Result<(), WireContractError> {
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

fn begin_handoff(value: &BeginScopeHandoff) -> Result<(), WireContractError> {
    scope_transfer(
        &value.scope_id,
        &value.source_partition_id,
        &value.destination_partition_id,
        value.routing_epoch,
    )
}

fn freeze_scope(value: &FreezeScope) -> Result<(), WireContractError> {
    scope_transfer(
        &value.scope_id,
        &value.source_partition_id,
        &value.destination_partition_id,
        value.routing_epoch,
    )?;
    nonzero(value.frozen_revision)?;
    valid_digest(&value.snapshot_digest)
}

fn activate_scope(value: &ActivateScope) -> Result<(), WireContractError> {
    scope_transfer(
        &value.scope_id,
        &value.source_partition_id,
        &value.destination_partition_id,
        value.routing_epoch,
    )?;
    nonzero(value.frozen_revision)?;
    valid_digest(&value.snapshot_digest)
}

fn abort_handoff(value: &AbortScopeHandoff) -> Result<(), WireContractError> {
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

fn fetch_identity(
    value: &FetchIdentityProjection,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    valid_optional_bytes(&value.cursor, limits.maximum_control_bytes())?;
    valid_page_limit(value.limit, limits)
}

fn identity_projection(
    value: &IdentityProjection,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    nonzero(value.identity_revision)?;
    validate_payloads(&value.records, limits, true)?;
    valid_optional_bytes(&value.next_cursor, limits.maximum_control_bytes())?;
    valid_nonempty_bytes(&value.signature, limits.maximum_control_bytes())
}

fn presence(value: &PublishPresence, limits: WireLimits) -> Result<(), WireContractError> {
    valid_identifier(&value.node_id)?;
    valid_count(value.roles.len(), limits, false)?;
    if value.roles.iter().any(|role| {
        crate::v1::NodeRole::try_from(*role)
            .map_or(true, |role| role == crate::v1::NodeRole::Unspecified)
    }) {
        return Err(WireContractError::InvalidMessage);
    }
    valid_count(value.private_addresses.len(), limits, false)?;
    for address in &value.private_addresses {
        valid_text(address, limits)?;
    }
    validate_payload(value.health.as_ref(), limits)?;
    nonzero(value.incarnation)?;
    nonzero(value.lease_expires_unix_micros)?;
    nonzero(value.presence_sequence)?;
    if value.observed_mesh_time <= 0
        || u64::try_from(value.observed_mesh_time)
            .map_or(true, |observed| value.lease_expires_unix_micros <= observed)
    {
        return Err(WireContractError::InvalidMessage);
    }
    Ok(())
}

fn component_support(
    value: &PublishComponentSupport,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    valid_count(value.components.len(), limits, false)?;
    for component in &value.components {
        valid_text(&component.implementation_id, limits)?;
        valid_count(component.versions.len(), limits, false)?;
        if component.contract_kind == 0
            || component.maximum_control_bytes == 0
            || component.maximum_items == 0
            || component.maximum_concurrency == 0
        {
            return Err(WireContractError::InvalidMessage);
        }
    }
    Ok(())
}

fn component_observation(
    value: &PublishComponentObservation,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    let lifecycle = ComponentLifecycleState::try_from(value.lifecycle_state)
        .map_err(|_| WireContractError::InvalidMessage)?;
    if value.contract_kind == 0
        || lifecycle == ComponentLifecycleState::Unspecified
        || value.desired_revision == 0
        || value.active_revision > value.desired_revision
    {
        return Err(WireContractError::InvalidMessage);
    }
    valid_text(&value.implementation_id, limits)?;
    validate_payload(value.detail.as_ref(), limits)
}

fn target_status(value: &PublishTargetStatus, limits: WireLimits) -> Result<(), WireContractError> {
    valid_identifier(&value.target_id)?;
    nonzero(value.target_generation)?;
    let accounted = value
        .available_bytes
        .checked_add(value.reserved_bytes)
        .ok_or(WireContractError::InvalidMessage)?;
    if accounted > value.capacity_bytes {
        return Err(WireContractError::InvalidMessage);
    }
    validate_payload(value.health.as_ref(), limits)
}

fn inventory_begin(value: &InventoryBegin) -> Result<(), WireContractError> {
    valid_identifier(&value.target_id)?;
    valid_identifier(&value.inventory_id)?;
    nonzero(value.target_generation)
}

fn inventory_batch(value: &InventoryBatch, limits: WireLimits) -> Result<(), WireContractError> {
    valid_identifier(&value.inventory_id)?;
    validate_payloads(&value.entries, limits, true)?;
    valid_optional_bytes(&value.next_cursor, limits.maximum_control_bytes())
}

fn inventory_finish(value: &InventoryFinish) -> Result<(), WireContractError> {
    valid_identifier(&value.inventory_id)?;
    valid_digest(&value.inventory_digest)
}

fn scrub_observation(value: &ScrubObservation) -> Result<(), WireContractError> {
    valid_identifier(&value.target_id)?;
    nonzero(value.target_generation)?;
    validate_shard(value.shard.as_ref())?;
    valid_digest(&value.observed_digest)
}

fn fetch_branch_commits(
    value: &FetchBranchCommits,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    valid_identifier(&value.scope_id)?;
    valid_digests(&value.commit_digests, limits, false)?;
    valid_optional_bytes(&value.cursor, limits.maximum_control_bytes())?;
    valid_page_limit(value.limit, limits)
}

fn fetch_objects(
    value: &FetchImmutableObjects,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    valid_digests(&value.object_digests, limits, false)?;
    valid_optional_bytes(&value.cursor, limits.maximum_control_bytes())?;
    valid_page_limit(value.limit, limits)
}

fn branch_inclusion(
    value: &ProposeBranchInclusion,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    valid_identifier(&value.scope_id)?;
    valid_digests(&value.head_digests, limits, false)?;
    valid_digest(&value.expected_converged_head)
}

fn branch_result(
    value: &BranchInclusionResult,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    validate_operation_result(value.result.as_ref(), limits)?;
    valid_digest(&value.converged_head)?;
    valid_digests(&value.alternative_heads, limits, true)
}

fn convergence_receipt(
    value: &PublishConvergenceReceipt,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    valid_identifier(&value.scope_id)?;
    valid_digest(&value.converged_head)?;
    valid_identifiers(&value.operation_ids, limits, false)?;
    validate_payloads(&value.achieved_predicates, limits, true)?;
    validate_payloads(&value.remaining_debt, limits, true)
}

fn publish_delegation(
    value: &PublishIsolationDelegation,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    valid_identifier(&value.delegation_id)?;
    nonzero(value.generation)?;
    validate_payload(value.signed_delegation.as_ref(), limits)
}

fn claim_work(value: &ClaimWork, limits: WireLimits) -> Result<(), WireContractError> {
    nonzero(u64::from(value.work_kind))?;
    valid_identifiers(&value.eligible_target_ids, limits, true)?;
    nonzero(value.requested_lease_micros)
}

fn work_lease(value: &WorkLease, limits: WireLimits) -> Result<(), WireContractError> {
    valid_identifier(&value.work_id)?;
    nonzero(value.fence)?;
    nonzero(value.lease_expires_unix_micros)?;
    validate_payload(value.assignment.as_ref(), limits)
}

fn renew_work(value: &RenewWork) -> Result<(), WireContractError> {
    valid_identifier(&value.work_id)?;
    nonzero(value.fence)?;
    nonzero(value.requested_lease_micros)
}

fn report_work(value: &ReportWorkProgress, limits: WireLimits) -> Result<(), WireContractError> {
    valid_identifier(&value.work_id)?;
    nonzero(value.fence)?;
    validate_payload(value.progress.as_ref(), limits)
}

fn complete_work(value: &CompleteWork, limits: WireLimits) -> Result<(), WireContractError> {
    valid_identifier(&value.work_id)?;
    nonzero(value.fence)?;
    if value.expected_revision == Some(0) {
        return Err(WireContractError::InvalidMessage);
    }
    validate_payloads(&value.receipts, limits, false)
}

fn publish_certificate(
    value: &PublishCertificateBundle,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    valid_identifier(&value.bundle_id)?;
    nonzero(value.generation)?;
    valid_nonempty_bytes(
        &value.public_certificate_chain,
        limits.maximum_control_bytes(),
    )?;
    validate_payloads(&value.recipient_envelopes, limits, false)
}

fn fetch_certificate(value: &FetchCertificateEnvelope) -> Result<(), WireContractError> {
    valid_identifier(&value.bundle_id)?;
    valid_identifier(&value.recipient_node_id)?;
    nonzero(value.generation)
}

fn acknowledge_certificate(value: &AcknowledgeCertificateInstall) -> Result<(), WireContractError> {
    valid_identifier(&value.bundle_id)?;
    nonzero(value.generation)?;
    valid_digest(&value.public_fingerprint)
}

fn revoke_certificate(value: &RevokeCertificateEnvelope) -> Result<(), WireContractError> {
    valid_identifier(&value.bundle_id)?;
    valid_identifier(&value.recipient_node_id)?;
    nonzero(value.generation)
}

const fn nonzero(value: u64) -> Result<(), WireContractError> {
    if value == 0 {
        Err(WireContractError::InvalidMessage)
    } else {
        Ok(())
    }
}
