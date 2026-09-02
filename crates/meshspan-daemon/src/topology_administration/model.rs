// SPDX-License-Identifier: GPL-2.0-only

//! Deterministic topology identities, strict cursors and public projections.

use std::fmt::Write;

use meshspan_api_contract::{
    AcknowledgementCellMode, AcknowledgementConsistency, AcknowledgementPolicySummary,
    AssignVolumePlacementPolicyRequest, AssignVolumePlacementPolicyResponse,
    AssignVolumeProtectionPolicyRequest, AssignVolumeProtectionPolicyResponse,
    AvailabilityCellSummary, CreateAcknowledgementCellRequirement,
    CreateAcknowledgementPolicyRequest, CreateAvailabilityCellRequest, CreateFaultGroupRequest,
    CreateLocalityPolicyRequest, CreateProtectionPolicyRequest, FaultGroupMembershipSummary,
    FaultGroupSummary, ListAcknowledgementPoliciesResponse, ListAvailabilityCellsResponse,
    ListFaultGroupMembershipsResponse, ListFaultGroupsResponse, ListLocalityPoliciesResponse,
    ListProtectionPoliciesResponse, ListTopologyNodesResponse, ListTopologyQuery,
    ListTopologyTargetsResponse, LocalityPolicySummary, LocalityRequirementSummary,
    OperationId as ApiOperationId, ProtectionFailureTermSummary, ProtectionPolicySummary,
    ProtectionScenarioSummary, SetAvailabilityCellMembershipResponse,
    SetFaultGroupMembershipRequest, StorageFolderUsageLimit, StrongFallback, TopologyCursor,
    TopologyNodeRoles, TopologyNodeState, TopologyNodeSummary, TopologyTargetState,
    TopologyTargetSummary,
};
use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    AcknowledgementPolicyId, AuditEventId, AvailabilityCellId, DurationMicros, FailureScenario,
    FailureTerm, FaultGroupClassId, FaultGroupId, HostId, LocalityPolicyId, LocalityRequirementId,
    OperationId, ProtectionPolicyId, ProtectionScenarioId, TargetId, VolumeId, uuid_v8,
};
use meshspan_metadata::{
    AcknowledgementCellRequirement, AcknowledgementCellRole, AcknowledgementConsistencyClass,
    AcknowledgementPolicyCursor, AcknowledgementPolicyRecord, AssignVolumeAcknowledgementPolicy,
    AssignVolumeLocalityPolicy, AssignVolumeProtectionPolicy, AuthoritativeCommand,
    AvailabilityCellCursor, AvailabilityCellRecord, CommandContext, CreateAcknowledgementPolicy,
    CreateAvailabilityCell, CreateFaultGroup, CreateLocalityPolicy, CreateProtectionPolicy,
    FaultGroupCursor, FaultGroupMembershipCursor, FaultGroupMembershipRecord, FaultGroupRecord,
    LocalityPolicyCursor, LocalityPolicyRecord, LocalityRequirementConfiguration, Page,
    ProtectionPolicyCursor, ProtectionPolicyRecord, ProtectionScenarioConfiguration, RecordName,
    SetHostAvailabilityCellMembership, SetHostFaultGroupMembership,
    SetTargetAvailabilityCellMembership, StorageUsageLimit, StrongFallbackMode, TopologyNodeCursor,
    TopologyNodeRecord, TopologyTargetCursor, TopologyTargetRecord,
};
use sha2::{Digest, Sha256};

use super::{IdentityAdministrator, TopologyAdministrationError};
use crate::create_mesh_setup::{format_uuid, parse_uuid};

const CLASS_ID_DOMAIN: &[u8] = b"meshspan.topology.fault-class-id.v1\0";
const GROUP_ID_DOMAIN: &[u8] = b"meshspan.topology.fault-group-id.v1\0";
const AUDIT_ID_DOMAIN: &[u8] = b"meshspan.topology.audit-id.v1\0";
const POLICY_ID_DOMAIN: &[u8] = b"meshspan.protection.policy-id.v1\0";
const SCENARIO_ID_DOMAIN: &[u8] = b"meshspan.protection.scenario-id.v1\0";
const CELL_ID_DOMAIN: &[u8] = b"meshspan.topology.availability-cell-id.v1\0";
const LOCALITY_POLICY_ID_DOMAIN: &[u8] = b"meshspan.locality.policy-id.v1\0";
const LOCALITY_REQUIREMENT_ID_DOMAIN: &[u8] = b"meshspan.locality.requirement-id.v1\0";
const ACKNOWLEDGEMENT_POLICY_ID_DOMAIN: &[u8] = b"meshspan.acknowledgement.policy-id.v1\0";

pub(super) fn create_command(
    request: &CreateFaultGroupRequest,
) -> Result<(OperationId, FaultGroupId, AuthoritativeCommand), TopologyAdministrationError> {
    let operation_id = domain_operation(&request.operation_id)?;
    let class_name = RecordName::new(request.class_name.as_str())
        .map_err(|_| TopologyAdministrationError::InvalidInput)?;
    if class_name.canonical().len() > 128 {
        return Err(TopologyAdministrationError::InvalidInput);
    }
    let group_name = RecordName::new(request.group_name.as_str())
        .map_err(|_| TopologyAdministrationError::InvalidInput)?;
    let class_id = FaultGroupClassId::from_bytes(derived_uuid(
        CLASS_ID_DOMAIN,
        class_name.canonical().as_bytes(),
    )?)
    .map_err(|_| TopologyAdministrationError::Failed)?;
    let group_id =
        FaultGroupId::from_bytes(derived_uuid(GROUP_ID_DOMAIN, &operation_id.as_bytes())?)
            .map_err(|_| TopologyAdministrationError::Failed)?;
    Ok((
        operation_id,
        group_id,
        AuthoritativeCommand::CreateFaultGroup(CreateFaultGroup {
            class_id,
            class_name,
            group_id,
            group_name,
        }),
    ))
}

pub(super) fn membership_command(
    group_id: &str,
    host_id: &str,
    request: &SetFaultGroupMembershipRequest,
) -> Result<(OperationId, FaultGroupId, HostId, AuthoritativeCommand), TopologyAdministrationError>
{
    let operation_id = domain_operation(&request.operation_id)?;
    let group_id = FaultGroupId::from_bytes(
        parse_uuid(group_id).map_err(|_| TopologyAdministrationError::InvalidInput)?,
    )
    .map_err(|_| TopologyAdministrationError::InvalidInput)?;
    let host_id = HostId::from_bytes(
        parse_uuid(host_id).map_err(|_| TopologyAdministrationError::InvalidInput)?,
    )
    .map_err(|_| TopologyAdministrationError::InvalidInput)?;
    Ok((
        operation_id,
        group_id,
        host_id,
        AuthoritativeCommand::SetHostFaultGroupMembership(SetHostFaultGroupMembership {
            group_id,
            host_id,
            present: request.present,
        }),
    ))
}

pub(super) fn availability_cell_command(
    request: &CreateAvailabilityCellRequest,
) -> Result<(OperationId, AvailabilityCellId, AuthoritativeCommand), TopologyAdministrationError> {
    let operation_id = domain_operation(&request.operation_id)?;
    let cell_id =
        AvailabilityCellId::from_bytes(derived_uuid(CELL_ID_DOMAIN, &operation_id.as_bytes())?)
            .map_err(|_| TopologyAdministrationError::Failed)?;
    let name = RecordName::new(request.name.as_str())
        .map_err(|_| TopologyAdministrationError::InvalidInput)?;
    let parent_cell_id = request
        .parent_cell_id
        .as_deref()
        .map(parse_uuid)
        .transpose()
        .map_err(|_| TopologyAdministrationError::InvalidInput)?
        .map(AvailabilityCellId::from_bytes)
        .transpose()
        .map_err(|_| TopologyAdministrationError::InvalidInput)?;
    Ok((
        operation_id,
        cell_id,
        AuthoritativeCommand::CreateAvailabilityCell(CreateAvailabilityCell {
            cell_id,
            name,
            parent_cell_id,
        }),
    ))
}

pub(super) fn host_cell_membership_command(
    cell_id: &str,
    host_id: &str,
    request: &SetFaultGroupMembershipRequest,
) -> Result<
    (
        OperationId,
        AvailabilityCellId,
        HostId,
        AuthoritativeCommand,
    ),
    TopologyAdministrationError,
> {
    let operation_id = domain_operation(&request.operation_id)?;
    let cell_id = domain_cell(cell_id)?;
    let host_id = HostId::from_bytes(
        parse_uuid(host_id).map_err(|_| TopologyAdministrationError::InvalidInput)?,
    )
    .map_err(|_| TopologyAdministrationError::InvalidInput)?;
    Ok((
        operation_id,
        cell_id,
        host_id,
        AuthoritativeCommand::SetHostAvailabilityCellMembership(
            SetHostAvailabilityCellMembership {
                cell_id,
                host_id,
                present: request.present,
            },
        ),
    ))
}

pub(super) fn target_cell_membership_command(
    cell_id: &str,
    target_id: &str,
    request: &SetFaultGroupMembershipRequest,
) -> Result<
    (
        OperationId,
        AvailabilityCellId,
        TargetId,
        AuthoritativeCommand,
    ),
    TopologyAdministrationError,
> {
    let operation_id = domain_operation(&request.operation_id)?;
    let cell_id = domain_cell(cell_id)?;
    let target_id = TargetId::from_bytes(
        parse_uuid(target_id).map_err(|_| TopologyAdministrationError::InvalidInput)?,
    )
    .map_err(|_| TopologyAdministrationError::InvalidInput)?;
    Ok((
        operation_id,
        cell_id,
        target_id,
        AuthoritativeCommand::SetTargetAvailabilityCellMembership(
            SetTargetAvailabilityCellMembership {
                cell_id,
                target_id,
                present: request.present,
            },
        ),
    ))
}

pub(super) fn protection_policy_command(
    request: &CreateProtectionPolicyRequest,
) -> Result<(OperationId, ProtectionPolicyId, AuthoritativeCommand), TopologyAdministrationError> {
    let operation_id = domain_operation(&request.operation_id)?;
    let policy_id =
        ProtectionPolicyId::from_bytes(derived_uuid(POLICY_ID_DOMAIN, &operation_id.as_bytes())?)
            .map_err(|_| TopologyAdministrationError::Failed)?;
    let name = RecordName::new(request.name.as_str())
        .map_err(|_| TopologyAdministrationError::InvalidInput)?;
    let scenarios = request
        .scenarios
        .iter()
        .enumerate()
        .map(|(index, scenario)| {
            let mut identity = operation_id.as_bytes().to_vec();
            identity.extend_from_slice(
                &u64::try_from(index)
                    .map_err(|_| TopologyAdministrationError::InvalidInput)?
                    .to_be_bytes(),
            );
            let scenario_id =
                ProtectionScenarioId::from_bytes(derived_uuid(SCENARIO_ID_DOMAIN, &identity)?)
                    .map_err(|_| TopologyAdministrationError::Failed)?;
            let name = RecordName::new(scenario.name.as_str())
                .map_err(|_| TopologyAdministrationError::InvalidInput)?;
            let terms = scenario
                .terms
                .iter()
                .map(|term| {
                    Ok(FailureTerm {
                        class_id: FaultGroupClassId::from_bytes(
                            parse_uuid(&term.class_id)
                                .map_err(|_| TopologyAdministrationError::InvalidInput)?,
                        )
                        .map_err(|_| TopologyAdministrationError::InvalidInput)?,
                        failure_count: term.failure_count,
                    })
                })
                .collect::<Result<Vec<_>, TopologyAdministrationError>>()?;
            Ok(ProtectionScenarioConfiguration {
                scenario_id,
                name,
                scenario: FailureScenario::new(terms)
                    .map_err(|_| TopologyAdministrationError::InvalidInput)?,
            })
        })
        .collect::<Result<Vec<_>, TopologyAdministrationError>>()?;
    Ok((
        operation_id,
        policy_id,
        AuthoritativeCommand::CreateProtectionPolicy(CreateProtectionPolicy {
            policy_id,
            name,
            scenarios: BoundedItems::new(scenarios, 16)
                .map_err(|_| TopologyAdministrationError::InvalidInput)?,
        }),
    ))
}

pub(super) fn protection_assignment_command(
    volume_id: &str,
    policy_id: &str,
    request: &AssignVolumeProtectionPolicyRequest,
) -> Result<
    (
        OperationId,
        VolumeId,
        ProtectionPolicyId,
        AuthoritativeCommand,
    ),
    TopologyAdministrationError,
> {
    let operation_id = domain_operation(&request.operation_id)?;
    let volume_id = VolumeId::from_bytes(
        parse_uuid(volume_id).map_err(|_| TopologyAdministrationError::InvalidInput)?,
    )
    .map_err(|_| TopologyAdministrationError::InvalidInput)?;
    let policy_id = ProtectionPolicyId::from_bytes(
        parse_uuid(policy_id).map_err(|_| TopologyAdministrationError::InvalidInput)?,
    )
    .map_err(|_| TopologyAdministrationError::InvalidInput)?;
    Ok((
        operation_id,
        volume_id,
        policy_id,
        AuthoritativeCommand::AssignVolumeProtectionPolicy(AssignVolumeProtectionPolicy {
            volume_id,
            policy_id,
        }),
    ))
}

pub(super) fn locality_policy_command(
    request: &CreateLocalityPolicyRequest,
) -> Result<(OperationId, LocalityPolicyId, AuthoritativeCommand), TopologyAdministrationError> {
    let operation_id = domain_operation(&request.operation_id)?;
    let policy_id = LocalityPolicyId::from_bytes(derived_uuid(
        LOCALITY_POLICY_ID_DOMAIN,
        &operation_id.as_bytes(),
    )?)
    .map_err(|_| TopologyAdministrationError::Failed)?;
    let requirements = request
        .requirements
        .iter()
        .enumerate()
        .map(|(index, requirement)| {
            let mut identity = operation_id.as_bytes().to_vec();
            identity.extend_from_slice(
                &u64::try_from(index)
                    .map_err(|_| TopologyAdministrationError::InvalidInput)?
                    .to_be_bytes(),
            );
            Ok(LocalityRequirementConfiguration {
                requirement_id: LocalityRequirementId::from_bytes(derived_uuid(
                    LOCALITY_REQUIREMENT_ID_DOMAIN,
                    &identity,
                )?)
                .map_err(|_| TopologyAdministrationError::Failed)?,
                cell_id: domain_cell(&requirement.cell_id)?,
                local_protection_policy_id: requirement
                    .local_protection_policy_id
                    .as_deref()
                    .map(domain_protection_policy)
                    .transpose()?,
            })
        })
        .collect::<Result<Vec<_>, TopologyAdministrationError>>()?;
    Ok((
        operation_id,
        policy_id,
        AuthoritativeCommand::CreateLocalityPolicy(CreateLocalityPolicy {
            policy_id,
            name: RecordName::new(request.name.as_str())
                .map_err(|_| TopologyAdministrationError::InvalidInput)?,
            maximum_lag: request.maximum_lag_micros.map(DurationMicros::new),
            requirements: BoundedItems::new(requirements, 64)
                .map_err(|_| TopologyAdministrationError::InvalidInput)?,
        }),
    ))
}

pub(super) fn acknowledgement_policy_command(
    request: &CreateAcknowledgementPolicyRequest,
) -> Result<(OperationId, AcknowledgementPolicyId, AuthoritativeCommand), TopologyAdministrationError>
{
    let operation_id = domain_operation(&request.operation_id)?;
    let policy_id = AcknowledgementPolicyId::from_bytes(derived_uuid(
        ACKNOWLEDGEMENT_POLICY_ID_DOMAIN,
        &operation_id.as_bytes(),
    )?)
    .map_err(|_| TopologyAdministrationError::Failed)?;
    let scenarios = request
        .required_scenario_ids
        .iter()
        .map(|value| {
            ProtectionScenarioId::from_bytes(
                parse_uuid(value.as_str())
                    .map_err(|_| TopologyAdministrationError::InvalidInput)?,
            )
            .map_err(|_| TopologyAdministrationError::InvalidInput)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let cells = request
        .cells
        .iter()
        .map(acknowledgement_cell)
        .collect::<Result<Vec<_>, _>>()?;
    Ok((
        operation_id,
        policy_id,
        AuthoritativeCommand::CreateAcknowledgementPolicy(CreateAcknowledgementPolicy {
            policy_id,
            name: RecordName::new(request.name.as_str())
                .map_err(|_| TopologyAdministrationError::InvalidInput)?,
            consistency: match request.consistency {
                AcknowledgementConsistency::Eventual => AcknowledgementConsistencyClass::Eventual,
                AcknowledgementConsistency::Strong => AcknowledgementConsistencyClass::Strong,
            },
            minimum_durable_targets: request.minimum_durable_targets,
            minimum_distinct_nodes: request.minimum_distinct_nodes,
            strong_wait: request.strong_wait_micros.map(DurationMicros::new),
            fallback: match request.fallback {
                StrongFallback::RemainPending => StrongFallbackMode::RemainPending,
                StrongFallback::FailAtDeadline => StrongFallbackMode::FailAtDeadline,
                StrongFallback::Eventual => StrongFallbackMode::Eventual,
            },
            required_scenarios: BoundedItems::new(scenarios, 64)
                .map_err(|_| TopologyAdministrationError::InvalidInput)?,
            cells: BoundedItems::new(cells, 256)
                .map_err(|_| TopologyAdministrationError::InvalidInput)?,
        }),
    ))
}

fn acknowledgement_cell(
    cell: &CreateAcknowledgementCellRequirement,
) -> Result<AcknowledgementCellRequirement, TopologyAdministrationError> {
    Ok(AcknowledgementCellRequirement {
        cell_id: domain_cell(&cell.cell_id)?,
        role: match cell.mode {
            AcknowledgementCellMode::RequiredBeforeCommit => {
                AcknowledgementCellRole::RequiredBeforeCommit
            }
            AcknowledgementCellMode::Eventual => AcknowledgementCellRole::Eventual,
            AcknowledgementCellMode::Excluded => AcknowledgementCellRole::Excluded,
        },
        minimum_durable_targets: cell.minimum_durable_targets,
        minimum_distinct_nodes: cell.minimum_distinct_nodes,
        local_protection_policy_id: cell
            .local_protection_policy_id
            .as_deref()
            .map(domain_protection_policy)
            .transpose()?,
    })
}

pub(super) fn locality_assignment_command(
    volume_id: &str,
    policy_id: &str,
    request: &AssignVolumePlacementPolicyRequest,
) -> Result<
    (
        OperationId,
        VolumeId,
        LocalityPolicyId,
        AuthoritativeCommand,
    ),
    TopologyAdministrationError,
> {
    let operation_id = domain_operation(&request.operation_id)?;
    let volume_id = domain_volume(volume_id)?;
    let policy_id = LocalityPolicyId::from_bytes(
        parse_uuid(policy_id).map_err(|_| TopologyAdministrationError::InvalidInput)?,
    )
    .map_err(|_| TopologyAdministrationError::InvalidInput)?;
    Ok((
        operation_id,
        volume_id,
        policy_id,
        AuthoritativeCommand::AssignVolumeLocalityPolicy(AssignVolumeLocalityPolicy {
            volume_id,
            policy_id,
        }),
    ))
}

pub(super) fn acknowledgement_assignment_command(
    volume_id: &str,
    policy_id: &str,
    request: &AssignVolumePlacementPolicyRequest,
) -> Result<
    (
        OperationId,
        VolumeId,
        AcknowledgementPolicyId,
        AuthoritativeCommand,
    ),
    TopologyAdministrationError,
> {
    let operation_id = domain_operation(&request.operation_id)?;
    let volume_id = domain_volume(volume_id)?;
    let policy_id = AcknowledgementPolicyId::from_bytes(
        parse_uuid(policy_id).map_err(|_| TopologyAdministrationError::InvalidInput)?,
    )
    .map_err(|_| TopologyAdministrationError::InvalidInput)?;
    Ok((
        operation_id,
        volume_id,
        policy_id,
        AuthoritativeCommand::AssignVolumeAcknowledgementPolicy(
            AssignVolumeAcknowledgementPolicy {
                volume_id,
                policy_id,
            },
        ),
    ))
}

pub(super) fn command_context(
    administrator: IdentityAdministrator,
    operation_id: OperationId,
) -> Result<CommandContext, TopologyAdministrationError> {
    let audit_event_id =
        AuditEventId::from_bytes(derived_uuid(AUDIT_ID_DOMAIN, &operation_id.as_bytes())?)
            .map_err(|_| TopologyAdministrationError::Failed)?;
    Ok(CommandContext {
        operation_id,
        actor_principal_id: administrator.principal_id,
        audit_event_id,
        occurred_at: administrator.now,
        expected_revision: None,
    })
}

pub(super) fn node_response(
    query: &ListTopologyQuery,
    page: Page<TopologyNodeRecord, TopologyNodeCursor>,
) -> Result<ListTopologyNodesResponse, TopologyAdministrationError> {
    Ok(ListTopologyNodesResponse {
        nodes: page
            .items
            .into_iter()
            .map(node_summary)
            .collect::<Result<_, _>>()?,
        next_page_url: page
            .next
            .as_ref()
            .map(encode_node_cursor)
            .transpose()?
            .map(|cursor| page_url("nodes", &cursor, query.limit))
            .transpose()?,
    })
}

pub(super) fn target_response(
    query: &ListTopologyQuery,
    page: Page<TopologyTargetRecord, TopologyTargetCursor>,
) -> Result<ListTopologyTargetsResponse, TopologyAdministrationError> {
    Ok(ListTopologyTargetsResponse {
        targets: page
            .items
            .into_iter()
            .map(target_summary)
            .collect::<Result<_, _>>()?,
        next_page_url: page
            .next
            .as_ref()
            .map(encode_target_cursor)
            .transpose()?
            .map(|cursor| page_url("targets", &cursor, query.limit))
            .transpose()?,
    })
}

pub(super) fn group_response(
    query: &ListTopologyQuery,
    page: Page<FaultGroupRecord, FaultGroupCursor>,
) -> Result<ListFaultGroupsResponse, TopologyAdministrationError> {
    Ok(ListFaultGroupsResponse {
        groups: page.items.into_iter().map(group_summary).collect(),
        next_page_url: page
            .next
            .as_ref()
            .map(encode_group_cursor)
            .transpose()?
            .map(|cursor| page_url("fault-groups", &cursor, query.limit))
            .transpose()?,
    })
}

pub(super) fn membership_response(
    query: &ListTopologyQuery,
    page: Page<FaultGroupMembershipRecord, FaultGroupMembershipCursor>,
) -> Result<ListFaultGroupMembershipsResponse, TopologyAdministrationError> {
    Ok(ListFaultGroupMembershipsResponse {
        memberships: page.items.into_iter().map(membership_summary).collect(),
        next_page_url: page
            .next
            .as_ref()
            .map(encode_membership_cursor)
            .transpose()?
            .map(|cursor| page_url("fault-group-memberships", &cursor, query.limit))
            .transpose()?,
    })
}

pub(super) fn availability_cell_response(
    query: &ListTopologyQuery,
    page: Page<AvailabilityCellRecord, AvailabilityCellCursor>,
) -> Result<ListAvailabilityCellsResponse, TopologyAdministrationError> {
    Ok(ListAvailabilityCellsResponse {
        cells: page.items.into_iter().map(cell_summary).collect(),
        next_page_url: page
            .next
            .as_ref()
            .map(encode_cell_cursor)
            .transpose()?
            .map(|cursor| page_url("availability-cells", &cursor, query.limit))
            .transpose()?,
    })
}

pub(super) fn cell_summary(record: AvailabilityCellRecord) -> AvailabilityCellSummary {
    AvailabilityCellSummary {
        cell_id: format_uuid(record.cell_id.as_bytes()),
        name: record.display_name,
        parent_cell_id: record
            .parent_cell_id
            .map(AvailabilityCellId::as_bytes)
            .map(format_uuid),
        revision: record.revision.get(),
    }
}

pub(super) fn cell_membership_response(
    operation_id: ApiOperationId,
    cell_id: AvailabilityCellId,
    member_id: [u8; 16],
    present: bool,
    revision: u64,
) -> SetAvailabilityCellMembershipResponse {
    SetAvailabilityCellMembershipResponse {
        operation_id,
        cell_id: format_uuid(cell_id.as_bytes()),
        member_id: format_uuid(member_id),
        present,
        revision,
    }
}

pub(super) fn protection_policy_response(
    query: &ListTopologyQuery,
    page: Page<ProtectionPolicyRecord, ProtectionPolicyCursor>,
) -> Result<ListProtectionPoliciesResponse, TopologyAdministrationError> {
    Ok(ListProtectionPoliciesResponse {
        policies: page.items.into_iter().map(policy_summary).collect(),
        next_page_url: page
            .next
            .as_ref()
            .map(encode_policy_cursor)
            .transpose()?
            .map(|cursor| protection_page_url(&cursor, query.limit))
            .transpose()?,
    })
}

pub(super) fn policy_summary(record: ProtectionPolicyRecord) -> ProtectionPolicySummary {
    ProtectionPolicySummary {
        policy_id: format_uuid(record.policy_id.as_bytes()),
        name: record.display_name,
        scenarios: record
            .scenarios
            .into_iter()
            .map(|scenario| ProtectionScenarioSummary {
                scenario_id: format_uuid(scenario.scenario_id.as_bytes()),
                name: scenario.display_name,
                terms: scenario
                    .terms
                    .into_iter()
                    .map(|term| ProtectionFailureTermSummary {
                        class_id: format_uuid(term.class_id.as_bytes()),
                        class_name: term.class_display_name,
                        failure_count: term.failure_count,
                    })
                    .collect(),
            })
            .collect(),
        revision: record.revision.get(),
    }
}

pub(super) fn assignment_response(
    operation_id: ApiOperationId,
    volume_id: VolumeId,
    policy_id: ProtectionPolicyId,
    revision: u64,
) -> AssignVolumeProtectionPolicyResponse {
    AssignVolumeProtectionPolicyResponse {
        operation_id,
        volume_id: format_uuid(volume_id.as_bytes()),
        policy_id: format_uuid(policy_id.as_bytes()),
        revision,
    }
}

pub(super) fn placement_assignment_response(
    operation_id: ApiOperationId,
    volume_id: VolumeId,
    policy_id: [u8; 16],
    revision: u64,
) -> AssignVolumePlacementPolicyResponse {
    AssignVolumePlacementPolicyResponse {
        operation_id,
        volume_id: format_uuid(volume_id.as_bytes()),
        policy_id: format_uuid(policy_id),
        revision,
    }
}

pub(super) fn locality_policy_response(
    query: &ListTopologyQuery,
    page: Page<LocalityPolicyRecord, LocalityPolicyCursor>,
) -> Result<ListLocalityPoliciesResponse, TopologyAdministrationError> {
    Ok(ListLocalityPoliciesResponse {
        policies: page
            .items
            .into_iter()
            .map(locality_policy_summary)
            .collect(),
        next_page_url: page
            .next
            .as_ref()
            .map(encode_locality_cursor)
            .transpose()?
            .map(|cursor| placement_page_url("locality-policies", &cursor, query.limit))
            .transpose()?,
    })
}

pub(super) fn locality_policy_summary(record: LocalityPolicyRecord) -> LocalityPolicySummary {
    LocalityPolicySummary {
        policy_id: format_uuid(record.policy_id.as_bytes()),
        name: record.display_name,
        maximum_lag_micros: record.maximum_lag.map(DurationMicros::get),
        requirements: record
            .requirements
            .into_iter()
            .map(|requirement| LocalityRequirementSummary {
                requirement_id: format_uuid(requirement.requirement_id.as_bytes()),
                cell_id: format_uuid(requirement.cell_id.as_bytes()),
                local_protection_policy_id: requirement
                    .local_protection_policy_id
                    .map(ProtectionPolicyId::as_bytes)
                    .map(format_uuid),
            })
            .collect(),
        revision: record.revision.get(),
    }
}

pub(super) fn acknowledgement_policy_response(
    query: &ListTopologyQuery,
    page: Page<AcknowledgementPolicyRecord, AcknowledgementPolicyCursor>,
) -> Result<ListAcknowledgementPoliciesResponse, TopologyAdministrationError> {
    Ok(ListAcknowledgementPoliciesResponse {
        policies: page
            .items
            .into_iter()
            .map(acknowledgement_policy_summary)
            .collect::<Result<_, _>>()?,
        next_page_url: page
            .next
            .as_ref()
            .map(encode_acknowledgement_cursor)
            .transpose()?
            .map(|cursor| placement_page_url("acknowledgement-policies", &cursor, query.limit))
            .transpose()?,
    })
}

pub(super) fn acknowledgement_policy_summary(
    record: AcknowledgementPolicyRecord,
) -> Result<AcknowledgementPolicySummary, TopologyAdministrationError> {
    Ok(AcknowledgementPolicySummary {
        policy_id: format_uuid(record.policy_id.as_bytes()),
        name: record.display_name,
        consistency: match record.consistency {
            AcknowledgementConsistencyClass::Eventual => AcknowledgementConsistency::Eventual,
            AcknowledgementConsistencyClass::Strong => AcknowledgementConsistency::Strong,
        },
        minimum_durable_targets: record.minimum_durable_targets,
        minimum_distinct_nodes: record.minimum_distinct_nodes,
        strong_wait_micros: record.strong_wait.map(DurationMicros::get),
        fallback: match record.fallback {
            StrongFallbackMode::RemainPending => StrongFallback::RemainPending,
            StrongFallbackMode::FailAtDeadline => StrongFallback::FailAtDeadline,
            StrongFallbackMode::Eventual => StrongFallback::Eventual,
        },
        required_scenario_ids: record
            .required_scenarios
            .into_iter()
            .map(ProtectionScenarioId::as_bytes)
            .map(meshspan_api_contract::ProtectionScenarioReferenceId::from_uuid_bytes)
            .collect::<Option<Vec<_>>>()
            .ok_or(TopologyAdministrationError::Failed)?,
        cells: record
            .cells
            .into_iter()
            .map(|cell| CreateAcknowledgementCellRequirement {
                cell_id: format_uuid(cell.cell_id.as_bytes()),
                mode: match cell.role {
                    AcknowledgementCellRole::RequiredBeforeCommit => {
                        AcknowledgementCellMode::RequiredBeforeCommit
                    }
                    AcknowledgementCellRole::Eventual => AcknowledgementCellMode::Eventual,
                    AcknowledgementCellRole::Excluded => AcknowledgementCellMode::Excluded,
                },
                minimum_durable_targets: cell.minimum_durable_targets,
                minimum_distinct_nodes: cell.minimum_distinct_nodes,
                local_protection_policy_id: cell
                    .local_protection_policy_id
                    .map(ProtectionPolicyId::as_bytes)
                    .map(format_uuid),
            })
            .collect(),
        revision: record.revision.get(),
    })
}

pub(super) fn group_summary(record: FaultGroupRecord) -> FaultGroupSummary {
    FaultGroupSummary {
        class_id: format_uuid(record.class_id.as_bytes()),
        class_name: record.class_display_name,
        group_id: format_uuid(record.group_id.as_bytes()),
        group_name: record.group_display_name,
        revision: record.revision.get(),
    }
}

pub(super) fn decode_node_cursor(
    cursor: &TopologyCursor,
) -> Result<TopologyNodeCursor, TopologyAdministrationError> {
    let fields = cursor_fields(cursor, "n", 2)?;
    let node_id = meshspan_domain::NodeId::from_bytes(parse_cursor_uuid(fields[0])?)
        .map_err(|_| TopologyAdministrationError::InvalidInput)?;
    Ok(TopologyNodeCursor::new(decode_text(fields[1])?, node_id))
}

pub(super) fn decode_target_cursor(
    cursor: &TopologyCursor,
) -> Result<TopologyTargetCursor, TopologyAdministrationError> {
    let fields = cursor_fields(cursor, "t", 2)?;
    let target_id = meshspan_domain::TargetId::from_bytes(parse_cursor_uuid(fields[0])?)
        .map_err(|_| TopologyAdministrationError::InvalidInput)?;
    Ok(TopologyTargetCursor::new(
        decode_text(fields[1])?,
        target_id,
    ))
}

pub(super) fn decode_group_cursor(
    cursor: &TopologyCursor,
) -> Result<FaultGroupCursor, TopologyAdministrationError> {
    let fields = cursor_fields(cursor, "g", 3)?;
    let group_id = FaultGroupId::from_bytes(parse_cursor_uuid(fields[0])?)
        .map_err(|_| TopologyAdministrationError::InvalidInput)?;
    Ok(FaultGroupCursor::new(
        decode_text(fields[1])?,
        decode_text(fields[2])?,
        group_id,
    ))
}

pub(super) fn decode_membership_cursor(
    cursor: &TopologyCursor,
) -> Result<FaultGroupMembershipCursor, TopologyAdministrationError> {
    let fields = cursor_fields(cursor, "m", 2)?;
    let host_id = HostId::from_bytes(parse_cursor_uuid(fields[0])?)
        .map_err(|_| TopologyAdministrationError::InvalidInput)?;
    let group_id = FaultGroupId::from_bytes(parse_cursor_uuid(fields[1])?)
        .map_err(|_| TopologyAdministrationError::InvalidInput)?;
    Ok(FaultGroupMembershipCursor::new(host_id, group_id))
}

pub(super) fn decode_policy_cursor(
    cursor: &TopologyCursor,
) -> Result<ProtectionPolicyCursor, TopologyAdministrationError> {
    let fields = cursor_fields(cursor, "p", 2)?;
    let policy_id = ProtectionPolicyId::from_bytes(parse_cursor_uuid(fields[0])?)
        .map_err(|_| TopologyAdministrationError::InvalidInput)?;
    Ok(ProtectionPolicyCursor::new(
        decode_text(fields[1])?,
        policy_id,
    ))
}

pub(super) fn decode_cell_cursor(
    cursor: &TopologyCursor,
) -> Result<AvailabilityCellCursor, TopologyAdministrationError> {
    let fields = cursor_fields(cursor, "c", 2)?;
    let cell_id = AvailabilityCellId::from_bytes(parse_cursor_uuid(fields[0])?)
        .map_err(|_| TopologyAdministrationError::InvalidInput)?;
    Ok(AvailabilityCellCursor::new(
        decode_text(fields[1])?,
        cell_id,
    ))
}

pub(super) fn decode_locality_cursor(
    cursor: &TopologyCursor,
) -> Result<LocalityPolicyCursor, TopologyAdministrationError> {
    let fields = cursor_fields(cursor, "l", 2)?;
    let policy_id = LocalityPolicyId::from_bytes(parse_cursor_uuid(fields[0])?)
        .map_err(|_| TopologyAdministrationError::InvalidInput)?;
    Ok(LocalityPolicyCursor::new(
        decode_text(fields[1])?,
        policy_id,
    ))
}

pub(super) fn decode_acknowledgement_cursor(
    cursor: &TopologyCursor,
) -> Result<AcknowledgementPolicyCursor, TopologyAdministrationError> {
    let fields = cursor_fields(cursor, "a", 2)?;
    let policy_id = AcknowledgementPolicyId::from_bytes(parse_cursor_uuid(fields[0])?)
        .map_err(|_| TopologyAdministrationError::InvalidInput)?;
    Ok(AcknowledgementPolicyCursor::new(
        decode_text(fields[1])?,
        policy_id,
    ))
}

fn node_summary(
    record: TopologyNodeRecord,
) -> Result<TopologyNodeSummary, TopologyAdministrationError> {
    Ok(TopologyNodeSummary {
        node_id: format_uuid(record.node_id.as_bytes()),
        host_id: format_uuid(record.host_id.as_bytes()),
        display_name: record.display_name,
        state: match record.state {
            1 => TopologyNodeState::Joining,
            2 => TopologyNodeState::Active,
            3 => TopologyNodeState::Draining,
            4 => TopologyNodeState::Retired,
            _ => return Err(TopologyAdministrationError::Failed),
        },
        incarnation: record.incarnation.to_string(),
        roles: TopologyNodeRoles {
            storage: record.roles & 1 != 0,
            gateway: record.roles & 2 != 0,
            metadata_eligible: record.roles & 4 != 0,
        },
        private_endpoint: record.private_endpoint,
        revision: record.revision.get(),
    })
}

fn target_summary(
    record: TopologyTargetRecord,
) -> Result<TopologyTargetSummary, TopologyAdministrationError> {
    Ok(TopologyTargetSummary {
        target_id: format_uuid(record.target_id.as_bytes()),
        node_id: format_uuid(record.node_id.as_bytes()),
        host_id: format_uuid(record.host_id.as_bytes()),
        display_name: record.display_name,
        state: match record.state {
            1 => TopologyTargetState::Active,
            2 => TopologyTargetState::Configuring,
            3 => TopologyTargetState::Draining,
            4 => TopologyTargetState::Unavailable,
            5 => TopologyTargetState::Retired,
            _ => return Err(TopologyAdministrationError::Failed),
        },
        generation: record.generation.to_string(),
        usage_limit: match record.usage_limit {
            StorageUsageLimit::Percent(percent) => StorageFolderUsageLimit::Percent { percent },
            StorageUsageLimit::Bytes(bytes) => StorageFolderUsageLimit::Bytes {
                bytes: bytes.to_string(),
            },
        },
        revision: record.revision.get(),
    })
}

fn membership_summary(record: FaultGroupMembershipRecord) -> FaultGroupMembershipSummary {
    FaultGroupMembershipSummary {
        host_id: format_uuid(record.host_id.as_bytes()),
        group_id: format_uuid(record.group_id.as_bytes()),
        revision: record.revision.get(),
    }
}

fn domain_operation(value: &ApiOperationId) -> Result<OperationId, TopologyAdministrationError> {
    OperationId::from_bytes(
        parse_uuid(value.as_str()).map_err(|_| TopologyAdministrationError::InvalidInput)?,
    )
    .map_err(|_| TopologyAdministrationError::InvalidInput)
}

fn domain_cell(value: &str) -> Result<AvailabilityCellId, TopologyAdministrationError> {
    AvailabilityCellId::from_bytes(
        parse_uuid(value).map_err(|_| TopologyAdministrationError::InvalidInput)?,
    )
    .map_err(|_| TopologyAdministrationError::InvalidInput)
}

fn domain_volume(value: &str) -> Result<VolumeId, TopologyAdministrationError> {
    VolumeId::from_bytes(parse_uuid(value).map_err(|_| TopologyAdministrationError::InvalidInput)?)
        .map_err(|_| TopologyAdministrationError::InvalidInput)
}

fn domain_protection_policy(
    value: &str,
) -> Result<ProtectionPolicyId, TopologyAdministrationError> {
    ProtectionPolicyId::from_bytes(
        parse_uuid(value).map_err(|_| TopologyAdministrationError::InvalidInput)?,
    )
    .map_err(|_| TopologyAdministrationError::InvalidInput)
}

fn derived_uuid(domain: &[u8], value: &[u8]) -> Result<[u8; 16], TopologyAdministrationError> {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(value);
    digest.finalize()[..16]
        .try_into()
        .map(uuid_v8)
        .map_err(|_| TopologyAdministrationError::Failed)
}

fn encode_node_cursor(
    cursor: &TopologyNodeCursor,
) -> Result<TopologyCursor, TopologyAdministrationError> {
    encoded_cursor("n", cursor.node_id().as_bytes(), &[cursor.canonical_name()])
}

fn encode_target_cursor(
    cursor: &TopologyTargetCursor,
) -> Result<TopologyCursor, TopologyAdministrationError> {
    encoded_cursor(
        "t",
        cursor.target_id().as_bytes(),
        &[cursor.canonical_name()],
    )
}

fn encode_group_cursor(
    cursor: &FaultGroupCursor,
) -> Result<TopologyCursor, TopologyAdministrationError> {
    encoded_cursor(
        "g",
        cursor.group_id().as_bytes(),
        &[cursor.class_name(), cursor.group_name()],
    )
}

fn encode_membership_cursor(
    cursor: &FaultGroupMembershipCursor,
) -> Result<TopologyCursor, TopologyAdministrationError> {
    let encoded = format!(
        "v1.m.{}.{}",
        format_uuid(cursor.host_id().as_bytes()),
        format_uuid(cursor.group_id().as_bytes())
    );
    TopologyCursor::from_encoded(encoded).ok_or(TopologyAdministrationError::Failed)
}

fn encode_policy_cursor(
    cursor: &ProtectionPolicyCursor,
) -> Result<TopologyCursor, TopologyAdministrationError> {
    encoded_cursor(
        "p",
        cursor.policy_id().as_bytes(),
        &[cursor.canonical_name()],
    )
}

fn encode_cell_cursor(
    cursor: &AvailabilityCellCursor,
) -> Result<TopologyCursor, TopologyAdministrationError> {
    encoded_cursor("c", cursor.cell_id().as_bytes(), &[cursor.canonical_name()])
}

fn encode_locality_cursor(
    cursor: &LocalityPolicyCursor,
) -> Result<TopologyCursor, TopologyAdministrationError> {
    encoded_cursor(
        "l",
        cursor.policy_id().as_bytes(),
        &[cursor.canonical_name()],
    )
}

fn encode_acknowledgement_cursor(
    cursor: &AcknowledgementPolicyCursor,
) -> Result<TopologyCursor, TopologyAdministrationError> {
    encoded_cursor(
        "a",
        cursor.policy_id().as_bytes(),
        &[cursor.canonical_name()],
    )
}

fn encoded_cursor(
    kind: &str,
    identifier: [u8; 16],
    names: &[&str],
) -> Result<TopologyCursor, TopologyAdministrationError> {
    let mut encoded = format!("v1.{kind}.{}", format_uuid(identifier));
    for name in names {
        encoded.push('.');
        append_hex(&mut encoded, name.as_bytes());
    }
    TopologyCursor::from_encoded(encoded).ok_or(TopologyAdministrationError::Failed)
}

fn cursor_fields<'a>(
    cursor: &'a TopologyCursor,
    kind: &str,
    count: usize,
) -> Result<Vec<&'a str>, TopologyAdministrationError> {
    let mut values = cursor.as_str().split('.');
    if values.next() != Some("v1") || values.next() != Some(kind) {
        return Err(TopologyAdministrationError::InvalidInput);
    }
    let fields = values.collect::<Vec<_>>();
    if fields.len() == count {
        Ok(fields)
    } else {
        Err(TopologyAdministrationError::InvalidInput)
    }
}

fn parse_cursor_uuid(value: &str) -> Result<[u8; 16], TopologyAdministrationError> {
    parse_uuid(value).map_err(|_| TopologyAdministrationError::InvalidInput)
}

fn append_hex(output: &mut String, value: &[u8]) {
    for byte in value {
        let _ = write!(output, "{byte:02x}");
    }
}

fn decode_text(value: &str) -> Result<String, TopologyAdministrationError> {
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(TopologyAdministrationError::InvalidInput);
    }
    let bytes = pairs
        .iter()
        .map(|pair| {
            let text =
                std::str::from_utf8(pair).map_err(|_| TopologyAdministrationError::InvalidInput)?;
            u8::from_str_radix(text, 16).map_err(|_| TopologyAdministrationError::InvalidInput)
        })
        .collect::<Result<Vec<_>, _>>()?;
    String::from_utf8(bytes).map_err(|_| TopologyAdministrationError::InvalidInput)
}

fn page_url(
    resource: &str,
    cursor: &TopologyCursor,
    limit: Option<u16>,
) -> Result<String, TopologyAdministrationError> {
    let mut url = format!(
        "/api/latest/admin/topology/{resource}?cursor={}",
        cursor.as_str()
    );
    if let Some(limit) = limit {
        write!(url, "&limit={limit}").map_err(|_| TopologyAdministrationError::Failed)?;
    }
    Ok(url)
}

fn protection_page_url(
    cursor: &TopologyCursor,
    limit: Option<u16>,
) -> Result<String, TopologyAdministrationError> {
    let mut url = format!(
        "/api/latest/admin/protection-policies?cursor={}",
        cursor.as_str()
    );
    if let Some(limit) = limit {
        write!(url, "&limit={limit}").map_err(|_| TopologyAdministrationError::Failed)?;
    }
    Ok(url)
}

fn placement_page_url(
    resource: &str,
    cursor: &TopologyCursor,
    limit: Option<u16>,
) -> Result<String, TopologyAdministrationError> {
    let mut url = format!("/api/latest/admin/{resource}?cursor={}", cursor.as_str());
    if let Some(limit) = limit {
        write!(url, "&limit={limit}").map_err(|_| TopologyAdministrationError::Failed)?;
    }
    Ok(url)
}
