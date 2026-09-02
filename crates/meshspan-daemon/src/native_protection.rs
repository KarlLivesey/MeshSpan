// SPDX-License-Identifier: GPL-2.0-only

//! Production protection snapshot derived from current replicated topology and local capacity.

use std::collections::{BTreeMap, BTreeSet};

use meshspan_contracts::{
    BoundedItems, PlacementCandidate, PlacementCellRequirement, PlacementCellRole,
};
use meshspan_domain::{
    AvailabilityCellId, FailureScenario, FailureTerm, FaultGroupClassId, FaultGroupId,
    FaultGroupMember, HostId, ProtectionPolicyId, ProtectionScenarioId, TargetId, Topology,
    VolumeId, machine_fault_class_id, storage_device_fault_class_id, uuid_v8,
};
use meshspan_filesystem::{
    ContentAcknowledgementClass, ContentAcknowledgementPolicy, ContentPublicationError,
    ContentStrongFallback, ProtectionConfiguration, ProtectionPolicySource,
};
use meshspan_metadata::{
    AcknowledgementCellRole, AcknowledgementPolicyRecord, AuthoritativeRepository, PageLimit,
    ProtectionPolicyRecord, StorageTargetProviderContext, StorageUsageLimit,
};

const PAGE_ITEMS: usize = 1_000;
const MAXIMUM_CELLS_PER_TARGET: usize = 256;
const MAXIMUM_CELL_SCENARIOS: usize = 16;
const PERCENT_CAPACITY_PLANNING_CEILING: u64 = 1_u64 << 50;

/// Live authoritative protection resolver used once for each new content publication.
pub(crate) struct NativeProtectionPolicySource {
    authority: AuthoritativeRepository,
    local_targets: Vec<StorageTargetProviderContext>,
}

impl NativeProtectionPolicySource {
    pub(crate) fn new(
        authority: AuthoritativeRepository,
        local_targets: Vec<StorageTargetProviderContext>,
    ) -> Self {
        Self {
            authority,
            local_targets,
        }
    }

    pub(crate) fn current_configuration(
        &self,
        volume_id: VolumeId,
    ) -> Result<ProtectionConfiguration, ContentPublicationError> {
        protection_configuration(&self.authority, &self.local_targets, volume_id)
    }
}

impl ProtectionPolicySource for NativeProtectionPolicySource {
    fn configuration(
        &self,
        volume_id: VolumeId,
    ) -> Result<ProtectionConfiguration, ContentPublicationError> {
        protection_configuration(&self.authority, &self.local_targets, volume_id)
    }
}

fn protection_configuration(
    authority: &AuthoritativeRepository,
    local_targets: &[StorageTargetProviderContext],
    volume_id: VolumeId,
) -> Result<ProtectionConfiguration, ContentPublicationError> {
    if local_targets.is_empty() {
        return Err(ContentPublicationError::Unavailable);
    }
    let capacity_revision = authority
        .current_revision()
        .map_err(|_| ContentPublicationError::Unavailable)?;
    let topology_revision = authority
        .mesh_configuration_revision()
        .map_err(|_| ContentPublicationError::Unavailable)?
        .ok_or(ContentPublicationError::Unavailable)?;
    let targets = active_targets(authority)?;
    if !local_targets.iter().all(|local| {
        targets
            .iter()
            .any(|(context, _)| same_target_generation(*context, *local))
    }) {
        return Err(ContentPublicationError::Unavailable);
    }
    let mut topology = Topology::default();
    let machine_class = machine_fault_class_id();
    let device_class = storage_device_fault_class_id();
    let mut registered_hosts = BTreeSet::new();
    for (context, host) in &targets {
        register_builtin_topology(
            &mut topology,
            &mut registered_hosts,
            *host,
            context.target_id,
            machine_class,
            device_class,
        )?;
    }
    register_administrator_fault_groups(authority, &mut topology, &registered_hosts)?;
    let protection_policy = authority
        .volume_protection_policy(volume_id)
        .map_err(|_| ContentPublicationError::Unavailable)?;
    let scenarios = protection_policy.as_ref().map_or_else(
        || default_scenarios(machine_class, device_class),
        |policy| Ok(policy.scenarios.clone()),
    )?;
    let acknowledgement = authority
        .volume_acknowledgement_policy(volume_id)
        .map_err(|_| ContentPublicationError::Unavailable)?;
    let locality = authority
        .volume_locality_policy(volume_id)
        .map_err(|_| ContentPublicationError::Unavailable)?;
    let cells = placement_cells(authority, locality.as_ref(), acknowledgement.as_ref())?;
    let required_scenarios = acknowledgement.as_ref().map_or_else(
        || Ok(Vec::new()),
        |policy| acknowledgement_scenarios(authority, protection_policy.as_ref(), policy),
    )?;
    let candidates = targets
        .iter()
        .map(|(context, host_id)| {
            let cells = authority
                .target_availability_cells(context.target_id, *host_id)
                .map_err(|_| ContentPublicationError::Unavailable)?;
            Ok(PlacementCandidate {
                target_id: context.target_id,
                host_id: *host_id,
                target_generation: context.generation,
                writable_bytes: planning_ceiling(context.usage_limit),
                performance_weight: 100,
                availability_cells: BoundedItems::new(cells, MAXIMUM_CELLS_PER_TARGET)
                    .map_err(|_| ContentPublicationError::InvalidInput)?,
            })
        })
        .collect::<Result<Vec<_>, ContentPublicationError>>()?;
    let (minimum_targets, minimum_nodes) = acknowledgement.as_ref().map_or((1, 1), |policy| {
        (
            policy.minimum_durable_targets,
            policy.minimum_distinct_nodes,
        )
    });
    ProtectionConfiguration::from_acknowledgement_snapshot(
        topology,
        topology_revision,
        capacity_revision,
        scenarios,
        candidates,
        required_scenarios,
        minimum_targets,
        minimum_nodes,
        cells,
        content_acknowledgement_policy(acknowledgement.as_ref()),
    )
}

fn content_acknowledgement_policy(
    policy: Option<&AcknowledgementPolicyRecord>,
) -> ContentAcknowledgementPolicy {
    policy.map_or(
        ContentAcknowledgementPolicy {
            class: ContentAcknowledgementClass::Eventual,
            strong_wait: None,
            fallback: ContentStrongFallback::RemainPending,
        },
        |policy| ContentAcknowledgementPolicy {
            class: match policy.consistency {
                meshspan_metadata::AcknowledgementConsistencyClass::Eventual => {
                    ContentAcknowledgementClass::Eventual
                }
                meshspan_metadata::AcknowledgementConsistencyClass::Strong => {
                    ContentAcknowledgementClass::Strong
                }
            },
            strong_wait: policy.strong_wait,
            fallback: match policy.fallback {
                meshspan_metadata::StrongFallbackMode::RemainPending => {
                    ContentStrongFallback::RemainPending
                }
                meshspan_metadata::StrongFallbackMode::FailAtDeadline => {
                    ContentStrongFallback::FailAtDeadline
                }
                meshspan_metadata::StrongFallbackMode::Eventual => ContentStrongFallback::Eventual,
            },
        },
    )
}

struct CellPolicyBuilder {
    role: PlacementCellRole,
    complete_local: bool,
    minimum_durable_targets: Option<u16>,
    minimum_distinct_nodes: Option<u16>,
    local_protection_policies: BTreeSet<ProtectionPolicyId>,
}

fn placement_cells(
    authority: &AuthoritativeRepository,
    locality: Option<&meshspan_metadata::VolumeLocalityPolicy>,
    acknowledgement: Option<&AcknowledgementPolicyRecord>,
) -> Result<Vec<PlacementCellRequirement>, ContentPublicationError> {
    let mut builders = BTreeMap::new();
    if let Some(locality) = locality {
        for requirement in &locality.requirements {
            let builder = builders
                .entry(requirement.cell_id)
                .or_insert_with(default_cell_builder);
            builder.complete_local = true;
            if let Some(policy_id) = requirement.local_protection_policy_id {
                builder.local_protection_policies.insert(policy_id);
            }
        }
    }
    if let Some(acknowledgement) = acknowledgement {
        for requirement in &acknowledgement.cells {
            let builder = builders
                .entry(requirement.cell_id)
                .or_insert_with(default_cell_builder);
            builder.role = placement_cell_role(requirement.role);
            builder.minimum_durable_targets = requirement.minimum_durable_targets;
            builder.minimum_distinct_nodes = requirement.minimum_distinct_nodes;
            if let Some(policy_id) = requirement.local_protection_policy_id {
                builder.local_protection_policies.insert(policy_id);
            }
        }
    }
    builders
        .into_iter()
        .map(|(cell_id, builder)| build_cell_requirement(authority, cell_id, builder))
        .collect()
}

fn default_cell_builder() -> CellPolicyBuilder {
    CellPolicyBuilder {
        role: PlacementCellRole::Eventual,
        complete_local: false,
        minimum_durable_targets: None,
        minimum_distinct_nodes: None,
        local_protection_policies: BTreeSet::new(),
    }
}

fn build_cell_requirement(
    authority: &AuthoritativeRepository,
    cell_id: AvailabilityCellId,
    builder: CellPolicyBuilder,
) -> Result<PlacementCellRequirement, ContentPublicationError> {
    let mut local_scenarios = Vec::new();
    for policy_id in builder.local_protection_policies {
        let policy = authority
            .protection_policy(policy_id)
            .map_err(|_| ContentPublicationError::Unavailable)?
            .ok_or(ContentPublicationError::InvalidInput)?;
        local_scenarios.extend(protection_scenarios(&policy)?);
    }
    local_scenarios.sort_by_key(|scenario| scenario.terms().first().map(|term| term.class_id));
    local_scenarios.dedup();
    Ok(PlacementCellRequirement {
        cell_id,
        role: builder.role,
        complete_local: builder.complete_local,
        minimum_durable_targets: builder.minimum_durable_targets,
        minimum_distinct_nodes: builder.minimum_distinct_nodes,
        local_scenarios: BoundedItems::new(local_scenarios, MAXIMUM_CELL_SCENARIOS)
            .map_err(|_| ContentPublicationError::InvalidInput)?,
    })
}

fn acknowledgement_scenarios(
    authority: &AuthoritativeRepository,
    selected: Option<&meshspan_metadata::VolumeProtectionPolicy>,
    acknowledgement: &AcknowledgementPolicyRecord,
) -> Result<Vec<FailureScenario>, ContentPublicationError> {
    if acknowledgement.required_scenarios.is_empty() {
        return Ok(Vec::new());
    }
    let selected = selected.ok_or(ContentPublicationError::InvalidInput)?;
    let policy = authority
        .protection_policy(selected.policy_id)
        .map_err(|_| ContentPublicationError::Unavailable)?
        .ok_or(ContentPublicationError::InvalidInput)?;
    acknowledgement
        .required_scenarios
        .iter()
        .map(|scenario_id| selected_scenario(&policy, *scenario_id))
        .collect()
}

fn selected_scenario(
    policy: &ProtectionPolicyRecord,
    scenario_id: ProtectionScenarioId,
) -> Result<FailureScenario, ContentPublicationError> {
    let scenario = policy
        .scenarios
        .iter()
        .find(|scenario| scenario.scenario_id == scenario_id)
        .ok_or(ContentPublicationError::InvalidInput)?;
    FailureScenario::new(
        scenario
            .terms
            .iter()
            .map(|term| FailureTerm {
                class_id: term.class_id,
                failure_count: term.failure_count,
            })
            .collect(),
    )
    .map_err(|_| ContentPublicationError::InvalidInput)
}

fn protection_scenarios(
    policy: &ProtectionPolicyRecord,
) -> Result<Vec<FailureScenario>, ContentPublicationError> {
    policy
        .scenarios
        .iter()
        .map(|scenario| selected_scenario(policy, scenario.scenario_id))
        .collect()
}

const fn placement_cell_role(role: AcknowledgementCellRole) -> PlacementCellRole {
    match role {
        AcknowledgementCellRole::RequiredBeforeCommit => PlacementCellRole::RequiredBeforeCommit,
        AcknowledgementCellRole::Eventual => PlacementCellRole::Eventual,
        AcknowledgementCellRole::Excluded => PlacementCellRole::Excluded,
    }
}

fn default_scenarios(
    machine_class: FaultGroupClassId,
    device_class: FaultGroupClassId,
) -> Result<Vec<FailureScenario>, ContentPublicationError> {
    [machine_class, device_class]
        .into_iter()
        .map(|class_id| {
            FailureScenario::new(vec![FailureTerm {
                class_id,
                failure_count: 1,
            }])
            .map_err(|_| ContentPublicationError::InvalidInput)
        })
        .collect()
}

fn same_target_generation(
    current: StorageTargetProviderContext,
    opened: StorageTargetProviderContext,
) -> bool {
    current.mesh_id == opened.mesh_id
        && current.node_id == opened.node_id
        && current.target_id == opened.target_id
        && current.generation == opened.generation
        && current.usage_limit == opened.usage_limit
        && current.policy_revision == opened.policy_revision
}

fn active_targets(
    authority: &AuthoritativeRepository,
) -> Result<Vec<(StorageTargetProviderContext, HostId)>, ContentPublicationError> {
    let limit = PageLimit::new(PAGE_ITEMS).map_err(|_| ContentPublicationError::Unavailable)?;
    let mut cursor = None;
    let mut targets = Vec::new();
    loop {
        let page = authority
            .topology_targets(cursor.as_ref(), limit)
            .map_err(|_| ContentPublicationError::Unavailable)?;
        for target in page.items {
            let Some(context) = authority
                .storage_target_provider_context_by_target(target.target_id)
                .map_err(|_| ContentPublicationError::Unavailable)?
            else {
                continue;
            };
            if context.node_id != target.node_id
                || context.generation != target.generation
                || context.usage_limit != target.usage_limit
            {
                return Err(ContentPublicationError::Unavailable);
            }
            targets.push((context, target.host_id));
        }
        let Some(next) = page.next else {
            return Ok(targets);
        };
        cursor = Some(next);
    }
}

fn register_builtin_topology(
    topology: &mut Topology,
    hosts: &mut BTreeSet<HostId>,
    host: HostId,
    target: TargetId,
    machine_class: FaultGroupClassId,
    device_class: FaultGroupClassId,
) -> Result<(), ContentPublicationError> {
    topology
        .register_host(host)
        .map_err(|_| ContentPublicationError::InvalidInput)?;
    topology
        .register_target(target, host)
        .map_err(|_| ContentPublicationError::InvalidInput)?;
    if hosts.insert(host) {
        let group = derived_group(b"meshspan.fault-group.machine.v1\0", host.as_bytes())?;
        topology
            .register_fault_group(group, machine_class)
            .map_err(|_| ContentPublicationError::InvalidInput)?;
        topology
            .add_fault_group_member(group, FaultGroupMember::Host(host))
            .map_err(|_| ContentPublicationError::InvalidInput)?;
    }
    let group = derived_group(
        b"meshspan.fault-group.storage-device.v1\0",
        target.as_bytes(),
    )?;
    topology
        .register_fault_group(group, device_class)
        .map_err(|_| ContentPublicationError::InvalidInput)?;
    topology
        .add_fault_group_member(group, FaultGroupMember::Target(target))
        .map_err(|_| ContentPublicationError::InvalidInput)?;
    Ok(())
}

fn register_administrator_fault_groups(
    authority: &AuthoritativeRepository,
    topology: &mut Topology,
    active_hosts: &BTreeSet<HostId>,
) -> Result<(), ContentPublicationError> {
    let limit = PageLimit::new(PAGE_ITEMS).map_err(|_| ContentPublicationError::Unavailable)?;
    let mut cursor = None;
    loop {
        let page = authority
            .fault_groups(cursor.as_ref(), limit)
            .map_err(|_| ContentPublicationError::Unavailable)?;
        for group in page.items {
            topology
                .register_fault_group(group.group_id, group.class_id)
                .map_err(|_| ContentPublicationError::InvalidInput)?;
        }
        let Some(next) = page.next else { break };
        cursor = Some(next);
    }
    let mut cursor = None;
    loop {
        let page = authority
            .fault_group_memberships(cursor, limit)
            .map_err(|_| ContentPublicationError::Unavailable)?;
        for membership in page.items {
            if active_hosts.contains(&membership.host_id) {
                topology
                    .add_fault_group_member(
                        membership.group_id,
                        FaultGroupMember::Host(membership.host_id),
                    )
                    .map_err(|_| ContentPublicationError::InvalidInput)?;
            }
        }
        let Some(next) = page.next else { break };
        cursor = Some(next);
    }
    Ok(())
}

const fn planning_ceiling(limit: StorageUsageLimit) -> u64 {
    match limit {
        StorageUsageLimit::Bytes(bytes) => bytes,
        StorageUsageLimit::Percent(_) => PERCENT_CAPACITY_PLANNING_CEILING,
    }
}

fn derived_group(domain: &[u8], input: [u8; 16]) -> Result<FaultGroupId, ContentPublicationError> {
    FaultGroupId::from_bytes(derived_identifier(domain, &input))
        .map_err(|_| ContentPublicationError::InvalidInput)
}

fn derived_identifier(domain: &[u8], input: &[u8]) -> [u8; 16] {
    let mut digest = blake3::Hasher::new();
    digest.update(domain);
    digest.update(input);
    let mut identifier = [0; 16];
    identifier.copy_from_slice(&digest.finalize().as_bytes()[..16]);
    uuid_v8(identifier)
}
