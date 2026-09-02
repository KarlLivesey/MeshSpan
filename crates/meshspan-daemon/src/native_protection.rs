// SPDX-License-Identifier: GPL-2.0-only

//! Production protection snapshot derived from current replicated topology and local capacity.

use std::collections::BTreeSet;

use meshspan_contracts::{PlacementCandidate, ShardAcknowledgement};
use meshspan_domain::{
    FailureScenario, FailureTerm, FaultGroupClassId, FaultGroupId, FaultGroupMember, HostId,
    TargetId, Topology, VolumeId, machine_fault_class_id, storage_device_fault_class_id, uuid_v8,
};
use meshspan_filesystem::{
    ContentPublicationError, ProtectionConfiguration, ProtectionPolicySource,
};
use meshspan_metadata::{
    AuthoritativeRepository, PageLimit, StorageTargetProviderContext, StorageUsageLimit,
};

const PAGE_ITEMS: usize = 1_000;
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
    let revision = authority
        .current_revision()
        .map_err(|_| ContentPublicationError::Unavailable)?;
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
    let scenarios = authority
        .volume_protection_policy(volume_id)
        .map_err(|_| ContentPublicationError::Unavailable)?
        .map_or_else(
            || default_scenarios(machine_class, device_class),
            |policy| Ok(policy.scenarios),
        )?;
    let candidates = targets
        .iter()
        .map(|(context, _)| PlacementCandidate {
            target_id: context.target_id,
            target_generation: context.generation,
            writable_bytes: planning_ceiling(context.usage_limit),
            performance_weight: 100,
            acknowledgement: ShardAcknowledgement::Required,
        })
        .collect();
    ProtectionConfiguration::from_untrusted(topology, revision, revision, scenarios, candidates)
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
