// SPDX-License-Identifier: GPL-2.0-only

//! Deterministic capacity-aware placement with exact fault-scenario proofs.

use std::cmp::Reverse;
use std::collections::BTreeSet;

use meshspan_contracts::{
    BoundedBytes, BoundedItems, CodingLayout, ComponentConfiguration, ComponentLifecycle,
    ComponentObservation, ComponentTransition, ContractError, ContractKind, ContractLimits,
    ContractVersion, ImplementationDescriptor, PlacementCandidate, PlacementPlan, PlacementPolicy,
    PlacementRequest, VersionedPayload,
};
use meshspan_domain::{
    FailureScenario, LifecycleState, ProtectionLayout, ProtectionProof, Revision, TargetId,
    Topology, UnixMicros, prove_protection,
};

const CONTRACT_VERSIONS: &[ContractVersion] = &[ContractVersion::V1_0];
const MAXIMUM_CONTROL_BYTES: usize = 4_096;
const MAXIMUM_CANDIDATES: usize = 256;
const MAXIMUM_SLICES: usize = 24;
const MAXIMUM_SCENARIOS: usize = 16;
const MAXIMUM_PROOF_LOSS_SETS: usize = 100_000;
const EXACT_SEARCH_CANDIDATES: usize = 10;
const DEFAULT_DATA_SLICES: u16 = 4;

/// Built-in planner that treats independence as mandatory and capacity/performance as preference.
#[derive(Clone, Copy, Debug)]
pub struct FaultAwarePlacement {
    lifecycle: LifecycleState,
    prepared_revision: Option<Revision>,
    active_revision: Revision,
}

struct CandidateSelection {
    targets: Vec<TargetId>,
    proofs: Vec<ProtectionProof>,
}

struct GeometrySelection {
    layout: CodingLayout,
    targets: Vec<TargetId>,
    proofs: Vec<ProtectionProof>,
}

impl Default for FaultAwarePlacement {
    fn default() -> Self {
        Self {
            lifecycle: LifecycleState::Active,
            prepared_revision: None,
            active_revision: Revision::ZERO,
        }
    }
}

impl FaultAwarePlacement {
    /// Creates the built-in planner in its active default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn require_active(&self) -> Result<(), ContractError> {
        if self.lifecycle == LifecycleState::Active {
            Ok(())
        } else {
            Err(ContractError::Unavailable)
        }
    }
}

impl ComponentLifecycle for FaultAwarePlacement {
    fn describe(&self) -> ImplementationDescriptor {
        ImplementationDescriptor {
            implementation_id: "fault-aware-v1",
            contract: ContractKind::PlacementPolicy,
            versions: CONTRACT_VERSIONS,
            limits: ContractLimits {
                maximum_control_bytes: MAXIMUM_CONTROL_BYTES,
                maximum_items: MAXIMUM_CANDIDATES,
                maximum_concurrency: 1,
            },
        }
    }

    fn validate_configuration(
        &self,
        configuration: &ComponentConfiguration,
    ) -> Result<(), ContractError> {
        if configuration.schema_version == 1
            && configuration.desired_revision != Revision::ZERO
            && configuration.canonical_bytes.is_empty()
        {
            Ok(())
        } else {
            Err(ContractError::InvalidInput)
        }
    }

    fn prepare(
        &mut self,
        configuration: &ComponentConfiguration,
    ) -> Result<ComponentTransition, ContractError> {
        self.validate_configuration(configuration)?;
        if configuration.desired_revision == self.active_revision {
            return Ok(ComponentTransition::Active);
        }
        if self.lifecycle == LifecycleState::Retired {
            return Err(ContractError::Stale);
        }
        self.prepared_revision = Some(configuration.desired_revision);
        Ok(ComponentTransition::Ready)
    }

    fn activate(
        &mut self,
        desired_revision: Revision,
    ) -> Result<ComponentTransition, ContractError> {
        if desired_revision == self.active_revision && self.lifecycle == LifecycleState::Active {
            return Ok(ComponentTransition::Active);
        }
        if self.prepared_revision != Some(desired_revision)
            || self.lifecycle == LifecycleState::Retired
        {
            return Err(ContractError::Stale);
        }
        self.active_revision = desired_revision;
        self.prepared_revision = None;
        self.lifecycle = LifecycleState::Active;
        Ok(ComponentTransition::Active)
    }

    fn drain(&mut self, _deadline: UnixMicros) -> Result<ComponentTransition, ContractError> {
        if self.lifecycle == LifecycleState::Retired {
            return Err(ContractError::Stale);
        }
        self.lifecycle = LifecycleState::Draining;
        Ok(ComponentTransition::Ready)
    }

    fn retire(&mut self, desired_revision: Revision) -> Result<ComponentTransition, ContractError> {
        if desired_revision != self.active_revision || self.lifecycle != LifecycleState::Draining {
            return Err(ContractError::Stale);
        }
        self.lifecycle = LifecycleState::Retired;
        Ok(ComponentTransition::Active)
    }

    fn observe(&self, observed_at: UnixMicros) -> ComponentObservation {
        ComponentObservation {
            desired_revision: self.prepared_revision.unwrap_or(self.active_revision),
            lifecycle: self.lifecycle,
            observed_at,
        }
    }
}

impl PlacementPolicy for FaultAwarePlacement {
    fn plan_write(&self, request: PlacementRequest<'_>) -> Result<PlacementPlan, ContractError> {
        self.require_active()?;
        validate_request(request)?;
        let mut candidates = request.candidates.to_vec();
        candidates.sort_by_key(|candidate| {
            (
                Reverse(candidate.performance_weight),
                Reverse(candidate.writable_bytes),
                candidate.target_id,
            )
        });

        for data_slices in (1..=preferred_data_slices(request.logical_stripe_bytes)).rev() {
            let slice_bytes = slice_bytes(request.logical_stripe_bytes, data_slices)?;
            let eligible = candidates
                .iter()
                .copied()
                .filter(|candidate| candidate.writable_bytes >= u64::from(slice_bytes))
                .collect::<Vec<_>>();
            if let Some(selection) = plan_geometry(
                request.topology,
                request.scenarios,
                data_slices,
                slice_bytes,
                &eligible,
            )? {
                return build_plan(
                    request,
                    selection.layout,
                    selection.targets,
                    selection.proofs,
                );
            }
        }
        Err(ContractError::ResourceExhausted)
    }

    fn evaluate(
        &self,
        scenario: &FailureScenario,
        layout: &ProtectionLayout,
        topology: &Topology,
    ) -> Result<ProtectionProof, ContractError> {
        self.require_active()?;
        prove_protection(topology, scenario, layout, MAXIMUM_PROOF_LOSS_SETS)
            .map_err(|_| ContractError::InvalidInput)
    }
}

fn validate_request(request: PlacementRequest<'_>) -> Result<(), ContractError> {
    if request.context.contract_version != ContractVersion::V1_0
        || request.context.deadline.get() == 0
        || request.logical_stripe_bytes == 0
        || request.scenarios.is_empty()
        || request.scenarios.len() > MAXIMUM_SCENARIOS
        || request.candidates.is_empty()
        || request.candidates.len() > MAXIMUM_CANDIDATES
        || request.topology_revision == Revision::ZERO
        || request.capacity_revision == Revision::ZERO
    {
        return Err(ContractError::InvalidInput);
    }
    let mut targets = BTreeSet::new();
    if request.candidates.iter().any(|candidate| {
        candidate.target_generation == 0
            || candidate.writable_bytes == 0
            || candidate.performance_weight == 0
            || !targets.insert(candidate.target_id)
    }) {
        return Err(ContractError::InvalidInput);
    }
    Ok(())
}

const fn preferred_data_slices(logical_bytes: u32) -> u16 {
    if logical_bytes >= 1_048_576 {
        DEFAULT_DATA_SLICES
    } else if logical_bytes >= 262_144 {
        2
    } else {
        1
    }
}

fn slice_bytes(logical_bytes: u32, data_slices: u16) -> Result<u32, ContractError> {
    let unrounded = logical_bytes.div_ceil(u32::from(data_slices));
    unrounded
        .checked_add(unrounded % 2)
        .filter(|bytes| *bytes != 0)
        .ok_or(ContractError::InvalidInput)
}

fn plan_geometry(
    topology: &Topology,
    scenarios: &[FailureScenario],
    data_slices: u16,
    slice_bytes: u32,
    candidates: &[PlacementCandidate],
) -> Result<Option<GeometrySelection>, ContractError> {
    if candidates.len() < usize::from(data_slices) {
        return Ok(None);
    }
    let selection = if candidates.len() <= EXACT_SEARCH_CANDIDATES {
        exact_selection(topology, scenarios, data_slices, candidates)?
    } else {
        pruned_selection(topology, scenarios, data_slices, candidates)?
    };
    let Some(selection) = selection else {
        return Ok(None);
    };
    let recovery_slices = u16::try_from(selection.targets.len())
        .map_err(|_| ContractError::InternalContract)?
        .checked_sub(data_slices)
        .ok_or(ContractError::InternalContract)?;
    let layout = CodingLayout::new(data_slices, recovery_slices, slice_bytes)
        .map_err(|_| ContractError::InternalContract)?;
    Ok(Some(GeometrySelection {
        layout,
        targets: selection.targets,
        proofs: selection.proofs,
    }))
}

fn exact_selection(
    topology: &Topology,
    scenarios: &[FailureScenario],
    data_slices: u16,
    candidates: &[PlacementCandidate],
) -> Result<Option<CandidateSelection>, ContractError> {
    for count in usize::from(data_slices)..=candidates.len().min(MAXIMUM_SLICES) {
        let mut selected = Vec::with_capacity(count);
        if let Some(plan) = choose_exact(
            topology,
            scenarios,
            data_slices,
            candidates,
            count,
            0,
            &mut selected,
        )? {
            return Ok(Some(plan));
        }
    }
    Ok(None)
}

fn choose_exact(
    topology: &Topology,
    scenarios: &[FailureScenario],
    data_slices: u16,
    candidates: &[PlacementCandidate],
    remaining: usize,
    start: usize,
    selected: &mut Vec<TargetId>,
) -> Result<Option<CandidateSelection>, ContractError> {
    if remaining == 0 {
        return prove_all(topology, scenarios, data_slices, selected).map(|proofs| {
            proofs.map(|proofs| CandidateSelection {
                targets: selected.clone(),
                proofs,
            })
        });
    }
    let last_start = candidates
        .len()
        .checked_sub(remaining)
        .ok_or(ContractError::InternalContract)?;
    for index in start..=last_start {
        selected.push(candidates[index].target_id);
        if let Some(plan) = choose_exact(
            topology,
            scenarios,
            data_slices,
            candidates,
            remaining - 1,
            index + 1,
            selected,
        )? {
            return Ok(Some(plan));
        }
        selected.pop();
    }
    Ok(None)
}

fn pruned_selection(
    topology: &Topology,
    scenarios: &[FailureScenario],
    data_slices: u16,
    candidates: &[PlacementCandidate],
) -> Result<Option<CandidateSelection>, ContractError> {
    let mut targets = candidates
        .iter()
        .take(MAXIMUM_SLICES)
        .map(|candidate| candidate.target_id)
        .collect::<Vec<_>>();
    let Some(mut proofs) = prove_all(topology, scenarios, data_slices, &targets)? else {
        return Ok(None);
    };
    let mut index = targets.len();
    while index != 0 && targets.len() > usize::from(data_slices) {
        index -= 1;
        let removed = targets.remove(index);
        match prove_all(topology, scenarios, data_slices, &targets)? {
            Some(smaller) => proofs = smaller,
            None => targets.insert(index, removed),
        }
    }
    Ok(Some(CandidateSelection { targets, proofs }))
}

fn prove_all(
    topology: &Topology,
    scenarios: &[FailureScenario],
    data_slices: u16,
    targets: &[TargetId],
) -> Result<Option<Vec<ProtectionProof>>, ContractError> {
    let layout = ProtectionLayout::new(data_slices, targets.to_vec())
        .map_err(|_| ContractError::InvalidInput)?;
    let proofs = scenarios
        .iter()
        .map(|scenario| {
            prove_protection(topology, scenario, &layout, MAXIMUM_PROOF_LOSS_SETS)
                .map_err(|_| ContractError::InvalidInput)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(proofs.iter().all(|proof| proof.survives).then_some(proofs))
}

fn build_plan(
    request: PlacementRequest<'_>,
    coding_layout: CodingLayout,
    targets: Vec<TargetId>,
    proofs: Vec<ProtectionProof>,
) -> Result<PlacementPlan, ContractError> {
    let evidence = policy_evidence(request, coding_layout, &targets, &proofs)?;
    Ok(PlacementPlan {
        coding_layout,
        slice_targets: BoundedItems::new(targets, MAXIMUM_SLICES)
            .map_err(|_| ContractError::InternalContract)?,
        topology_revision: request.topology_revision,
        capacity_revision: request.capacity_revision,
        protection_proofs: BoundedItems::new(proofs, MAXIMUM_SCENARIOS)
            .map_err(|_| ContractError::InternalContract)?,
        policy_evidence: VersionedPayload {
            format_version: 1,
            bytes: BoundedBytes::copy_from(evidence.as_bytes(), 32)
                .map_err(|_| ContractError::InternalContract)?,
        },
    })
}

fn policy_evidence(
    request: PlacementRequest<'_>,
    layout: CodingLayout,
    targets: &[TargetId],
    proofs: &[ProtectionProof],
) -> Result<blake3::Hash, ContractError> {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.placement-policy-evidence.v1\0");
    digest.update(&request.topology_revision.get().to_be_bytes());
    digest.update(&request.capacity_revision.get().to_be_bytes());
    digest.update(&layout.data_slices().to_be_bytes());
    digest.update(&layout.recovery_slices().to_be_bytes());
    digest.update(&layout.slice_bytes().to_be_bytes());
    for target in targets {
        digest.update(&target.as_bytes());
    }
    for proof in proofs {
        digest.update(&[u8::from(proof.survives)]);
        digest.update(
            &u64::try_from(proof.evaluated_loss_sets)
                .map_err(|_| ContractError::InternalContract)?
                .to_be_bytes(),
        );
        digest.update(
            &u64::try_from(proof.minimum_remaining_slices)
                .map_err(|_| ContractError::InternalContract)?
                .to_be_bytes(),
        );
    }
    Ok(digest.finalize())
}

#[cfg(test)]
mod tests {
    use meshspan_contracts::{
        PlacementCandidate, PlacementPolicy, PlacementRequest, RequestContext,
    };
    use meshspan_domain::{
        FailureScenario, FailureTerm, FaultGroupClassId, FaultGroupId, FaultGroupMember, HostId,
        OperationId, Revision, TargetId, Topology, UnixMicros,
    };

    use super::FaultAwarePlacement;

    #[test]
    fn automatically_proves_two_machine_and_three_extra_device_failures()
    -> Result<(), Box<dyn std::error::Error>> {
        let (topology, candidates) = six_machine_topology()?;
        let scenario = FailureScenario::new(vec![
            FailureTerm {
                class_id: class(1)?,
                failure_count: 2,
            },
            FailureTerm {
                class_id: class(2)?,
                failure_count: 3,
            },
        ])?;
        let plan = FaultAwarePlacement::new().plan_write(request(
            &topology,
            &candidates,
            std::slice::from_ref(&scenario),
            4 * 1_024 * 1_024,
        )?)?;

        assert_eq!(plan.coding_layout.data_slices(), 4);
        assert!(plan.coding_layout.recovery_slices() >= 7);
        assert_eq!(plan.protection_proofs.len(), 1);
        assert!(plan.protection_proofs.as_slice()[0].survives);
        Ok(())
    }

    #[test]
    fn small_topology_selects_the_oracle_minimum_for_any_two_devices()
    -> Result<(), Box<dyn std::error::Error>> {
        let (topology, candidates) = independent_targets(6)?;
        let scenario = FailureScenario::new(vec![FailureTerm {
            class_id: class(2)?,
            failure_count: 2,
        }])?;
        let plan = FaultAwarePlacement::new().plan_write(request(
            &topology,
            &candidates,
            std::slice::from_ref(&scenario),
            512 * 1_024,
        )?)?;

        assert_eq!(plan.coding_layout.data_slices(), 2);
        assert_eq!(plan.coding_layout.recovery_slices(), 2);
        assert_eq!(plan.slice_targets.len(), 4);
        assert_eq!(
            plan.protection_proofs.as_slice()[0].minimum_remaining_slices,
            2
        );
        Ok(())
    }

    #[test]
    fn small_and_full_targets_do_not_manufacture_independence()
    -> Result<(), Box<dyn std::error::Error>> {
        let (topology, mut candidates) = independent_targets(4)?;
        candidates[0].writable_bytes = 1;
        let scenario = FailureScenario::new(vec![FailureTerm {
            class_id: class(2)?,
            failure_count: 2,
        }])?;
        let plan = FaultAwarePlacement::new().plan_write(request(
            &topology,
            &candidates,
            std::slice::from_ref(&scenario),
            512 * 1_024,
        )?)?;
        assert_eq!(plan.coding_layout.data_slices(), 1);
        assert_eq!(plan.coding_layout.recovery_slices(), 2);
        assert!(
            !plan
                .slice_targets
                .as_slice()
                .contains(&candidates[0].target_id)
        );
        assert!(plan.protection_proofs.as_slice()[0].survives);
        Ok(())
    }

    fn six_machine_topology()
    -> Result<(Topology, Vec<PlacementCandidate>), Box<dyn std::error::Error>> {
        let mut topology = Topology::default();
        let mut candidates = Vec::new();
        for machine in 1_u8..=6 {
            let host = host(machine)?;
            topology.register_host(host)?;
            let machine_group = group(machine)?;
            topology.register_fault_group(machine_group, class(1)?)?;
            topology.add_fault_group_member(machine_group, FaultGroupMember::Host(host))?;
            for device_offset in 0_u8..2 {
                let value = machine * 2 - device_offset;
                let target = target(value)?;
                topology.register_target(target, host)?;
                let device_group = group(value + 32)?;
                topology.register_fault_group(device_group, class(2)?)?;
                topology.add_fault_group_member(device_group, FaultGroupMember::Target(target))?;
                candidates.push(candidate(target));
            }
        }
        Ok((topology, candidates))
    }

    fn independent_targets(
        count: u8,
    ) -> Result<(Topology, Vec<PlacementCandidate>), Box<dyn std::error::Error>> {
        let mut topology = Topology::default();
        let mut candidates = Vec::new();
        for value in 1..=count {
            let host = host(value)?;
            let target = target(value)?;
            topology.register_host(host)?;
            topology.register_target(target, host)?;
            topology.register_fault_group(group(value)?, class(2)?)?;
            topology.add_fault_group_member(group(value)?, FaultGroupMember::Target(target))?;
            candidates.push(candidate(target));
        }
        Ok((topology, candidates))
    }

    fn request<'a>(
        topology: &'a Topology,
        candidates: &'a [PlacementCandidate],
        scenarios: &'a [FailureScenario],
        logical_stripe_bytes: u32,
    ) -> Result<PlacementRequest<'a>, Box<dyn std::error::Error>> {
        Ok(PlacementRequest {
            context: RequestContext {
                contract_version: meshspan_contracts::ContractVersion::V1_0,
                operation_id: OperationId::from_bytes([90; 16])?,
                deadline: UnixMicros::new(1),
                expected_revision: None,
            },
            logical_stripe_bytes,
            scenarios,
            topology,
            topology_revision: Revision::new(1),
            capacity_revision: Revision::new(1),
            candidates,
        })
    }

    const fn candidate(target_id: TargetId) -> PlacementCandidate {
        PlacementCandidate {
            target_id,
            target_generation: 1,
            writable_bytes: 8 * 1_024 * 1_024,
            performance_weight: 100,
        }
    }

    fn host(value: u8) -> Result<HostId, meshspan_domain::IdentifierError> {
        HostId::from_bytes([value; 16])
    }

    fn target(value: u8) -> Result<TargetId, meshspan_domain::IdentifierError> {
        TargetId::from_bytes([value; 16])
    }

    fn group(value: u8) -> Result<FaultGroupId, meshspan_domain::IdentifierError> {
        FaultGroupId::from_bytes([value; 16])
    }

    fn class(value: u8) -> Result<FaultGroupClassId, meshspan_domain::IdentifierError> {
        FaultGroupClassId::from_bytes([value; 16])
    }
}
