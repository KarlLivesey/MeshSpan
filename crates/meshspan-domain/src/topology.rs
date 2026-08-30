// SPDX-License-Identifier: GPL-2.0-only

//! Fault topology and exact simultaneous-loss scenario proof.

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use crate::{FaultGroupClassId, FaultGroupId, HostId, TargetId};

const MAX_HOSTS: usize = 65_536;
const MAX_TARGETS: usize = 262_144;
const MAX_FAULT_GROUPS: usize = 16_384;
const MAX_SCENARIO_TERMS: usize = 16;
const MAX_SLICES_PER_STRIPE: usize = 24;

/// One resource directly affected when a fault group fails.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FaultGroupMember {
    /// A host failure affects every target registered on that host.
    Host(HostId),
    /// A target failure affects only that target.
    Target(TargetId),
}

#[derive(Clone, Debug)]
struct FaultGroup {
    class_id: FaultGroupClassId,
    members: BTreeSet<FaultGroupMember>,
}

/// Bounded authoritative topology used by the pure protection oracle.
#[derive(Clone, Debug, Default)]
pub struct Topology {
    hosts: BTreeSet<HostId>,
    target_hosts: BTreeMap<TargetId, HostId>,
    fault_groups: BTreeMap<FaultGroupId, FaultGroup>,
}

impl Topology {
    /// Registers a host identity.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectionError::CapacityExceeded`] at the explicit oracle bound.
    pub fn register_host(&mut self, host_id: HostId) -> Result<bool, ProtectionError> {
        if !self.hosts.contains(&host_id) && self.hosts.len() == MAX_HOSTS {
            return Err(ProtectionError::CapacityExceeded);
        }
        Ok(self.hosts.insert(host_id))
    }

    /// Registers one target on exactly one host.
    ///
    /// # Errors
    ///
    /// Rejects an unknown host, a conflicting existing target identity or excessive topology.
    pub fn register_target(
        &mut self,
        target_id: TargetId,
        host_id: HostId,
    ) -> Result<bool, ProtectionError> {
        if !self.hosts.contains(&host_id) {
            return Err(ProtectionError::UnknownHost);
        }
        match self.target_hosts.get(&target_id) {
            Some(existing) if *existing != host_id => Err(ProtectionError::IdentityConflict),
            Some(_) => Ok(false),
            None if self.target_hosts.len() == MAX_TARGETS => {
                Err(ProtectionError::CapacityExceeded)
            }
            None => {
                self.target_hosts.insert(target_id, host_id);
                Ok(true)
            }
        }
    }

    /// Registers a named fault group in exactly one class.
    ///
    /// # Errors
    ///
    /// Rejects a conflicting group identity or excessive topology.
    pub fn register_fault_group(
        &mut self,
        group_id: FaultGroupId,
        class_id: FaultGroupClassId,
    ) -> Result<bool, ProtectionError> {
        match self.fault_groups.get(&group_id) {
            Some(existing) if existing.class_id != class_id => {
                Err(ProtectionError::IdentityConflict)
            }
            Some(_) => Ok(false),
            None if self.fault_groups.len() == MAX_FAULT_GROUPS => {
                Err(ProtectionError::CapacityExceeded)
            }
            None => {
                self.fault_groups.insert(
                    group_id,
                    FaultGroup {
                        class_id,
                        members: BTreeSet::new(),
                    },
                );
                Ok(true)
            }
        }
    }

    /// Adds a host or target to an existing fault group.
    ///
    /// # Errors
    ///
    /// Rejects unknown groups and resources instead of accepting dangling authority claims.
    pub fn add_fault_group_member(
        &mut self,
        group_id: FaultGroupId,
        member: FaultGroupMember,
    ) -> Result<bool, ProtectionError> {
        self.require_member_exists(member)?;
        self.fault_groups
            .get_mut(&group_id)
            .ok_or(ProtectionError::UnknownFaultGroup)
            .map(|group| group.members.insert(member))
    }

    fn require_member_exists(&self, member: FaultGroupMember) -> Result<(), ProtectionError> {
        let exists = match member {
            FaultGroupMember::Host(host_id) => self.hosts.contains(&host_id),
            FaultGroupMember::Target(target_id) => self.target_hosts.contains_key(&target_id),
        };
        if exists {
            Ok(())
        } else {
            Err(ProtectionError::UnknownResource)
        }
    }

    fn groups_in_class(&self, class_id: FaultGroupClassId) -> Vec<FaultGroupId> {
        self.fault_groups
            .iter()
            .filter_map(|(group_id, group)| (group.class_id == class_id).then_some(*group_id))
            .collect()
    }

    fn targets_affected_by(&self, failed_groups: &[FaultGroupId]) -> BTreeSet<TargetId> {
        let mut targets = BTreeSet::new();
        for group_id in failed_groups {
            if let Some(group) = self.fault_groups.get(group_id) {
                for member in &group.members {
                    match member {
                        FaultGroupMember::Host(host_id) => {
                            targets.extend(self.target_hosts.iter().filter_map(
                                |(target_id, target_host)| {
                                    (target_host == host_id).then_some(*target_id)
                                },
                            ));
                        }
                        FaultGroupMember::Target(target_id) => {
                            targets.insert(*target_id);
                        }
                    }
                }
            }
        }
        targets
    }
}

/// One simultaneous term such as any two groups in the machine class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FailureTerm {
    /// Fault-group class from which failures are selected.
    pub class_id: FaultGroupClassId,
    /// Exact number of groups in this term that fail simultaneously.
    pub failure_count: u16,
}

/// One required protection promise whose terms occur simultaneously.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailureScenario {
    terms: Vec<FailureTerm>,
}

impl FailureScenario {
    /// Constructs a bounded scenario and rejects ambiguous duplicate classes.
    ///
    /// # Errors
    ///
    /// Rejects empty, zero-count, duplicate-class or excessively large scenarios.
    pub fn new(terms: Vec<FailureTerm>) -> Result<Self, ProtectionError> {
        if terms.is_empty() || terms.len() > MAX_SCENARIO_TERMS {
            return Err(ProtectionError::InvalidScenario);
        }
        let mut classes = BTreeSet::new();
        for term in &terms {
            if term.failure_count == 0 || !classes.insert(term.class_id) {
                return Err(ProtectionError::InvalidScenario);
            }
        }
        Ok(Self { terms })
    }

    /// Returns the simultaneous terms in their canonical input order.
    #[must_use]
    pub fn terms(&self) -> &[FailureTerm] {
        &self.terms
    }

    fn group_loss_sets(
        &self,
        topology: &Topology,
        maximum_sets: usize,
    ) -> Result<Vec<Vec<FaultGroupId>>, ProtectionError> {
        if maximum_sets == 0 {
            return Err(ProtectionError::InvalidProofBound);
        }
        let mut combined = vec![Vec::new()];
        for term in &self.terms {
            let groups = topology.groups_in_class(term.class_id);
            let count = usize::from(term.failure_count);
            if count > groups.len() {
                return Err(ProtectionError::InsufficientTopology);
            }
            let selections = combinations(&groups, count, maximum_sets)?;
            combined = cartesian_union(&combined, &selections, maximum_sets)?;
        }
        Ok(combined)
    }
}

/// Slice locations and the number of verified slices needed to decode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectionLayout {
    required_slices: u16,
    slice_targets: Vec<TargetId>,
}

impl ProtectionLayout {
    /// Constructs a bounded layout.
    ///
    /// # Errors
    ///
    /// Rejects an impossible decode threshold or more than 24 slices.
    pub fn new(
        required_slices: u16,
        slice_targets: Vec<TargetId>,
    ) -> Result<Self, ProtectionError> {
        if required_slices == 0
            || usize::from(required_slices) > slice_targets.len()
            || slice_targets.len() > MAX_SLICES_PER_STRIPE
        {
            return Err(ProtectionError::InvalidLayout);
        }
        Ok(Self {
            required_slices,
            slice_targets,
        })
    }
}

/// Exact result of enumerating a failure scenario against one layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectionProof {
    /// Whether every enumerated simultaneous loss remains decodable.
    pub survives: bool,
    /// Number of distinct loss sets evaluated.
    pub evaluated_loss_sets: usize,
    /// Fewest remaining valid slices in any evaluated loss set.
    pub minimum_remaining_slices: usize,
}

/// Proves one layout against every loss set described by the scenario.
///
/// # Errors
///
/// Rejects unknown target locations, impossible topology or an enumeration beyond the caller's
/// explicit work bound.
pub fn prove_protection(
    topology: &Topology,
    scenario: &FailureScenario,
    layout: &ProtectionLayout,
    maximum_loss_sets: usize,
) -> Result<ProtectionProof, ProtectionError> {
    if layout
        .slice_targets
        .iter()
        .any(|target| !topology.target_hosts.contains_key(target))
    {
        return Err(ProtectionError::UnknownResource);
    }
    let loss_sets = scenario.group_loss_sets(topology, maximum_loss_sets)?;
    let minimum_remaining_slices = loss_sets
        .iter()
        .map(|groups| {
            let lost_targets = topology.targets_affected_by(groups);
            layout
                .slice_targets
                .iter()
                .filter(|target| !lost_targets.contains(target))
                .count()
        })
        .min()
        .ok_or(ProtectionError::InvalidScenario)?;
    Ok(ProtectionProof {
        survives: minimum_remaining_slices >= usize::from(layout.required_slices),
        evaluated_loss_sets: loss_sets.len(),
        minimum_remaining_slices,
    })
}

fn combinations<T: Copy>(
    values: &[T],
    count: usize,
    maximum_sets: usize,
) -> Result<Vec<Vec<T>>, ProtectionError> {
    let mut output = Vec::new();
    build_combinations(values, count, 0, &mut Vec::new(), &mut output, maximum_sets)?;
    Ok(output)
}

fn build_combinations<T: Copy>(
    values: &[T],
    remaining: usize,
    start: usize,
    current: &mut Vec<T>,
    output: &mut Vec<Vec<T>>,
    maximum_sets: usize,
) -> Result<(), ProtectionError> {
    if remaining == 0 {
        if output.len() == maximum_sets {
            return Err(ProtectionError::ProofBoundExceeded);
        }
        output.push(current.clone());
        return Ok(());
    }
    let last_start = values.len() - remaining;
    for index in start..=last_start {
        current.push(values[index]);
        build_combinations(
            values,
            remaining - 1,
            index + 1,
            current,
            output,
            maximum_sets,
        )?;
        current.pop();
    }
    Ok(())
}

fn cartesian_union<T: Copy>(
    left: &[Vec<T>],
    right: &[Vec<T>],
    maximum_sets: usize,
) -> Result<Vec<Vec<T>>, ProtectionError> {
    let result_count = left
        .len()
        .checked_mul(right.len())
        .filter(|count| *count <= maximum_sets)
        .ok_or(ProtectionError::ProofBoundExceeded)?;
    let mut output = Vec::with_capacity(result_count);
    for first in left {
        for second in right {
            let mut joined = Vec::with_capacity(first.len() + second.len());
            joined.extend_from_slice(first);
            joined.extend_from_slice(second);
            output.push(joined);
        }
    }
    Ok(output)
}

/// Rejection of invalid topology, policy or bounded proof work.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProtectionError {
    /// A referenced host is not registered.
    #[error("host is unknown")]
    UnknownHost,
    /// A referenced fault group is not registered.
    #[error("fault group is unknown")]
    UnknownFaultGroup,
    /// A referenced host or target is not registered.
    #[error("fault-group resource is unknown")]
    UnknownResource,
    /// One stable identity was reused with different meaning.
    #[error("stable topology identity conflicts with existing state")]
    IdentityConflict,
    /// Topology exceeded an explicit deterministic-oracle bound.
    #[error("topology exceeds its bounded capacity")]
    CapacityExceeded,
    /// A scenario is empty, excessive, duplicate or contains a zero failure count.
    #[error("failure scenario is invalid")]
    InvalidScenario,
    /// Current topology has fewer groups than a required failure count.
    #[error("topology cannot prove the requested failure count")]
    InsufficientTopology,
    /// The caller supplied a zero proof-work bound.
    #[error("proof-work bound must be positive")]
    InvalidProofBound,
    /// Complete enumeration would exceed the caller's explicit work bound.
    #[error("failure proof exceeds its work bound")]
    ProofBoundExceeded,
    /// Slice count or decode threshold is invalid.
    #[error("protection layout is invalid")]
    InvalidLayout,
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "fixed non-nil topology identifiers are test fixtures"
    )]

    use super::{
        FailureScenario, FailureTerm, FaultGroupMember, ProtectionError, ProtectionLayout,
        ProtectionProof, Topology, prove_protection,
    };
    use crate::{FaultGroupClassId, FaultGroupId, HostId, TargetId};

    fn host(value: u8) -> HostId {
        HostId::from_bytes([value; 16]).expect("fixture host ID is non-nil")
    }

    fn target(value: u8) -> TargetId {
        TargetId::from_bytes([value; 16]).expect("fixture target ID is non-nil")
    }

    fn group(value: u8) -> FaultGroupId {
        FaultGroupId::from_bytes([value; 16]).expect("fixture group ID is non-nil")
    }

    fn class(value: u8) -> FaultGroupClassId {
        FaultGroupClassId::from_bytes([value; 16]).expect("fixture class ID is non-nil")
    }

    fn three_host_topology() -> Topology {
        let mut topology = Topology::default();
        for value in 1..=3 {
            topology.register_host(host(value)).expect("host fits");
            topology
                .register_target(target(value), host(value))
                .expect("target fits");
            topology
                .register_fault_group(group(value), class(9))
                .expect("group fits");
            topology
                .add_fault_group_member(group(value), FaultGroupMember::Host(host(value)))
                .expect("member exists");
        }
        topology
    }

    #[test]
    fn proves_and_refutes_exact_two_machine_loss() {
        let topology = three_host_topology();
        let scenario = FailureScenario::new(vec![FailureTerm {
            class_id: class(9),
            failure_count: 2,
        }])
        .expect("scenario is valid");
        let replicated = ProtectionLayout::new(1, vec![target(1), target(2), target(3)])
            .expect("layout is valid");
        let needs_two = ProtectionLayout::new(2, vec![target(1), target(2), target(3)])
            .expect("layout is valid");

        assert_eq!(
            prove_protection(&topology, &scenario, &replicated, 10),
            Ok(ProtectionProof {
                survives: true,
                evaluated_loss_sets: 3,
                minimum_remaining_slices: 1,
            })
        );
        assert_eq!(
            prove_protection(&topology, &scenario, &needs_two, 10),
            Ok(ProtectionProof {
                survives: false,
                evaluated_loss_sets: 3,
                minimum_remaining_slices: 1,
            })
        );
    }

    #[test]
    fn overlapping_groups_remove_the_union_without_double_counting() {
        let mut topology = three_host_topology();
        topology
            .register_fault_group(group(8), class(7))
            .expect("group fits");
        topology
            .add_fault_group_member(group(8), FaultGroupMember::Host(host(1)))
            .expect("host exists");
        topology
            .add_fault_group_member(group(8), FaultGroupMember::Target(target(2)))
            .expect("target exists");
        let scenario = FailureScenario::new(vec![FailureTerm {
            class_id: class(7),
            failure_count: 1,
        }])
        .expect("scenario is valid");
        let layout = ProtectionLayout::new(2, vec![target(1), target(2), target(3)])
            .expect("layout is valid");

        assert_eq!(
            prove_protection(&topology, &scenario, &layout, 10),
            Ok(ProtectionProof {
                survives: false,
                evaluated_loss_sets: 1,
                minimum_remaining_slices: 1,
            })
        );
    }

    #[test]
    fn one_machine_reports_device_protection_separately_from_machine_ha() {
        let mut topology = Topology::default();
        topology.register_host(host(1)).expect("host fits");
        topology
            .register_fault_group(group(1), class(1))
            .expect("machine group fits");
        topology
            .add_fault_group_member(group(1), FaultGroupMember::Host(host(1)))
            .expect("host exists");
        for value in 1..=3 {
            topology
                .register_target(target(value), host(1))
                .expect("target fits");
            topology
                .register_fault_group(group(value.saturating_add(10)), class(2))
                .expect("device group fits");
            topology
                .add_fault_group_member(
                    group(value.saturating_add(10)),
                    FaultGroupMember::Target(target(value)),
                )
                .expect("target exists");
        }
        let layout = ProtectionLayout::new(1, vec![target(1), target(2), target(3)])
            .expect("layout is valid");
        let device_loss = FailureScenario::new(vec![FailureTerm {
            class_id: class(2),
            failure_count: 2,
        }])
        .expect("device scenario is valid");
        let machine_loss = FailureScenario::new(vec![FailureTerm {
            class_id: class(1),
            failure_count: 1,
        }])
        .expect("machine scenario is valid");

        assert_eq!(
            prove_protection(&topology, &device_loss, &layout, 10),
            Ok(ProtectionProof {
                survives: true,
                evaluated_loss_sets: 3,
                minimum_remaining_slices: 1,
            })
        );
        assert_eq!(
            prove_protection(&topology, &machine_loss, &layout, 10),
            Ok(ProtectionProof {
                survives: false,
                evaluated_loss_sets: 1,
                minimum_remaining_slices: 0,
            })
        );
    }

    #[test]
    fn refuses_vacuous_or_unbounded_protection_claims() {
        let topology = three_host_topology();
        let scenario = FailureScenario::new(vec![FailureTerm {
            class_id: class(9),
            failure_count: 4,
        }])
        .expect("shape is valid even when current topology is insufficient");
        let layout = ProtectionLayout::new(1, vec![target(1)]).expect("layout is valid");

        assert_eq!(
            prove_protection(&topology, &scenario, &layout, 10),
            Err(ProtectionError::InsufficientTopology)
        );
        let combinatorial = FailureScenario::new(vec![FailureTerm {
            class_id: class(9),
            failure_count: 2,
        }])
        .expect("scenario is valid");
        assert_eq!(
            prove_protection(&topology, &combinatorial, &layout, 2),
            Err(ProtectionError::ProofBoundExceeded)
        );
    }
}
