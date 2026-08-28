// SPDX-License-Identifier: GPL-2.0-only

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::error::Error;
use std::io;

use meshspan_domain::{NodeId, OperationId, PartitionId, QuorumPlanId};

use super::{
    ConsensusCore, CoreConfig, CoreEffect, CoreInput, CoreMessage, MemberIncarnations, ProposalId,
    Role,
};
use crate::{CompiledQuorumPlan, QuorumFamily, compile_plan, flat_plan};

#[test]
fn every_multi_way_partition_for_one_to_nine_voters_has_at_most_one_leader()
-> Result<(), Box<dyn Error>> {
    let mut partition_count = 0_u64;
    for voter_count in 1..=9 {
        let template = SimulationTemplate::new(voter_count)?;
        for_each_set_partition(voter_count, |components| {
            partition_count += 1;
            let mut simulation = template.simulation(components)?;
            let representatives = simulation.component_representatives();
            for representative in representatives {
                simulation.input(representative, CoreInput::ElectionTimeout)?;
                simulation.drain_network()?;
            }
            let leaders = simulation.leaders();
            let authoritative_components = simulation
                .component_sets()
                .into_iter()
                .filter(|members| template.plan.satisfies(QuorumFamily::Election, members))
                .count();
            if leaders.len() > 1 || leaders.len() != authoritative_components {
                return Err(io::Error::other(format!(
                    "partition {components:?} elected {leaders:?}, expected \
                     {authoritative_components}"
                ))
                .into());
            }
            if let Some(leader) = leaders.first().copied() {
                simulation.input(
                    leader,
                    CoreInput::Propose {
                        proposal_id: ProposalId(1),
                        operation_id: OperationId::from_bytes([70; 16])?,
                        command_version: 1,
                        command: b"partition-write".to_vec(),
                    },
                )?;
                simulation.drain_network()?;
                let leader_component = simulation.component_members(leader);
                let should_commit = template
                    .plan
                    .satisfies(QuorumFamily::Commit, &leader_component);
                if (simulation.commit_index(leader) == 1) != should_commit {
                    return Err(io::Error::other("commit result violated compiled W family").into());
                }
            }
            Ok(())
        })?;
    }
    assert_eq!(partition_count, 26_442);
    Ok(())
}

#[test]
fn healed_cluster_catches_up_then_re_elects_after_leader_loss() -> Result<(), Box<dyn Error>> {
    for voter_count in [3_u8, 5, 9] {
        let template = SimulationTemplate::new(voter_count)?;
        let components: Vec<u8> = (0..voter_count)
            .map(|offset| u8::from(offset > voter_count / 2))
            .collect();
        let mut simulation = template.simulation(&components)?;
        for representative in simulation.component_representatives() {
            simulation.input(representative, CoreInput::ElectionTimeout)?;
            simulation.drain_network()?;
        }
        let leader = only_node(&simulation.leaders())?;
        simulation.input(
            leader,
            CoreInput::Propose {
                proposal_id: ProposalId(1),
                operation_id: OperationId::from_bytes([71; 16])?,
                command_version: 1,
                command: b"surviving-write".to_vec(),
            },
        )?;
        simulation.drain_network()?;
        assert_eq!(simulation.commit_index(leader), 1);

        simulation.heal();
        simulation.input(leader, CoreInput::Heartbeat)?;
        simulation.drain_network()?;
        assert!(
            simulation
                .nodes
                .values()
                .all(|core| core.commit_index() == 1)
        );

        simulation.remove(leader);
        let replacement = simulation
            .nodes
            .keys()
            .next()
            .copied()
            .ok_or_else(|| io::Error::other("replacement voter is missing"))?;
        simulation.input(replacement, CoreInput::ElectionTimeout)?;
        simulation.drain_network()?;
        assert_eq!(only_node(&simulation.leaders())?, replacement);
        assert_eq!(simulation.commit_index(replacement), 1);
    }
    Ok(())
}

struct SimulationTemplate {
    voters: Vec<NodeId>,
    plan: CompiledQuorumPlan,
    incarnations: MemberIncarnations,
    partition_id: PartitionId,
}

impl SimulationTemplate {
    fn new(voter_count: u8) -> Result<Self, Box<dyn Error>> {
        let voters = (1..=voter_count).map(node).collect::<Result<Vec<_>, _>>()?;
        let voter_set = voters.iter().copied().collect();
        let plan = compile_plan(flat_plan(
            QuorumPlanId::from_bytes([90_u8.saturating_add(voter_count); 16])?,
            1,
            voter_set,
            BTreeSet::new(),
        )?)?;
        let incarnations = MemberIncarnations::new(
            voters.iter().copied().map(|voter| (voter, 1)).collect(),
            &plan,
        )?;
        Ok(Self {
            voters,
            plan,
            incarnations,
            partition_id: PartitionId::from_bytes([80; 16])?,
        })
    }

    fn simulation(&self, components: &[u8]) -> Result<Simulation, Box<dyn Error>> {
        if components.len() != self.voters.len() {
            return Err(io::Error::other("component fixture length mismatch").into());
        }
        let nodes = self
            .voters
            .iter()
            .copied()
            .map(|local_node_id| {
                Ok((
                    local_node_id,
                    ConsensusCore::new(CoreConfig {
                        partition_id: self.partition_id,
                        local_node_id,
                        local_incarnation: 1,
                        plan: self.plan.clone(),
                        member_incarnations: self.incarnations.clone(),
                    })?,
                ))
            })
            .collect::<Result<_, CoreErrorBox>>()?;
        Ok(Simulation {
            nodes,
            components: self
                .voters
                .iter()
                .copied()
                .zip(components.iter().copied())
                .collect(),
            messages: VecDeque::new(),
        })
    }
}

type CoreErrorBox = Box<dyn Error>;

struct Simulation {
    nodes: BTreeMap<NodeId, ConsensusCore>,
    components: BTreeMap<NodeId, u8>,
    messages: VecDeque<(NodeId, NodeId, CoreMessage)>,
}

impl Simulation {
    fn input(&mut self, node: NodeId, input: CoreInput) -> Result<(), Box<dyn Error>> {
        let effects = self
            .nodes
            .get_mut(&node)
            .ok_or_else(|| io::Error::other("simulation input target is missing"))?
            .step(input)?;
        self.process_effects(node, effects)
    }

    fn process_effects(
        &mut self,
        source: NodeId,
        effects: Vec<CoreEffect>,
    ) -> Result<(), Box<dyn Error>> {
        let mut pending: VecDeque<CoreEffect> = effects.into();
        while let Some(effect) = pending.pop_front() {
            match effect {
                CoreEffect::Persist { id, .. } => {
                    let resulting = self
                        .nodes
                        .get_mut(&source)
                        .ok_or_else(|| io::Error::other("persist source is missing"))?
                        .step(CoreInput::Persisted(id))?;
                    resulting
                        .into_iter()
                        .rev()
                        .for_each(|effect| pending.push_front(effect));
                }
                CoreEffect::Send { to, message } => {
                    self.messages.push_back((source, to, message));
                }
                CoreEffect::RoleChanged { .. }
                | CoreEffect::ProposalAppended { .. }
                | CoreEffect::CommitReady { .. }
                | CoreEffect::ReadBarrierReady { .. }
                | CoreEffect::Rejected { .. } => {}
            }
        }
        Ok(())
    }

    fn drain_network(&mut self) -> Result<(), Box<dyn Error>> {
        while let Some((from, to, message)) = self.messages.pop_front() {
            if !self.nodes.contains_key(&from)
                || !self.nodes.contains_key(&to)
                || self.components.get(&from) != self.components.get(&to)
            {
                continue;
            }
            self.input(
                to,
                CoreInput::Message {
                    from,
                    sender_incarnation: 1,
                    message,
                },
            )?;
        }
        Ok(())
    }

    fn leaders(&self) -> Vec<NodeId> {
        self.nodes
            .iter()
            .filter_map(|(node, core)| (core.role() == Role::Leader).then_some(*node))
            .collect()
    }

    fn component_representatives(&self) -> Vec<NodeId> {
        let mut seen = BTreeSet::new();
        self.components
            .iter()
            .filter_map(|(node, component)| seen.insert(*component).then_some(*node))
            .collect()
    }

    fn component_sets(&self) -> Vec<BTreeSet<NodeId>> {
        let mut groups: BTreeMap<u8, BTreeSet<NodeId>> = BTreeMap::new();
        for (node, component) in &self.components {
            groups.entry(*component).or_default().insert(*node);
        }
        groups.into_values().collect()
    }

    fn component_members(&self, member: NodeId) -> BTreeSet<NodeId> {
        let component = self.components.get(&member);
        self.components
            .iter()
            .filter_map(|(node, candidate)| (Some(candidate) == component).then_some(*node))
            .collect()
    }

    fn commit_index(&self, node: NodeId) -> u64 {
        self.nodes.get(&node).map_or(0, ConsensusCore::commit_index)
    }

    fn heal(&mut self) {
        self.components
            .values_mut()
            .for_each(|component| *component = 0);
    }

    fn remove(&mut self, node: NodeId) {
        self.nodes.remove(&node);
        self.components.remove(&node);
    }
}

fn for_each_set_partition(
    voter_count: u8,
    mut visit: impl FnMut(&[u8]) -> Result<(), Box<dyn Error>>,
) -> Result<(), Box<dyn Error>> {
    let mut components = vec![0; usize::from(voter_count)];
    enumerate_component(1, 0, &mut components, &mut visit)
}

fn enumerate_component(
    index: usize,
    maximum_component: u8,
    components: &mut [u8],
    visit: &mut impl FnMut(&[u8]) -> Result<(), Box<dyn Error>>,
) -> Result<(), Box<dyn Error>> {
    if index == components.len() {
        return visit(components);
    }
    for component in 0..=maximum_component.saturating_add(1) {
        components[index] = component;
        enumerate_component(
            index + 1,
            maximum_component.max(component),
            components,
            visit,
        )?;
    }
    Ok(())
}

fn only_node(nodes: &[NodeId]) -> Result<NodeId, Box<dyn Error>> {
    let [node] = nodes else {
        return Err(io::Error::other("expected exactly one leader").into());
    };
    Ok(*node)
}

fn node(value: u8) -> Result<NodeId, CoreErrorBox> {
    Ok(NodeId::from_bytes([value; 16])?)
}
