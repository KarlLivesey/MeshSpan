// SPDX-License-Identifier: GPL-2.0-only

//! Two-authority route handoff proof over independent consensus cores and SQLite files.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use ed25519_dalek::{Signer, SigningKey};
use meshspan_consensus::{
    ConsensusCore, CoreConfig, CoreInput, MemberIncarnations, ProposalId, Role, compile_plan,
    flat_plan,
};
use meshspan_domain::{
    AuditEventId, DelegatedMetadataScope, DelegationAdmission, GroupId, HandoffEvidence, HostId,
    MeshId, MetadataKeyRange, MetadataOperationFamily, NodeId, OperationId, PartitionId,
    PrincipalId, QuorumPlanId, Revision, RoleId, RootDelegatedRoute, ScopeId, ScopeRoute,
    UnixMicros,
};
use meshspan_metadata::{
    ActivateScopeHandoff, AuthoritativeCommand, AuthoritativeRepository, BeginScopeHandoff,
    BootstrapMesh, CommandContext, CreateGroup, CreateMetadataPartition, CreateScopeRoute,
    FreezeScopeHandoff, InstallScopeRouteProjection, LogPosition as MetadataLogPosition,
    PartitionDatabase, RecordName, RegisterRoutingSigner, RouteAttestation,
};

use crate::{ClusterDriverError, DriverEffect, PartitionConsensusDriver, ScopedProposal};

const ROUTING_EPOCH_INITIAL: u64 = 1;
const ROUTING_EPOCH_HANDOFF: u64 = 2;

#[test]
fn independent_authorities_never_accept_the_same_scoped_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let source_id = partition(31)?;
    let destination_id = partition(32)?;
    let scope_id = ScopeId::from_bytes([33; 16])?;
    let mut source = Authority::new(
        &directory.path().join("source.sqlite"),
        source_id,
        QuorumPlanId::from_bytes([34; 16])?,
    )?;
    let mut destination = Authority::new(
        &directory.path().join("destination.sqlite"),
        destination_id,
        QuorumPlanId::from_bytes([35; 16])?,
    )?;

    initialise_catalogue(&mut source, source_id, destination_id, scope_id)?;
    initialise_catalogue(&mut destination, destination_id, source_id, scope_id)?;
    assert_exact_writers(
        &mut source,
        &mut destination,
        scope_id,
        ROUTING_EPOCH_INITIAL,
        1,
    )?;

    let preparing = preparing_route(scope_id, source_id, destination_id)?;
    source.commit(begin_handoff(scope_id, destination_id, &preparing)?)?;
    assert_exact_writers(&mut source, &mut destination, scope_id, 2, 1)?;
    destination.commit(install_projection(&preparing)?)?;
    assert_exact_writers(&mut source, &mut destination, scope_id, 2, 1)?;

    let evidence = handoff_evidence();
    let frozen = frozen_route(scope_id, source_id, destination_id, evidence)?;
    source.commit(freeze_handoff(scope_id, evidence, &frozen)?)?;
    assert_exact_writers(&mut source, &mut destination, scope_id, 2, 0)?;
    destination.commit(install_projection(&frozen)?)?;
    assert_exact_writers(&mut source, &mut destination, scope_id, 2, 0)?;

    let active_destination =
        active_destination_route(scope_id, source_id, destination_id, evidence)?;
    source.commit(activate_handoff(
        scope_id,
        destination_id,
        evidence,
        &active_destination,
    )?)?;
    assert_exact_writers(&mut source, &mut destination, scope_id, 2, 0)?;
    destination.commit(install_projection(&active_destination)?)?;
    assert_exact_writers(&mut source, &mut destination, scope_id, 2, 1)?;

    assert_eq!(source.route(scope_id)?.source_partition(), destination_id);
    assert_eq!(
        destination.route(scope_id)?.source_partition(),
        destination_id
    );
    Ok(())
}

struct Authority {
    driver: PartitionConsensusDriver<AuthoritativeRepository>,
    next_operation: u64,
}

impl Authority {
    fn new(
        file_path: &std::path::Path,
        partition_id: PartitionId,
        plan_id: QuorumPlanId,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let node_id = node_id()?;
        let plan = compile_plan(flat_plan(
            plan_id,
            1,
            BTreeSet::from([node_id]),
            BTreeSet::new(),
        )?)?;
        let database = PartitionDatabase::open(file_path, partition_id, UnixMicros::new(1))?;
        let mut repository = AuthoritativeRepository::new(database);
        repository.initialise_consensus_quorum_plan(&plan, UnixMicros::new(2))?;
        let incarnations = MemberIncarnations::new(BTreeMap::from([(node_id, 1)]), &plan)?;
        let core = ConsensusCore::new(CoreConfig {
            partition_id,
            local_node_id: node_id,
            local_incarnation: 1,
            plan,
            member_incarnations: incarnations,
        })?;
        let mut authority = Self {
            driver: PartitionConsensusDriver::new(core, repository),
            next_operation: 1,
        };
        let effects = authority
            .driver
            .step(CoreInput::ElectionTimeout, UnixMicros::new(3))?;
        authority.drain(effects, None)?;
        assert_eq!(authority.driver.role(), Role::Leader);
        Ok(authority)
    }

    fn commit(&mut self, command: AuthoritativeCommand) -> Result<(), Box<dyn std::error::Error>> {
        let context = self.context()?;
        let effects = self.driver.step(
            CoreInput::Propose {
                proposal_id: ProposalId(self.next_operation),
                operation_id: context.operation_id,
                command_version: 1,
                command: command.request_digest(context).to_vec(),
            },
            self.now(),
        )?;
        self.next_operation += 1;
        let applied = (context, command);
        self.drain(effects, Some(&applied))
    }

    fn probe_scope(
        &mut self,
        scope_id: ScopeId,
        routing_epoch: u64,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let context = self.context()?;
        let group = AuthoritativeCommand::CreateGroup(CreateGroup {
            group_id: GroupId::from_bytes(operation_bytes(self.next_operation, 70))?,
            name: RecordName::new(&format!("Scoped probe {}", self.next_operation))?,
            activation_policy_id: None,
        });
        let previous_tail = self.driver.last_log_entry().map(|entry| entry.position);
        let previous_commit = self.driver.commit_index();
        let result = self.driver.propose_scoped(
            ScopedProposal {
                scope_id,
                routing_epoch,
                proposal_id: ProposalId(self.next_operation),
                operation_id: context.operation_id,
                command_version: 1,
                command: group.request_digest(context).to_vec(),
            },
            self.now(),
        );
        match result {
            Ok(effects) => {
                self.next_operation += 1;
                let applied = (context, group);
                self.drain(effects, Some(&applied))?;
                Ok(true)
            }
            Err(ClusterDriverError::WriteFenced) => {
                assert_eq!(
                    self.driver.last_log_entry().map(|entry| entry.position),
                    previous_tail
                );
                assert_eq!(self.driver.commit_index(), previous_commit);
                self.next_operation += 1;
                Ok(false)
            }
            Err(error) => Err(error.into()),
        }
    }

    fn route(&self, scope_id: ScopeId) -> Result<ScopeRoute, Box<dyn std::error::Error>> {
        Ok(self.driver.persistence().scope_route(scope_id)?)
    }

    fn context(&self) -> Result<CommandContext, Box<dyn std::error::Error>> {
        Ok(CommandContext {
            operation_id: OperationId::from_bytes(operation_bytes(self.next_operation, 1))?,
            actor_principal_id: administrator_id()?,
            audit_event_id: AuditEventId::from_bytes(operation_bytes(self.next_operation, 2))?,
            occurred_at: self.now(),
            expected_revision: Some(self.driver.persistence().current_revision()?),
        })
    }

    fn now(&self) -> UnixMicros {
        UnixMicros::new(i64::try_from(self.next_operation).unwrap_or(i64::MAX) + 10)
    }

    fn drain(
        &mut self,
        effects: Vec<DriverEffect>,
        applied: Option<&(CommandContext, AuthoritativeCommand)>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut pending = VecDeque::from(effects);
        while let Some(effect) = pending.pop_front() {
            if let DriverEffect::ApplyCommitted { entries } = effect {
                let (context, command) = applied.ok_or("unexpected committed entry")?;
                for entry in entries {
                    self.driver.persistence_mut().apply_committed(
                        MetadataLogPosition {
                            term: entry.position.term,
                            index: entry.position.index,
                        },
                        *context,
                        command,
                    )?;
                    pending.extend(
                        self.driver
                            .step(CoreInput::AppliedThrough(entry.position.index), self.now())?,
                    );
                }
            }
        }
        Ok(())
    }
}

fn initialise_catalogue(
    authority: &mut Authority,
    local_partition: PartitionId,
    other_partition: PartitionId,
    scope_id: ScopeId,
) -> Result<(), Box<dyn std::error::Error>> {
    authority.commit(AuthoritativeCommand::BootstrapMesh(BootstrapMesh {
        mesh_id: MeshId::from_bytes([41; 16])?,
        mesh_name: RecordName::new("Handoff proof mesh")?,
        administrator_id: administrator_id()?,
        administrator_name: RecordName::new("Handoff administrator")?,
        administrator_role_id: RoleId::from_bytes([42; 16])?,
        host_id: HostId::from_bytes([43; 16])?,
        host_name: RecordName::new("Handoff host")?,
        node_id: node_id()?,
        node_name: RecordName::new("Handoff node")?,
        partition_name: RecordName::new(&format!("Partition {}", local_partition.as_bytes()[0]))?,
    }))?;
    authority.commit(AuthoritativeCommand::RegisterRoutingSigner(
        RegisterRoutingSigner {
            node_id: node_id()?,
            generation: 1,
            verifying_key: signing_key().verifying_key().to_bytes(),
        },
    ))?;
    authority.commit(AuthoritativeCommand::CreateMetadataPartition(
        CreateMetadataPartition {
            partition_id: other_partition,
            name: RecordName::new("Peer partition")?,
            partition_kind: 2,
        },
    ))?;
    let route = RootDelegatedRoute::new(
        partition(31)?,
        delegated_scope(scope_id)?,
        1,
        ROUTING_EPOCH_INITIAL,
    )?;
    if local_partition == partition(31)? {
        authority.commit(AuthoritativeCommand::CreateScopeRoute(CreateScopeRoute {
            root_partition_id: partition(31)?,
            scope: delegated_scope(scope_id)?,
            routing_epoch: ROUTING_EPOCH_INITIAL,
            attestation: attest(&route)?,
        }))?;
    } else {
        authority.commit(install_projection(&route)?)?;
    }
    Ok(())
}

fn assert_exact_writers(
    source: &mut Authority,
    destination: &mut Authority,
    scope_id: ScopeId,
    routing_epoch: u64,
    expected: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let accepted = usize::from(source.probe_scope(scope_id, routing_epoch)?)
        + usize::from(destination.probe_scope(scope_id, routing_epoch)?);
    assert_eq!(accepted, expected);
    assert!(accepted <= 1);
    Ok(())
}

fn begin_handoff(
    scope_id: ScopeId,
    destination: PartitionId,
    route: &RootDelegatedRoute,
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    Ok(AuthoritativeCommand::BeginScopeHandoff(BeginScopeHandoff {
        scope_id,
        destination_partition_id: destination,
        routing_epoch: ROUTING_EPOCH_HANDOFF,
        admission: delegation_admission()?,
        attestation: attest(route)?,
    }))
}

fn install_projection(
    route: &RootDelegatedRoute,
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    Ok(AuthoritativeCommand::InstallScopeRouteProjection(
        InstallScopeRouteProjection {
            route: *route,
            attestation: attest(route)?,
        },
    ))
}

fn freeze_handoff(
    scope_id: ScopeId,
    evidence: HandoffEvidence,
    route: &RootDelegatedRoute,
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    Ok(AuthoritativeCommand::FreezeScopeHandoff(
        FreezeScopeHandoff {
            scope_id,
            routing_epoch: ROUTING_EPOCH_HANDOFF,
            evidence,
            attestation: attest(route)?,
        },
    ))
}

fn activate_handoff(
    scope_id: ScopeId,
    destination: PartitionId,
    evidence: HandoffEvidence,
    route: &RootDelegatedRoute,
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    Ok(AuthoritativeCommand::ActivateScopeHandoff(
        ActivateScopeHandoff {
            scope_id,
            destination_partition_id: destination,
            routing_epoch: ROUTING_EPOCH_HANDOFF,
            evidence,
            attestation: attest(route)?,
        },
    ))
}

fn preparing_route(
    scope_id: ScopeId,
    source: PartitionId,
    destination: PartitionId,
) -> Result<RootDelegatedRoute, Box<dyn std::error::Error>> {
    let mut route = RootDelegatedRoute::new(source, delegated_scope(scope_id)?, 1, 1)?;
    route.begin_delegation(destination, 2, delegation_admission()?)?;
    Ok(route)
}

fn frozen_route(
    scope_id: ScopeId,
    source: PartitionId,
    destination: PartitionId,
    evidence: HandoffEvidence,
) -> Result<RootDelegatedRoute, Box<dyn std::error::Error>> {
    let mut route = preparing_route(scope_id, source, destination)?;
    route.freeze(2, evidence)?;
    Ok(route)
}

fn active_destination_route(
    scope_id: ScopeId,
    source: PartitionId,
    destination: PartitionId,
    evidence: HandoffEvidence,
) -> Result<RootDelegatedRoute, Box<dyn std::error::Error>> {
    let mut route = frozen_route(scope_id, source, destination, evidence)?;
    route.activate(destination, 2, evidence)?;
    Ok(route)
}

fn attest(
    route: &RootDelegatedRoute,
) -> Result<RouteAttestation, meshspan_domain::IdentifierError> {
    Ok(RouteAttestation {
        signer_node_id: node_id()?,
        signer_generation: 1,
        signature: signing_key().sign(&route.signing_payload()).to_bytes(),
    })
}

fn delegated_scope(
    scope_id: ScopeId,
) -> Result<DelegatedMetadataScope, meshspan_domain::DelegationError> {
    DelegatedMetadataScope::new(
        scope_id,
        MetadataOperationFamily::Namespace,
        MetadataKeyRange::All,
    )
}

fn delegation_admission() -> Result<DelegationAdmission, meshspan_domain::DelegationError> {
    DelegationAdmission::new(3, 3, [81; 32], [82; 32], UnixMicros::new(5))
}

const fn handoff_evidence() -> HandoffEvidence {
    HandoffEvidence {
        frozen_revision: Revision::new(500),
        snapshot_digest: [44; 32],
    }
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[45; 32])
}

fn operation_bytes(value: u64, namespace: u8) -> [u8; 16] {
    let mut bytes = [namespace; 16];
    bytes[8..].copy_from_slice(&value.to_be_bytes());
    bytes
}

fn administrator_id() -> Result<PrincipalId, meshspan_domain::IdentifierError> {
    PrincipalId::from_bytes([46; 16])
}

fn node_id() -> Result<NodeId, meshspan_domain::IdentifierError> {
    NodeId::from_bytes([47; 16])
}

fn partition(value: u8) -> Result<PartitionId, meshspan_domain::IdentifierError> {
    PartitionId::from_bytes([value; 16])
}
