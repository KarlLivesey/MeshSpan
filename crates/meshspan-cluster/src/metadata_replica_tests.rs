// SPDX-License-Identifier: GPL-2.0-only

use std::collections::{BTreeMap, BTreeSet};

use meshspan_consensus::{
    ConsensusCore, CoreConfig, CoreInput, MemberIncarnations, ProposalId, compile_plan, flat_plan,
};
use meshspan_domain::{
    AuditEventId, GroupId, HostId, MeshId, OperationId, PrincipalId, QuorumPlanId, Revision, RoleId,
};
use meshspan_metadata::{
    AuthoritativeCommand, BootstrapMesh, CommandContext, CreateGroup, PartitionDatabase,
    RecordName, encode_authoritative_command,
};

use super::*;
use crate::DriverEffect;

#[path = "metadata_replica_membership_tests.rs"]
mod membership;

#[path = "metadata_replica_network_tests.rs"]
mod network;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn term_confirmation_replicates_and_reopens_without_application_mutations() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.apply_bootstrap()?;
    let bootstrap_page = fixture
        .source
        .metadata_replica_page(fixture.replica.cursor()?)?;
    fixture
        .replica
        .apply(fixture.voter, 1, &bootstrap_page, UnixMicros::new(20))?;
    fixture.source.step(
        CoreInput::ConfirmTerm {
            proposal_id: ProposalId(2),
            operation_id: OperationId::from_bytes([91; 16])?,
        },
        UnixMicros::new(21),
    )?;
    let entry = fixture
        .source
        .last_log_entry()
        .ok_or("confirmation missing")?
        .clone();
    assert!(entry.is_term_confirmation());
    assert_eq!(entry.position.index, 2);
    assert!(
        fixture
            .replica
            .repository
            .apply_term_confirmation(&entry)
            .is_err(),
        "missing durable entry was accepted"
    );
    fixture
        .source
        .apply_term_confirmation(&entry, UnixMicros::new(22))?;
    let page = fixture
        .source
        .metadata_replica_page(fixture.replica.cursor()?)?;
    assert_eq!(page.entries, vec![entry.clone()]);
    let mut corrupted = page.clone();
    corrupted
        .entries
        .first_mut()
        .ok_or("entry missing")?
        .command
        .push(0);
    assert!(matches!(
        fixture
            .replica
            .apply(fixture.voter, 1, &corrupted, UnixMicros::new(23)),
        Err(MetadataReplicaError::InvalidPage)
    ));
    let applied = fixture
        .replica
        .apply(fixture.voter, 1, &page, UnixMicros::new(24))?;
    assert_eq!(applied.applied, LogPosition { term: 1, index: 2 });
    assert_eq!(applied.applied_digest, entry.entry_digest());
    fixture.reopen()?;
    assert_eq!(fixture.replica.cursor()?, applied);
    assert_eq!(
        fixture.replica.repository.current_revision()?,
        Revision::new(1)
    );
    assert!(
        fixture
            .replica
            .repository
            .resolve_operation(entry.operation_id)?
            .is_none()
    );
    assert_eq!(
        fixture
            .replica
            .apply(fixture.voter, 1, &page, UnixMicros::new(25))?,
        applied
    );
    Ok(())
}

struct Fixture {
    directory: tempfile::TempDir,
    source: PartitionConsensusDriver<AuthoritativeRepository>,
    replica: MetadataReplica,
    bootstrap: LogEntry,
    voter: NodeId,
    storage: NodeId,
    partition: PartitionId,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let voter = NodeId::from_bytes([1; 16])?;
        let storage = NodeId::from_bytes([2; 16])?;
        let partition = PartitionId::from_bytes([3; 16])?;
        let plan = compile_plan(flat_plan(
            QuorumPlanId::from_bytes([4; 16])?,
            1,
            BTreeSet::from([voter]),
            BTreeSet::new(),
        )?)?;
        let mut repositories = Vec::new();
        for file in ["source.sqlite3", "replica.sqlite3"] {
            let mut repository = AuthoritativeRepository::new(PartitionDatabase::open(
                &directory.path().join(file),
                partition,
                UnixMicros::new(1),
            )?);
            repository.initialise_consensus_quorum_plan(&plan, UnixMicros::new(1))?;
            repositories.push(repository);
        }
        let replica_repository = repositories.pop().ok_or("replica missing")?;
        let repository = repositories.pop().ok_or("source missing")?;
        let members = MemberIncarnations::new(BTreeMap::from([(voter, 1)]), &plan)?;
        let core = ConsensusCore::new(CoreConfig {
            partition_id: partition,
            local_node_id: voter,
            local_incarnation: 1,
            member_incarnations: members,
            plan,
        })?;
        let mut source = PartitionConsensusDriver::new(core, repository);
        source.step(CoreInput::ElectionTimeout, UnixMicros::new(2))?;
        let command = crate::protected_volume_test_support::protected_bootstrap(BootstrapMesh {
            mesh_id: MeshId::from_bytes([5; 16])?,
            mesh_name: RecordName::new("Replica mesh")?,
            administrator_id: PrincipalId::from_bytes([6; 16])?,
            administrator_name: RecordName::new("Administrator")?,
            administrator_role_id: RoleId::from_bytes([7; 16])?,
            host_id: HostId::from_bytes([8; 16])?,
            host_name: RecordName::new("Host")?,
            node_id: voter,
            node_name: RecordName::new("Voter")?,
            partition_name: RecordName::new("Root")?,
        })?;
        let bootstrap = propose(&mut source, 1, &command)?;
        let replica = MetadataReplica::new(replica_repository, storage)?;
        Ok(Self {
            directory,
            source,
            replica,
            bootstrap,
            voter,
            storage,
            partition,
        })
    }

    fn apply_bootstrap(&mut self) -> TestResult {
        self.source
            .apply_authoritative_committed(&self.bootstrap, UnixMicros::new(3))?;
        Ok(())
    }

    fn reopen(&mut self) -> TestResult {
        // Open the replacement handle before replacing the old owner; no database file is copied.
        let repository = AuthoritativeRepository::new(PartitionDatabase::open(
            &self.directory.path().join("replica.sqlite3"),
            self.partition,
            UnixMicros::new(50),
        )?);
        self.replica = MetadataReplica::new(repository, self.storage)?;
        Ok(())
    }
}

fn propose(
    source: &mut PartitionConsensusDriver<AuthoritativeRepository>,
    index: u8,
    command: &AuthoritativeCommand,
) -> Result<LogEntry, Box<dyn std::error::Error>> {
    let context = context(index)?;
    let effects = source.step(
        CoreInput::Propose {
            proposal_id: ProposalId(u64::from(index)),
            operation_id: context.operation_id,
            command_version: METADATA_COMMAND_VERSION,
            command: encode_authoritative_command(context, command)?,
        },
        UnixMicros::new(10 + i64::from(index)),
    )?;
    effects
        .into_iter()
        .find_map(|effect| match effect {
            DriverEffect::ApplyCommitted { mut entries } if entries.len() == 1 => entries.pop(),
            _ => None,
        })
        .ok_or_else(|| "proposal did not commit".into())
}

fn context(index: u8) -> Result<CommandContext, Box<dyn std::error::Error>> {
    Ok(CommandContext {
        operation_id: OperationId::from_bytes([index + 20; 16])?,
        actor_principal_id: PrincipalId::from_bytes([6; 16])?,
        audit_event_id: AuditEventId::from_bytes([index + 100; 16])?,
        occurred_at: UnixMicros::new(10 + i64::from(index)),
        expected_revision: Some(Revision::new(u64::from(index) - 1)),
    })
}

#[test]
fn metadata_replica_applies_only_exported_applied_history_and_reopens() -> TestResult {
    let mut fixture = Fixture::new()?;
    let initial = fixture.replica.cursor()?;
    assert_eq!(fixture.source.commit_index(), 1);
    assert_eq!(fixture.source.applied_index(), 0);
    assert!(
        fixture
            .source
            .metadata_replica_page(initial)?
            .entries
            .is_empty()
    );
    fixture.apply_bootstrap()?;
    let page = fixture.source.metadata_replica_page(initial)?;
    assert_eq!(page.entries, vec![fixture.bootstrap.clone()]);
    let applied = fixture
        .replica
        .apply(fixture.voter, 1, &page, UnixMicros::new(20))?;
    assert_eq!(applied.applied, LogPosition { term: 1, index: 1 });
    assert_eq!(
        fixture.replica.repository().current_revision()?,
        Revision::new(1)
    );
    let receipt = fixture
        .replica
        .repository()
        .resolve_operation(fixture.bootstrap.operation_id)?
        .ok_or("receipt missing")?;
    assert_eq!(receipt.committed_position.index, 1);
    assert_eq!(
        fixture
            .replica
            .apply(fixture.voter, 1, &page, UnixMicros::new(21))?,
        applied
    );
    fixture.reopen()?;
    assert_eq!(fixture.replica.cursor()?, applied);
    assert_eq!(
        fixture
            .replica
            .repository()
            .resolve_operation(fixture.bootstrap.operation_id)?,
        Some(receipt)
    );
    assert!(!fixture.replica.plan.members().contains(&fixture.storage));
    assert_eq!(fixture.replica.durable.voted_for, None);
    assert!(
        fixture
            .source
            .metadata_replica_page(applied)?
            .entries
            .is_empty()
    );
    Ok(())
}

#[test]
fn metadata_replica_refuses_to_replace_an_existing_voter_runtime() -> TestResult {
    let fixture = Fixture::new()?;
    assert!(matches!(
        MetadataReplica::new(fixture.source.into_persistence(), fixture.voter),
        Err(MetadataReplicaError::LocalMember),
    ));
    Ok(())
}

#[test]
fn metadata_replica_rejects_stale_sources_and_malformed_pages_without_writes() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.apply_bootstrap()?;
    let initial = fixture.replica.cursor()?;
    let page = fixture.source.metadata_replica_page(initial)?;
    for (node, incarnation) in [(fixture.storage, 1), (fixture.voter, 0), (fixture.voter, 2)] {
        assert!(matches!(
            fixture
                .replica
                .apply(node, incarnation, &page, UnixMicros::new(20)),
            Err(MetadataReplicaError::Source)
        ));
    }
    let mut malformed = Vec::new();
    let mut candidate = page.clone();
    candidate.after.partition_id = PartitionId::from_bytes([99; 16])?;
    malformed.push(candidate);
    let mut candidate = page.clone();
    candidate.after.applied_digest[0] ^= 1;
    malformed.push(candidate);
    let mut candidate = page.clone();
    candidate.after.membership_epoch += 1;
    malformed.push(candidate);
    let mut candidate = page.clone();
    candidate.after.plan_digest[0] ^= 1;
    malformed.push(candidate);
    let mut candidate = page.clone();
    candidate.entries[0].command_digest[0] ^= 1;
    malformed.push(candidate);
    let mut candidate = page.clone();
    candidate.entries[0].position.index = 2;
    malformed.push(candidate);
    let mut candidate = page.clone();
    candidate.entries[0].operation_id = OperationId::from_bytes([99; 16])?;
    malformed.push(candidate);
    let mut candidate = page.clone();
    candidate.entries = vec![candidate.entries[0].clone(); MAXIMUM_METADATA_REPLICA_ENTRIES + 1];
    malformed.push(candidate);
    for candidate in malformed {
        assert!(
            fixture
                .replica
                .apply(fixture.voter, 1, &candidate, UnixMicros::new(20))
                .is_err()
        );
        assert_eq!(fixture.replica.cursor()?, initial);
        assert_eq!(
            fixture.replica.repository().current_revision()?,
            Revision::ZERO
        );
    }
    let durable = fixture.replica.repository().load_consensus_state(1)?;
    assert!(durable.log.is_empty());
    assert_eq!(durable.current_term, 0);
    Ok(())
}

#[test]
fn metadata_replica_replaces_only_unapplied_tail_and_preserves_higher_term() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.apply_bootstrap()?;
    let tail = LogEntry::new(
        LogPosition { term: 9, index: 1 },
        OperationId::from_bytes([90; 16])?,
        99,
        vec![90],
    )?;
    fixture.replica.repository.persist_consensus_mutation(
        1,
        &DurableMutation {
            vote_state: Some((9, None)),
            truncate_from: None,
            append: vec![tail],
            membership_epoch: None,
            quorum_plan: None,
        },
        UnixMicros::new(5),
    )?;
    fixture.reopen()?;
    let page = fixture
        .source
        .metadata_replica_page(fixture.replica.cursor()?)?;
    fixture
        .replica
        .apply(fixture.voter, 1, &page, UnixMicros::new(20))?;
    fixture.reopen()?;
    assert_eq!(fixture.replica.durable.current_term, 9);
    assert_eq!(fixture.replica.durable.voted_for, None);
    assert_eq!(fixture.replica.durable.log, vec![fixture.bootstrap]);
    assert_eq!(fixture.replica.cursor()?.applied.index, 1);
    Ok(())
}

#[test]
fn metadata_replica_reopens_after_failed_application_without_trusting_persisted_tail() -> TestResult
{
    let mut fixture = Fixture::new()?;
    fixture.apply_bootstrap()?;
    let initial = fixture.replica.cursor()?;
    let good = fixture.source.metadata_replica_page(initial)?;
    let decoded = decode_authoritative_command(&fixture.bootstrap.command)?;
    let mut wrong_context = decoded.context;
    wrong_context.expected_revision = Some(Revision::new(99));
    let bad = MetadataReplicaPage {
        after: initial,
        entries: vec![LogEntry::new(
            fixture.bootstrap.position,
            wrong_context.operation_id,
            METADATA_COMMAND_VERSION,
            encode_authoritative_command(wrong_context, &decoded.command)?,
        )?],
    };
    assert!(matches!(
        fixture
            .replica
            .apply(fixture.voter, 1, &bad, UnixMicros::new(20)),
        Err(MetadataReplicaError::Repository(_))
    ));
    assert!(matches!(
        fixture.replica.cursor(),
        Err(MetadataReplicaError::ReloadRequired)
    ));
    fixture.reopen()?;
    assert_eq!(fixture.replica.cursor()?, initial);
    assert_eq!(
        fixture.replica.repository().current_revision()?,
        Revision::ZERO
    );
    fixture
        .replica
        .apply(fixture.voter, 1, &good, UnixMicros::new(21))?;
    assert_eq!(fixture.replica.cursor()?.applied.index, 1);
    Ok(())
}

#[test]
fn metadata_replica_pages_are_bounded_and_follow_exact_continuations() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.apply_bootstrap()?;
    for index in 2..=66_u8 {
        let command = AuthoritativeCommand::CreateGroup(CreateGroup {
            group_id: GroupId::from_bytes([index + 80; 16])?,
            name: RecordName::new(&format!("Group {index}"))?,
            activation_policy_id: None,
        });
        let entry = propose(&mut fixture.source, index, &command)?;
        fixture
            .source
            .apply_authoritative_committed(&entry, UnixMicros::new(100))?;
    }
    let page = fixture
        .source
        .metadata_replica_page(fixture.replica.cursor()?)?;
    assert_eq!(page.entries.len(), 64);
    let cursor = fixture
        .replica
        .apply(fixture.voter, 1, &page, UnixMicros::new(200))?;
    assert_eq!(cursor.applied.index, 64);
    let page = fixture.source.metadata_replica_page(cursor)?;
    assert_eq!(page.entries.len(), 2);
    fixture
        .replica
        .apply(fixture.voter, 1, &page, UnixMicros::new(201))?;
    fixture.reopen()?;
    assert_eq!(fixture.replica.cursor()?.applied.index, 66);
    assert_eq!(
        fixture.replica.repository().current_revision()?,
        Revision::new(66)
    );
    Ok(())
}

#[tokio::test]
async fn metadata_replica_reads_through_the_bounded_live_authority_owner() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.apply_bootstrap()?;
    let cursor = fixture.replica.cursor()?;
    let (authority, worker) = crate::spawn_metadata_authority(
        fixture.source,
        std::sync::Arc::new(|_, _| {}),
        crate::MetadataAuthorityConfig::default(),
    )?;
    let result = authority.replica_page(cursor).await;
    authority.shutdown().await?;
    worker.await??;
    let page = result?;
    assert_eq!(page.entries, vec![fixture.bootstrap]);
    fixture
        .replica
        .apply(fixture.voter, 1, &page, UnixMicros::new(20))?;
    assert_eq!(fixture.replica.cursor()?.applied.index, 1);
    assert!(matches!(
        authority.replica_page(cursor).await,
        Err(MetadataReplicaError::Unavailable)
    ));
    Ok(())
}
