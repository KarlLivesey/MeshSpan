// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::JoinGrantId;
use meshspan_metadata::{ActivateNode, ConsumeJoinGrant, IssueJoinGrant, JoinRoles};
use sha2::{Digest, Sha256};

use super::*;

#[test]
fn metadata_replica_crosses_joint_and_stable_history_without_joining_consensus() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.apply_bootstrap()?;
    enrol_learner(&mut fixture, NodeId::from_bytes([19; 16])?)?;
    let membership = fixture
        .source
        .persistence()
        .partition_membership()?
        .ok_or("membership missing")?;
    let command = crate::membership::plan_next_transition(
        fixture.source.active_plan(),
        fixture.source.member_incarnations(),
        membership.active_voters(),
        membership.admitted_learners(),
        membership.retiring_members(),
        fixture.source.committed_entry(),
        |_| None,
    )?
    .ok_or("learner admission missing")?;
    let initial = fixture.replica.cursor()?;
    apply_transition(&mut fixture.source, command, 6)?;
    let page = fixture.source.metadata_replica_page(initial)?;
    assert_eq!(page.entries.len(), 6);
    assert_eq!(
        page.entries.last().ok_or("empty")?.command_version,
        MEMBERSHIP_COMMAND_VERSION
    );
    fixture
        .replica
        .apply(fixture.voter, 1, &page, UnixMicros::new(100))?;
    assert_eq!(fixture.replica.cursor()?.applied.index, 6);
    assert_eq!(&fixture.replica.plan, fixture.source.active_plan());
    fixture.reopen()?;
    let ActiveQuorumPlan::Joint(joint) = fixture.source.active_plan() else {
        return Err("joint phase missing".into());
    };
    let command = MembershipTransitionCommand::FinaliseStable {
        plan: Box::new(joint.new_plan().clone()),
    };
    let joint_cursor = fixture.replica.cursor()?;
    apply_transition(&mut fixture.source, command, 7)?;
    // The old phase cannot leak records beyond its own committed transition.
    assert_eq!(
        fixture.source.metadata_replica_page(initial)?.entries.len(),
        6
    );
    let page = fixture.source.metadata_replica_page(joint_cursor)?;
    assert_eq!(page.entries.len(), 1);
    fixture
        .replica
        .apply(fixture.voter, 1, &page, UnixMicros::new(101))?;
    fixture.reopen()?;
    assert_eq!(&fixture.replica.plan, fixture.source.active_plan());
    assert_eq!(fixture.replica.cursor()?.applied.index, 7);
    assert_eq!(
        fixture.replica.repository().current_revision()?,
        Revision::new(5)
    );
    assert!(!fixture.replica.plan.members().contains(&fixture.storage));
    assert_eq!(fixture.replica.durable.voted_for, None);
    Ok(())
}

fn enrol_learner(fixture: &mut Fixture, learner: NodeId) -> TestResult {
    let grant = JoinGrantId::from_bytes([18; 16])?;
    let roles = JoinRoles::new(JoinRoles::METADATA_ELIGIBLE)?;
    let certificate = vec![77; 64];
    let endpoint = "127.0.0.1:4401".to_owned();
    let commands = [
        crate::protected_volume_test_support::confirm_recovery(MeshId::from_bytes([5; 16])?),
        AuthoritativeCommand::IssueJoinGrant(IssueJoinGrant {
            join_grant_id: grant,
            secret_digest: [18; 32],
            allowed_roles: roles,
            maximum_uses: 1,
            expires_at: UnixMicros::new(500),
        }),
        AuthoritativeCommand::ConsumeJoinGrant(ConsumeJoinGrant {
            join_grant_id: grant,
            secret_digest: [18; 32],
            host_id: HostId::from_bytes([19; 16])?,
            new_host_name: Some(RecordName::new("Learner host")?),
            node_id: learner,
            node_name: RecordName::new("Learner")?,
            incarnation: 1,
            requested_roles: roles,
            wrapping_public_key: [19; 32],
            private_endpoint: endpoint.clone(),
            certificate_fingerprint: Sha256::digest(&certificate).into(),
            certificate_der: certificate,
            certificate_valid_until: UnixMicros::new(500),
        }),
        AuthoritativeCommand::ActivateNode(ActivateNode {
            node_id: learner,
            incarnation: 1,
            private_endpoint: endpoint,
            capability_digest: [20; 32],
        }),
    ];
    for (offset, command) in commands.into_iter().enumerate() {
        let entry = propose(&mut fixture.source, 2 + u8::try_from(offset)?, &command)?;
        fixture
            .source
            .apply_authoritative_committed(&entry, UnixMicros::new(50))?;
    }
    Ok(())
}

#[test]
fn metadata_replica_stops_passive_work_when_its_local_node_is_admitted() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.apply_bootstrap()?;
    let storage = fixture.storage;
    enrol_learner(&mut fixture, storage)?;
    let membership = fixture
        .source
        .persistence()
        .partition_membership()?
        .ok_or("membership missing")?;
    let command = crate::membership::plan_next_transition(
        fixture.source.active_plan(),
        fixture.source.member_incarnations(),
        membership.active_voters(),
        membership.admitted_learners(),
        membership.retiring_members(),
        fixture.source.committed_entry(),
        |_| None,
    )?
    .ok_or("learner admission missing")?;
    let cursor = fixture.replica.cursor()?;
    apply_transition(&mut fixture.source, command, 6)?;
    let page = fixture.source.metadata_replica_page(cursor)?;
    let admitted = fixture
        .replica
        .apply(fixture.voter, 1, &page, UnixMicros::new(100))?;
    assert_eq!(admitted.applied.index, 6);
    assert!(fixture.replica.plan.members().contains(&storage));
    assert!(matches!(
        fixture
            .replica
            .apply(fixture.voter, 1, &page, UnixMicros::new(101)),
        Err(MetadataReplicaError::LocalMember)
    ));
    assert_eq!(fixture.replica.durable.voted_for, None);
    assert!(
        matches!(fixture.reopen(), Err(error) if error.downcast_ref::<MetadataReplicaError>().is_some_and(|error| matches!(error, MetadataReplicaError::LocalMember)))
    );
    Ok(())
}

pub(super) fn apply_transition(
    source: &mut PartitionConsensusDriver<AuthoritativeRepository>,
    command: MembershipTransitionCommand,
    index: u64,
) -> TestResult {
    let effects = source.step(
        CoreInput::Propose {
            proposal_id: ProposalId(index),
            operation_id: OperationId::from_bytes([u8::try_from(index)? + 20; 16])?,
            command_version: MEMBERSHIP_COMMAND_VERSION,
            command: command.encode()?,
        },
        UnixMicros::new(70),
    )?;
    let entry = effects
        .into_iter()
        .find_map(|effect| match effect {
            DriverEffect::ApplyCommitted { mut entries } if entries.len() == 1 => entries.pop(),
            _ => None,
        })
        .ok_or("transition did not commit")?;
    source.step(
        CoreInput::AppliedThrough(entry.position.index),
        UnixMicros::new(71),
    )?;
    let next = match command {
        MembershipTransitionCommand::AdmitLearner { joint_plan, .. }
        | MembershipTransitionCommand::PromoteLearner { joint_plan, .. }
        | MembershipTransitionCommand::RemoveMember { joint_plan, .. } => {
            ActiveQuorumPlan::Joint(joint_plan)
        }
        MembershipTransitionCommand::FinaliseStable { plan } => ActiveQuorumPlan::Stable(plan),
    };
    let members = restore_member_incarnations(source.persistence(), &next)?;
    let input = match next {
        ActiveQuorumPlan::Joint(joint_plan) => CoreInput::ActivateJointPlan {
            joint_plan,
            member_incarnations: members,
            committed_position: entry.position,
        },
        ActiveQuorumPlan::Stable(plan) => CoreInput::ActivateStablePlan {
            plan,
            member_incarnations: members,
            committed_position: entry.position,
        },
    };
    source.step(input, UnixMicros::new(72))?;
    Ok(())
}
