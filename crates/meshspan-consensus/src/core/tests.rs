// SPDX-License-Identifier: GPL-2.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::io;

use meshspan_domain::{NodeId, OperationId, PartitionId, QuorumPlanId};

use super::{
    AppendRequest, AppendResponse, ConsensusCore, CoreConfig, CoreEffect, CoreError, CoreInput,
    CoreMessage, LogEntry, LogPosition, MemberIncarnations, PersistenceId, ProposalId,
    ReadBarrierId, Role, VoteResponse,
};
use crate::{JointQuorumPlan, compile_plan, flat_plan};

#[test]
fn campaign_is_durable_before_messages_or_role_change() -> Result<(), Box<dyn Error>> {
    let mut core = core(3)?;
    let effects = core.step(CoreInput::ElectionTimeout)?;
    let persistence_id = only_persistence_id(&effects)?;

    assert_eq!(core.role(), Role::Follower);
    assert_eq!(core.current_term(), 0);
    assert_eq!(
        core.step(CoreInput::ElectionTimeout),
        Err(CoreError::PersistencePending)
    );

    let effects = core.step(CoreInput::Persisted(persistence_id))?;
    assert_eq!(core.role(), Role::Candidate);
    assert_eq!(core.current_term(), 1);
    assert!(matches!(
        effects.first(),
        Some(CoreEffect::RoleChanged {
            role: Role::Candidate,
            term: 1
        })
    ));
    assert_eq!(
        effects
            .iter()
            .filter(|effect| matches!(effect, CoreEffect::Send { .. }))
            .count(),
        2
    );
    Ok(())
}

#[test]
fn single_voter_elects_and_commits_after_local_persistence() -> Result<(), Box<dyn Error>> {
    let mut core = core(1)?;
    persist_only_effect(&mut core, CoreInput::ElectionTimeout)?;
    assert_eq!(core.role(), Role::Leader);

    let effects = core.step(proposal(1, b"first".to_vec())?)?;
    let persistence_id = only_persistence_id(&effects)?;
    assert_eq!(core.commit_index(), 0);

    let effects = core.step(CoreInput::Persisted(persistence_id))?;
    assert_eq!(core.commit_index(), 1);
    assert!(effects.iter().any(|effect| matches!(
        effect,
        CoreEffect::ProposalAppended {
            proposal_id: ProposalId(1),
            position: LogPosition { term: 1, index: 1 }
        }
    )));
    assert!(effects.iter().any(|effect| matches!(
        effect,
        CoreEffect::CommitReady { entries } if entries.len() == 1
    )));
    Ok(())
}

#[test]
fn three_voters_require_peer_election_and_commit_acknowledgements() -> Result<(), Box<dyn Error>> {
    let mut core = elected_core(3, 2)?;
    assert_eq!(core.role(), Role::Leader);

    let persistence_id = only_persistence_id(&core.step(proposal(1, b"write".to_vec())?)?)?;
    let effects = core.step(CoreInput::Persisted(persistence_id))?;
    assert_eq!(core.commit_index(), 0);
    assert!(
        !effects
            .iter()
            .any(|effect| matches!(effect, CoreEffect::CommitReady { .. }))
    );

    let effects = core.step(message(
        2,
        CoreMessage::AppendResponse(AppendResponse {
            term: 1,
            accepted: true,
            matched_index: 1,
            next_index_hint: 2,
            read_barrier_id: None,
            membership_epoch: 1,
            plan_digest: fixture_plan_digest()?,
        }),
    )?)?;
    assert_eq!(core.commit_index(), 1);
    assert!(matches!(
        effects.as_slice(),
        [CoreEffect::CommitReady { entries }] if entries.len() == 1
    ));
    Ok(())
}

#[test]
fn four_voters_elect_with_three_and_commit_with_two() -> Result<(), Box<dyn Error>> {
    let mut core = core(4)?;
    let plan_digest = core.plan_digest();
    persist_only_effect(&mut core, CoreInput::ElectionTimeout)?;
    core.step(vote_for_plan(2, 1, true, plan_digest)?)?;
    assert_eq!(core.role(), Role::Candidate);
    core.step(vote_for_plan(3, 1, true, plan_digest)?)?;
    assert_eq!(core.role(), Role::Leader);

    let persistence_id = only_persistence_id(&core.step(proposal(1, b"write".to_vec())?)?)?;
    core.step(CoreInput::Persisted(persistence_id))?;
    assert_eq!(core.commit_index(), 0);
    core.step(message(
        4,
        CoreMessage::AppendResponse(AppendResponse {
            term: 1,
            accepted: true,
            matched_index: 1,
            next_index_hint: 2,
            read_barrier_id: None,
            membership_epoch: 1,
            plan_digest,
        }),
    )?)?;
    assert_eq!(core.commit_index(), 1);
    Ok(())
}

#[test]
fn stale_identity_epoch_and_persistence_fail_closed() -> Result<(), Box<dyn Error>> {
    let mut core = core(3)?;
    let persistence_id = only_persistence_id(&core.step(CoreInput::ElectionTimeout)?)?;
    assert_eq!(
        core.step(CoreInput::Persisted(PersistenceId(persistence_id.0 + 1))),
        Err(CoreError::StalePersistence)
    );
    core.step(CoreInput::Persisted(persistence_id))?;

    assert_eq!(
        core.step(CoreInput::Message {
            from: node(2)?,
            sender_incarnation: 2,
            message: CoreMessage::VoteResponse(VoteResponse {
                term: 1,
                granted: true,
                membership_epoch: 1,
                plan_digest: fixture_plan_digest()?,
            }),
        }),
        Err(CoreError::StaleMember)
    );
    assert_eq!(
        core.step(message(
            2,
            CoreMessage::VoteResponse(VoteResponse {
                term: 1,
                granted: true,
                membership_epoch: 2,
                plan_digest: fixture_plan_digest()?,
            }),
        )?),
        Err(CoreError::StaleMember)
    );
    Ok(())
}

#[test]
fn higher_term_is_persisted_before_step_down() -> Result<(), Box<dyn Error>> {
    let mut core = elected_core(3, 2)?;
    let effects = core.step(message(
        2,
        CoreMessage::AppendResponse(AppendResponse {
            term: 2,
            accepted: false,
            matched_index: 0,
            next_index_hint: 1,
            read_barrier_id: None,
            membership_epoch: 1,
            plan_digest: fixture_plan_digest()?,
        }),
    )?)?;
    let persistence_id = only_persistence_id(&effects)?;
    assert_eq!(core.role(), Role::Leader);
    assert_eq!(core.current_term(), 1);

    let effects = core.step(CoreInput::Persisted(persistence_id))?;
    assert_eq!(core.role(), Role::Follower);
    assert_eq!(core.current_term(), 2);
    assert!(matches!(
        effects.as_slice(),
        [CoreEffect::RoleChanged {
            role: Role::Follower,
            term: 2
        }]
    ));
    Ok(())
}

#[test]
fn read_barrier_requires_current_read_quorum_response() -> Result<(), Box<dyn Error>> {
    let mut core = elected_core(3, 2)?;
    let read_barrier_id = ReadBarrierId(41);
    let effects = core.step(CoreInput::BeginReadBarrier(read_barrier_id))?;
    assert_eq!(effects.len(), 2);
    assert!(effects.iter().all(|effect| matches!(
        effect,
        CoreEffect::Send {
            message: CoreMessage::AppendRequest(AppendRequest {
                read_barrier_id: Some(ReadBarrierId(41)),
                ..
            }),
            ..
        }
    )));

    let effects = core.step(message(
        2,
        CoreMessage::AppendResponse(AppendResponse {
            term: 1,
            accepted: false,
            matched_index: 0,
            next_index_hint: 1,
            read_barrier_id: Some(read_barrier_id),
            membership_epoch: 1,
            plan_digest: fixture_plan_digest()?,
        }),
    )?)?;
    assert!(matches!(
        effects.as_slice(),
        [CoreEffect::ReadBarrierReady {
            read_barrier_id: ReadBarrierId(41),
            applied_index: 0
        }]
    ));
    Ok(())
}

#[test]
fn read_barrier_waits_for_local_state_machine_application() -> Result<(), Box<dyn Error>> {
    let mut core = elected_core(3, 2)?;
    let persistence_id = only_persistence_id(&core.step(proposal(1, b"write".to_vec())?)?)?;
    core.step(CoreInput::Persisted(persistence_id))?;
    core.step(message(
        2,
        CoreMessage::AppendResponse(AppendResponse {
            term: 1,
            accepted: true,
            matched_index: 1,
            next_index_hint: 2,
            read_barrier_id: None,
            membership_epoch: 1,
            plan_digest: fixture_plan_digest()?,
        }),
    )?)?;

    let read_barrier_id = ReadBarrierId(42);
    core.step(CoreInput::BeginReadBarrier(read_barrier_id))?;
    let effects = core.step(message(
        2,
        CoreMessage::AppendResponse(AppendResponse {
            term: 1,
            accepted: true,
            matched_index: 1,
            next_index_hint: 2,
            read_barrier_id: Some(read_barrier_id),
            membership_epoch: 1,
            plan_digest: fixture_plan_digest()?,
        }),
    )?)?;
    assert!(effects.is_empty());

    let effects = core.step(CoreInput::AppliedThrough(1))?;
    assert!(matches!(
        effects.as_slice(),
        [CoreEffect::ReadBarrierReady {
            read_barrier_id: ReadBarrierId(42),
            applied_index: 1
        }]
    ));
    Ok(())
}

#[test]
fn conflicting_uncommitted_tail_is_replaced_but_committed_tail_is_protected()
-> Result<(), Box<dyn Error>> {
    let mut follower = elected_core(3, 2)?;
    let persistence_id = only_persistence_id(&follower.step(proposal(1, b"old".to_vec())?)?)?;
    follower.step(CoreInput::Persisted(persistence_id))?;
    assert_eq!(follower.commit_index(), 0);

    let replacement = LogEntry::new(
        LogPosition { term: 2, index: 1 },
        operation(2)?,
        1,
        b"new".to_vec(),
    )?;
    let persistence_id =
        only_persistence_id(&follower.step(append(2, 2, replacement.clone())?)?)?;
    let effects = follower.step(CoreInput::Persisted(persistence_id))?;
    assert_eq!(follower.role(), Role::Follower);
    assert!(matches!(
        effects.last(),
        Some(CoreEffect::Send {
            message: CoreMessage::AppendResponse(AppendResponse {
                accepted: true,
                matched_index: 1,
                ..
            }),
            ..
        })
    ));

    let persistence_id = only_persistence_id(&follower.step(CoreInput::ElectionTimeout)?)?;
    follower.step(CoreInput::Persisted(persistence_id))?;
    follower.step(vote_with_term(3, 3, true)?)?;
    let persistence_id = only_persistence_id(&follower.step(proposal(3, b"committed".to_vec())?)?)?;
    follower.step(CoreInput::Persisted(persistence_id))?;
    follower.step(message(
        2,
        CoreMessage::AppendResponse(AppendResponse {
            term: 3,
            accepted: true,
            matched_index: 2,
            next_index_hint: 3,
            read_barrier_id: None,
            membership_epoch: 1,
            plan_digest: fixture_plan_digest()?,
        }),
    )?)?;
    assert_eq!(follower.commit_index(), 2);

    let invalid = LogEntry::new(
        LogPosition { term: 4, index: 2 },
        operation(4)?,
        1,
        b"rewrite-committed".to_vec(),
    )?;
    assert_eq!(
        follower.step(append_after(
            2,
            4,
            replacement.position,
            replacement.entry_digest(),
            invalid,
        )?),
        Err(CoreError::InvalidInput)
    );
    Ok(())
}

#[test]
fn committed_membership_change_admits_a_learner_through_durable_joint_and_stable_plans()
-> Result<(), Box<dyn Error>> {
    let mut fixture = membership_admission_fixture()?;
    let core = &mut fixture.core;
    persist_only_effect(core, CoreInput::ElectionTimeout)?;
    core.step(vote_for_plan(2, 1, true, fixture.old.proof_digest())?)?;

    persist_only_effect(core, proposal(1, b"enter-joint".to_vec())?)?;
    let transition = LogPosition { term: 1, index: 1 };
    assert_eq!(
        core.step(CoreInput::ActivateJointPlan {
            joint_plan: Box::new(fixture.joint.clone()),
            member_incarnations: fixture.expanded_incarnations.clone(),
            committed_position: transition,
        }),
        Err(CoreError::InvalidInput)
    );
    core.step(CoreInput::AppliedThrough(1))?;

    let changed_incumbent = MemberIncarnations::for_members(
        BTreeMap::from([(fixture.first, 2), (fixture.second, 1), (fixture.third, 1)]),
        &fixture.joint.members(),
    )?;
    assert_eq!(
        core.step(CoreInput::ActivateJointPlan {
            joint_plan: Box::new(fixture.joint.clone()),
            member_incarnations: changed_incumbent,
            committed_position: transition,
        }),
        Err(CoreError::InvalidInput)
    );

    let effects = core.step(CoreInput::ActivateJointPlan {
        joint_plan: Box::new(fixture.joint.clone()),
        member_incarnations: fixture.expanded_incarnations.clone(),
        committed_position: transition,
    })?;
    let [CoreEffect::Persist { id, mutation }] = effects.as_slice() else {
        return Err(io::Error::other("joint activation was not a lone persistence effect").into());
    };
    assert_eq!(mutation.membership_epoch, Some(2));
    assert_eq!(core.membership_epoch(), 1);
    assert_eq!(core.plan_digest(), fixture.old.proof_digest());
    core.step(CoreInput::Persisted(*id))?;
    assert_eq!(core.membership_epoch(), 2);
    assert_eq!(core.plan_digest(), fixture.joint.proof_digest());

    assert_eq!(
        core.step(message(
            2,
            CoreMessage::VoteResponse(VoteResponse {
                term: 1,
                granted: true,
                membership_epoch: 1,
                plan_digest: fixture.old.proof_digest(),
            }),
        )?),
        Err(CoreError::StaleMember)
    );

    persist_only_effect(core, proposal(2, b"leave-joint".to_vec())?)?;
    assert_eq!(core.commit_index(), 2);
    core.step(CoreInput::AppliedThrough(2))?;

    let effects = core.step(CoreInput::ActivateStablePlan {
        plan: Box::new(fixture.new.clone()),
        member_incarnations: fixture.expanded_incarnations,
        committed_position: LogPosition { term: 1, index: 2 },
    })?;
    let [CoreEffect::Persist { id, mutation }] = effects.as_slice() else {
        return Err(io::Error::other("stable activation was not a lone persistence effect").into());
    };
    assert_eq!(mutation.membership_epoch, Some(2));
    assert_eq!(core.plan_digest(), fixture.joint.proof_digest());
    let effects = core.step(CoreInput::Persisted(*id))?;
    assert_eq!(core.membership_epoch(), 2);
    assert_eq!(core.plan_digest(), fixture.new.proof_digest());
    assert!(effects.iter().any(|effect| matches!(
        effect,
        CoreEffect::Send {
            to,
            message: CoreMessage::AppendRequest(AppendRequest {
                previous: LogPosition { term: 1, index: 1 },
                entries,
                ..
            }),
        } if *to == fixture.third
            && matches!(entries.as_slice(), [entry] if entry.position.index == 2)
    )));
    Ok(())
}

struct MembershipAdmissionFixture {
    core: ConsensusCore,
    old: crate::CompiledQuorumPlan,
    new: crate::CompiledQuorumPlan,
    joint: JointQuorumPlan,
    expanded_incarnations: MemberIncarnations,
    first: NodeId,
    second: NodeId,
    third: NodeId,
}

fn membership_admission_fixture() -> Result<MembershipAdmissionFixture, Box<dyn Error>> {
    let first = node(1)?;
    let second = node(2)?;
    let third = node(3)?;
    let old = compile_plan(flat_plan(
        QuorumPlanId::from_bytes([91; 16])?,
        1,
        BTreeSet::from([first, second]),
        BTreeSet::new(),
    )?)?;
    let new = compile_plan(flat_plan(
        QuorumPlanId::from_bytes([92; 16])?,
        2,
        BTreeSet::from([first, second]),
        BTreeSet::from([third]),
    )?)?;
    let joint = JointQuorumPlan::new(old.clone(), new.clone())?;
    let old_incarnations =
        MemberIncarnations::new(BTreeMap::from([(first, 1), (second, 1)]), &old)?;
    let expanded_incarnations =
        MemberIncarnations::new(BTreeMap::from([(first, 1), (second, 1), (third, 1)]), &new)?;
    let core = ConsensusCore::new(CoreConfig {
        partition_id: PartitionId::from_bytes([81; 16])?,
        local_node_id: first,
        local_incarnation: 1,
        plan: old.clone(),
        member_incarnations: old_incarnations,
    })?;
    Ok(MembershipAdmissionFixture {
        core,
        old,
        new,
        joint,
        expanded_incarnations,
        first,
        second,
        third,
    })
}

fn core(voter_count: u8) -> Result<ConsensusCore, Box<dyn Error>> {
    let voters = (1..=voter_count)
        .map(node)
        .collect::<Result<BTreeSet<_>, _>>()?;
    let plan = compile_plan(flat_plan(
        QuorumPlanId::from_bytes([90; 16])?,
        1,
        voters.clone(),
        BTreeSet::new(),
    )?)?;
    let member_incarnations = MemberIncarnations::new(
        voters.iter().copied().map(|member| (member, 1)).collect(),
        &plan,
    )?;
    Ok(ConsensusCore::new(CoreConfig {
        partition_id: PartitionId::from_bytes([80; 16])?,
        local_node_id: node(1)?,
        local_incarnation: 1,
        plan,
        member_incarnations,
    })?)
}

fn elected_core(voter_count: u8, peer: u8) -> Result<ConsensusCore, Box<dyn Error>> {
    let mut core = core(voter_count)?;
    persist_only_effect(&mut core, CoreInput::ElectionTimeout)?;
    core.step(vote(peer, true)?)?;
    Ok(core)
}

fn persist_only_effect(
    core: &mut ConsensusCore,
    input: CoreInput,
) -> Result<Vec<CoreEffect>, Box<dyn Error>> {
    let persistence_id = only_persistence_id(&core.step(input)?)?;
    Ok(core.step(CoreInput::Persisted(persistence_id))?)
}

fn only_persistence_id(effects: &[CoreEffect]) -> Result<PersistenceId, Box<dyn Error>> {
    let [CoreEffect::Persist { id, .. }] = effects else {
        return Err(io::Error::other("expected exactly one persistence effect").into());
    };
    Ok(*id)
}

fn proposal(id: u64, command: Vec<u8>) -> Result<CoreInput, Box<dyn Error>> {
    Ok(CoreInput::Propose {
        proposal_id: ProposalId(id),
        operation_id: operation(u8::try_from(id)?)?,
        command_version: 1,
        command,
    })
}

fn vote(from: u8, granted: bool) -> Result<CoreInput, Box<dyn Error>> {
    vote_with_term(from, 1, granted)
}

fn vote_with_term(from: u8, term: u64, granted: bool) -> Result<CoreInput, Box<dyn Error>> {
    vote_for_plan(from, term, granted, fixture_plan_digest()?)
}

fn vote_for_plan(
    from: u8,
    term: u64,
    granted: bool,
    plan_digest: [u8; 32],
) -> Result<CoreInput, Box<dyn Error>> {
    message(
        from,
        CoreMessage::VoteResponse(VoteResponse {
            term,
            granted,
            membership_epoch: 1,
            plan_digest,
        }),
    )
}

fn append(from: u8, term: u64, entry: LogEntry) -> Result<CoreInput, Box<dyn Error>> {
    append_after(from, term, LogPosition::GENESIS, [0; 32], entry)
}

fn append_after(
    from: u8,
    term: u64,
    previous: LogPosition,
    previous_digest: [u8; 32],
    entry: LogEntry,
) -> Result<CoreInput, Box<dyn Error>> {
    let sender = node(from)?;
    message(
        from,
        CoreMessage::AppendRequest(AppendRequest {
            term,
            leader: sender,
            leader_incarnation: 1,
            previous,
            previous_digest,
            entries: vec![entry],
            leader_commit_index: 0,
            read_barrier_id: None,
            membership_epoch: 1,
            plan_digest: fixture_plan_digest()?,
        }),
    )
}

fn message(from: u8, message: CoreMessage) -> Result<CoreInput, Box<dyn Error>> {
    Ok(CoreInput::Message {
        from: node(from)?,
        sender_incarnation: 1,
        message,
    })
}

fn node(value: u8) -> Result<NodeId, Box<dyn Error>> {
    Ok(NodeId::from_bytes([value; 16])?)
}

fn operation(value: u8) -> Result<OperationId, Box<dyn Error>> {
    Ok(OperationId::from_bytes([value; 16])?)
}

fn fixture_plan_digest() -> Result<[u8; 32], Box<dyn Error>> {
    Ok(core(3)?.plan_digest())
}
