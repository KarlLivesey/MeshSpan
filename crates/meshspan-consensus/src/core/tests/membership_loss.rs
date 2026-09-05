// SPDX-License-Identifier: GPL-2.0-only

//! Reconfiguration must recover a lost commit notification without weakening term fencing.

use super::{
    BTreeMap, ConsensusCore, CoreConfig, CoreEffect, CoreInput, CoreMessage, Error, LogPosition,
    MemberIncarnations, PartitionId, Role, membership_admission_fixture, message, node, operation,
    persist_only_effect, vote_for_plan,
};
use crate::{
    DurableCoreState, MEMBERSHIP_COMMAND_VERSION, MembershipTransitionCommand, ProposalId,
};

#[test]
fn historical_reply_cannot_acknowledge_new_writes_or_reads() -> Result<(), Box<dyn Error>> {
    let (mut source, follower) = recovery_pair(1)?;
    persist_only_effect(
        &mut source,
        super::proposal(2, b"later operation".to_vec())?,
    )?;
    let matched = source.peer_matched_index(node(2)?);
    let response = super::AppendResponse {
        term: 99,
        accepted: true,
        matched_index: u64::MAX,
        next_index_hint: u64::MAX,
        read_barrier_id: Some(super::ReadBarrierId(99)),
        membership_epoch: follower.membership_epoch(),
        plan_digest: follower.plan_digest(),
    };
    let replay = sent_to(
        source.step(message(2, CoreMessage::AppendResponse(response))?)?,
        2,
    )?;
    assert!(
        matches!(replay, CoreMessage::CommittedPrefix(prefix) if prefix.committed_index == 1 && prefix.entries.is_empty())
    );
    assert_eq!(source.commit_index(), 2);
    assert_eq!(source.current_term(), 1);
    assert_eq!(source.peer_matched_index(node(2)?), matched);
    Ok(())
}

#[test]
fn replay_never_overwrites_committed_content_or_accepts_an_unbounded_commit()
-> Result<(), Box<dyn Error>> {
    let (mut source, mut follower) = recovery_pair(1)?;
    let response = super::AppendResponse {
        term: 1,
        accepted: false,
        matched_index: 0,
        next_index_hint: 1,
        read_barrier_id: None,
        membership_epoch: follower.membership_epoch(),
        plan_digest: follower.plan_digest(),
    };
    let CoreMessage::CommittedPrefix(mut prefix) = sent_to(
        source.step(message(2, CoreMessage::AppendResponse(response))?)?,
        2,
    )?
    else {
        return Err("missing committed prefix".into());
    };
    prefix.committed_index = 2;
    assert_eq!(
        follower.step(message(1, CoreMessage::CommittedPrefix(prefix.clone()))?),
        Err(super::CoreError::InvalidInput)
    );
    assert_eq!(follower.commit_index(), 0);
    prefix.committed_index = 1;
    follower.step(message(1, CoreMessage::CommittedPrefix(prefix.clone()))?)?;
    assert_eq!(follower.commit_index(), 1);
    prefix.entries = vec![super::LogEntry::new(
        LogPosition { term: 1, index: 1 },
        operation(3)?,
        1,
        b"conflicting commit".to_vec(),
    )?];
    assert_eq!(
        follower.step(message(1, CoreMessage::CommittedPrefix(prefix))?),
        Err(super::CoreError::InvalidInput)
    );
    assert_eq!(follower.commit_index(), 1);
    Ok(())
}

#[test]
fn follower_recovers_after_losing_membership_commit_notification() -> Result<(), Box<dyn Error>> {
    let (mut source, mut follower) = recovery_pair(1)?;
    recover_from_heartbeat(&mut source, &mut follower)?;
    assert_eq!(follower.commit_index(), 1);
    assert_eq!(follower.current_term(), 1);
    assert_eq!(follower.leader_id(), None);
    Ok(())
}

#[test]
fn historical_replay_preserves_a_newer_follower_term() -> Result<(), Box<dyn Error>> {
    let (mut source, mut follower) = recovery_pair(7)?;
    recover_from_heartbeat(&mut source, &mut follower)?;
    assert_eq!(follower.commit_index(), 1);
    assert_eq!(follower.current_term(), 7);
    assert_eq!(source.current_term(), 1);
    assert_eq!(follower.leader_id(), None);
    Ok(())
}

#[test]
fn restarted_source_repairs_membership_before_an_election_can_complete()
-> Result<(), Box<dyn Error>> {
    let (source, mut follower) = recovery_pair(7)?;
    let mut source = restart(&source)?;
    assert_eq!(source.role(), Role::Follower);
    let election = persist_only_effect(&mut follower, CoreInput::ElectionTimeout)?;
    let request = sent_to(election, 1)?;
    let replay = sent_to(source.step(message(2, request)?)?, 2)?;
    assert!(matches!(&replay, CoreMessage::CommittedPrefix(prefix) if prefix.committed_index == 1));
    follower.step(message(1, replay)?)?;
    assert_eq!(follower.commit_index(), 1);
    assert_eq!(follower.current_term(), 8);
    assert_eq!(source.current_term(), 1);
    assert_eq!(source.role(), Role::Follower);
    assert_eq!(follower.role(), Role::Follower);
    Ok(())
}

fn recover_from_heartbeat(
    source: &mut ConsensusCore,
    follower: &mut ConsensusCore,
) -> Result<(), Box<dyn Error>> {
    let request = sent_to(source.step(CoreInput::Heartbeat)?, 2)?;
    let response = sent_to(follower.step(message(1, request)?)?, 1)?;
    let replay = sent_to(source.step(message(2, response)?)?, 2)?;
    assert!(matches!(&replay, CoreMessage::CommittedPrefix(prefix) if prefix.committed_index == 1));
    follower.step(message(1, replay)?)?;
    Ok(())
}

fn recovery_pair(follower_term: u64) -> Result<(ConsensusCore, ConsensusCore), Box<dyn Error>> {
    let mut fixture = membership_admission_fixture()?;
    let leader = &mut fixture.core;
    persist_only_effect(leader, CoreInput::ElectionTimeout)?;
    leader.step(vote_for_plan(2, 1, true, fixture.old.proof_digest())?)?;
    let transition = MembershipTransitionCommand::AdmitLearner {
        joint_plan: Box::new(fixture.joint.clone()),
        node_id: fixture.third,
        incarnation: 1,
    };
    persist_only_effect(
        leader,
        CoreInput::Propose {
            proposal_id: ProposalId(1),
            operation_id: operation(1)?,
            command_version: MEMBERSHIP_COMMAND_VERSION,
            command: transition.encode()?,
        },
    )?;
    assert_eq!(leader.commit_index(), 1);
    // The transition reached disk, but its commit notification was lost.
    let follower = ConsensusCore::restore(
        CoreConfig {
            partition_id: PartitionId::from_bytes([81; 16])?,
            local_node_id: fixture.second,
            local_incarnation: 1,
            plan: fixture.old.clone(),
            member_incarnations: MemberIncarnations::new(
                BTreeMap::from([(fixture.first, 1), (fixture.second, 1)]),
                &fixture.old,
            )?,
        },
        DurableCoreState {
            current_term: follower_term,
            voted_for: Some(fixture.first),
            log: vec![leader.last_log_entry().ok_or("missing transition")?.clone()],
            applied_index: 0,
        },
    )?;
    leader.step(CoreInput::AppliedThrough(1))?;
    persist_only_effect(
        leader,
        CoreInput::ActivateJointPlan {
            joint_plan: Box::new(fixture.joint),
            member_incarnations: fixture.expanded_incarnations,
            committed_position: LogPosition { term: 1, index: 1 },
        },
    )?;
    Ok((fixture.core, follower))
}

fn restart(source: &ConsensusCore) -> Result<ConsensusCore, Box<dyn Error>> {
    let active = source.active_plan().clone();
    Ok(ConsensusCore::restore_active(
        CoreConfig {
            partition_id: PartitionId::from_bytes([81; 16])?,
            local_node_id: node(1)?,
            local_incarnation: 1,
            plan: active.recovery_configuration_plan().clone(),
            member_incarnations: source.member_incarnations().clone(),
        },
        DurableCoreState {
            current_term: source.current_term(),
            voted_for: Some(node(1)?),
            log: vec![source.last_log_entry().ok_or("missing transition")?.clone()],
            applied_index: source.applied_index(),
        },
        active,
    )?)
}

fn sent_to(effects: Vec<CoreEffect>, recipient: u8) -> Result<CoreMessage, Box<dyn Error>> {
    let recipient = node(recipient)?;
    effects
        .into_iter()
        .find_map(|effect| match effect {
            CoreEffect::Send { to, message } if to == recipient => Some(message),
            _ => None,
        })
        .ok_or_else(|| "missing expected peer message".into())
}
