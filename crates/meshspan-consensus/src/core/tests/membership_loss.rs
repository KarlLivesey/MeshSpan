// SPDX-License-Identifier: GPL-2.0-only

//! Reconfiguration must not depend on delivery of the last old-plan heartbeat.

use super::{
    AppendRequest, BTreeMap, ConsensusCore, CoreConfig, CoreEffect, CoreInput, CoreMessage, Error,
    LogPosition, MemberIncarnations, PartitionId, membership_admission_fixture, message, node,
    persist_only_effect, proposal, vote_for_plan,
};
use crate::DurableCoreState;

#[test]
fn follower_recovers_after_losing_membership_commit_notification() -> Result<(), Box<dyn Error>> {
    let mut fixture = membership_admission_fixture()?;
    let leader = &mut fixture.core;
    persist_only_effect(leader, CoreInput::ElectionTimeout)?;
    leader.step(vote_for_plan(2, 1, true, fixture.old.proof_digest())?)?;
    persist_only_effect(leader, proposal(1, b"enter-joint".to_vec())?)?;
    assert_eq!(leader.commit_index(), 1);

    // The follower has durably appended the transition but has not learnt its commit.
    // This is also its legitimate state after a restart at that exact boundary.
    let mut follower = ConsensusCore::restore(
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
            current_term: 1,
            voted_for: Some(fixture.first),
            log: vec![leader.last_log_entry().ok_or("missing transition")?.clone()],
            applied_index: 0,
        },
    )?;
    leader.step(CoreInput::AppliedThrough(1))?;
    let lost_notification = append_to_second(leader.step(CoreInput::Heartbeat)?)?;
    assert_eq!(lost_notification.leader_commit_index, 1);
    assert_eq!(lost_notification.plan_digest, fixture.old.proof_digest());

    // Drop the old-plan notification, then deliver every subsequent heartbeat reliably.
    persist_only_effect(
        leader,
        CoreInput::ActivateJointPlan {
            joint_plan: Box::new(fixture.joint),
            member_incarnations: fixture.expanded_incarnations,
            committed_position: LogPosition { term: 1, index: 1 },
        },
    )?;
    let mut rejected = Vec::new();
    for _ in 0..3 {
        let request = append_to_second(leader.step(CoreInput::Heartbeat)?)?;
        if let Err(error) = follower.step(message(1, CoreMessage::AppendRequest(request))?) {
            rejected.push(error);
        }
    }
    let recovered_commit_index = follower.commit_index();
    // Control: delivering the packet we deliberately lost advances this exact follower.
    // Normal future heartbeats must recover without needing that vanished packet.
    follower.step(message(1, CoreMessage::AppendRequest(lost_notification))?)?;
    assert_eq!(follower.commit_index(), 1);
    assert_eq!(
        recovered_commit_index, 1,
        "reliable retransmission must recover the committed transition; rejections={rejected:?}"
    );
    Ok(())
}

fn append_to_second(effects: Vec<CoreEffect>) -> Result<AppendRequest, Box<dyn Error>> {
    let second = node(2)?;
    effects
        .into_iter()
        .find_map(|effect| match effect {
            CoreEffect::Send {
                to,
                message: CoreMessage::AppendRequest(request),
            } if to == second => Some(request),
            _ => None,
        })
        .ok_or_else(|| "missing append to follower".into())
}
