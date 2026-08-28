// SPDX-License-Identifier: GPL-2.0-only

use std::collections::BTreeSet;
use std::error::Error;
use std::io;

use meshspan_domain::{NodeId, OperationId, PartitionId, QuorumPlanId};

use super::{
    AppendRequest, AppendResponse, ConsensusCore, CoreConfig, CoreEffect, CoreError, CoreInput,
    CoreMessage, LogEntry, LogPosition, MemberIncarnations, PersistenceId, ProposalId, Role,
    VoteResponse,
};
use crate::{compile_plan, flat_plan};

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
    persist_only_effect(&mut core, CoreInput::ElectionTimeout)?;
    core.step(vote(2, true)?)?;
    assert_eq!(core.role(), Role::Candidate);
    core.step(vote(3, true)?)?;
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
    message(
        from,
        CoreMessage::VoteResponse(VoteResponse {
            term,
            granted,
            membership_epoch: 1,
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
