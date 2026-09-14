// SPDX-License-Identifier: GPL-2.0-only

use super::*;

#[test]
fn retransmission_after_restore_proves_only_the_requested_prefix() -> Result<(), Box<dyn Error>> {
    let (_, entries) = uncommitted_tail()?;
    for persisted_term in [1, 2] {
        // Model a crash before term persistence, or after persistence but before the reply.
        // The durable log still contains the longer uncommitted tail in either case.
        let durable = DurableCoreState {
            current_term: persisted_term,
            voted_for: None,
            log: entries.clone(),
            applied_index: 0,
        };
        let mut restored = restore_core(3, 1, durable)?;
        let request = prefix_request(&entries, false)?;
        let mut effects = restored.step(message(2, CoreMessage::AppendRequest(request))?)?;
        if let [CoreEffect::Persist { id, .. }] = effects.as_slice() {
            assert_eq!(restored.commit_index(), 0);
            effects = restored.step(CoreInput::Persisted(*id))?;
        }
        assert_eq!(restored.commit_index(), 64);
        assert!(matches!(
            effects.last(),
            Some(CoreEffect::Send {
                message: CoreMessage::AppendResponse(AppendResponse {
                    matched_index: 64,
                    ..
                }),
                ..
            })
        ));
    }
    Ok(())
}

#[test]
fn append_proof_rejects_wrong_bytes_and_unrequested_read_contact() -> Result<(), Box<dyn Error>> {
    let mut leader = elected_core(3, 2)?;
    persist_only_effect(&mut leader, proposal(1, b"exact bytes".to_vec())?)?;
    let response = reply_to(&leader.step(CoreInput::Heartbeat)?, 2, true)?;
    for invalid in [
        AppendResponse {
            matched_index: 2,
            ..response
        },
        AppendResponse {
            matched_digest: [5; 32],
            ..response
        },
        AppendResponse {
            read_barrier_id: Some(ReadBarrierId(9)),
            ..response
        },
    ] {
        assert_eq!(
            leader.step(message(2, CoreMessage::AppendResponse(invalid))?),
            Err(CoreError::InvalidInput)
        );
        assert_eq!(leader.peer_matched_index(node(2)?), Some(0));
        assert_eq!(leader.commit_index(), 0);
    }
    // A rejected forgery does not consume the valid outstanding request.
    leader.step(message(2, CoreMessage::AppendResponse(response))?)?;
    assert_eq!(leader.commit_index(), 1);
    assert!(
        leader
            .step(message(2, CoreMessage::AppendResponse(response))?)?
            .is_empty()
    );
    Ok(())
}

#[test]
fn expired_append_probes_cannot_supply_match_or_read_evidence() -> Result<(), Box<dyn Error>> {
    let mut leader = elected_core(3, 2)?;
    persist_only_effect(&mut leader, proposal(1, b"exact bytes".to_vec())?)?;
    let effects = leader.step(CoreInput::BeginReadBarrier(ReadBarrierId(9)))?;
    let expired = reply_to(&effects, 2, true)?;
    for _ in 0..65 {
        leader.step(CoreInput::Heartbeat)?;
    }
    assert!(
        leader
            .step(message(2, CoreMessage::AppendResponse(expired))?)?
            .is_empty()
    );
    assert_eq!(leader.peer_matched_index(node(2)?), Some(0));
    acknowledge(&mut leader, 2)?;
    assert!(leader.step(CoreInput::AppliedThrough(1))?.is_empty());
    let effects = leader.step(CoreInput::BeginReadBarrier(ReadBarrierId(10)))?;
    let fresh = reply_to(&effects, 2, false)?;
    let effects = leader.step(message(2, CoreMessage::AppendResponse(fresh))?)?;
    assert!(matches!(
        effects.as_slice(),
        [CoreEffect::ReadBarrierReady {
            read_barrier_id: ReadBarrierId(10),
            applied_index: 1
        }]
    ));
    Ok(())
}

#[test]
fn delayed_append_responses_cannot_regress_peer_match() -> Result<(), Box<dyn Error>> {
    let (mut leader, _) = uncommitted_tail()?;
    let earlier = reply_to(&leader.step(CoreInput::Heartbeat)?, 2, true)?;
    let failure = reply_to(&leader.step(CoreInput::Heartbeat)?, 2, false)?;
    let first = reply_to(&leader.step(CoreInput::Heartbeat)?, 2, true)?;
    assert_eq!(earlier.matched_index, 64);
    let effects = leader.step(message(2, CoreMessage::AppendResponse(first))?)?;
    let newer = reply_to(&effects, 2, true)?;
    assert_eq!(newer.matched_index, 100);
    leader.step(message(2, CoreMessage::AppendResponse(newer))?)?;
    assert_eq!(leader.peer_matched_index(node(2)?), Some(100));
    leader.step(message(2, CoreMessage::AppendResponse(earlier))?)?;
    assert_eq!(leader.peer_matched_index(node(2)?), Some(100));
    let effects = leader.step(message(2, CoreMessage::AppendResponse(failure))?)?;
    assert_eq!(leader.peer_matched_index(node(2)?), Some(100));
    assert!(effects.is_empty());
    Ok(())
}

#[test]
fn equal_length_divergent_suffix_catches_up_after_bounded_backtracking()
-> Result<(), Box<dyn Error>> {
    let (mut leader, _) = uncommitted_tail()?;
    let mut follower = core_for_node(3, 2)?;
    persist_only_effect(&mut follower, CoreInput::ElectionTimeout)?;
    follower.step(vote(1, true)?)?;
    for index in 1..=100 {
        let bytes = if index <= 64 {
            b"local-tail".to_vec()
        } else {
            b"divergent-tail".to_vec()
        };
        persist_only_effect(&mut follower, proposal(index, bytes)?)?;
    }
    persist_only_effect(&mut leader, vote_with_term(2, 2, false)?)?;
    persist_only_effect(&mut leader, CoreInput::ElectionTimeout)?;
    let mut effects = leader.step(vote_with_term(2, 3, true)?)?;
    for _ in 0..40 {
        let request = effects
            .into_iter()
            .find_map(|effect| match effect {
                CoreEffect::Send {
                    to,
                    message: CoreMessage::AppendRequest(request),
                } if to == follower.local_node_id() => Some(request),
                _ => None,
            })
            .ok_or_else(|| io::Error::other("missing backtracking request"))?;
        let mut replies = follower.step(message(1, CoreMessage::AppendRequest(request))?)?;
        if let [CoreEffect::Persist { id, .. }] = replies.as_slice() {
            replies = follower.step(CoreInput::Persisted(*id))?;
        }
        effects = Vec::new();
        for reply in replies {
            if let CoreEffect::Send {
                message: CoreMessage::AppendResponse(response),
                ..
            } = reply
            {
                effects.extend(leader.step(message(2, CoreMessage::AppendResponse(response))?)?);
            }
        }
        if leader.peer_matched_index(node(2)?) == Some(100) {
            for index in 1..=100 {
                assert_eq!(leader.log_entry(index), follower.log_entry(index));
            }
            return Ok(());
        }
    }
    Err(io::Error::other("equal-length divergence did not converge in 40 probes").into())
}

#[test]
fn append_ack_and_commit_stop_at_this_requests_proven_prefix() -> Result<(), Box<dyn Error>> {
    for empty in [false, true] {
        let (mut follower, entries) = uncommitted_tail()?;
        let request = prefix_request(&entries, empty)?;
        let effects = persist_only_effect(
            &mut follower,
            message(2, CoreMessage::AppendRequest(request.clone()))?,
        )?;
        assert_eq!(follower.commit_index(), 64);
        assert!(
            matches!(effects.first(), Some(CoreEffect::CommitReady { entries }) if entries.len() == 64)
        );
        assert!(matches!(
            effects.last(),
            Some(CoreEffect::Send {
                message: CoreMessage::AppendResponse(AppendResponse {
                    accepted: true,
                    matched_index: 64,
                    ..
                }),
                ..
            })
        ));
        // A delayed heartbeat cannot retreat an already established commit or fail the contact.
        let delayed = AppendRequest {
            leader_commit_index: 0,
            ..request
        };
        let effects = follower.step(message(2, CoreMessage::AppendRequest(delayed))?)?;
        assert_eq!(follower.commit_index(), 64);
        assert!(
            !effects
                .iter()
                .any(|effect| matches!(effect, CoreEffect::CommitReady { .. }))
        );
    }
    Ok(())
}

#[test]
fn append_prefix_proof_cannot_escape_before_persistence() -> Result<(), Box<dyn Error>> {
    let (mut follower, entries) = uncommitted_tail()?;
    let request = prefix_request(&entries, false)?;
    let effects = follower.step(message(2, CoreMessage::AppendRequest(request))?)?;
    let id = only_persistence_id(&effects)?;
    assert_eq!(follower.commit_index(), 0);
    assert_eq!(follower.current_term(), 1);
    let effects = follower.step(CoreInput::Persisted(id))?;
    assert_eq!(follower.commit_index(), 64);
    assert!(matches!(
        effects.last(),
        Some(CoreEffect::Send {
            message: CoreMessage::AppendResponse(AppendResponse {
                matched_index: 64,
                ..
            }),
            ..
        })
    ));
    Ok(())
}

fn uncommitted_tail() -> Result<(ConsensusCore, Vec<LogEntry>), Box<dyn Error>> {
    let mut follower = elected_core(3, 2)?;
    let mut entries = Vec::new();
    for index in 1..=100 {
        persist_only_effect(&mut follower, proposal(index, b"local-tail".to_vec())?)?;
        entries.push(
            follower
                .last_log_entry()
                .ok_or_else(|| io::Error::other("missing proposal"))?
                .clone(),
        );
    }
    assert_eq!(follower.commit_index(), 0);
    Ok((follower, entries))
}

fn prefix_request(entries: &[LogEntry], empty: bool) -> Result<AppendRequest, Box<dyn Error>> {
    let previous = &entries[63];
    Ok(AppendRequest {
        probe_id: AppendProbeId(1),
        term: 2,
        leader: node(2)?,
        leader_incarnation: 1,
        previous: if empty {
            previous.position
        } else {
            LogPosition::GENESIS
        },
        previous_digest: if empty {
            previous.entry_digest()
        } else {
            [0; 32]
        },
        entries: if empty {
            Vec::new()
        } else {
            entries[..64].to_vec()
        },
        leader_commit_index: 100,
        read_barrier_id: None,
        membership_epoch: 1,
        plan_digest: fixture_plan_digest()?,
    })
}
