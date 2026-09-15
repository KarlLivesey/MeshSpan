// SPDX-License-Identifier: GPL-2.0-only

use super::*;

#[test]
fn replication_proof_survives_more_than_sixty_four_heartbeats() -> Result<(), Box<dyn Error>> {
    let mut leader = elected_core(3, 2)?;
    let bytes = vec![73; 70 * 1024];
    let sent = persist_only_effect(&mut leader, proposal(1, bytes.clone())?)?;
    let original = reply_to(&sent, 2, true)?;
    for _ in 0..70 {
        leader.step(CoreInput::Heartbeat)?;
    }
    leader.step(message(2, CoreMessage::AppendResponse(original))?)?;
    assert_eq!(leader.peer_matched_index(node(2)?), Some(1));
    assert_eq!(
        leader.commit_index(),
        1,
        "heartbeat churn lost the genuine data proof"
    );
    assert!(
        leader
            .log_entry(1)
            .is_some_and(|entry| entry.command.as_ref() == bytes)
    );
    Ok(())
}

#[test]
fn empty_contact_preserves_data_correlation_and_cannot_commit_undelivered_bytes()
-> Result<(), Box<dyn Error>> {
    let mut leader = elected_core(3, 2)?;
    let mut follower = core_for_node(3, 2)?;
    let bytes = vec![74; 70 * 1024];
    let sent = persist_only_effect(&mut leader, proposal(1, bytes.clone())?)?;
    let data = sent
        .iter()
        .find_map(|effect| match effect {
            CoreEffect::Send {
                to,
                message: CoreMessage::AppendRequest(request),
            } if *to == follower.local_node_id() => Some(request.clone()),
            _ => None,
        })
        .ok_or("missing original data request")?;
    for _ in 0..70 {
        let effects = leader.step(CoreInput::Heartbeat)?;
        let contact = contact_to(&effects, follower.local_node_id())?;
        assert_ne!(contact.probe_id, data.probe_id);
        assert_eq!(contact.previous, LogPosition::GENESIS);
        assert_eq!(contact.previous_digest, [0; 32]);
        assert_eq!(contact.read_barrier_id, None);
        let response = deliver(&mut follower, contact)?;
        assert!(response.accepted);
        assert_eq!(response.matched_index, 0);
        assert_eq!(response.matched_digest, [0; 32]);
        assert_eq!(
            leader.step(message(
                2,
                CoreMessage::AppendResponse(AppendResponse {
                    matched_index: 1,
                    matched_digest: data.entries[0].entry_digest(),
                    ..response
                })
            )?),
            Err(CoreError::InvalidInput)
        );
        leader.step(message(2, CoreMessage::AppendResponse(response))?)?;
        assert_eq!(leader.peer_matched_index(node(2)?), Some(0));
        assert_eq!(leader.commit_index(), 0);
        assert_eq!(follower.commit_index(), 0);
        assert!(follower.last_log_entry().is_none());
    }
    let response = deliver(&mut follower, data.clone())?;
    assert_eq!(response.probe_id, Some(data.probe_id));
    leader.step(message(2, CoreMessage::AppendResponse(response))?)?;
    assert_eq!(leader.commit_index(), 1);
    let effects = leader.step(CoreInput::Heartbeat)?;
    let contact = contact_to(&effects, follower.local_node_id())?;
    deliver(&mut follower, contact)?;
    assert_eq!(follower.commit_index(), 1);
    for core in [&mut leader, &mut follower] {
        core.step(CoreInput::AppliedThrough(1))?;
        assert_eq!(core.applied_index(), 1);
        assert!(
            core.log_entry(1)
                .is_some_and(|entry| entry.command.as_ref() == bytes)
        );
    }
    Ok(())
}

fn contact_to(effects: &[CoreEffect], peer: NodeId) -> Result<AppendRequest, Box<dyn Error>> {
    effects
        .iter()
        .find_map(|effect| match effect {
            CoreEffect::Send {
                to,
                message: CoreMessage::AppendRequest(request),
            } if *to == peer && request.entries.is_empty() => Some(request.clone()),
            _ => None,
        })
        .ok_or_else(|| {
            io::Error::other("heartbeat did not emit an independent empty leader contact").into()
        })
}

fn deliver(
    follower: &mut ConsensusCore,
    request: AppendRequest,
) -> Result<AppendResponse, Box<dyn Error>> {
    let mut effects = follower.step(message(1, CoreMessage::AppendRequest(request))?)?;
    if let [CoreEffect::Persist { id, .. }] = effects.as_slice() {
        effects = follower.step(CoreInput::Persisted(*id))?;
    }
    effects
        .into_iter()
        .find_map(|effect| match effect {
            CoreEffect::Send {
                message: CoreMessage::AppendResponse(response),
                ..
            } => Some(response),
            _ => None,
        })
        .ok_or_else(|| io::Error::other("follower did not return the exact append proof").into())
}
