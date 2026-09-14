// SPDX-License-Identifier: GPL-2.0-only

use super::*;

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
