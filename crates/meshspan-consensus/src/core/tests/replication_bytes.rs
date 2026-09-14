// SPDX-License-Identifier: GPL-2.0-only

use super::*;

#[test]
fn replication_batches_bound_command_bytes_and_continue_after_acknowledgement()
-> Result<(), Box<dyn Error>> {
    let mut leader = elected_core(3, 2)?;
    for id in 1..=2 {
        persist_only_effect(&mut leader, proposal(id, vec![42; 9 * 1_024 * 1_024])?)?;
    }
    let effects = leader.step(CoreInput::Heartbeat)?;
    let first = request_to(&effects, 2)?;
    assert_eq!(first.entries.len(), 1);
    assert_eq!(first.entries[0].position.index, 1);
    assert_eq!(first.entries[0].command.len(), 9 * 1_024 * 1_024);
    let response = reply_to(&effects, 2, true)?;
    leader.step(message(2, CoreMessage::AppendResponse(response))?)?;
    let effects = leader.step(CoreInput::Heartbeat)?;
    let second = request_to(&effects, 2)?;
    assert_eq!(second.previous.index, 1);
    assert_eq!(second.entries.len(), 1);
    assert_eq!(second.entries[0].position.index, 2);
    Ok(())
}

#[test]
fn oversized_replication_batch_is_rejected_before_any_persistence() -> Result<(), Box<dyn Error>> {
    let mut leader = elected_core(3, 2)?;
    for id in 1..=2 {
        persist_only_effect(&mut leader, proposal(id, vec![42; 9 * 1_024 * 1_024])?)?;
    }
    let effects = leader.step(CoreInput::Heartbeat)?;
    let mut request = request_to(&effects, 2)?.clone();
    request.entries = vec![
        leader
            .log_entry(1)
            .ok_or_else(|| io::Error::other("missing first entry"))?
            .clone(),
        leader
            .log_entry(2)
            .ok_or_else(|| io::Error::other("missing second entry"))?
            .clone(),
    ];
    let mut follower = core_for_node(3, 2)?;
    assert!(matches!(
        follower.step(message(1, CoreMessage::AppendRequest(request.clone()))?),
        Err(CoreError::InvalidInput)
    ));
    assert_eq!(follower.current_term(), 0);
    assert!(follower.last_log_entry().is_none());
    let prefix = crate::CommittedPrefix {
        previous: LogPosition::GENESIS,
        previous_digest: [0; 32],
        entries: request.entries,
        committed_index: 2,
        membership_epoch: 1,
        plan_digest: fixture_plan_digest()?,
    };
    assert_eq!(
        super::super::types::validate_committed_prefix(&prefix),
        Err(CoreError::InvalidInput)
    );
    Ok(())
}

fn request_to(effects: &[CoreEffect], peer: u8) -> Result<&AppendRequest, Box<dyn Error>> {
    let peer = node(peer)?;
    effects
        .iter()
        .find_map(|effect| match effect {
            CoreEffect::Send {
                to,
                message: CoreMessage::AppendRequest(request),
            } if *to == peer => Some(request),
            _ => None,
        })
        .ok_or_else(|| io::Error::other("missing append request").into())
}
