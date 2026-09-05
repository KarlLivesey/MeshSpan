// SPDX-License-Identifier: GPL-2.0-only

//! Historical replication never supplies current-plan quorum or read evidence.

use super::super::types::validate_committed_prefix;
use super::{
    AfterPersistence, AppendResponse, ConsensusCore, CoreEffect, CoreError, CoreMessage,
    DurableMutation, LogEntry, LogPosition, MAXIMUM_APPEND_ENTRIES, NodeId,
};
use crate::CommittedPrefix;

impl ConsensusCore {
    pub(super) fn replay_membership_prefix(
        &self,
        peer: NodeId,
        response: AppendResponse,
    ) -> Result<Vec<CoreEffect>, CoreError> {
        if response.term == 0 || response.next_index_hint == 0 {
            return Err(CoreError::StaleMember);
        }
        let boundary = self
            .membership_history
            .find(response.membership_epoch, response.plan_digest)
            .ok_or(CoreError::StaleMember)?;
        if !boundary.plan.voters().contains(&self.config.local_node_id)
            || !boundary.plan.members().contains(&peer)
            || boundary.committed_position.index > self.applied_index
        {
            return Err(CoreError::StaleMember);
        }
        let end = boundary.committed_position.index;
        let next = response.next_index_hint.min(end.saturating_add(1));
        let previous = if next == 1 {
            LogPosition::GENESIS
        } else {
            self.entry(next - 1)
                .ok_or(CoreError::InvalidInput)?
                .position
        };
        let previous_digest = if previous == LogPosition::GENESIS {
            [0; 32]
        } else {
            self.entry(previous.index)
                .ok_or(CoreError::InvalidInput)?
                .entry_digest()
        };
        let entries: Vec<LogEntry> = self
            .log
            .iter()
            .filter(|entry| entry.position.index >= next && entry.position.index <= end)
            .take(MAXIMUM_APPEND_ENTRIES)
            .cloned()
            .collect();
        let sent_through = entries
            .last()
            .map_or(previous.index, |entry| entry.position.index);
        Ok(vec![CoreEffect::Send {
            to: peer,
            message: CoreMessage::CommittedPrefix(CommittedPrefix {
                previous,
                previous_digest,
                entries,
                committed_index: sent_through.min(end),
                membership_epoch: boundary.plan.membership_epoch(),
                plan_digest: boundary.plan.proof_digest(),
            }),
        }])
    }

    pub(super) fn receive_committed_prefix(
        &mut self,
        from: NodeId,
        prefix: &CommittedPrefix,
    ) -> Result<Vec<CoreEffect>, CoreError> {
        validate_committed_prefix(prefix)?;
        if !self.active_voters().contains(&from) {
            return Err(CoreError::StaleMember);
        }
        if self
            .validate_plan(prefix.membership_epoch, prefix.plan_digest)
            .is_err()
            || prefix.committed_index <= self.applied_index
        {
            return Ok(vec![self.append_response_effect(from, false, None)]);
        }
        if !self.position_matches(prefix.previous, prefix.previous_digest) {
            let mut response = self.append_response_effect(from, false, None);
            if let CoreEffect::Send {
                message: CoreMessage::AppendResponse(reply),
                ..
            } = &mut response
            {
                reply.next_index_hint = reply.next_index_hint.min(prefix.previous.index.max(1));
            }
            return Ok(vec![response]);
        }
        let (truncate_from, append) = self.log_delta(&prefix.entries)?;
        let observed_term = prefix
            .entries
            .last()
            .map_or(prefix.previous.term, |entry| entry.position.term);
        if truncate_from.is_some() || !append.is_empty() || observed_term > self.current_term {
            return self.begin_persistence(
                DurableMutation {
                    vote_state: (observed_term > self.current_term)
                        .then_some((observed_term, None)),
                    truncate_from,
                    append,
                    membership_epoch: None,
                    quorum_plan: None,
                },
                AfterPersistence::CommittedPrefix {
                    from,
                    committed_index: prefix.committed_index,
                },
            );
        }
        self.finish_committed_prefix(from, prefix.committed_index)
    }

    pub(super) fn finish_committed_prefix(
        &mut self,
        from: NodeId,
        committed_index: u64,
    ) -> Result<Vec<CoreEffect>, CoreError> {
        // Historical evidence does not elect its supplier or erase a newer durable vote.
        self.follow_leader(None);
        let mut effects = self.advance_follower_commit(committed_index.max(self.commit_index))?;
        effects.push(self.append_response_effect(from, false, None));
        Ok(effects)
    }
}
