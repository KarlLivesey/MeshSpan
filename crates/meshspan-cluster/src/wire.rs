// SPDX-License-Identifier: GPL-2.0-only

//! Exact conversion between validated Protobuf and consensus-owned values.

use meshspan_consensus::{
    AppendRequest, AppendResponse, CommittedPrefix, CoreMessage, LogEntry, LogPosition,
    ReadBarrierId, VoteRequest, VoteResponse,
};
use meshspan_domain::{NodeId, OperationId};
use meshspan_protocol::ValidatedControlEnvelope;
use meshspan_protocol::v1::control_envelope::Message;
use meshspan_protocol::v1::{
    AppendRequest as WireAppendRequest, AppendResponse as WireAppendResponse, ErrorCode,
    LogEntry as WireLogEntry, LogPosition as WireLogPosition, VersionedPayload,
    VoteRequest as WireVoteRequest, VoteResponse as WireVoteResponse, WireError,
};
use thiserror::Error;

/// Encodes one already valid core message without a request header.
#[must_use]
pub fn encode_consensus_message(message: &CoreMessage) -> Message {
    match message {
        CoreMessage::VoteRequest(value) => Message::VoteRequest(WireVoteRequest {
            term: value.term,
            candidate_node_id: value.candidate.as_bytes().to_vec(),
            candidate_incarnation: value.candidate_incarnation,
            last_log: Some(position(value.last_log)),
            membership_epoch: value.membership_epoch,
            quorum_plan_digest: value.plan_digest.to_vec(),
        }),
        CoreMessage::VoteResponse(value) => Message::VoteResponse(WireVoteResponse {
            term: value.term,
            granted: value.granted,
            membership_epoch: value.membership_epoch,
            rejection: rejection(!value.granted),
            quorum_plan_digest: value.plan_digest.to_vec(),
        }),
        CoreMessage::AppendRequest(value) => Message::AppendRequest(WireAppendRequest {
            term: value.term,
            leader_node_id: value.leader.as_bytes().to_vec(),
            leader_incarnation: value.leader_incarnation,
            previous: Some(position(value.previous)),
            previous_digest: value.previous_digest.to_vec(),
            entries: value.entries.iter().map(wire_entry).collect(),
            leader_commit_index: value.leader_commit_index,
            membership_epoch: value.membership_epoch,
            quorum_plan_digest: value.plan_digest.to_vec(),
            read_barrier_id: value.read_barrier_id.map(|value| value.0),
        }),
        CoreMessage::AppendResponse(value) => Message::AppendResponse(WireAppendResponse {
            term: value.term,
            accepted: value.accepted,
            matched_index: value.matched_index,
            next_index_hint: value.next_index_hint,
            rejection: rejection(!value.accepted),
            membership_epoch: value.membership_epoch,
            quorum_plan_digest: value.plan_digest.to_vec(),
            read_barrier_id: value.read_barrier_id.map(|value| value.0),
        }),
        CoreMessage::CommittedPrefix(value) => {
            Message::CommittedPrefix(meshspan_protocol::v1::CommittedPrefix {
                previous: Some(position(value.previous)),
                previous_digest: value.previous_digest.to_vec(),
                entries: value.entries.iter().map(wire_entry).collect(),
                committed_index: value.committed_index,
                membership_epoch: value.membership_epoch,
                quorum_plan_digest: value.plan_digest.to_vec(),
            })
        }
    }
}

/// Converts one fully framed/semantically validated consensus envelope into core-owned values.
///
/// # Errors
///
/// Rejects non-consensus messages and any identity, digest or reconstructed-entry mismatch.
pub fn decode_consensus_message(
    envelope: &ValidatedControlEnvelope,
) -> Result<CoreMessage, ConsensusWireError> {
    match envelope
        .as_inner()
        .message
        .as_ref()
        .ok_or(ConsensusWireError::InvalidMessage)?
    {
        Message::VoteRequest(value) => Ok(CoreMessage::VoteRequest(VoteRequest {
            term: value.term,
            candidate: node_id(&value.candidate_node_id)?,
            candidate_incarnation: value.candidate_incarnation,
            last_log: core_position(value.last_log.as_ref())?,
            membership_epoch: value.membership_epoch,
            plan_digest: digest(&value.quorum_plan_digest)?,
        })),
        Message::VoteResponse(value) => Ok(CoreMessage::VoteResponse(VoteResponse {
            term: value.term,
            granted: value.granted,
            membership_epoch: value.membership_epoch,
            plan_digest: digest(&value.quorum_plan_digest)?,
        })),
        Message::AppendRequest(value) => Ok(CoreMessage::AppendRequest(AppendRequest {
            term: value.term,
            leader: node_id(&value.leader_node_id)?,
            leader_incarnation: value.leader_incarnation,
            previous: core_position(value.previous.as_ref())?,
            previous_digest: digest(&value.previous_digest)?,
            entries: value
                .entries
                .iter()
                .map(core_entry)
                .collect::<Result<_, _>>()?,
            leader_commit_index: value.leader_commit_index,
            read_barrier_id: value.read_barrier_id.map(ReadBarrierId),
            membership_epoch: value.membership_epoch,
            plan_digest: digest(&value.quorum_plan_digest)?,
        })),
        Message::AppendResponse(value) => Ok(CoreMessage::AppendResponse(AppendResponse {
            term: value.term,
            accepted: value.accepted,
            matched_index: value.matched_index,
            next_index_hint: value.next_index_hint,
            read_barrier_id: value.read_barrier_id.map(ReadBarrierId),
            membership_epoch: value.membership_epoch,
            plan_digest: digest(&value.quorum_plan_digest)?,
        })),
        Message::CommittedPrefix(value) => Ok(CoreMessage::CommittedPrefix(CommittedPrefix {
            previous: core_position(value.previous.as_ref())?,
            previous_digest: digest(&value.previous_digest)?,
            entries: value
                .entries
                .iter()
                .map(core_entry)
                .collect::<Result<_, _>>()?,
            committed_index: value.committed_index,
            membership_epoch: value.membership_epoch,
            plan_digest: digest(&value.quorum_plan_digest)?,
        })),
        _ => Err(ConsensusWireError::InvalidMessage),
    }
}

fn wire_entry(entry: &LogEntry) -> WireLogEntry {
    WireLogEntry {
        position: Some(position(entry.position)),
        operation_id: entry.operation_id.as_bytes().to_vec(),
        command_digest: entry.entry_digest().to_vec(),
        command: Some(VersionedPayload {
            format_version: u32::from(entry.command_version),
            canonical_bytes: entry.command.clone(),
        }),
    }
}

fn core_entry(entry: &WireLogEntry) -> Result<LogEntry, ConsensusWireError> {
    let command = entry
        .command
        .as_ref()
        .ok_or(ConsensusWireError::InvalidMessage)?;
    let command_version =
        u16::try_from(command.format_version).map_err(|_| ConsensusWireError::InvalidMessage)?;
    let rebuilt = LogEntry::new(
        core_position(entry.position.as_ref())?,
        operation_id(&entry.operation_id)?,
        command_version,
        command.canonical_bytes.clone(),
    )
    .map_err(|_| ConsensusWireError::InvalidMessage)?;
    if rebuilt.entry_digest().as_slice() != entry.command_digest {
        return Err(ConsensusWireError::DigestMismatch);
    }
    Ok(rebuilt)
}

const fn position(value: LogPosition) -> WireLogPosition {
    WireLogPosition {
        term: value.term,
        index: value.index,
    }
}

fn core_position(value: Option<&WireLogPosition>) -> Result<LogPosition, ConsensusWireError> {
    let value = value.ok_or(ConsensusWireError::InvalidMessage)?;
    Ok(LogPosition {
        term: value.term,
        index: value.index,
    })
}

fn rejection(include: bool) -> Option<WireError> {
    include.then_some(WireError {
        code: ErrorCode::Stale.into(),
        diagnostic_code: 1,
        retry_after_micros: None,
    })
}

fn node_id(bytes: &[u8]) -> Result<NodeId, ConsensusWireError> {
    NodeId::from_bytes(exact(bytes)?).map_err(|_| ConsensusWireError::InvalidMessage)
}

fn operation_id(bytes: &[u8]) -> Result<OperationId, ConsensusWireError> {
    OperationId::from_bytes(exact(bytes)?).map_err(|_| ConsensusWireError::InvalidMessage)
}

fn digest(bytes: &[u8]) -> Result<[u8; 32], ConsensusWireError> {
    exact(bytes)
}

fn exact<const SIZE: usize>(bytes: &[u8]) -> Result<[u8; SIZE], ConsensusWireError> {
    bytes
        .try_into()
        .map_err(|_| ConsensusWireError::InvalidMessage)
}

/// Closed conversion failures after wire validation.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ConsensusWireError {
    /// Envelope/message fields cannot form the exact core type.
    #[error("validated consensus wire message is not representable")]
    InvalidMessage,
    /// Rebuilt log-entry digest does not match the sender's explicit digest.
    #[error("consensus wire log entry digest does not match")]
    DigestMismatch,
}

#[cfg(test)]
mod tests {
    use meshspan_protocol::v1::{ControlEnvelope, ProtocolVersion, RequestHeader};
    use meshspan_protocol::{WireLimits, decode_control_frame, encode_control_frame};

    use super::*;

    #[test]
    fn every_core_message_round_trips_through_validated_protobuf()
    -> Result<(), Box<dyn std::error::Error>> {
        let entry = LogEntry::new(
            LogPosition { term: 4, index: 8 },
            OperationId::from_bytes([5; 16])?,
            2,
            b"metadata-command".to_vec(),
        )?;
        let messages = [
            CoreMessage::VoteRequest(VoteRequest {
                term: 4,
                candidate: NodeId::from_bytes([1; 16])?,
                candidate_incarnation: 2,
                last_log: LogPosition { term: 3, index: 7 },
                membership_epoch: 9,
                plan_digest: [6; 32],
            }),
            CoreMessage::VoteResponse(VoteResponse {
                term: 4,
                granted: false,
                membership_epoch: 9,
                plan_digest: [6; 32],
            }),
            CoreMessage::AppendRequest(AppendRequest {
                term: 4,
                leader: NodeId::from_bytes([1; 16])?,
                leader_incarnation: 2,
                previous: LogPosition { term: 3, index: 7 },
                previous_digest: [7; 32],
                entries: vec![entry.clone()],
                leader_commit_index: 7,
                read_barrier_id: Some(ReadBarrierId(11)),
                membership_epoch: 9,
                plan_digest: [6; 32],
            }),
            CoreMessage::AppendResponse(AppendResponse {
                term: 4,
                accepted: false,
                matched_index: 0,
                next_index_hint: 8,
                read_barrier_id: Some(ReadBarrierId(11)),
                membership_epoch: 9,
                plan_digest: [6; 32],
            }),
            CoreMessage::CommittedPrefix(CommittedPrefix {
                previous: LogPosition { term: 3, index: 7 },
                previous_digest: [7; 32],
                entries: vec![entry],
                committed_index: 8,
                membership_epoch: 9,
                plan_digest: [6; 32],
            }),
        ];
        for message in messages {
            let envelope = ControlEnvelope {
                header: Some(header()),
                message: Some(encode_consensus_message(&message)),
            };
            let limits = limits()?;
            let frame = encode_control_frame(&envelope, limits)?;
            let validated = decode_control_frame(&frame, limits)?;
            assert_eq!(decode_consensus_message(&validated)?, message);
        }
        Ok(())
    }

    #[test]
    fn committed_prefix_rejects_commit_overreach_and_corrupt_entry_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let entry = LogEntry::new(
            LogPosition { term: 1, index: 1 },
            OperationId::from_bytes([5; 16])?,
            1,
            b"committed".to_vec(),
        )?;
        let mut envelope = ControlEnvelope {
            header: Some(header()),
            message: Some(encode_consensus_message(&CoreMessage::CommittedPrefix(
                CommittedPrefix {
                    previous: LogPosition::GENESIS,
                    previous_digest: [0; 32],
                    entries: vec![entry],
                    committed_index: 1,
                    membership_epoch: 1,
                    plan_digest: [6; 32],
                },
            ))),
        };
        let Some(Message::CommittedPrefix(prefix)) = &mut envelope.message else {
            return Err("missing prefix".into());
        };
        prefix.committed_index = 2;
        assert!(encode_control_frame(&envelope, limits()?).is_err());
        let Some(Message::CommittedPrefix(prefix)) = &mut envelope.message else {
            return Err("missing prefix".into());
        };
        prefix.committed_index = 1;
        prefix.entries[0]
            .command
            .as_mut()
            .ok_or("missing command")?
            .canonical_bytes = b"corrupt".to_vec();
        let frame = encode_control_frame(&envelope, limits()?)?;
        let validated = decode_control_frame(&frame, limits()?)?;
        assert_eq!(
            decode_consensus_message(&validated),
            Err(ConsensusWireError::DigestMismatch)
        );
        Ok(())
    }

    fn header() -> RequestHeader {
        RequestHeader {
            version: Some(ProtocolVersion { major: 1, minor: 0 }),
            mesh_id: vec![1; 16],
            partition_id: vec![2; 16],
            routing_epoch: 1,
            sender_node_id: vec![3; 16],
            sender_incarnation: 1,
            request_id: vec![4; 16],
            operation_id: vec![5; 16],
            deadline_unix_micros: 1,
            trace_id: vec![6; 16],
        }
    }

    fn limits() -> Result<WireLimits, Box<dyn std::error::Error>> {
        Ok(WireLimits::new(64 * 1_024, 64 * 1_024, 256, 4_096)?)
    }
}
