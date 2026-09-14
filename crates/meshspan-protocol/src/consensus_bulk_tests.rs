// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::v1::{
    AppendRequest, CommittedPrefix, LogEntry, LogPosition, ProtocolVersion, RequestHeader,
    VersionedPayload,
};

#[test]
fn bulk_consensus_preserves_probe_phase_and_large_bytes_without_enlarging_control()
-> Result<(), WireContractError> {
    let body = body(1024 * 1024);
    let bytes = encode_consensus_bulk_entries(&body)?;
    let start = descriptor(&bytes, 1);
    let decoded = decode_consensus_bulk(start.clone(), &bytes)?;
    let Some(Message::AppendRequest(append)) = decoded.as_inner().message.as_ref() else {
        return Err(WireContractError::InvalidMessage);
    };
    assert_eq!(append.probe_id, 29);
    assert_eq!(append.read_barrier_id, Some(31));
    assert_eq!(append.membership_epoch, 7);
    assert_eq!(append.entries, body.entries);
    let limits = WireLimits::new(64 * 1024, 64 * 1024, 64, 4096)?;
    assert!(crate::encode_control_frame(decoded.as_inner(), limits).is_err());
    let mut prefix = start;
    prefix.metadata = Some(Metadata::Prefix(CommittedPrefix {
        previous: Some(LogPosition { term: 0, index: 0 }),
        previous_digest: vec![0; 32],
        entries: vec![],
        committed_index: 1,
        membership_epoch: 7,
        quorum_plan_digest: vec![9; 32],
    }));
    let decoded = decode_consensus_bulk(prefix, &bytes)?;
    let Some(Message::CommittedPrefix(prefix)) = decoded.as_inner().message.as_ref() else {
        return Err(WireContractError::InvalidMessage);
    };
    assert_eq!(prefix.entries, body.entries);
    Ok(())
}

#[test]
fn bulk_consensus_rejects_substitution_duplicate_fields_and_hidden_excess_entries()
-> Result<(), Box<dyn std::error::Error>> {
    let body = body(8);
    let bytes = encode_consensus_bulk_entries(&body)?;
    let mut start = descriptor(&bytes, 1);
    start.header.as_mut().ok_or("header missing")?.request_id = vec![2; 16];
    assert!(decode_consensus_bulk(start, &bytes).is_err());
    let mut corrupt = bytes.clone();
    corrupt.push(0);
    assert!(decode_consensus_bulk(descriptor(&bytes, 1), &corrupt).is_err());
    // A forged count cannot bypass the decoder's independent per-repeated-field allocation cap.
    let mut excess = body.clone();
    excess.entries = vec![body.entries[0].clone(); 65];
    let bytes = excess.encode_to_vec()?;
    assert!(decode_consensus_bulk(descriptor(&bytes, 64), &bytes).is_err());
    let mut duplicate = encode_consensus_bulk_entries(&body)?;
    duplicate.extend_from_slice(&[8, 1]);
    assert!(decode_consensus_bulk(descriptor(&duplicate, 1), &duplicate).is_err());
    let mut missing_probe = descriptor(&encode_consensus_bulk_entries(&body)?, 1);
    let Some(Metadata::Append(append)) = &mut missing_probe.metadata else {
        return Err("append missing".into());
    };
    append.probe_id = 0;
    assert!(super::start(&missing_probe).is_err());
    Ok(())
}

#[test]
fn bulk_consensus_retains_generic_sixteen_mebibyte_command_limit() -> Result<(), WireContractError>
{
    let body = body(MAXIMUM_CONSENSUS_COMMAND_BYTES);
    let bytes = encode_consensus_bulk_entries(&body)?;
    assert!(bytes.len() > MAXIMUM_CONSENSUS_COMMAND_BYTES);
    assert!(decode_consensus_bulk(descriptor(&bytes, 1), &bytes).is_ok());
    let too_large = body_with_extra_byte(body);
    assert!(encode_consensus_bulk_entries(&too_large).is_err());
    Ok(())
}

fn body_with_extra_byte(mut body: ConsensusBulkEntries) -> ConsensusBulkEntries {
    if let Some(command) = body.entries[0].command.as_mut() {
        command.canonical_bytes.push(1);
    }
    body
}

fn body(length: usize) -> ConsensusBulkEntries {
    ConsensusBulkEntries {
        format_version: 1,
        request_id: vec![1; 16],
        entries: vec![LogEntry {
            position: Some(LogPosition { term: 3, index: 1 }),
            operation_id: vec![3; 16],
            command_digest: vec![4; 32],
            command: Some(VersionedPayload {
                format_version: 1,
                canonical_bytes: vec![5; length],
            }),
        }],
    }
}

fn descriptor(bytes: &[u8], entry_count: u32) -> ConsensusBulkStart {
    ConsensusBulkStart {
        header: Some(RequestHeader {
            version: Some(ProtocolVersion { major: 1, minor: 0 }),
            mesh_id: vec![1; 16],
            partition_id: vec![2; 16],
            routing_epoch: 1,
            sender_node_id: vec![3; 16],
            sender_incarnation: 1,
            request_id: vec![1; 16],
            operation_id: vec![4; 16],
            deadline_unix_micros: i64::MAX,
            trace_id: vec![5; 16],
        }),
        format_version: 1,
        byte_length: bytes.len() as u64,
        body_digest: Sha256::digest(bytes).to_vec(),
        entry_count,
        metadata: Some(Metadata::Append(AppendRequest {
            term: 3,
            leader_node_id: vec![3; 16],
            leader_incarnation: 1,
            previous: Some(LogPosition { term: 0, index: 0 }),
            previous_digest: vec![0; 32],
            entries: vec![],
            leader_commit_index: 1,
            membership_epoch: 7,
            quorum_plan_digest: vec![9; 32],
            read_barrier_id: Some(31),
            probe_id: 29,
        })),
    }
}
