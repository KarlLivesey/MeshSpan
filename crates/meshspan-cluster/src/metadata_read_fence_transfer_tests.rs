// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use meshspan_protocol::v1::{LogPosition, MetadataReadFence as WireFence, RequestHeader};

fn exchange() -> (ControlEnvelope, ControlEnvelope) {
    let header = RequestHeader {
        mesh_id: vec![1; 16],
        partition_id: vec![2; 16],
        routing_epoch: 1,
        sender_node_id: vec![3; 16],
        sender_incarnation: 1,
        request_id: vec![4; 16],
        operation_id: vec![5; 16],
        trace_id: vec![6; 16],
        deadline_unix_micros: 10_000_010,
        version: Some(meshspan_protocol::v1::ProtocolVersion { major: 1, minor: 0 }),
    };
    let request = ControlEnvelope {
        header: Some(header.clone()),
        message: Some(Message::FetchMetadataReadFence(FetchMetadataReadFence {
            nonce: vec![7; 32],
        })),
    };
    let mut reply_header = header;
    reply_header.sender_node_id = vec![8; 16];
    let response = ControlEnvelope {
        header: Some(reply_header),
        message: Some(Message::MetadataReadFenceResult(MetadataReadFenceResult {
            nonce: vec![7; 32],
            outcome: Some(Outcome::Fence(WireFence {
                partition_id: vec![2; 16],
                leader_node_id: vec![8; 16],
                term: 3,
                membership_epoch: 2,
                plan_digest: vec![9; 32],
                applied: Some(LogPosition { term: 3, index: 10 }),
                applied_digest: vec![10; 32],
                revision: 8,
            })),
        })),
    };
    (request, response)
}

#[test]
fn read_fence_rejects_cross_request_or_cross_authority_responses()
-> Result<(), Box<dyn std::error::Error>> {
    let (request, response) = exchange();
    let source = NodeId::from_bytes([8; 16])?;
    let fence = parse_response(&request, &response, source)?;
    assert_eq!(fence.partition_id, PartitionId::from_bytes([2; 16])?);
    assert_eq!(fence.leader_node_id, source);
    assert_eq!((fence.term, fence.membership_epoch), (3, 2));
    assert_eq!(fence.plan_digest, [9; 32]);
    assert_eq!(
        fence.applied,
        meshspan_consensus::LogPosition { term: 3, index: 10 }
    );
    assert_eq!(fence.applied_digest, [10; 32]);
    assert_eq!(fence.revision, Revision::new(8));
    for field in 0..9 {
        let mut changed = response.clone();
        let header = changed.header.as_mut().ok_or("header missing")?;
        match field {
            0 => header.mesh_id = vec![11; 16],
            1 => header.partition_id = vec![11; 16],
            2 => header.routing_epoch += 1,
            3 => header.request_id = vec![11; 16],
            4 => header.operation_id = vec![11; 16],
            5 => header.trace_id = vec![11; 16],
            6 => header.deadline_unix_micros += 1,
            7 => header.sender_node_id = vec![11; 16],
            _ => {
                let Some(Message::MetadataReadFenceResult(result)) = &mut changed.message else {
                    return Err("result missing".into());
                };
                result.nonce = vec![11; 32];
            }
        }
        assert_eq!(
            parse_response(&request, &changed, source),
            Err(RequestError::Failed)
        );
    }
    for field in 0..2 {
        let mut changed = response.clone();
        let Some(Message::MetadataReadFenceResult(result)) = &mut changed.message else {
            return Err("result missing".into());
        };
        let Some(Outcome::Fence(fence)) = &mut result.outcome else {
            return Err("fence missing".into());
        };
        if field == 0 {
            fence.partition_id = vec![11; 16];
        } else {
            fence.leader_node_id = vec![11; 16];
        }
        assert_eq!(
            parse_response(&request, &changed, source),
            Err(RequestError::Failed)
        );
    }
    Ok(())
}

#[test]
fn read_fence_rejection_is_never_a_success() -> Result<(), Box<dyn std::error::Error>> {
    let (request, mut response) = exchange();
    let source = NodeId::from_bytes([8; 16])?;
    for (code, expected) in [
        (ErrorCode::Unavailable, RequestError::Unavailable),
        (ErrorCode::Deadline, RequestError::Unavailable),
        (ErrorCode::Unauthorised, RequestError::Rejected),
        (ErrorCode::InternalContract, RequestError::Failed),
    ] {
        let Some(Message::MetadataReadFenceResult(result)) = &mut response.message else {
            return Err("result missing".into());
        };
        result.outcome = Some(Outcome::Rejection(WireError {
            code: code.into(),
            diagnostic_code: 1,
            retry_after_micros: None,
        }));
        assert_eq!(parse_response(&request, &response, source), Err(expected));
    }
    Ok(())
}
