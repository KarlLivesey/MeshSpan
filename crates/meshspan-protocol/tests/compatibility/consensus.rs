// SPDX-License-Identifier: GPL-2.0-only

use meshspan_protobuf::Message as _;
use meshspan_protocol::v1::{AppendRequest, AppendResponse, ErrorCode, LogPosition, WireError};

use super::{
    ControlEnvelope, Message, WireContractError, decode_control_frame, encode_control_frame,
};

#[test]
fn append_probe_and_matched_digest_use_additive_wire_tags() -> Result<(), Box<dyn std::error::Error>>
{
    let response = accepted_response();
    let mut expected = vec![0x08, 4, 0x10, 1, 0x18, 8, 0x20, 9, 0x30, 3, 0x3a, 32];
    expected.extend_from_slice(&[9; 32]);
    expected.extend_from_slice(&[0x40, 11, 0x48, 13, 0x52, 32]);
    expected.extend_from_slice(&[17; 32]);
    assert_eq!(response.encode_to_vec()?, expected);
    let request = append_request();
    assert!(request.encode_to_vec()?.ends_with(&[0x58, 13]));
    assert_round_trip(Message::AppendRequest(request))?;
    assert_round_trip(Message::AppendResponse(response))
}

#[test]
fn append_success_requires_nonzero_probe_and_exact_matched_digest()
-> Result<(), Box<dyn std::error::Error>> {
    let mut invalid = vec![accepted_response(); 8];
    invalid[0].probe_id = None;
    invalid[1].probe_id = Some(0);
    invalid[2].matched_digest.clear();
    invalid[3].matched_digest.pop();
    invalid[4].matched_digest.push(17);
    invalid[5].matched_digest = vec![0; 32];
    invalid[6].matched_index = 0;
    invalid[7].read_barrier_id = Some(0);
    for response in invalid {
        assert_rejected(Message::AppendResponse(response))?;
    }
    let genesis = AppendResponse {
        matched_index: 0,
        matched_digest: vec![0; 32],
        ..accepted_response()
    };
    assert_round_trip(Message::AppendResponse(genesis))
}

#[test]
fn append_rejection_allows_uncorrelated_phase_notice_without_read_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let rejection = AppendResponse {
        accepted: false,
        matched_index: 0,
        matched_digest: vec![0; 32],
        rejection: Some(WireError {
            code: ErrorCode::Stale.into(),
            diagnostic_code: 1,
            retry_after_micros: None,
        }),
        ..accepted_response()
    };
    assert_round_trip(Message::AppendResponse(rejection.clone()))?;
    let notice = AppendResponse {
        probe_id: None,
        read_barrier_id: None,
        ..rejection
    };
    assert_round_trip(Message::AppendResponse(notice.clone()))?;
    let mut invalid = vec![notice; 5];
    invalid[0].read_barrier_id = Some(11);
    invalid[1].matched_digest = vec![17; 32];
    invalid[2].matched_index = 8;
    invalid[3].probe_id = Some(0);
    invalid[4].rejection = None;
    for response in invalid {
        assert_rejected(Message::AppendResponse(response))?;
    }
    Ok(())
}

#[test]
fn legacy_append_request_without_probe_is_rejected_before_dispatch()
-> Result<(), Box<dyn std::error::Error>> {
    let request = AppendRequest {
        probe_id: 0,
        ..append_request()
    };
    assert_rejected(Message::AppendRequest(request))
}

fn append_request() -> AppendRequest {
    AppendRequest {
        term: 4,
        leader_node_id: vec![1; 16],
        leader_incarnation: 2,
        previous: Some(LogPosition { term: 3, index: 8 }),
        previous_digest: vec![17; 32],
        entries: Vec::new(),
        leader_commit_index: 8,
        membership_epoch: 3,
        quorum_plan_digest: vec![9; 32],
        read_barrier_id: Some(11),
        probe_id: 13,
    }
}

fn accepted_response() -> AppendResponse {
    AppendResponse {
        term: 4,
        accepted: true,
        matched_index: 8,
        next_index_hint: 9,
        rejection: None,
        membership_epoch: 3,
        quorum_plan_digest: vec![9; 32],
        read_barrier_id: Some(11),
        probe_id: Some(13),
        matched_digest: vec![17; 32],
    }
}

fn assert_round_trip(message: Message) -> Result<(), Box<dyn std::error::Error>> {
    let envelope = ControlEnvelope {
        header: Some(super::valid_header()),
        message: Some(message),
    };
    let frame = encode_control_frame(&envelope, super::limits()?)?;
    assert_eq!(
        decode_control_frame(&frame, super::limits()?)?.into_inner(),
        envelope
    );
    Ok(())
}

fn assert_rejected(message: Message) -> Result<(), Box<dyn std::error::Error>> {
    let envelope = ControlEnvelope {
        header: Some(super::valid_header()),
        message: Some(message),
    };
    assert_eq!(
        encode_control_frame(&envelope, super::limits()?),
        Err(WireContractError::InvalidMessage)
    );
    // Bypass only sender-side validation to exercise hostile bytes at the real receiver boundary.
    let payload = envelope.encode_to_vec()?;
    let mut frame = u32::try_from(payload.len())?.to_be_bytes().to_vec();
    frame.extend_from_slice(&payload);
    assert_eq!(
        decode_control_frame(&frame, super::limits()?),
        Err(WireContractError::InvalidMessage)
    );
    Ok(())
}
