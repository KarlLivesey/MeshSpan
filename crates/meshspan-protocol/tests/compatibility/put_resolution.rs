// SPDX-License-Identifier: GPL-2.0-only

//! Resolution outcomes cannot confuse unknown/prepared evidence with a verified receipt.

use super::*;
use meshspan_protocol::v1::{
    ResolveShardPutRequest, ResolveShardPutResult, resolve_shard_put_result::Outcome,
};

#[test]
fn exact_put_resolution_frames_round_trip_without_claiming_unknown_as_durable()
-> Result<(), Box<dyn std::error::Error>> {
    let limits = WireLimits::new(4096, 65536, 32, 1024)?;
    let request = DataMessage::ResolveShardPutRequest(ResolveShardPutRequest {
        header: Some(valid_header()),
        target_id: vec![8; 16],
        target_generation: 3,
        original: Some(VersionedPayload {
            format_version: 1,
            canonical_bytes: vec![1; 208],
        }),
        write_capability: vec![2; 159],
    });
    let outcomes = [
        Outcome::Unknown(true),
        Outcome::Prepared(true),
        Outcome::Verified(VersionedPayload {
            format_version: 1,
            canonical_bytes: vec![3; 126],
        }),
    ];
    let mut messages = vec![request];
    for outcome in outcomes {
        messages.push(DataMessage::ResolveShardPutResult(ResolveShardPutResult {
            original_request_digest: vec![4; 32],
            outcome: Some(outcome),
        }));
    }
    for message in messages {
        let envelope = DataControlEnvelope {
            message: Some(message),
        };
        assert_eq!(
            decode_data_control_frame(&encode_data_control_frame(&envelope, limits)?, limits)?
                .into_inner(),
            envelope
        );
    }
    Ok(())
}

#[test]
fn put_resolution_rejects_ambiguous_or_unbound_outcomes() -> Result<(), Box<dyn std::error::Error>>
{
    let limits = WireLimits::new(4096, 65536, 32, 1024)?;
    for outcome in [
        None,
        Some(Outcome::Unknown(false)),
        Some(Outcome::Prepared(false)),
        Some(Outcome::Verified(VersionedPayload {
            format_version: 1,
            canonical_bytes: Vec::new(),
        })),
    ] {
        let envelope = DataControlEnvelope {
            message: Some(DataMessage::ResolveShardPutResult(ResolveShardPutResult {
                original_request_digest: vec![4; 32],
                outcome,
            })),
        };
        assert!(encode_data_control_frame(&envelope, limits).is_err());
    }
    let envelope = DataControlEnvelope {
        message: Some(DataMessage::ResolveShardPutResult(ResolveShardPutResult {
            original_request_digest: vec![0; 32],
            outcome: Some(Outcome::Unknown(true)),
        })),
    };
    assert!(encode_data_control_frame(&envelope, limits).is_err());
    Ok(())
}
