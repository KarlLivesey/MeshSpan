// SPDX-License-Identifier: GPL-2.0-only

//! Resolution outcomes cannot confuse unknown/prepared evidence with a verified receipt.

use super::*;
use meshspan_protocol::v1::{
    ResolveShardPutRequest, ResolveShardPutResult, ResumeShardPutReady, ResumeShardPutRequest,
    ResumeShardPutResult, resolve_shard_put_result::Outcome,
    resume_shard_put_result::Outcome as ResumeOutcome,
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
fn repair_resume_frames_bind_exact_original_intent_and_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let limits = WireLimits::new(4096, 65536, 32, 1024)?;
    let messages = [
        DataMessage::ResumeShardPutRequest(ResumeShardPutRequest {
            header: Some(valid_header()),
            target_id: vec![8; 16],
            target_generation: 3,
            intent: Some(resume_payload(152)),
            write_capability: vec![2; 159],
        }),
        DataMessage::ResumeShardPutResult(ResumeShardPutResult {
            intent: Some(resume_payload(152)),
            outcome: Some(ResumeOutcome::Ready(ResumeShardPutReady {
                original: Some(resume_payload(208)),
                maximum_frame_bytes: 1024,
            })),
        }),
        DataMessage::ResumeShardPutResult(ResumeShardPutResult {
            intent: Some(resume_payload(152)),
            outcome: Some(ResumeOutcome::Verified(resume_payload(126))),
        }),
    ];
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
fn repair_resume_rejects_unbound_or_unbounded_admission() -> Result<(), Box<dyn std::error::Error>>
{
    let limits = WireLimits::new(4096, 65536, 32, 1024)?;
    for outcome in [
        None,
        Some(ResumeOutcome::Verified(resume_payload(0))),
        Some(ResumeOutcome::Ready(ResumeShardPutReady {
            original: None,
            maximum_frame_bytes: 1024,
        })),
        Some(ResumeOutcome::Ready(ResumeShardPutReady {
            original: Some(resume_payload(208)),
            maximum_frame_bytes: 0,
        })),
        Some(ResumeOutcome::Ready(ResumeShardPutReady {
            original: Some(resume_payload(208)),
            maximum_frame_bytes: 65537,
        })),
    ] {
        assert!(
            encode_data_control_frame(
                &DataControlEnvelope {
                    message: Some(DataMessage::ResumeShardPutResult(ResumeShardPutResult {
                        intent: Some(resume_payload(152)),
                        outcome,
                    })),
                },
                limits
            )
            .is_err()
        );
    }
    for intent in [
        None,
        Some(resume_payload(151)),
        Some(resume_payload(153)),
        Some(VersionedPayload {
            format_version: 2,
            ..resume_payload(152)
        }),
    ] {
        assert!(
            encode_data_control_frame(
                &DataControlEnvelope {
                    message: Some(DataMessage::ResumeShardPutResult(ResumeShardPutResult {
                        intent,
                        outcome: Some(ResumeOutcome::Verified(resume_payload(126))),
                    })),
                },
                limits
            )
            .is_err()
        );
    }
    Ok(())
}

fn resume_payload(size: usize) -> VersionedPayload {
    VersionedPayload {
        format_version: 1,
        canonical_bytes: vec![1; size],
    }
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
