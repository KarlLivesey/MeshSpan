// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::v1::{ErrorCode, LogEntry, LogPosition, VersionedPayload, WireError};

fn body() -> MetadataReplicaBody {
    MetadataReplicaBody {
        format_version: 1,
        after: Some(MetadataReplicaCursor {
            partition_id: vec![1; 16],
            membership_epoch: 1,
            plan_digest: vec![2; 32],
            applied: Some(LogPosition { term: 0, index: 0 }),
            applied_digest: vec![0; 32],
        }),
        entries: vec![LogEntry {
            position: Some(LogPosition { term: 1, index: 1 }),
            operation_id: vec![3; 16],
            command_digest: vec![4; 32],
            command: Some(VersionedPayload {
                format_version: 1,
                canonical_bytes: vec![5; 96 * 1024],
            }),
        }],
    }
}

#[test]
fn metadata_replica_body_roundtrips_above_control_limit_and_rejects_noncanonical_bytes()
-> Result<(), WireContractError> {
    let expected = body();
    let bytes = encode_metadata_replica_body(&expected)?;
    assert!(bytes.len() > 64 * 1024);
    assert_eq!(decode_metadata_replica_body(&bytes)?, expected);
    let mut duplicate = bytes.clone();
    duplicate.extend_from_slice(&[8, 1]);
    assert!(decode_metadata_replica_body(&duplicate).is_err());
    let mut unknown = bytes.clone();
    unknown.extend_from_slice(&[32, 1]);
    assert!(decode_metadata_replica_body(&unknown).is_err());
    assert!(decode_metadata_replica_body(&bytes[..bytes.len() - 1]).is_err());
    Ok(())
}

#[test]
fn metadata_replica_body_rejects_gaps_oversized_pages_and_invalid_origins()
-> Result<(), WireContractError> {
    let mut invalid = body();
    invalid.entries[0].position = Some(LogPosition { term: 1, index: 2 });
    assert!(encode_metadata_replica_body(&invalid).is_err());
    let mut invalid = body();
    invalid.entries = vec![invalid.entries[0].clone(); 65];
    assert!(encode_metadata_replica_body(&invalid).is_err());
    let mut invalid = body();
    invalid
        .after
        .as_mut()
        .ok_or(WireContractError::InvalidMessage)?
        .applied_digest = vec![9; 32];
    assert!(encode_metadata_replica_body(&invalid).is_err());
    let mut invalid = body();
    invalid.entries[0]
        .command
        .as_mut()
        .ok_or(WireContractError::InvalidMessage)?
        .canonical_bytes = vec![0; MAXIMUM_METADATA_REPLICA_COMMAND_BYTES + 1];
    assert!(encode_metadata_replica_body(&invalid).is_err());
    Ok(())
}

#[test]
fn metadata_replica_response_rejects_mixed_success_error_and_excess_frames()
-> Result<(), WireContractError> {
    let limits = WireLimits::new(64 * 1024, 64 * 1024, 64, 1024)?;
    let mut response = MetadataReplicaPageHeader {
        request_id: vec![3; 16],
        after: None,
        byte_length: 0,
        digest: vec![],
        maximum_frame_bytes: 0,
        rejection: Some(WireError {
            code: ErrorCode::Unauthorised.into(),
            diagnostic_code: 1,
            retry_after_micros: None,
        }),
    };
    header(&response, limits)?;
    response.after = body().after;
    assert!(header(&response, limits).is_err());
    response.rejection = None;
    response.byte_length = 1;
    response.digest = vec![4; 32];
    response.maximum_frame_bytes = 64 * 1024 + 1;
    assert!(header(&response, limits).is_err());
    response.maximum_frame_bytes = 64 * 1024;
    header(&response, limits)?;
    response.byte_length = MAXIMUM_METADATA_REPLICA_BODY_BYTES as u64 + 1;
    assert!(header(&response, limits).is_err());
    Ok(())
}
