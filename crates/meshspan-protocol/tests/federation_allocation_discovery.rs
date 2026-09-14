// SPDX-License-Identifier: GPL-2.0-only

//! Independent canonical continuation and hostile allocation-page vectors.

use meshspan_protocol::v1::{
    FederatedBackupAllocationCursor, FederationEnvelope, FederationHeader,
    FetchFederatedBackupAllocations, ProtocolVersion, federation_envelope::Message,
};
use meshspan_protocol::{
    WireLimits, decode_backup_allocation_cursor, decode_federation_frame,
    encode_backup_allocation_cursor, encode_federation_frame,
    federation_backup_allocation_request_digest_payload,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn allocation_cursor_has_exact_canonical_bytes_and_rejects_ambiguity() -> TestResult {
    let cursor = cursor();
    let mut expected = vec![0x08, 1, 0x12, 16];
    expected.extend_from_slice(&[1; 16]);
    expected.extend_from_slice(&[0x18, 1, 0x22, 16]);
    expected.extend_from_slice(&[2; 16]);
    expected.extend_from_slice(&[0x28, 0x80, 0x08, 0x30, 6, 0x38, 20, 0x40, 40, 0x4a, 16]);
    expected.extend_from_slice(&[3; 16]);
    assert_eq!(encode_backup_allocation_cursor(&cursor)?, expected);
    assert_eq!(decode_backup_allocation_cursor(&expected)?, cursor);
    for suffix in [vec![0x08, 1], vec![0x50, 1]] {
        let mut changed = expected.clone();
        changed.extend(suffix);
        assert!(decode_backup_allocation_cursor(&changed).is_err());
    }
    assert!(decode_backup_allocation_cursor(&[1; 129]).is_err());
    let mut changed = cursor;
    changed.valid_until_unix_micros = 10;
    assert!(encode_backup_allocation_cursor(&changed).is_err());
    Ok(())
}

#[test]
fn allocation_query_binds_cursor_scope_size_epoch_and_unsigned_digest() -> TestResult {
    let limits = WireLimits::new(8192, 16384, 32, 4096)?;
    let mut request = FetchFederatedBackupAllocations {
        grant_id: vec![2; 16],
        required_bytes: 1024,
        cursor: encode_backup_allocation_cursor(&cursor())?,
        limit: 1,
        signature: vec![4; 64],
    };
    let envelope = envelope(request.clone());
    assert_eq!(
        decode_federation_frame(&encode_federation_frame(&envelope, limits)?, limits)?.into_inner(),
        envelope
    );
    let digest_bytes = federation_backup_allocation_request_digest_payload(&request)?;
    request.signature.fill(5);
    assert_eq!(
        federation_backup_allocation_request_digest_payload(&request)?,
        digest_bytes
    );
    for (index, mut changed) in [request.clone(), request.clone(), request.clone()]
        .into_iter()
        .enumerate()
    {
        match index {
            0 => changed.required_bytes = 2048,
            1 => changed.grant_id = vec![6; 16],
            _ => changed.limit = 0,
        }
        assert!(encode_federation_frame(&self::envelope(changed), limits).is_err());
    }
    let mut reflected = envelope;
    reflected.header.as_mut().ok_or("header")?.authority_epoch = 2;
    assert!(encode_federation_frame(&reflected, limits).is_err());
    request.cursor.clear();
    request.required_bytes = 2048;
    assert_ne!(
        federation_backup_allocation_request_digest_payload(&request)?,
        digest_bytes
    );
    Ok(())
}

fn cursor() -> FederatedBackupAllocationCursor {
    FederatedBackupAllocationCursor {
        format_version: 1,
        relationship_id: vec![1; 16],
        authority_epoch: 1,
        grant_id: vec![2; 16],
        required_bytes: 1024,
        snapshot_revision: 6,
        valid_from_unix_micros: 10,
        valid_until_unix_micros: 20,
        allocation_id: vec![3; 16],
    }
}

fn envelope(request: FetchFederatedBackupAllocations) -> FederationEnvelope {
    FederationEnvelope {
        header: Some(FederationHeader {
            version: Some(ProtocolVersion { major: 1, minor: 0 }),
            relationship_id: vec![1; 16],
            sender_mesh_id: vec![7; 16],
            recipient_mesh_id: vec![8; 16],
            request_id: vec![9; 16],
            operation_id: vec![10; 16],
            authority_epoch: 1,
            deadline_unix_micros: 100,
            trace_id: vec![11; 16],
            replay_nonce: vec![12; 32],
        }),
        message: Some(Message::FetchBackupAllocations(request)),
    }
}
