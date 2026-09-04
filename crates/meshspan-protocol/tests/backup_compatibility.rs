// SPDX-License-Identifier: GPL-2.0-only

//! Private remote-backup control-stream compatibility and hostile-input vectors.

use meshspan_protocol::v1::data_control_envelope::Message;
use meshspan_protocol::v1::{
    BackupDeleteReceipt, BackupObjectIdentity, BackupObjectReceipt, BackupReadReceipt,
    DataControlEnvelope, DeleteBackupRequest, DeleteBackupResult, ErrorCode, OperationOutcome,
    OperationResult, ProtocolVersion, ReadBackupHeader, ReadBackupRequest, ReadBackupResult,
    RequestHeader, StoreBackupBegin, StoreBackupFinish, StoreBackupReady, StoreBackupResult,
    VerifyBackupRequest, VerifyBackupResult, WireError,
};
use meshspan_protocol::{
    WireContractError, WireLimits, decode_data_control_frame, encode_data_control_frame,
};

#[test]
fn exact_backup_operations_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let limits = limits()?;
    let object = object();
    let object_receipt = BackupObjectReceipt {
        operation_id: vec![5; 16],
        object: Some(object.clone()),
        object_reference: "objects/backup-7".to_owned(),
    };
    let accepted = [
        envelope(Message::StoreBackupBegin(StoreBackupBegin {
            header: Some(header()),
            object: Some(object.clone()),
            authority_revision: 9,
        })),
        envelope(Message::StoreBackupReady(StoreBackupReady {
            reservation: vec![11; 16],
            maximum_frame_bytes: 1_024,
            rejection: None,
        })),
        envelope(Message::StoreBackupFinish(StoreBackupFinish {
            final_length: object.byte_length,
            final_digest: object.digest.clone(),
        })),
        envelope(Message::StoreBackupResult(StoreBackupResult {
            result: Some(durable_result()),
            receipt: Some(object_receipt.clone()),
        })),
        envelope(Message::ReadBackupRequest(ReadBackupRequest {
            header: Some(header()),
            object: Some(object.clone()),
            object_reference: object_receipt.object_reference.clone(),
            authority_revision: 9,
        })),
        envelope(Message::ReadBackupHeader(ReadBackupHeader {
            byte_length: object.byte_length,
            digest: object.digest.clone(),
            maximum_frame_bytes: 1_024,
            rejection: None,
        })),
        envelope(Message::ReadBackupResult(ReadBackupResult {
            result: Some(durable_result()),
            receipt: Some(BackupReadReceipt {
                operation_id: vec![5; 16],
                byte_length: object.byte_length,
                digest: object.digest.clone(),
            }),
        })),
        envelope(Message::VerifyBackupRequest(VerifyBackupRequest {
            header: Some(header()),
            object: Some(object.clone()),
            object_reference: object_receipt.object_reference.clone(),
            authority_revision: 9,
        })),
        envelope(Message::VerifyBackupResult(VerifyBackupResult {
            result: Some(durable_result()),
            receipt: Some(object_receipt),
        })),
        envelope(Message::DeleteBackupRequest(DeleteBackupRequest {
            header: Some(header()),
            object: Some(object.clone()),
            object_reference: "objects/backup-7".to_owned(),
            retirement_revision: 10,
        })),
        envelope(Message::DeleteBackupResult(DeleteBackupResult {
            result: Some(durable_result()),
            receipt: Some(BackupDeleteReceipt {
                operation_id: vec![5; 16],
                object: Some(object),
                retirement_revision: 10,
            }),
        })),
    ];

    for message in accepted {
        let encoded = encode_data_control_frame(&message, limits)?;
        assert_eq!(
            decode_data_control_frame(&encoded, limits)?.into_inner(),
            message
        );
    }
    Ok(())
}

#[test]
fn rejected_backup_operations_have_no_success_evidence() -> Result<(), Box<dyn std::error::Error>> {
    let limits = limits()?;
    for message in [
        envelope(Message::StoreBackupReady(StoreBackupReady {
            reservation: Vec::new(),
            maximum_frame_bytes: 0,
            rejection: Some(unavailable()),
        })),
        envelope(Message::ReadBackupHeader(ReadBackupHeader {
            byte_length: 0,
            digest: Vec::new(),
            maximum_frame_bytes: 0,
            rejection: Some(unavailable()),
        })),
        envelope(Message::StoreBackupResult(StoreBackupResult {
            result: Some(rejected_result()),
            receipt: None,
        })),
        envelope(Message::ReadBackupResult(ReadBackupResult {
            result: Some(rejected_result()),
            receipt: None,
        })),
        envelope(Message::VerifyBackupResult(VerifyBackupResult {
            result: Some(rejected_result()),
            receipt: None,
        })),
        envelope(Message::DeleteBackupResult(DeleteBackupResult {
            result: Some(rejected_result()),
            receipt: None,
        })),
    ] {
        assert!(encode_data_control_frame(&message, limits).is_ok());
    }
    Ok(())
}

#[test]
fn backup_controls_reject_ambiguous_or_unbounded_values() -> Result<(), Box<dyn std::error::Error>>
{
    let limits = limits()?;
    let invalid = [
        envelope(Message::StoreBackupBegin(StoreBackupBegin {
            header: Some(header()),
            object: Some(BackupObjectIdentity {
                digest: vec![0; 32],
                ..object()
            }),
            authority_revision: 9,
        })),
        envelope(Message::StoreBackupBegin(StoreBackupBegin {
            header: Some(header()),
            object: Some(object()),
            authority_revision: 0,
        })),
        envelope(Message::StoreBackupReady(StoreBackupReady {
            reservation: vec![11; 16],
            maximum_frame_bytes: 1_024,
            rejection: Some(unavailable()),
        })),
        envelope(Message::ReadBackupRequest(ReadBackupRequest {
            header: Some(header()),
            object: Some(object()),
            object_reference: "x".repeat(2_049),
            authority_revision: 9,
        })),
        envelope(Message::ReadBackupHeader(ReadBackupHeader {
            byte_length: 10,
            digest: vec![9; 32],
            maximum_frame_bytes: 1_024,
            rejection: Some(unavailable()),
        })),
        envelope(Message::StoreBackupResult(StoreBackupResult {
            result: Some(durable_result()),
            receipt: None,
        })),
        envelope(Message::DeleteBackupRequest(DeleteBackupRequest {
            header: Some(header()),
            object: Some(object()),
            object_reference: "objects/backup-7".to_owned(),
            retirement_revision: 0,
        })),
    ];

    for message in invalid {
        assert_eq!(
            encode_data_control_frame(&message, limits),
            Err(WireContractError::InvalidMessage)
        );
    }
    Ok(())
}

fn envelope(message: Message) -> DataControlEnvelope {
    DataControlEnvelope {
        message: Some(message),
    }
}

fn object() -> BackupObjectIdentity {
    BackupObjectIdentity {
        backup_id: vec![7; 16],
        destination_id: vec![8; 16],
        provider_generation: 2,
        byte_length: 10,
        digest: vec![9; 32],
    }
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

fn durable_result() -> OperationResult {
    OperationResult {
        outcome: OperationOutcome::Durable.into(),
        committed_revision: None,
        error: None,
        result: None,
        result_digest: Vec::new(),
    }
}

fn rejected_result() -> OperationResult {
    OperationResult {
        outcome: OperationOutcome::Rejected.into(),
        committed_revision: None,
        error: Some(unavailable()),
        result: None,
        result_digest: Vec::new(),
    }
}

fn unavailable() -> WireError {
    WireError {
        code: ErrorCode::Unavailable.into(),
        diagnostic_code: 1,
        retry_after_micros: Some(1),
    }
}

fn limits() -> Result<WireLimits, WireContractError> {
    WireLimits::new(4 * 1_024 * 1_024, 1_024 * 1_024, 4_096, 4_096)
}
