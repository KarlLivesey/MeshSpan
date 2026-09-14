// SPDX-License-Identifier: GPL-2.0-only

//! Internal relay framing retains the consumer signature without inventing owner signatures.

use super::*;
use meshspan_protocol::v1::{
    DataControlEnvelope, ForwardFederatedBackupReady, ForwardFederatedBackupRequest,
    ForwardFederatedBackupResult, RequestHeader, data_control_envelope::Message as DataMessage,
};
use meshspan_protocol::{decode_data_control_frame, encode_data_control_frame};

#[test]
fn relay_round_trips_every_operation_and_preserves_the_signed_envelope() -> TestResult {
    for action in [
        RemoteBackupAction::Store,
        RemoteBackupAction::Read,
        RemoteBackupAction::Verify,
        RemoteBackupAction::Delete,
    ] {
        let value = forwarded(action)?;
        let original = value.request.clone();
        let decoded = round_trip(DataMessage::ForwardFederatedBackupRequest(value))?;
        let Some(DataMessage::ForwardFederatedBackupRequest(decoded)) = decoded.message else {
            return Err("wrong relay variant".into());
        };
        assert_eq!(decoded.request, original);
        round_trip(DataMessage::ForwardFederatedBackupResult(
            ForwardFederatedBackupResult {
                request_digest: vec![40; 32],
                result: Some(result(action)),
            },
        ))?;
    }
    Ok(())
}

#[test]
fn relay_rejects_owner_and_correlation_substitution() -> TestResult {
    let original = forwarded(RemoteBackupAction::Store)?;
    let mut wrong_owner = original.clone();
    wrong_owner.provider_node_id = vec![99; 16];
    invalid_relay(wrong_owner)?;
    for field in ["mesh", "request", "operation", "trace", "deadline", "frame"] {
        let mut changed = original.clone();
        let header = changed.header.as_mut().ok_or("header")?;
        match field {
            "mesh" => header.mesh_id = vec![99; 16],
            "request" => header.request_id = vec![99; 16],
            "operation" => header.operation_id = vec![99; 16],
            "trace" => header.trace_id = vec![99; 16],
            "deadline" => header.deadline_unix_micros = 91,
            "frame" => changed.maximum_frame_bytes = 65_537,
            _ => return Err("unknown vector".into()),
        }
        invalid_relay(changed)?;
    }
    let mut wrong_family = original;
    wrong_family.request = encode_federation_frame(
        &envelope(
            Message::RequestBackupCapability(request(RemoteBackupAction::Store)),
            false,
        ),
        limits()?,
    )?;
    invalid_relay(wrong_family)
}

#[test]
fn unsigned_internal_replies_cannot_be_used_as_external_replies() -> TestResult {
    let ready = FederatedBackupReady {
        permit_digest: vec![24; 32],
        maximum_frame_bytes: 64,
        rejection: None,
        signature: Vec::new(),
    };
    round_trip(DataMessage::ForwardFederatedBackupReady(
        ForwardFederatedBackupReady {
            request_digest: vec![40; 32],
            ready: Some(ready.clone()),
        },
    ))?;
    invalid(&envelope(Message::BackupReady(ready.clone()), true))?;
    invalid(&envelope(
        Message::BackupResult(result(RemoteBackupAction::Store)),
        true,
    ))?;
    let mut signed = ready;
    signed.signature = vec![23; 64];
    assert_eq!(
        encode_data_control_frame(
            &DataControlEnvelope {
                message: Some(DataMessage::ForwardFederatedBackupReady(
                    ForwardFederatedBackupReady {
                        request_digest: vec![40; 32],
                        ready: Some(signed),
                    },
                )),
            },
            limits()?,
        ),
        Err(WireContractError::InvalidMessage)
    );
    Ok(())
}

#[test]
fn malformed_relay_streams_never_become_valid_requests() -> TestResult {
    let frame = encode_data_control_frame(
        &DataControlEnvelope {
            message: Some(DataMessage::ForwardFederatedBackupRequest(forwarded(
                RemoteBackupAction::Store,
            )?)),
        },
        limits()?,
    )?;
    for length in 0..frame.len() {
        assert!(
            decode_data_control_frame(frame.get(..length).ok_or("prefix")?, limits()?).is_err()
        );
    }
    let mut trailing = frame;
    trailing.push(0);
    assert!(decode_data_control_frame(&trailing, limits()?).is_err());
    Ok(())
}

fn forwarded(
    action: RemoteBackupAction,
) -> Result<ForwardFederatedBackupRequest, Box<dyn std::error::Error>> {
    Ok(ForwardFederatedBackupRequest {
        header: Some(RequestHeader {
            version: Some(ProtocolVersion { major: 1, minor: 0 }),
            mesh_id: vec![3; 16],
            partition_id: vec![31; 16],
            routing_epoch: 1,
            sender_node_id: vec![30; 16],
            sender_incarnation: 1,
            request_id: vec![4; 16],
            operation_id: vec![5; 16],
            deadline_unix_micros: 90,
            trace_id: vec![6; 16],
        }),
        provider_node_id: vec![10; 16],
        request: encode_federation_frame(
            &envelope(
                Message::ExecuteBackup(ExecuteFederatedBackup {
                    permit: Some(permit(&request(action))),
                    signature: vec![22; 64],
                }),
                false,
            ),
            limits()?,
        )?,
        maximum_frame_bytes: 64,
    })
}

fn result(action: RemoteBackupAction) -> FederatedBackupResult {
    FederatedBackupResult {
        permit_digest: vec![24; 32],
        completed_at_unix_micros: 50,
        outcome: Some(outcome(action)),
        signature: Vec::new(),
    }
}

fn round_trip(message: DataMessage) -> Result<DataControlEnvelope, Box<dyn std::error::Error>> {
    let envelope = DataControlEnvelope {
        message: Some(message),
    };
    let decoded =
        decode_data_control_frame(&encode_data_control_frame(&envelope, limits()?)?, limits()?)?
            .into_inner();
    assert_eq!(decoded, envelope);
    Ok(decoded)
}

fn invalid_relay(request: ForwardFederatedBackupRequest) -> TestResult {
    assert_eq!(
        encode_data_control_frame(
            &DataControlEnvelope {
                message: Some(DataMessage::ForwardFederatedBackupRequest(request)),
            },
            limits()?,
        ),
        Err(WireContractError::InvalidMessage)
    );
    Ok(())
}
