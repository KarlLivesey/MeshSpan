// SPDX-License-Identifier: GPL-2.0-only

//! Public framing vectors for every backup phase and operation.

use meshspan_protocol::v1::{
    BackupDeleteReceipt, BackupObjectIdentity, BackupObjectReceipt, BackupReadReceipt,
    ExecuteFederatedBackup, FederatedBackupCapability, FederatedBackupOperation,
    FederatedBackupPermit, FederatedBackupReady, FederatedBackupResult, FederatedBackupScope,
    FederationEnvelope, FederationHeader, ProtocolVersion, RemoteBackupAction,
    RequestFederatedBackupCapability, federated_backup_result::Outcome,
    federation_envelope::Message,
};
use meshspan_protocol::{
    WireContractError, WireLimits, decode_federation_frame, encode_federation_frame,
    federation_backup_request_digest_payload, federation_backup_signing_payload,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[path = "federation_backup/relay.rs"]
mod relay;

#[test]
fn all_backup_operations_round_trip_through_all_five_conversation_phases() -> TestResult {
    let limits = limits()?;
    for action in [
        RemoteBackupAction::Lookup,
        RemoteBackupAction::Store,
        RemoteBackupAction::Read,
        RemoteBackupAction::Verify,
        RemoteBackupAction::Delete,
    ] {
        let request = request(action);
        let permit = permit(&request);
        let messages = [
            envelope(Message::RequestBackupCapability(request.clone()), false),
            envelope(
                Message::BackupCapability(FederatedBackupCapability {
                    request_digest: vec![20; 32],
                    permit: Some(permit.clone()),
                    rejection: None,
                    signature: vec![21; 64],
                }),
                true,
            ),
            envelope(
                Message::ExecuteBackup(ExecuteFederatedBackup {
                    permit: Some(permit),
                    signature: vec![22; 64],
                }),
                false,
            ),
            envelope(
                Message::BackupReady(FederatedBackupReady {
                    permit_digest: vec![24; 32],
                    maximum_frame_bytes: 64,
                    rejection: None,
                    signature: vec![23; 64],
                }),
                true,
            ),
            envelope(
                Message::BackupResult(FederatedBackupResult {
                    permit_digest: vec![24; 32],
                    completed_at_unix_micros: 50,
                    outcome: Some(outcome(action)),
                    signature: vec![25; 64],
                }),
                true,
            ),
        ];
        for message in messages {
            assert_eq!(
                decode_federation_frame(&encode_federation_frame(&message, limits)?, limits)?
                    .into_inner(),
                message
            );
        }
    }
    Ok(())
}

#[test]
fn backup_attempt_may_end_before_its_operation_but_never_after_it() -> TestResult {
    let limits = limits()?;
    let mut request = request(RemoteBackupAction::Read);
    request
        .operation
        .as_mut()
        .ok_or("operation")?
        .deadline_unix_micros = 3_600_000_000;
    let permit = permit(&request);
    for message in [
        envelope(Message::RequestBackupCapability(request), false),
        envelope(
            Message::BackupCapability(FederatedBackupCapability {
                request_digest: vec![20; 32],
                permit: Some(permit.clone()),
                rejection: None,
                signature: vec![21; 64],
            }),
            true,
        ),
        envelope(
            Message::ExecuteBackup(ExecuteFederatedBackup {
                permit: Some(permit),
                signature: vec![22; 64],
            }),
            false,
        ),
    ] {
        assert_eq!(
            decode_federation_frame(&encode_federation_frame(&message, limits)?, limits)?
                .into_inner(),
            message
        );
        let mut expired = message;
        // The permit expires at 90: shortening the enclosing attempt to 89 cannot
        // silently extend that capability beyond the authenticated exchange.
        expired
            .header
            .as_mut()
            .ok_or("header")?
            .deadline_unix_micros = 89;
        if !matches!(expired.message, Some(Message::RequestBackupCapability(_))) {
            invalid(&expired)?;
        }
    }
    Ok(())
}

#[test]
fn namespace_origin_is_required_and_covered_by_the_signed_request() -> TestResult {
    let original = request(RemoteBackupAction::Store);
    let digest = federation_backup_request_digest_payload(&original)?;
    for invalid_origin in [Vec::new(), vec![0; 16], vec![9; 15], vec![9; 17]] {
        let mut changed = original.clone();
        changed.scope.as_mut().ok_or("scope")?.namespace_grant_id = invalid_origin;
        invalid(&envelope(Message::RequestBackupCapability(changed), false))?;
    }
    let mut changed = original;
    changed.scope.as_mut().ok_or("scope")?.namespace_grant_id = vec![8; 16];
    assert_ne!(federation_backup_request_digest_payload(&changed)?, digest);
    Ok(())
}

#[test]
fn backup_operations_reject_ambiguous_actions_and_context_substitution() -> TestResult {
    let original = request(RemoteBackupAction::Store);
    let mut changed = vec![original.clone(); 8];
    changed
        .get_mut(0)
        .ok_or("vector")?
        .operation
        .as_mut()
        .ok_or("operation")?
        .action = 99;
    changed
        .get_mut(1)
        .ok_or("vector")?
        .operation
        .as_mut()
        .ok_or("operation")?
        .authority_revision = None;
    changed
        .get_mut(2)
        .ok_or("vector")?
        .operation
        .as_mut()
        .ok_or("operation")?
        .authority_revision = Some(0);
    changed
        .get_mut(3)
        .ok_or("vector")?
        .operation
        .as_mut()
        .ok_or("operation")?
        .object_reference = "not a store field".into();
    changed
        .get_mut(4)
        .ok_or("vector")?
        .operation
        .as_mut()
        .ok_or("operation")?
        .retirement_revision = Some(9);
    changed
        .get_mut(5)
        .ok_or("vector")?
        .operation
        .as_mut()
        .ok_or("operation")?
        .deadline_unix_micros = 99;
    changed
        .get_mut(6)
        .ok_or("vector")?
        .scope
        .as_mut()
        .ok_or("scope")?
        .provider_mesh_id = vec![2; 16];
    changed
        .get_mut(7)
        .ok_or("vector")?
        .scope
        .as_mut()
        .ok_or("scope")?
        .relationship_authority_epoch = 2;
    for request in changed {
        invalid(&envelope(Message::RequestBackupCapability(request), false))?;
    }
    let mut deletion = request(RemoteBackupAction::Delete);
    deletion
        .operation
        .as_mut()
        .ok_or("operation")?
        .retirement_revision = Some(8);
    invalid(&envelope(Message::RequestBackupCapability(deletion), false))?;
    let mut read = request(RemoteBackupAction::Read);
    read.operation.as_mut().ok_or("operation")?.object_reference = "../\n".into();
    invalid(&envelope(Message::RequestBackupCapability(read), false))
}

#[test]
fn permit_and_response_shapes_cannot_claim_conflicting_success() -> TestResult {
    let request = request(RemoteBackupAction::Store);
    let original = permit(&request);
    let mut bad = vec![original.clone(); 4];
    bad.get_mut(0).ok_or("vector")?.expires_at_unix_micros = 30;
    bad.get_mut(1).ok_or("vector")?.expires_at_unix_micros = i64::MAX;
    bad.get_mut(2).ok_or("vector")?.capability_nonce = vec![0; 32];
    bad.get_mut(3).ok_or("vector")?.permit_digest.clear();
    for permit in bad {
        invalid(&envelope(
            Message::ExecuteBackup(ExecuteFederatedBackup {
                permit: Some(permit),
                signature: vec![1; 64],
            }),
            false,
        ))?;
    }
    invalid(&envelope(
        Message::BackupCapability(FederatedBackupCapability {
            request_digest: vec![1; 32],
            permit: None,
            rejection: None,
            signature: vec![1; 64],
        }),
        true,
    ))?;
    invalid(&envelope(
        Message::BackupReady(FederatedBackupReady {
            permit_digest: vec![1; 32],
            maximum_frame_bytes: 65_537,
            rejection: None,
            signature: vec![1; 64],
        }),
        true,
    ))?;
    let mut result = FederatedBackupResult {
        permit_digest: vec![1; 32],
        completed_at_unix_micros: 101,
        outcome: Some(outcome(RemoteBackupAction::Store)),
        signature: vec![1; 64],
    };
    invalid(&envelope(Message::BackupResult(result.clone()), true))?;
    result.completed_at_unix_micros = 50;
    let Some(Outcome::Stored(receipt)) = result.outcome.as_mut() else {
        return Err("receipt".into());
    };
    receipt.operation_id = vec![99; 16];
    invalid(&envelope(Message::BackupResult(result), true))
}

#[test]
fn signing_domains_cover_context_and_body_but_exclude_only_the_signature() -> TestResult {
    let request = request(RemoteBackupAction::Store);
    let original = envelope(Message::RequestBackupCapability(request.clone()), false);
    let header = original.header.as_ref().ok_or("header")?;
    let message = original.message.as_ref().ok_or("message")?;
    let expected = federation_backup_signing_payload(header, message)?;
    assert!(expected.starts_with(b"meshspan.federation.backup-capability-request.v1\0"));
    let mut resign = request.clone();
    resign.signature = vec![77; 64];
    assert_eq!(
        federation_backup_signing_payload(
            header,
            &Message::RequestBackupCapability(resign.clone())
        )?,
        expected
    );
    assert_eq!(
        federation_backup_request_digest_payload(&resign)?,
        federation_backup_request_digest_payload(&request)?
    );
    resign.scope.as_mut().ok_or("scope")?.allocation_id = vec![77; 16];
    assert_ne!(
        federation_backup_signing_payload(
            header,
            &Message::RequestBackupCapability(resign.clone())
        )?,
        expected
    );
    assert_ne!(
        federation_backup_request_digest_payload(&resign)?,
        federation_backup_request_digest_payload(&request)?
    );
    let mut changed_header = header.clone();
    changed_header.trace_id = vec![88; 16];
    assert_ne!(
        federation_backup_signing_payload(&changed_header, message)?,
        expected
    );
    Ok(())
}

fn invalid(value: &FederationEnvelope) -> TestResult {
    assert_eq!(
        encode_federation_frame(value, limits()?),
        Err(WireContractError::InvalidMessage)
    );
    Ok(())
}

fn limits() -> Result<WireLimits, WireContractError> {
    // The field budget counts the complete nested envelope, not just repeated items.
    WireLimits::new(4096, 65536, 128, 2048)
}

#[test]
fn a_peer_with_insufficient_nested_field_budget_rejects_before_admission() -> TestResult {
    let frame = encode_federation_frame(
        &envelope(
            Message::RequestBackupCapability(request(RemoteBackupAction::Store)),
            false,
        ),
        limits()?,
    )?;
    assert_eq!(
        decode_federation_frame(&frame, WireLimits::new(4096, 65536, 32, 2048)?),
        Err(WireContractError::Malformed)
    );
    Ok(())
}

fn request(action: RemoteBackupAction) -> RequestFederatedBackupCapability {
    RequestFederatedBackupCapability {
        scope: Some(FederatedBackupScope {
            relationship_id: vec![1; 16],
            remote_mesh_id: vec![2; 16],
            provider_mesh_id: vec![3; 16],
            allocation_id: vec![8; 16],
            grant_id: vec![9; 16],
            namespace_grant_id: vec![9; 16],
            provider_node_id: vec![10; 16],
            target_id: vec![11; 16],
            target_generation: 1,
            relationship_authority_epoch: 1,
            grant_revision: 9,
            allocation_revision: 10,
        }),
        operation: Some(FederatedBackupOperation {
            contract_version: Some(ProtocolVersion { major: 1, minor: 0 }),
            operation_id: vec![5; 16],
            deadline_unix_micros: 100,
            authority_revision: Some(9),
            object: Some(object()),
            action: action.into(),
            object_reference: if matches!(
                action,
                RemoteBackupAction::Store | RemoteBackupAction::Lookup
            ) {
                String::new()
            } else {
                "backup.ms".into()
            },
            retirement_revision: (action == RemoteBackupAction::Delete).then_some(9),
        }),
        signature: vec![1; 64],
    }
}

fn permit(request: &RequestFederatedBackupCapability) -> FederatedBackupPermit {
    FederatedBackupPermit {
        scope: request.scope.clone(),
        operation: request.operation.clone(),
        issued_at_unix_micros: 30,
        expires_at_unix_micros: 90,
        capability_nonce: vec![23; 32],
        permit_digest: vec![24; 32],
    }
}

fn object() -> BackupObjectIdentity {
    BackupObjectIdentity {
        backup_id: vec![12; 16],
        destination_id: vec![13; 16],
        provider_generation: 7,
        byte_length: 10,
        digest: vec![14; 32],
    }
}

fn outcome(action: RemoteBackupAction) -> Outcome {
    let receipt = BackupObjectReceipt {
        operation_id: vec![5; 16],
        object: Some(object()),
        object_reference: "backup.ms".into(),
    };
    match action {
        RemoteBackupAction::Lookup => Outcome::LookedUp(receipt),
        RemoteBackupAction::Store => Outcome::Stored(receipt),
        RemoteBackupAction::Verify => Outcome::Verified(receipt),
        RemoteBackupAction::Read => Outcome::Read(BackupReadReceipt {
            operation_id: vec![5; 16],
            byte_length: 10,
            digest: vec![14; 32],
        }),
        RemoteBackupAction::Delete | RemoteBackupAction::Unspecified => {
            Outcome::Deleted(BackupDeleteReceipt {
                operation_id: vec![5; 16],
                object: Some(object()),
                retirement_revision: 9,
            })
        }
    }
}

fn envelope(message: Message, response: bool) -> FederationEnvelope {
    FederationEnvelope {
        header: Some(FederationHeader {
            version: Some(ProtocolVersion { major: 1, minor: 0 }),
            relationship_id: vec![1; 16],
            sender_mesh_id: vec![if response { 3 } else { 2 }; 16],
            recipient_mesh_id: vec![if response { 2 } else { 3 }; 16],
            request_id: vec![4; 16],
            operation_id: vec![5; 16],
            authority_epoch: 1,
            deadline_unix_micros: 100,
            trace_id: vec![6; 16],
            replay_nonce: vec![7; 32],
        }),
        message: Some(message),
    }
}
