// SPDX-License-Identifier: GPL-2.0-only

//! Altered and out-of-order owner payloads cannot become gateway-signed receipts.

use super::{NOW, TestResult};
use crate::FederationBackupOwnerResponseExpectation;
use meshspan_protocol::{
    ValidatedDataControlEnvelope, WireLimits,
    v1::{
        BackupObjectReceipt, DataControlEnvelope, FederatedBackupReady, FederatedBackupResult,
        ForwardFederatedBackupReady, ForwardFederatedBackupRequest, ForwardFederatedBackupResult,
        data_control_envelope::Message, federated_backup_result::Outcome,
    },
};

pub(super) fn prove(request: &ForwardFederatedBackupRequest, limits: WireLimits) -> TestResult<()> {
    let decoded =
        meshspan_protocol::decode_federation_frame(&request.request, limits)?.into_inner();
    let Some(meshspan_protocol::v1::federation_envelope::Message::ExecuteBackup(execution)) =
        decoded.message
    else {
        return Err("execute".into());
    };
    let permit = execution.permit.ok_or("permit")?;
    let operation = permit.operation.as_ref().ok_or("operation")?;
    let digest = crate::federation_backup_relay_digest(request, limits)?.to_vec();
    let ready = ForwardFederatedBackupReady {
        request_digest: digest.clone(),
        ready: Some(FederatedBackupReady {
            permit_digest: permit.permit_digest.clone(),
            maximum_frame_bytes: 64,
            rejection: None,
            signature: Vec::new(),
        }),
    };
    let result = ForwardFederatedBackupResult {
        request_digest: digest,
        result: Some(FederatedBackupResult {
            permit_digest: permit.permit_digest.clone(),
            completed_at_unix_micros: NOW.get(),
            signature: Vec::new(),
            outcome: Some(Outcome::Stored(BackupObjectReceipt {
                operation_id: operation.operation_id.clone(),
                object: operation.object.clone(),
                object_reference: "backup.ms".into(),
            })),
        }),
    };
    let accepted_ready = validate(Message::ForwardFederatedBackupReady(ready.clone()), limits)?;
    let accepted_result = validate(
        Message::ForwardFederatedBackupResult(result.clone()),
        limits,
    )?;
    prove_ready_rejections(request, &ready, limits)?;
    for field in [
        "request",
        "permit",
        "operation",
        "object",
        "future",
        "before-issued",
    ] {
        let mut altered = result.clone();
        let payload = altered.result.as_mut().ok_or("result")?;
        let Some(Outcome::Stored(receipt)) = payload.outcome.as_mut() else {
            return Err("receipt".into());
        };
        match field {
            "request" => altered.request_digest.fill(99),
            "permit" => payload.permit_digest.fill(99),
            "operation" => receipt.operation_id.fill(99),
            "object" => receipt.object.as_mut().ok_or("object")?.backup_id.fill(99),
            "future" => payload.completed_at_unix_micros = NOW.get() + 1,
            "before-issued" => payload.completed_at_unix_micros = permit.issued_at_unix_micros - 1,
            _ => return Err("vector".into()),
        }
        let mut expected = FederationBackupOwnerResponseExpectation::new(request, limits)?;
        expected.accept(&accepted_ready, NOW)?;
        assert!(
            expected
                .accept(
                    &validate(Message::ForwardFederatedBackupResult(altered), limits)?,
                    NOW
                )
                .is_err(),
            "{field}"
        );
        expected.accept(&accepted_result, NOW)?;
    }
    let mut expected = FederationBackupOwnerResponseExpectation::new(request, limits)?;
    assert!(expected.accept(&accepted_result, NOW).is_err());
    expected.accept(&accepted_ready, NOW)?;
    assert!(expected.accept(&accepted_ready, NOW).is_err());
    expected.accept(&accepted_result, NOW)?;
    assert!(expected.accept(&accepted_result, NOW).is_err());
    let mut expected = FederationBackupOwnerResponseExpectation::new(request, limits)?;
    assert!(
        expected
            .accept(
                &accepted_ready,
                meshspan_domain::UnixMicros::new(permit.expires_at_unix_micros)
            )
            .is_err()
    );
    Ok(())
}

fn prove_ready_rejections(
    request: &ForwardFederatedBackupRequest,
    ready: &ForwardFederatedBackupReady,
    limits: WireLimits,
) -> TestResult<()> {
    for field in ["request", "permit", "size"] {
        let mut altered = ready.clone();
        match field {
            "request" => altered.request_digest.fill(99),
            "permit" => altered
                .ready
                .as_mut()
                .ok_or("ready")?
                .permit_digest
                .fill(99),
            "size" => altered.ready.as_mut().ok_or("ready")?.maximum_frame_bytes = 65,
            _ => return Err("vector".into()),
        }
        let mut expected = FederationBackupOwnerResponseExpectation::new(request, limits)?;
        assert!(
            expected
                .accept(
                    &validate(Message::ForwardFederatedBackupReady(altered), limits)?,
                    NOW
                )
                .is_err(),
            "{field}"
        );
        expected.accept(
            &validate(Message::ForwardFederatedBackupReady(ready.clone()), limits)?,
            NOW,
        )?;
    }
    Ok(())
}

fn validate(message: Message, limits: WireLimits) -> TestResult<ValidatedDataControlEnvelope> {
    Ok(meshspan_protocol::decode_data_control_frame(
        &meshspan_protocol::encode_data_control_frame(
            &DataControlEnvelope {
                message: Some(message),
            },
            limits,
        )?,
        limits,
    )?)
}
