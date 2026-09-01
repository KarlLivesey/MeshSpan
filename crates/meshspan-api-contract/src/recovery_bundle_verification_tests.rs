// SPDX-License-Identifier: GPL-2.0-only

use serde_json::json;

use crate::{
    ConfirmRecoveryBundleResponse, OperationId, decode_confirm_recovery_bundle_request,
    encode_confirm_recovery_bundle_response,
};

#[test]
fn request_requires_exact_identifiers_and_canonical_challenge()
-> Result<(), Box<dyn std::error::Error>> {
    let valid = json!({
        "operation_id": "00000000-0000-4000-8000-000000000041",
        "mesh_id": "00000000-0000-4000-8000-000000000042",
        "recovery_challenge": "meshspan-check-v1.0102030405060708"
    });
    assert!(decode_confirm_recovery_bundle_request(&serde_json::to_vec(&valid)?).is_ok());
    for value in [
        json!({
            "operation_id": "00000000-0000-4000-8000-000000000041",
            "mesh_id": "00000000-0000-4000-8000-000000000042",
            "recovery_challenge": "meshspan-check-v1.0102030405060708",
            "unknown": true
        }),
        json!({
            "operation_id": "00000000-0000-4000-8000-000000000041",
            "mesh_id": "00000000-0000-4000-8000-000000000042",
            "recovery_challenge": "meshspan-check-v1.010203040506070A"
        }),
        json!({
            "operation_id": "00000000-0000-4000-8000-000000000041",
            "mesh_id": "not-a-mesh",
            "recovery_challenge": "meshspan-check-v1.0102030405060708"
        }),
    ] {
        assert!(decode_confirm_recovery_bundle_request(&serde_json::to_vec(&value)?).is_err());
    }
    Ok(())
}

#[test]
fn response_is_validated_before_emission() -> Result<(), Box<dyn std::error::Error>> {
    let operation_id =
        OperationId::parse("00000000-0000-4000-8000-000000000041").ok_or("invalid operation")?;
    let valid = ConfirmRecoveryBundleResponse {
        operation_id: operation_id.clone(),
        mesh_id: "00000000-0000-4000-8000-000000000042".to_owned(),
        verified_at_epoch_micros: 50,
        revision: 2,
    };
    assert!(encode_confirm_recovery_bundle_response(&valid).is_ok());
    assert!(
        encode_confirm_recovery_bundle_response(&ConfirmRecoveryBundleResponse {
            revision: 0,
            ..valid
        })
        .is_err()
    );
    Ok(())
}
