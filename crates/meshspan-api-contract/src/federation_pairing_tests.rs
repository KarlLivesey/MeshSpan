// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::{
    AcceptFederationPairingResponse, MAX_FEDERATION_CONNECTION_BYTES,
    decode_accept_federation_pairing_request, decode_accept_federation_pairing_response,
    encode_accept_federation_pairing_response,
};
use serde_json::json;

#[test]
fn federation_acceptance_validates_both_directions() -> Result<(), Box<dyn std::error::Error>> {
    let request = json!({"operation_id": "11111111-1111-8111-8111-111111111111", "peer_record": "A".repeat(172)});
    let accepted = decode_accept_federation_pairing_request(&serde_json::to_vec(&request)?)?;
    for (field, value) in [
        ("unknown", json!(true)),
        ("peer_record", json!(null)),
        ("peer_record", json!("A".repeat(171))),
        ("peer_record", json!("A".repeat(24577))),
        ("peer_record", json!("=".repeat(172))),
        ("operation_id", json!(7)),
    ] {
        let mut invalid = request.clone();
        invalid[field] = value;
        assert!(decode_accept_federation_pairing_request(&serde_json::to_vec(&invalid)?).is_err());
    }
    assert!(matches!(
        decode_accept_federation_pairing_request(&vec![b' '; MAX_FEDERATION_CONNECTION_BYTES + 1]),
        Err(BoundaryError::BodyTooLarge { .. })
    ));
    let mut response = AcceptFederationPairingResponse {
        operation_id: accepted.operation_id.clone(),
        relationship_id: accepted.operation_id,
        peer_record: accepted.peer_record,
        committed_revision: 4,
    };
    let encoded = encode_accept_federation_pairing_response(&response)?;
    assert_eq!(
        decode_accept_federation_pairing_response(&encoded)?.committed_revision,
        4
    );
    response.committed_revision = 0;
    assert!(encode_accept_federation_pairing_response(&response).is_err());
    response.committed_revision = 9_007_199_254_740_992;
    assert!(encode_accept_federation_pairing_response(&response).is_err());
    Ok(())
}

#[test]
fn federation_pairing_requests_reject_coercion_unknown_fields_and_bounds()
-> Result<(), Box<dyn std::error::Error>> {
    let request = json!({"operation_id": "11111111-1111-8111-8111-111111111111",
        "pairing_endpoint": "https://files.example.test", "valid_for_seconds": 900});
    assert_eq!(
        decode_create_federation_pairing_request(&serde_json::to_vec(&request)?)?.valid_for_seconds,
        900
    );
    for (field, value) in [
        ("unknown", json!(true)),
        ("valid_for_seconds", json!("900")),
        ("valid_for_seconds", json!(59)),
        ("valid_for_seconds", json!(3601)),
        ("pairing_endpoint", json!("http://files.example.test")),
        (
            "pairing_endpoint",
            json!("https://user:secret@files.example.test"),
        ),
    ] {
        let mut invalid = request.clone();
        invalid[field] = value;
        assert!(decode_create_federation_pairing_request(&serde_json::to_vec(&invalid)?).is_err());
    }
    assert!(matches!(
        decode_create_federation_pairing_request(&vec![b' '; 2049]),
        Err(BoundaryError::BodyTooLarge { .. })
    ));
    Ok(())
}

#[test]
fn federation_pairing_cancellation_rejects_missing_revision_and_invalid_response()
-> Result<(), Box<dyn std::error::Error>> {
    let mut request = json!({"operation_id": "11111111-1111-8111-8111-111111111111",
        "invitation_id": "21111111-1111-8111-8111-111111111111", "reason": "Withdraw", "expected_invitation_revision": 1});
    let valid = decode_cancel_federation_pairing_request(&serde_json::to_vec(&request)?)?;
    request["expected_invitation_revision"] = serde_json::Value::Null;
    assert!(decode_cancel_federation_pairing_request(&serde_json::to_vec(&request)?).is_err());
    let mut response = CancelFederationPairingInvitationResponse {
        operation_id: valid.operation_id,
        invitation_id: valid.invitation_id,
        committed_revision: 2,
    };
    assert!(encode_cancel_federation_pairing_response(&response).is_ok());
    response.committed_revision = 0;
    assert!(encode_cancel_federation_pairing_response(&response).is_err());
    Ok(())
}
