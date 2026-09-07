// SPDX-License-Identifier: GPL-2.0-only

use crate::{UpdatesResponse, decode_manage_update_request, encode_updates_response};
use serde_json::json;

#[test]
fn update_boundary_rejects_unknown_coerced_and_duplicate_actions()
-> Result<(), Box<dyn std::error::Error>> {
    let valid = json!({"operation_id":"00000000-0000-4000-8000-000000000001", "action": {
        "kind":"control", "rollout_id":"00000000-0000-4000-8000-000000000002", "expected_sequence":1, "control":"pause"
    }});
    decode_manage_update_request(&serde_json::to_vec(&valid)?)?;
    for (field, value) in [
        ("kind", json!("advance_node")),
        ("control", json!("verified")),
        ("expected_sequence", json!("1")),
        ("expected_sequence", json!(0)),
        ("rollout_id", json!(null)),
        ("extra", json!(true)),
    ] {
        let mut invalid = valid.clone();
        invalid["action"][field] = value;
        assert!(decode_manage_update_request(&serde_json::to_vec(&invalid)?).is_err());
    }
    let duplicate = serde_json::to_string(&valid)?.replace(
        "\"control\":\"pause\"",
        "\"control\":\"pause\",\"control\":\"cancel\"",
    );
    assert!(decode_manage_update_request(duplicate.as_bytes()).is_err());
    assert!(decode_manage_update_request(&vec![b' '; crate::MAX_MANAGE_UPDATE_BYTES + 1]).is_err());
    assert_eq!(
        encode_updates_response(&UpdatesResponse {
            signers: vec![],
            rollout: None,
            installation_available: false
        })?,
        br#"{"installation_available":false,"rollout":null,"signers":[]}"#
    );
    Ok(())
}
