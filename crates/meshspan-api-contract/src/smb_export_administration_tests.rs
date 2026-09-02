// SPDX-License-Identifier: GPL-2.0-only

use crate::{BoundaryError, decode_publish_smb_export_request, decode_withdraw_smb_export_request};

#[test]
fn publication_rejects_unknown_fields_and_noncanonical_gateway_sets()
-> Result<(), Box<dyn std::error::Error>> {
    let valid = serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000001",
        "root_object_id": "00000000-0000-4000-8000-000000000002",
        "share_name": "Finance",
        "gateways": {
            "kind": "selected",
            "node_ids": [
                "00000000-0000-4000-8000-000000000003",
                "00000000-0000-4000-8000-000000000004"
            ]
        },
        "encryption_required": true
    });
    assert!(decode_publish_smb_export_request(&serde_json::to_vec(&valid)?).is_ok());
    let mut reversed = valid.clone();
    reversed["gateways"]["node_ids"] = serde_json::json!([
        "00000000-0000-4000-8000-000000000004",
        "00000000-0000-4000-8000-000000000003"
    ]);
    assert!(matches!(
        decode_publish_smb_export_request(&serde_json::to_vec(&reversed)?),
        Err(BoundaryError::DecodeMismatch)
    ));
    let mut unknown = valid;
    unknown["implicit"] = serde_json::json!(true);
    assert!(decode_publish_smb_export_request(&serde_json::to_vec(&unknown)?).is_err());
    Ok(())
}

#[test]
fn withdrawal_rejects_blank_or_oversized_audit_input() -> Result<(), Box<dyn std::error::Error>> {
    for reason in ["", "   "] {
        let value = serde_json::json!({
            "operation_id": "00000000-0000-4000-8000-000000000005",
            "reason": reason
        });
        assert!(decode_withdraw_smb_export_request(&serde_json::to_vec(&value)?).is_err());
    }
    assert!(matches!(
        decode_withdraw_smb_export_request(&vec![b'x'; 8 * 1_024 + 1]),
        Err(BoundaryError::BodyTooLarge { limit }) if limit == 8 * 1_024
    ));
    Ok(())
}
