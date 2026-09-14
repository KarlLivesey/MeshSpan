// SPDX-License-Identifier: GPL-2.0-only

use super::{
    MAX_RECOVERY_SELECTION_BYTES, RecoveryQuorumSelection, decode_recovery_preparation_selection,
};

#[test]
fn recovery_target_restore_request_is_closed_and_bounded() -> Result<(), Box<dyn std::error::Error>>
{
    let value = serde_json::json!({"path":"/replacement", "inventory_directory":"/salvage",
        "source_target_id":"abababab-abab-abab-abab-abababababab", "source_generation":"1"});
    assert_eq!(
        super::decode_recovery_target_restore_request(&serde_json::to_vec(&value)?)?
            .source_generation,
        "1"
    );
    for (field, invalid) in [
        ("source_generation", serde_json::json!(1)),
        ("source_generation", serde_json::json!("0")),
        ("source_target_id", serde_json::json!("not-a-uuid")),
        ("path", serde_json::json!(null)),
        ("unexpected", serde_json::json!(true)),
    ] {
        let mut changed = value.clone();
        changed[field] = invalid;
        assert!(
            super::decode_recovery_target_restore_request(&serde_json::to_vec(&changed)?).is_err()
        );
    }
    let repeated = serde_json::to_string(&value)?.replacen('{', "{\"path\":\"/other\",", 1);
    assert!(super::decode_recovery_target_restore_request(repeated.as_bytes()).is_err());
    assert!(super::decode_recovery_target_restore_request(&vec![b' '; 32 * 1024 + 1]).is_err());
    Ok(())
}
use crate::BoundaryError;
use serde_json::{Value, json};

#[test]
fn recovery_selection_defaults_quorum_without_accepting_null()
-> Result<(), Box<dyn std::error::Error>> {
    let mut value = selection();
    let parsed = decode_recovery_preparation_selection(&serde_json::to_vec(&value)?)?;
    assert!(matches!(parsed.quorum, RecoveryQuorumSelection::Automatic));
    assert_eq!(parsed.nodes.len(), 1);
    assert_eq!(parsed.nodes[0].incarnation, "1");
    value["quorum"] = Value::Null;
    assert!(decode_recovery_preparation_selection(&serde_json::to_vec(&value)?).is_err());
    value["quorum"] = json!({"kind": "compiled", "specification": "abcd"});
    assert!(
        matches!(decode_recovery_preparation_selection(&serde_json::to_vec(&value)?)?.quorum,
        RecoveryQuorumSelection::Compiled { specification } if specification == "abcd")
    );
    Ok(())
}

#[test]
fn recovery_selection_rejects_shape_coercion_and_unknown_fields()
-> Result<(), Box<dyn std::error::Error>> {
    for (pointer, replacement) in [
        ("/nodes/0/incarnation", json!(1)),
        ("/nodes/0/roles", json!(["administrator"])),
        ("/nodes/0/identity_public_key", json!("04")),
        ("/storage", Value::Null),
        ("/nodes", json!([])),
    ] {
        let mut value = selection();
        *value.pointer_mut(pointer).ok_or("fixture field absent")? = replacement;
        assert!(
            decode_recovery_preparation_selection(&serde_json::to_vec(&value)?).is_err(),
            "{pointer}"
        );
    }
    let mut value = selection();
    value["nodes"][0]["private_key"] = json!("forbidden");
    assert!(decode_recovery_preparation_selection(&serde_json::to_vec(&value)?).is_err());
    let mut value = selection();
    value["activate"] = json!(true);
    assert!(decode_recovery_preparation_selection(&serde_json::to_vec(&value)?).is_err());
    let mut value = selection();
    value["target_inventory_sha256"] = json!("13".repeat(32));
    assert!(decode_recovery_preparation_selection(&serde_json::to_vec(&value)?).is_err());
    Ok(())
}

#[test]
fn recovery_selection_rejects_duplicate_fields_and_excessive_input()
-> Result<(), Box<dyn std::error::Error>> {
    let original = serde_json::to_string(&selection())?;
    let changed = original.replace(
        "\"node_name\":\"Replacement\"",
        "\"node_name\":\"Replacement\",\"node_name\":\"Other\"",
    );
    assert_ne!(changed, original);
    assert!(decode_recovery_preparation_selection(changed.as_bytes()).is_err());
    assert!(matches!(
        decode_recovery_preparation_selection(&vec![b' '; MAX_RECOVERY_SELECTION_BYTES + 1]),
        Err(BoundaryError::BodyTooLarge {
            limit: MAX_RECOVERY_SELECTION_BYTES
        })
    ));
    let mut value = selection();
    value["nodes"] = Value::Array(vec![value["nodes"][0].clone(); 1025]);
    assert!(decode_recovery_preparation_selection(&serde_json::to_vec(&value)?).is_err());
    Ok(())
}

fn selection() -> Value {
    json!({
        "recovery_id": "aeaeaeae-aeae-8eae-aeae-aeaeaeaeaeae",
        "storage": {"maximum_copied_bytes": "1048576", "targets": [{
            "target_id": "abababab-abab-abab-abab-abababababab", "generation": "1", "storage_path": "/surviving"
        }]},
        "nodes": [{
            "node_id": "abababab-abab-abab-abab-abababababab",
            "host_id": "acacacac-acac-acac-acac-acacacacacac",
            "host_name": "Host", "node_name": "Replacement", "incarnation": "1",
            "roles": ["storage", "gateway", "metadata"],
            // Structural schema fixture, not a claim that this public point is on the curve.
            "identity_public_key": format!("04{}", "11".repeat(64)),
            "wrapping_public_key": "22".repeat(32), "private_endpoint": "127.0.0.1:10000"
        }]
    })
}

#[test]
fn recovery_storage_selection_rejects_unknown_duplicate_and_coerced_values()
-> Result<(), Box<dyn std::error::Error>> {
    let value = json!({"maximum_copied_bytes": "1048576", "targets": [{
        "target_id": "abababab-abab-abab-abab-abababababab", "generation": "1", "storage_path": "/surviving"
    }]});
    let parsed = super::decode_recovery_storage_selection(&serde_json::to_vec(&value)?)?;
    assert_eq!(parsed.maximum_copied_bytes, "1048576");
    assert_eq!(parsed.targets[0].storage_path, "/surviving");
    for (pointer, replacement) in [
        ("/maximum_copied_bytes", json!(1024)),
        ("/maximum_copied_bytes", json!("0")),
        ("/targets/0/generation", json!("01")),
        ("/targets/0/storage_path", Value::Null),
        ("/targets/0/target_id", json!("some-target")),
        ("/targets", json!([])),
    ] {
        let mut changed = value.clone();
        *changed.pointer_mut(pointer).ok_or("fixture field absent")? = replacement;
        assert!(
            super::decode_recovery_storage_selection(&serde_json::to_vec(&changed)?).is_err(),
            "{pointer}"
        );
    }
    let original = serde_json::to_string(&value)?;
    let duplicate = original.replace(
        "\"generation\":\"1\"",
        "\"generation\":\"1\",\"generation\":\"2\"",
    );
    assert_ne!(original, duplicate);
    assert!(super::decode_recovery_storage_selection(duplicate.as_bytes()).is_err());
    let mut changed = value;
    changed["targets"][0]["marker_fingerprint"] = json!("untrusted");
    assert!(super::decode_recovery_storage_selection(&serde_json::to_vec(&changed)?).is_err());
    Ok(())
}
