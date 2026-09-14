// SPDX-License-Identifier: GPL-2.0-only

use crate::*;
use serde_json::{Value, json};

fn request() -> Value {
    json!({"operation_id":"01900000-0000-7000-8000-000000000001",
        "destination_id":"01900000-0000-7000-8000-000000000002", "expected_revision":0,
        "name":"Recovery", "provider":{"kind":"registered_target", "target_id":"01900000-0000-7000-8000-000000000003"},
        "provider_generation":"1", "enabled":true})
}

#[test]
fn backup_destination_requests_reject_missing_unknown_null_and_coercion()
-> Result<(), Box<dyn std::error::Error>> {
    let original = request();
    assert_eq!(
        decode_configure_backup_destination_request(&serde_json::to_vec(&original)?)?.name,
        "Recovery"
    );
    for (field, value) in [
        ("provider_generation", json!(0)),
        ("provider_generation", json!(1)),
        (
            "provider",
            json!({"kind":"registered_target", "target_id":"not-a-uuid"}),
        ),
        ("enabled", Value::Null),
        ("enabled", json!("true")),
        ("expected_revision", json!(-1)),
        ("expected_revision", json!(9_007_199_254_740_992_u64)),
        ("name", json!("")),
        ("name", json!("secret\nname")),
        ("extra", json!(true)),
    ] {
        let mut changed = original.clone();
        changed[field] = value;
        assert!(
            decode_configure_backup_destination_request(&serde_json::to_vec(&changed)?).is_err(),
            "accepted {field}"
        );
    }
    let mut missing = original;
    missing.as_object_mut().ok_or("object")?.remove("enabled");
    assert!(decode_configure_backup_destination_request(&serde_json::to_vec(&missing)?).is_err());
    assert!(matches!(
        decode_configure_backup_destination_request(&vec![b' '; 2049]),
        Err(BoundaryError::BodyTooLarge { limit: 2048 })
    ));
    Ok(())
}

#[test]
fn backup_destination_requests_accept_only_exact_provider_variants()
-> Result<(), Box<dyn std::error::Error>> {
    for (kind, field) in [
        ("registered_target", "target_id"),
        ("federated_mesh", "remote_mesh_id"),
        ("component_provider", "instance_id"),
    ] {
        let mut input = request();
        input["provider"] = json!({"kind":kind, field:"01900000-0000-7000-8000-000000000003"});
        let decoded = decode_configure_backup_destination_request(&serde_json::to_vec(&input)?)?;
        assert_eq!(serde_json::to_value(decoded)?, input);
        input["provider"]["path"] = json!("/tmp/not-authority");
        assert!(decode_configure_backup_destination_request(&serde_json::to_vec(&input)?).is_err());
    }
    Ok(())
}

#[test]
fn backup_destination_responses_validate_receipts_pages_and_relative_links()
-> Result<(), Box<dyn std::error::Error>> {
    let receipt: ConfigureBackupDestinationResponse = serde_json::from_value(json!({
        "operation_id":request()["operation_id"], "destination_id":request()["destination_id"], "committed_revision":7
    }))?;
    assert!(encode_configure_backup_destination_response(&receipt).is_ok());
    assert!(
        encode_configure_backup_destination_response(&ConfigureBackupDestinationResponse {
            committed_revision: 0,
            ..receipt
        })
        .is_err()
    );
    let mut page = ListBackupDestinationsResponse {
        destinations: vec![],
        next_page_url: None,
    };
    assert!(encode_list_backup_destinations_response(&page).is_ok());
    page.next_page_url = Some("https://attacker.example/".to_owned());
    assert!(encode_list_backup_destinations_response(&page).is_err());
    assert!(
        validate_list_backup_destinations_query(&ListBackupDestinationsQuery {
            limit: Some(0),
            cursor: None
        })
        .is_err()
    );
    Ok(())
}
