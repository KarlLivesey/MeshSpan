// SPDX-License-Identifier: GPL-2.0-only

use crate::*;
use serde_json::{Value, json};
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn request() -> Value {
    json!({"operation_id":"01900000-0000-7000-8000-000000000001", "expected_metadata_revision": 3,
        "change":{"kind":"issue", "grant_id":"01900000-0000-7000-8000-000000000002",
            "relationship_id":"01900000-0000-7000-8000-000000000003",
            "policy":{"maximum_bytes":"1024", "counts_towards_protection":true,
                "serves_reads":false, "allow_downstream_delegation":false}}})
}

#[test]
fn federation_storage_grant_contract_preserves_missing_null_and_explicit_lifetime() -> TestResult {
    let mut input = request();
    let decoded = decode_federation_storage_grant_request(&serde_json::to_vec(&input)?)?;
    assert_eq!(serde_json::to_value(&decoded)?, input);
    assert!(matches!(
        decoded.change,
        FederationStorageGrantChange::Issue {
            valid_for_seconds: NullableField::Missing,
            ..
        }
    ));
    input["change"]["valid_for_seconds"] = Value::Null;
    let decoded = decode_federation_storage_grant_request(&serde_json::to_vec(&input)?)?;
    assert!(matches!(
        decoded.change,
        FederationStorageGrantChange::Issue {
            valid_for_seconds: NullableField::Null,
            ..
        }
    ));
    assert_eq!(serde_json::to_value(&decoded)?, input);
    input["change"]["valid_for_seconds"] = json!(60);
    let decoded = decode_federation_storage_grant_request(&serde_json::to_vec(&input)?)?;
    assert!(matches!(
        decoded.change,
        FederationStorageGrantChange::Issue {
            valid_for_seconds: NullableField::Value(FederationStorageGrantLifetime(60)),
            ..
        }
    ));
    for invalid in [
        json!(0),
        json!(59),
        json!(31_536_001),
        json!("60"),
        json!(false),
    ] {
        input["change"]["valid_for_seconds"] = invalid;
        assert!(decode_federation_storage_grant_request(&serde_json::to_vec(&input)?).is_err());
    }
    Ok(())
}

#[test]
fn federation_storage_grant_contract_rejects_ambiguous_and_unbounded_input() -> TestResult {
    for (pointer, value) in [
        ("/expected_metadata_revision", json!(0)),
        (
            "/expected_metadata_revision",
            json!(9_007_199_254_740_992_u64),
        ),
        ("/change/kind", json!("unknown")),
        ("/change/grant_id", json!("bad")),
        ("/change/policy/maximum_bytes", json!(0)),
        ("/change/policy/maximum_bytes", json!("01")),
        (
            "/change/policy/maximum_bytes",
            json!("10000000000000000000"),
        ),
        ("/change/policy/serves_reads", json!("false")),
    ] {
        let mut input = request();
        *input.pointer_mut(pointer).ok_or("fixture pointer")? = value;
        assert!(
            decode_federation_storage_grant_request(&serde_json::to_vec(&input)?).is_err(),
            "{pointer}"
        );
    }
    for pointer in ["", "/change", "/change/policy"] {
        let mut input = request();
        input.pointer_mut(pointer).ok_or("fixture pointer")?["extra"] = json!(true);
        assert!(decode_federation_storage_grant_request(&serde_json::to_vec(&input)?).is_err());
    }
    assert!(matches!(
        decode_federation_storage_grant_request(&vec![b' '; 4097]),
        Err(BoundaryError::BodyTooLarge { limit: 4096 })
    ));
    Ok(())
}

#[test]
fn federation_storage_grant_contract_validates_outgoing_receipts_and_records() -> TestResult {
    let operation = OperationId::parse("01900000-0000-7000-8000-000000000001").ok_or("id")?;
    let mut receipt = ConfigureFederationStorageGrantResponse {
        operation_id: operation.clone(),
        grant_id: operation,
        committed_revision: 4,
    };
    assert!(encode_federation_storage_grant_receipt(&receipt).is_ok());
    receipt.committed_revision = 0;
    assert!(encode_federation_storage_grant_receipt(&receipt).is_err());
    let mut response = FederationStorageGrantResponse {
        metadata_revision: 3,
        grant: None,
    };
    assert_eq!(
        serde_json::from_slice::<Value>(&encode_federation_storage_grant_response(&response)?)?,
        json!({"metadata_revision":3,"grant":null})
    );
    response.metadata_revision = 0;
    assert!(encode_federation_storage_grant_response(&response).is_err());
    Ok(())
}
