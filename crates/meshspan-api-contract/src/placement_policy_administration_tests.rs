// SPDX-License-Identifier: GPL-2.0-only

use serde_json::json;

use crate::{
    BoundaryError, decode_create_acknowledgement_policy_request,
    decode_create_locality_policy_request,
};

#[test]
fn locality_policy_accepts_valid_shape_and_rejects_unknown_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let valid = json!({
        "operation_id": "123e4567-e89b-42d3-a456-426614174000",
        "name": "Complete in Building A",
        "maximum_lag_micros": 1_000_000,
        "requirements": [{
            "cell_id": "223e4567-e89b-42d3-a456-426614174000",
            "local_protection_policy_id": null
        }]
    });
    assert!(decode_create_locality_policy_request(&serde_json::to_vec(&valid)?).is_ok());

    let mut unknown = valid;
    unknown["surprise"] = json!(true);
    assert!(matches!(
        decode_create_locality_policy_request(&serde_json::to_vec(&unknown)?),
        Err(BoundaryError::Invalid { .. })
    ));
    Ok(())
}

#[test]
fn acknowledgement_policy_rejects_malformed_nested_identifiers()
-> Result<(), Box<dyn std::error::Error>> {
    let invalid = json!({
        "operation_id": "123e4567-e89b-42d3-a456-426614174000",
        "name": "Strong campus write",
        "consistency": "strong",
        "minimum_durable_targets": 3,
        "minimum_distinct_nodes": 2,
        "strong_wait_micros": 5_000_000,
        "fallback": "remain_pending",
        "required_scenario_ids": ["not-a-uuid"],
        "cells": []
    });
    assert!(matches!(
        decode_create_acknowledgement_policy_request(&serde_json::to_vec(&invalid)?),
        Err(BoundaryError::Invalid { .. })
    ));
    Ok(())
}
