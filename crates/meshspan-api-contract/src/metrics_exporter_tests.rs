// SPDX-License-Identifier: GPL-2.0-only

use crate::{
    ConfigureMetricsExporterResponse, MAX_CONFIGURE_METRICS_EXPORTER_BYTES,
    MetricsExporterResponse, decode_configure_metrics_exporter_request,
    encode_configure_metrics_exporter_response, encode_metrics_exporter_response,
};
use serde_json::json;

fn request() -> serde_json::Value {
    json!({"operation_id": "10000000-0000-4000-8000-000000000001", "expected_sequence": 0,
        "policy": {"enabled": true, "allowed_principals": ["10000000-0000-4000-8000-000000000002"]}})
}

#[test]
fn metrics_exporter_boundaries_reject_ambiguous_or_excessive_policies()
-> Result<(), Box<dyn std::error::Error>> {
    let original = request();
    let parsed = decode_configure_metrics_exporter_request(&serde_json::to_vec(&original)?)?;
    assert!(parsed.policy.enabled);
    assert_eq!(parsed.expected_sequence, 0);
    for (field, value) in [
        ("enabled", json!("true")),
        ("enabled", json!(null)),
        ("allowed_principals", json!([])),
        ("allowed_principals", json!(["not-an-id"])),
        ("unknown", json!(false)),
        (
            "allowed_principals",
            json!([
                "10000000-0000-4000-8000-000000000002",
                "10000000-0000-4000-8000-000000000002"
            ]),
        ),
    ] {
        let mut changed = original.clone();
        changed["policy"][field] = value;
        assert!(decode_configure_metrics_exporter_request(&serde_json::to_vec(&changed)?).is_err());
    }
    let mut changed = original;
    changed["expected_sequence"] = json!(9_007_199_254_740_991_u64);
    assert!(decode_configure_metrics_exporter_request(&serde_json::to_vec(&changed)?).is_err());
    assert!(
        decode_configure_metrics_exporter_request(&vec![
            b' ';
            MAX_CONFIGURE_METRICS_EXPORTER_BYTES + 1
        ])
        .is_err()
    );
    Ok(())
}

#[test]
fn metrics_exporter_outputs_validate_unconfigured_state_policy_and_receipts()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        encode_metrics_exporter_response(&MetricsExporterResponse {
            configuration: None
        })?,
        br#"{"configuration":null}"#
    );
    let valid = json!({"configuration": {"sequence": 1, "committed_revision": 2, "policy": request()["policy"]}});
    let response: MetricsExporterResponse = serde_json::from_value(valid.clone())?;
    encode_metrics_exporter_response(&response)?;
    let mut invalid = valid;
    invalid["configuration"]["policy"]["allowed_principals"] = json!([]);
    assert!(encode_metrics_exporter_response(&serde_json::from_value(invalid)?).is_err());
    let mut receipt: ConfigureMetricsExporterResponse = serde_json::from_value(json!({
        "operation_id": request()["operation_id"], "sequence": 1, "committed_revision": 2
    }))?;
    encode_configure_metrics_exporter_response(&receipt)?;
    receipt.sequence = 0;
    assert!(encode_configure_metrics_exporter_response(&receipt).is_err());
    Ok(())
}
