// SPDX-License-Identifier: GPL-2.0-only

use crate::{DiagnosticsBundleResponse, encode_diagnostics_bundle_response};

fn fixture() -> serde_json::Value {
    serde_json::json!({
        "metadata": crate::metadata_diagnostics_tests::fixture(),
        "runtime": {
            "uptime_millis": "2000", "observation_sequence": "4", "dropped_updates": "0",
            "target_check_evictions": "0", "event_evictions": "0",
            "reconciliation_cycles": "2", "reconciliation_failures": "1",
            "target_probe_passes": "1", "target_probe_failures": "1",
            "storage_reconciliation": null,
            "target_checks": [{
                "target": {"target_id": "11111111-1111-4111-8111-111111111111", "generation": "1"},
                "observation": {"sequence": "3", "observed_at_epoch_micros": 100, "age_millis": "1000"},
                "duration_millis": "7", "result": "passed"
            }],
            "recent_events": [{
                "observation": {"sequence": "4", "observed_at_epoch_micros": 90, "age_millis": "500"},
                "code": "storage_reconciliation_recovered", "target": null
            }]
        }
    })
}

#[test]
fn diagnostic_bundle_validates_runtime_evidence_and_explicit_unavailability()
-> Result<(), Box<dyn std::error::Error>> {
    let value = fixture();
    let mut bundle: DiagnosticsBundleResponse = serde_json::from_value(value.clone())?;
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&encode_diagnostics_bundle_response(&bundle)?)?,
        value
    );
    bundle.runtime = None;
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&encode_diagnostics_bundle_response(&bundle)?)?
            ["runtime"],
        serde_json::Value::Null
    );
    Ok(())
}

#[test]
fn diagnostic_bundle_rejects_invalid_counters_subjects_ages_and_arbitrary_logs()
-> Result<(), Box<dyn std::error::Error>> {
    for (pointer, invalid) in [
        (
            "/runtime/uptime_millis",
            serde_json::json!("18446744073709551616"),
        ),
        ("/runtime/reconciliation_failures", serde_json::json!("3")),
        (
            "/runtime/target_checks/0/target/generation",
            serde_json::json!("0"),
        ),
        (
            "/runtime/target_checks/0/result",
            serde_json::json!("healthy"),
        ),
        (
            "/runtime/target_checks/0/observation/sequence",
            serde_json::json!("5"),
        ),
        (
            "/runtime/target_checks/0/observation/age_millis",
            serde_json::json!("2001"),
        ),
        (
            "/runtime/recent_events/0/code",
            serde_json::json!("target_probe_failed"),
        ),
        (
            "/metadata/revision_before",
            serde_json::json!("18446744073709551615"),
        ),
    ] {
        let mut value = fixture();
        *value.pointer_mut(pointer).ok_or("fixture pointer")? = invalid;
        assert!(
            !serde_json::from_value::<DiagnosticsBundleResponse>(value)
                .is_ok_and(|value| encode_diagnostics_bundle_response(&value).is_ok()),
            "{pointer}"
        );
    }
    for field in ["target_checks", "recent_events"] {
        let mut value = fixture();
        value["runtime"][field] = serde_json::json!(vec![value["runtime"][field][0].clone(); 101]);
        assert!(encode_diagnostics_bundle_response(&serde_json::from_value(value)?).is_err());
    }
    let mut value = fixture();
    value["runtime"]["recent_events"][0]["message"] = serde_json::json!("private/path credential");
    assert!(serde_json::from_value::<DiagnosticsBundleResponse>(value).is_err());
    Ok(())
}
