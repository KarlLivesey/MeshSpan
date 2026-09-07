// SPDX-License-Identifier: GPL-2.0-only

use crate::{MetadataDiagnosticsResponse, encode_metadata_diagnostics_response};

pub(crate) fn fixture() -> serde_json::Value {
    serde_json::json!({
        "mesh_id": "11111111-1111-4111-8111-111111111111",
        "partition_id": "22222222-2222-4222-8222-222222222222",
        "node_id": "33333333-3333-4333-8333-333333333333",
        "daemon_version": "0.1.0", "collected_at_epoch_micros": 100,
        "configuration": {
            "operating_system": "linux", "architecture": "aarch64",
            "metrics_exporter_enabled": false, "backup": null,
            "public_certificate_source": "mesh_local", "node_certificate_generation": "1"
        },
        "pending_work": {"items": [], "truncated": false},
        "revision_before": "9007199254740993", "revision_after": "9007199254740994",
        "consensus": {
            "partition_id": "22222222-2222-4222-8222-222222222222",
            "node_id": "33333333-3333-4333-8333-333333333333",
            "role": "follower", "known_leader": null, "term": "1",
            "commit_index": "9007199254740994", "applied_index": "9007199254740993",
            "membership_epoch": "1", "plan_digest": "a".repeat(64),
            "persistence_blocked": false, "pending_operations": "0", "queued_operations": "0"
        },
        "nodes": {"items": [], "truncated": false},
        "targets": {"items": [], "truncated": false},
        "recent_operations": {"items": [], "truncated": false}
    })
}

#[test]
fn operational_diagnostics_reject_secrets_and_contradictory_policy()
-> Result<(), Box<dyn std::error::Error>> {
    let mut value = fixture();
    value["configuration"]["backup"] = serde_json::json!({
        "enabled": true, "interval_micros": "60000000", "retained_generations": 3,
        "minimum_verified_copies": 2, "minimum_independent_copies": 1,
    });
    value["pending_work"]["items"] = serde_json::json!([{
        "work_id": "44444444-4444-4444-8444-444444444444", "kind": "repair",
        "state": "queued", "attempt_count": "0", "revision": "1",
        "next_attempt_at_epoch_micros": 100,
    }]);
    encode_metadata_diagnostics_response(&serde_json::from_value(value.clone())?)?;
    for (pointer, invalid) in [
        (
            "/configuration/backup/interval_micros",
            serde_json::json!("0"),
        ),
        (
            "/configuration/backup/minimum_independent_copies",
            serde_json::json!(3),
        ),
        ("/pending_work/items/0/revision", serde_json::json!("0")),
        (
            "/pending_work/items/0/attempt_count",
            serde_json::json!("18446744073709551616"),
        ),
        (
            "/pending_work/items/0/kind",
            serde_json::json!("private/path"),
        ),
    ] {
        let mut invalid_value = value.clone();
        *invalid_value
            .pointer_mut(pointer)
            .ok_or("fixture pointer")? = invalid;
        assert!(
            !serde_json::from_value::<MetadataDiagnosticsResponse>(invalid_value)
                .is_ok_and(|response| encode_metadata_diagnostics_response(&response).is_ok())
        );
    }
    value["pending_work"]["items"][0]["subject_payload"] = serde_json::json!("private contents");
    assert!(serde_json::from_value::<MetadataDiagnosticsResponse>(value).is_err());
    Ok(())
}

#[test]
fn metadata_diagnostics_preserves_exact_counters_and_explicit_missing_observation()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture();
    let response: MetadataDiagnosticsResponse = serde_json::from_value(fixture.clone())?;
    let bytes = encode_metadata_diagnostics_response(&response)?;
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes)?,
        fixture
    );
    let mut response = response;
    response.consensus = None;
    let bytes = encode_metadata_diagnostics_response(&response)?;
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes)?["consensus"],
        serde_json::Value::Null
    );
    Ok(())
}

#[test]
fn metadata_diagnostics_rejects_invalid_and_contradictory_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    for (pointer, invalid) in [
        ("/node_id", serde_json::json!("../../private")),
        (
            "/configuration/architecture",
            serde_json::json!("private/path"),
        ),
        (
            "/configuration/node_certificate_generation",
            serde_json::json!("0"),
        ),
        (
            "/configuration/public_certificate_source",
            serde_json::json!("private_key"),
        ),
        ("/revision_before", serde_json::json!("9007199254740995")),
        ("/revision_after", serde_json::json!("18446744073709551616")),
        (
            "/consensus/applied_index",
            serde_json::json!("9007199254740995"),
        ),
        (
            "/consensus/node_id",
            serde_json::json!("11111111-1111-4111-8111-111111111111"),
        ),
        ("/consensus/term", serde_json::json!("01")),
        ("/consensus/role", serde_json::json!("healthy")),
        ("/consensus/plan_digest", serde_json::json!("credentials")),
        ("/revision_before", serde_json::json!(42)),
        ("/collected_at_epoch_micros", serde_json::json!(-1)),
    ] {
        let mut invalid_fixture = fixture();
        *invalid_fixture
            .pointer_mut(pointer)
            .ok_or("fixture pointer")? = invalid;
        let accepted = serde_json::from_value::<MetadataDiagnosticsResponse>(invalid_fixture)
            .is_ok_and(|value| encode_metadata_diagnostics_response(&value).is_ok());
        assert!(!accepted, "{pointer}");
    }
    for pointer in [
        "",
        "/consensus",
        "/nodes",
        "/configuration",
        "/pending_work",
    ] {
        let mut value = fixture();
        value
            .pointer_mut(pointer)
            .and_then(serde_json::Value::as_object_mut)
            .ok_or("fixture object")?
            .insert("secret".to_owned(), serde_json::json!("rejected"));
        assert!(serde_json::from_value::<MetadataDiagnosticsResponse>(value).is_err());
    }
    let mut value = fixture();
    value["nodes"]["items"] = serde_json::json!(vec![
        serde_json::json!({
            "node_id": "33333333-3333-4333-8333-333333333333",
            "host_id": "44444444-4444-4444-8444-444444444444",
            "configured_state": "active", "incarnation": "1",
            "roles": {"storage": true, "gateway": true, "metadata_eligible": true}
        });
        101
    ]);
    assert!(encode_metadata_diagnostics_response(&serde_json::from_value(value)?).is_err());
    Ok(())
}
