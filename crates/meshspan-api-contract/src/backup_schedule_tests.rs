// SPDX-License-Identifier: GPL-2.0-only

use serde_json::{Value, json};

use crate::{
    BackupScheduleResponse, BoundaryError, MAX_CONFIGURE_BACKUP_SCHEDULE_BYTES,
    decode_configure_backup_schedule_request, encode_backup_schedule_response,
};

fn request() -> Value {
    json!({
        "operation_id": "01900000-0000-7000-8000-000000000001",
        "expected_sequence": 0,
        "policy": { "interval_seconds": 3600, "retained_generations": 7,
            "minimum_verified_copies": 2, "minimum_independent_copies": 1, "enabled": true }
    })
}

#[test]
fn backup_policy_rejects_unknown_missing_null_coerced_and_contradictory_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let original = request();
    let parsed = decode_configure_backup_schedule_request(&serde_json::to_vec(&original)?)?;
    assert_eq!(parsed.policy.interval_seconds, 3600);
    assert_eq!(parsed.expected_sequence, 0);
    for (pointer, value) in [
        ("/expected_sequence", json!(-1)),
        ("/expected_sequence", json!(9_007_199_254_740_991_u64)),
        ("/policy", Value::Null),
        ("/policy/enabled", json!("true")),
        ("/policy/interval_seconds", json!(0)),
        ("/policy/retained_generations", json!(0)),
        ("/policy/retained_generations", json!(1025)),
        ("/policy/minimum_verified_copies", json!(0)),
        ("/policy/minimum_independent_copies", json!(3)),
    ] {
        let mut changed = original.clone();
        *changed
            .pointer_mut(pointer)
            .ok_or("fixture field missing")? = value;
        assert!(
            decode_configure_backup_schedule_request(&serde_json::to_vec(&changed)?).is_err(),
            "accepted {pointer}"
        );
    }
    let mut unknown = original.clone();
    unknown["policy"]["hidden_setting"] = json!(true);
    assert!(decode_configure_backup_schedule_request(&serde_json::to_vec(&unknown)?).is_err());
    let mut missing = original;
    missing["policy"]
        .as_object_mut()
        .ok_or("policy object")?
        .remove("enabled");
    assert!(decode_configure_backup_schedule_request(&serde_json::to_vec(&missing)?).is_err());
    assert!(matches!(
        decode_configure_backup_schedule_request(&vec![
            b' ';
            MAX_CONFIGURE_BACKUP_SCHEDULE_BYTES + 1
        ]),
        Err(BoundaryError::BodyTooLarge { .. })
    ));
    Ok(())
}

#[test]
fn backup_policy_response_distinguishes_unconfigured_from_disabled()
-> Result<(), Box<dyn std::error::Error>> {
    let mut value =
        json!({ "partition_id": "01900000-0000-7000-8000-000000000002", "schedule": null });
    let response: BackupScheduleResponse = serde_json::from_value(value.clone())?;
    assert_eq!(
        serde_json::from_slice::<Value>(&encode_backup_schedule_response(&response)?)?,
        value
    );
    value["schedule"] =
        json!({ "sequence": 1, "policy": request()["policy"], "next_due_at_epoch_micros": 100 });
    value["schedule"]["policy"]["enabled"] = json!(false);
    let response: BackupScheduleResponse = serde_json::from_value(value.clone())?;
    assert!(encode_backup_schedule_response(&response).is_ok());
    value["schedule"]["policy"]["minimum_independent_copies"] = json!(3);
    let invalid: BackupScheduleResponse = serde_json::from_value(value)?;
    assert!(encode_backup_schedule_response(&invalid).is_err());
    Ok(())
}
