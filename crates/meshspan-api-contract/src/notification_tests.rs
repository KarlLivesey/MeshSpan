// SPDX-License-Identifier: GPL-2.0-only

use crate::{
    NotificationWorkerStatus, NotificationsResponse, decode_configure_notification_request,
    encode_notifications_response,
};
use serde_json::json;

#[test]
fn notification_configuration_validates_request_and_redacted_response()
-> Result<(), Box<dyn std::error::Error>> {
    let valid = json!({ "operation_id": "00000000-0000-4000-8000-000000000001",
        "channel_id": "00000000-0000-4000-8000-000000000002", "expected_sequence": 0,
        "display_name": "Operations", "enabled": true, "event_filter": 15,
        "settings": { "mode": "replace", "destination": { "kind": "webhook",
            "endpoint": "https://example.test/events", "bearer_token": "test-token-0123456789" } } });
    let bytes = serde_json::to_vec(&valid)?;
    assert_eq!(
        decode_configure_notification_request(&bytes)?.event_filter,
        15
    );
    for (field, value) in [
        ("settings", json!(null)),
        ("settings", json!({})),
        ("enabled", json!("true")),
        ("event_filter", json!(0)),
        ("unknown", json!(1)),
    ] {
        let mut invalid = valid.clone();
        invalid[field] = value;
        assert!(decode_configure_notification_request(&serde_json::to_vec(&invalid)?).is_err());
    }
    let duplicate = String::from_utf8(bytes)?.replacen(
        "\"enabled\":true",
        "\"enabled\":true,\"enabled\":false",
        1,
    );
    assert!(decode_configure_notification_request(duplicate.as_bytes()).is_err());
    assert_eq!(
        encode_notifications_response(&NotificationsResponse {
            channels: vec![],
            worker: NotificationWorkerStatus::Running
        })?,
        br#"{"channels":[],"worker":"running"}"#
    );
    Ok(())
}
