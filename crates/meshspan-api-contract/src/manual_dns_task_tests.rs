// SPDX-License-Identifier: GPL-2.0-only

use crate::{
    BoundaryError, ListManualDnsTasksQuery, ListManualDnsTasksResponse, ManualDnsTaskAction,
    ManualDnsTaskCursor, ManualDnsTaskSummary, encode_list_manual_dns_tasks_response,
    validate_list_manual_dns_tasks_query,
};

#[test]
fn query_and_response_enforce_bounds_and_deadline_order() -> Result<(), Box<dyn std::error::Error>>
{
    let invalid_query = ListManualDnsTasksQuery {
        cursor: ManualDnsTaskCursor::from_encoded("v1.1.1.a".to_owned()),
        limit: Some(0),
    };
    assert!(matches!(
        validate_list_manual_dns_tasks_query(&invalid_query),
        Err(BoundaryError::Invalid { .. })
    ));
    let later = summary(20, "02");
    let earlier = summary(10, "01");
    let unordered = ListManualDnsTasksResponse {
        tasks: vec![later, earlier],
        next_page_url: None,
    };
    assert!(matches!(
        encode_list_manual_dns_tasks_response(&unordered),
        Err(BoundaryError::EncodeMismatch)
    ));
    let valid = ListManualDnsTasksResponse {
        tasks: vec![summary(10, "01"), summary(20, "02")],
        next_page_url: Some(
            "/api/latest/admin/certificate-tasks/manual-dns?cursor=v1.20.10.02".to_owned(),
        ),
    };
    assert!(!encode_list_manual_dns_tasks_response(&valid)?.is_empty());
    Ok(())
}

fn summary(expiry: i64, digest_byte: &str) -> ManualDnsTaskSummary {
    ManualDnsTaskSummary {
        task_digest: digest_byte.repeat(32),
        order_id: "00000000-0000-4000-8000-000000000001".to_owned(),
        order_fence: "1".to_owned(),
        record_name: "_acme-challenge.files.example.test".to_owned(),
        record_value: "exact_value-1".to_owned(),
        action: ManualDnsTaskAction::Publish,
        expires_at_epoch_micros: expiry,
        created_at_epoch_micros: 10,
        transitioned_at_epoch_micros: 10,
        revision: 1,
    }
}
