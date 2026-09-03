// SPDX-License-Identifier: GPL-2.0-only

use std::sync::{Arc, Mutex};

use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode};
use meshspan_api_contract::{
    ListManualDnsTasksQuery, ListManualDnsTasksResponse, ManualDnsTaskAction, ManualDnsTaskSummary,
};
use meshspan_domain::{PrincipalId, UnixMicros, uuid_v8};
use tower::ServiceExt;

use crate::{
    BrowserRequestProtection, IdentityAdministrator, ManualDnsTaskAdministrationController,
    ManualDnsTaskAdministrationError, manual_dns_task_administration_api_router,
};

#[tokio::test]
async fn authentication_rejects_before_an_invalid_query_reaches_task_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let router = manual_dns_task_administration_api_router(FakeController {
        calls: Arc::clone(&calls),
    })?;
    let response = router
        .oneshot(
            Request::get("/api/latest/admin/certificate-tasks/manual-dns?limit=nope")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        calls.lock().map_err(|_| "poisoned calls")?.as_slice(),
        ["authenticate"]
    );
    Ok(())
}

#[tokio::test]
async fn authenticated_inventory_returns_exact_validated_operator_work()
-> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let router = manual_dns_task_administration_api_router(FakeController {
        calls: Arc::clone(&calls),
    })?;
    let response = router
        .oneshot(
            Request::get("/api/latest/admin/certificate-tasks/manual-dns?limit=1")
                .header("x-test-auth", "yes")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let response: ListManualDnsTasksResponse =
        serde_json::from_slice(&to_bytes(response.into_body(), 16_384).await?)?;
    assert_eq!(response.tasks, vec![summary()]);
    assert_eq!(
        calls.lock().map_err(|_| "poisoned calls")?.as_slice(),
        ["authenticate", "list"]
    );
    Ok(())
}

struct FakeController {
    calls: Arc<Mutex<Vec<&'static str>>>,
}

impl ManualDnsTaskAdministrationController for FakeController {
    fn authenticate(
        &self,
        headers: &HeaderMap,
        _protection: BrowserRequestProtection,
        now: UnixMicros,
    ) -> Result<IdentityAdministrator, ManualDnsTaskAdministrationError> {
        self.calls
            .lock()
            .map_err(|_| ManualDnsTaskAdministrationError::Unavailable)?
            .push("authenticate");
        if headers
            .get("x-test-auth")
            .and_then(|value| value.to_str().ok())
            != Some("yes")
        {
            return Err(ManualDnsTaskAdministrationError::Unauthenticated);
        }
        Ok(IdentityAdministrator {
            principal_id: PrincipalId::from_bytes(uuid_v8(versioned(4)))
                .map_err(|_| ManualDnsTaskAdministrationError::Failed)?,
            now,
        })
    }

    fn list_manual_dns_tasks(
        &self,
        _administrator: IdentityAdministrator,
        query: ListManualDnsTasksQuery,
    ) -> Result<ListManualDnsTasksResponse, ManualDnsTaskAdministrationError> {
        if query.limit != Some(1) {
            return Err(ManualDnsTaskAdministrationError::InvalidInput);
        }
        self.calls
            .lock()
            .map_err(|_| ManualDnsTaskAdministrationError::Unavailable)?
            .push("list");
        Ok(ListManualDnsTasksResponse {
            tasks: vec![summary()],
            next_page_url: None,
        })
    }
}

fn summary() -> ManualDnsTaskSummary {
    ManualDnsTaskSummary {
        task_digest: "01".repeat(32),
        order_id: "00000000-0000-4000-8000-000000000001".to_owned(),
        order_fence: "2".to_owned(),
        record_name: "_acme-challenge.files.example.test".to_owned(),
        record_value: "exact_value-1".to_owned(),
        action: ManualDnsTaskAction::Publish,
        expires_at_epoch_micros: 30,
        created_at_epoch_micros: 10,
        transitioned_at_epoch_micros: 20,
        revision: 3,
    }
}

fn versioned(seed: u8) -> [u8; 16] {
    let mut value = [seed; 16];
    value[6] = 0x40;
    value[8] = 0x80;
    value
}
