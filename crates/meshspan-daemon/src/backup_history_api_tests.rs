// SPDX-License-Identifier: GPL-2.0-only

use crate::{BackupHistoryController, BackupScheduleError, backup_history_api_router};
use axum::{
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode},
};
use meshspan_api_contract::{ListBackupRunsQuery, ListBackupRunsResponse};
use meshspan_domain::UnixMicros;
use tower::ServiceExt;

#[tokio::test]
async fn backup_history_authenticates_before_query_and_rejects_invalid_output()
-> Result<(), Box<dyn std::error::Error>> {
    for (query, authenticated, expected) in [
        ("?limit=0", false, StatusCode::UNAUTHORIZED),
        ("?limit=0", true, StatusCode::BAD_REQUEST),
        ("?limit=101", true, StatusCode::BAD_REQUEST),
        ("?limit=1&limit=2", true, StatusCode::BAD_REQUEST),
        ("?cursor=%zz", true, StatusCode::BAD_REQUEST),
        ("?unexpected=1", true, StatusCode::BAD_REQUEST),
        ("?limit=2", true, StatusCode::OK),
        ("?limit=1", true, StatusCode::INTERNAL_SERVER_ERROR),
    ] {
        let mut request = Request::get(format!("/api/latest/admin/backups/runs{query}"));
        if authenticated {
            request = request.header("x-test-auth", "yes");
        }
        let response = backup_history_api_router(Controller)?
            .oneshot(request.body(Body::empty())?)
            .await?;
        assert_eq!(response.status(), expected, "{query}");
        let value: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
        if expected == StatusCode::OK {
            assert_eq!(
                value,
                serde_json::json!({"runs": [], "next_page_url": null})
            );
        } else {
            assert!(value.get("runs").is_none());
        }
    }
    Ok(())
}

struct Controller;
impl BackupHistoryController for Controller {
    fn authenticate(
        &self,
        headers: &HeaderMap,
        _now: UnixMicros,
    ) -> Result<(), BackupScheduleError> {
        if headers
            .get("x-test-auth")
            .is_some_and(|value| value == "yes")
        {
            Ok(())
        } else {
            Err(BackupScheduleError::Unauthenticated)
        }
    }
    fn list(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
        query: &ListBackupRunsQuery,
    ) -> Result<ListBackupRunsResponse, BackupScheduleError> {
        self.authenticate(headers, now)?;
        Ok(ListBackupRunsResponse {
            runs: vec![],
            next_page_url: (query.limit == Some(1)).then(|| "https://attacker.example/".to_owned()),
        })
    }
}
