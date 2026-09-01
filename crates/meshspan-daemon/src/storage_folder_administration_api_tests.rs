// SPDX-License-Identifier: GPL-2.0-only

use std::sync::{Arc, Mutex};

use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode};
use meshspan_api_contract::{
    ListStorageFoldersQuery, ListStorageFoldersResponse, RegisterStorageFolderRequest,
    RegisterStorageFolderResponse, StorageFolderState, StorageFolderSummary,
    StorageFolderUsageLimit,
};
use meshspan_domain::{PrincipalId, UnixMicros, uuid_v8};
use tower::ServiceExt;

use crate::{
    BrowserRequestProtection, IdentityAdministrator, StorageFolderAdministrationController,
    StorageFolderAdministrationError, storage_folder_administration_api_router,
};

#[tokio::test]
async fn rejects_before_consuming_or_decoding_a_registration_body()
-> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let router = storage_folder_administration_api_router(FakeController {
        calls: Arc::clone(&calls),
    })?;
    let response = router
        .oneshot(
            Request::post("/api/latest/admin/storage-folders")
                .header("content-type", "application/json")
                .body(Body::from("not-json"))?,
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
async fn lists_and_registers_exact_validated_storage_folders()
-> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let router = storage_folder_administration_api_router(FakeController {
        calls: Arc::clone(&calls),
    })?;
    let listed = router
        .clone()
        .oneshot(
            Request::get("/api/latest/admin/storage-folders?limit=1")
                .header("x-test-auth", "yes")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(listed.status(), StatusCode::OK);
    let listed: ListStorageFoldersResponse =
        serde_json::from_slice(&to_bytes(listed.into_body(), 16_384).await?)?;
    assert_eq!(listed.folders, vec![summary()]);

    let request = RegisterStorageFolderRequest {
        operation_id: meshspan_api_contract::OperationId::from_uuid_bytes(versioned(3))
            .ok_or("operation")?,
        path: serde_json::from_value(serde_json::json!("/srv/meshspan"))?,
        usage_limit: StorageFolderUsageLimit::Percent { percent: 95 },
    };
    let registered = router
        .oneshot(
            Request::post("/api/latest/admin/storage-folders")
                .header("content-type", "application/json")
                .header("x-test-auth", "yes")
                .body(Body::from(serde_json::to_vec(&request)?))?,
        )
        .await?;
    assert_eq!(registered.status(), StatusCode::CREATED);
    let registered: RegisterStorageFolderResponse =
        serde_json::from_slice(&to_bytes(registered.into_body(), 16_384).await?)?;
    assert_eq!(registered.operation_id, request.operation_id);
    assert_eq!(registered.folder, summary());
    assert_eq!(
        calls.lock().map_err(|_| "poisoned calls")?.as_slice(),
        ["authenticate", "list", "authenticate", "register"]
    );
    Ok(())
}

struct FakeController {
    calls: Arc<Mutex<Vec<&'static str>>>,
}

impl StorageFolderAdministrationController for FakeController {
    fn authenticate(
        &self,
        headers: &HeaderMap,
        _protection: BrowserRequestProtection,
        now: UnixMicros,
    ) -> Result<IdentityAdministrator, StorageFolderAdministrationError> {
        self.calls
            .lock()
            .map_err(|_| StorageFolderAdministrationError::Unavailable)?
            .push("authenticate");
        if headers
            .get("x-test-auth")
            .and_then(|value| value.to_str().ok())
            != Some("yes")
        {
            return Err(StorageFolderAdministrationError::Unauthenticated);
        }
        Ok(IdentityAdministrator {
            principal_id: PrincipalId::from_bytes(uuid_v8(versioned(4)))
                .map_err(|_| StorageFolderAdministrationError::Failed)?,
            now,
        })
    }

    fn list_storage_folders(
        &self,
        _administrator: IdentityAdministrator,
        query: ListStorageFoldersQuery,
    ) -> Result<ListStorageFoldersResponse, StorageFolderAdministrationError> {
        if query.limit != Some(1) {
            return Err(StorageFolderAdministrationError::InvalidInput);
        }
        self.calls
            .lock()
            .map_err(|_| StorageFolderAdministrationError::Unavailable)?
            .push("list");
        Ok(ListStorageFoldersResponse {
            folders: vec![summary()],
            next_page_url: None,
        })
    }

    fn register_storage_folder(
        &mut self,
        _administrator: IdentityAdministrator,
        request: RegisterStorageFolderRequest,
    ) -> Result<RegisterStorageFolderResponse, StorageFolderAdministrationError> {
        self.calls
            .lock()
            .map_err(|_| StorageFolderAdministrationError::Unavailable)?
            .push("register");
        Ok(RegisterStorageFolderResponse {
            operation_id: request.operation_id,
            folder: summary(),
        })
    }
}

fn summary() -> StorageFolderSummary {
    StorageFolderSummary {
        target_id: "00000000-0000-4000-8000-000000000001".to_owned(),
        node_id: "00000000-0000-4000-8000-000000000002".to_owned(),
        path: Some("/srv/meshspan".to_owned()),
        generation: "1".to_owned(),
        usage_limit: StorageFolderUsageLimit::Percent { percent: 95 },
        state: StorageFolderState::Active,
    }
}

fn versioned(seed: u8) -> [u8; 16] {
    let mut value = [seed; 16];
    value[6] = 0x40;
    value[8] = 0x80;
    value
}
