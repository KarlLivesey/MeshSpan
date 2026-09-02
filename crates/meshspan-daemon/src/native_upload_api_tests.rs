// SPDX-License-Identifier: GPL-2.0-only

//! Real HTTP proofs for the specialised native resumable-upload boundary.

#![allow(
    clippy::expect_used,
    reason = "HTTP fixtures must stop immediately when their own evidence is invalid"
)]

use std::sync::{Arc, Mutex};

use axum::body::{Body, to_bytes};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use meshspan_api_contract::{
    AbortUploadRequest, AbortUploadResponse, BeginUploadRequest, BeginUploadResponse,
    CommitUploadRequest, CommitUploadResponse, ListUploadRangesResponse, UploadStatusResponse,
    WriteUploadRangeResponse,
};
use meshspan_domain::{AssuranceLevel, AuthenticationService, NodeId, UnixMicros};
use meshspan_filesystem::FilesystemAccessContext;
use tower::ServiceExt;

use crate::{
    FileApiAuthenticationError, NativeFileRequestProtection, NativeUploadController,
    NativeUploadError, UploadRangePageRequest, UploadRangeWriteRequest, native_upload_api_router,
};

const VOLUME_ID: &str = "01010101-0101-4101-8101-010101010101";
const UPLOAD_ID: &str = "06060606-0606-4606-8606-060606060606";
const OPERATION_ID: &str = "07070707-0707-4707-8707-070707070707";

#[tokio::test]
async fn native_upload_http_lifecycle_is_bounded_authenticated_and_explicit()
-> Result<(), Box<dyn std::error::Error>> {
    let evidence = Evidence::default();
    let router = native_upload_api_router(TestController {
        evidence: evidence.clone(),
    })?;

    let begin = router
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/api/latest/volumes/{VOLUME_ID}/uploads"),
            &serde_json::json!({
                "disposition": { "mode": "create_new" },
                "maximum_bytes": 1024,
                "operation_id": OPERATION_ID,
                "path": "reports/accounts.csv"
            }),
        ))
        .await?;
    assert_eq!(begin.status(), StatusCode::CREATED);

    let write = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/api/latest/uploads/{UPLOAD_ID}/ranges/0"))
                .header(AUTHORIZATION, "MeshSpan proof")
                .header(CONTENT_TYPE, "application/octet-stream")
                .header("MeshSpan-Operation-Id", OPERATION_ID)
                .header("MeshSpan-Stage-Fence", "1")
                .header("MeshSpan-Content-BLAKE3", "a".repeat(64))
                .body(Body::from("safe"))?,
        )
        .await?;
    assert_eq!(write.status(), StatusCode::OK);

    let status = router
        .clone()
        .oneshot(read_request(&format!("/api/latest/uploads/{UPLOAD_ID}"))?)
        .await?;
    assert_eq!(status.status(), StatusCode::OK);

    let ranges = router
        .clone()
        .oneshot(read_request(&format!(
            "/api/latest/uploads/{UPLOAD_ID}/ranges?cursor=v1.1.0&limit=2"
        ))?)
        .await?;
    assert_eq!(ranges.status(), StatusCode::OK);

    let commit = router
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/api/latest/uploads/{UPLOAD_ID}/commits"),
            &serde_json::json!({
                "expected_blake3": "a".repeat(64),
                "expected_sequence": 1,
                "final_length": 4,
                "operation_id": OPERATION_ID,
                "sparse": false,
                "stage_fence": 1
            }),
        ))
        .await?;
    assert_eq!(commit.status(), StatusCode::OK);

    let abort = router
        .oneshot(json_request(
            "POST",
            &format!("/api/latest/uploads/{UPLOAD_ID}/aborts"),
            &serde_json::json!({
                "operation_id": OPERATION_ID,
                "stage_fence": 1
            }),
        ))
        .await?;
    assert_eq!(abort.status(), StatusCode::OK);
    assert_eq!(
        evidence.operations(),
        vec![
            "auth:mutation",
            "begin",
            "auth:mutation",
            "write",
            "auth:read",
            "status",
            "auth:read",
            "ranges",
            "auth:mutation",
            "commit",
            "auth:mutation",
            "abort",
        ]
    );
    Ok(())
}

#[tokio::test]
async fn rejected_credentials_stop_before_large_upload_body_is_consumed()
-> Result<(), Box<dyn std::error::Error>> {
    let evidence = Evidence::default();
    let response = native_upload_api_router(TestController {
        evidence: evidence.clone(),
    })?
    .oneshot(
        Request::builder()
            .method("PUT")
            .uri(format!("/api/latest/uploads/{UPLOAD_ID}/ranges/0"))
            .header(CONTENT_TYPE, "application/octet-stream")
            .header("MeshSpan-Operation-Id", OPERATION_ID)
            .header("MeshSpan-Stage-Fence", "1")
            .header("MeshSpan-Content-BLAKE3", "a".repeat(64))
            .body(Body::from(vec![7_u8; 8 * 1_024 * 1_024 + 1]))?,
    )
    .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(evidence.operations(), vec!["auth:mutation"]);
    assert!(to_bytes(response.into_body(), 4_096).await?.len() < 4_096);
    Ok(())
}

#[derive(Clone, Default)]
struct Evidence(Arc<Mutex<Vec<&'static str>>>);

impl Evidence {
    fn record(&self, value: &'static str) {
        self.0
            .lock()
            .expect("evidence lock must remain live")
            .push(value);
    }

    fn operations(&self) -> Vec<&'static str> {
        self.0
            .lock()
            .expect("evidence lock must remain live")
            .clone()
    }
}

struct TestController {
    evidence: Evidence,
}

impl NativeUploadController for TestController {
    fn authenticate(
        &self,
        headers: &HeaderMap,
        protection: NativeFileRequestProtection,
        now: UnixMicros,
    ) -> Result<FilesystemAccessContext, FileApiAuthenticationError> {
        self.evidence.record(match protection {
            NativeFileRequestProtection::Read => "auth:read",
            NativeFileRequestProtection::Mutation => "auth:mutation",
        });
        if headers.get(AUTHORIZATION) != Some(&HeaderValue::from_static("MeshSpan proof")) {
            return Err(FileApiAuthenticationError::Rejected);
        }
        Ok(FilesystemAccessContext {
            authentication_service: AuthenticationService::HeadlessApi,
            credential_digest: [9; 32],
            required_assurance: AssuranceLevel::SingleFactor,
            gateway_node_id: NodeId::from_bytes(versioned(9))
                .map_err(|_| FileApiAuthenticationError::InvalidGateway)?,
            gateway_incarnation: 1,
            now,
        })
    }

    fn begin_upload(
        &mut self,
        _context: FilesystemAccessContext,
        _volume_id: &str,
        _request: BeginUploadRequest,
    ) -> Result<BeginUploadResponse, NativeUploadError> {
        self.evidence.record("begin");
        status("active", 0, None, None)
    }

    fn get_upload(
        &mut self,
        _context: FilesystemAccessContext,
        _upload_id: &str,
    ) -> Result<UploadStatusResponse, NativeUploadError> {
        self.evidence.record("status");
        status("active", 1, None, None)
    }

    fn list_upload_ranges(
        &mut self,
        _context: FilesystemAccessContext,
        _upload_id: &str,
        request: UploadRangePageRequest,
    ) -> Result<ListUploadRangesResponse, NativeUploadError> {
        self.evidence.record("ranges");
        if request.cursor.is_none() || request.limit != 2 {
            return Err(NativeUploadError::InvalidInput);
        }
        serde_json::from_value(serde_json::json!({
            "checkpoint_sequence": 1,
            "next_page_url": null,
            "ranges": [{ "end": 4, "start": 0 }],
            "upload_id": UPLOAD_ID
        }))
        .map_err(|_| NativeUploadError::Failed)
    }

    fn write_upload_range(
        &mut self,
        _context: FilesystemAccessContext,
        _upload_id: &str,
        request: UploadRangeWriteRequest,
    ) -> Result<WriteUploadRangeResponse, NativeUploadError> {
        self.evidence.record("write");
        if request.bytes.as_slice() != b"safe" || request.content_blake3 != [0xaa; 32] {
            return Err(NativeUploadError::InvalidInput);
        }
        status("active", 1, None, None)
    }

    fn commit_upload(
        &mut self,
        _context: FilesystemAccessContext,
        _upload_id: &str,
        _request: CommitUploadRequest,
    ) -> Result<CommitUploadResponse, NativeUploadError> {
        self.evidence.record("commit");
        serde_json::from_value(serde_json::json!({
            "acknowledgement": {
                "achieved_protection_blake3": "b".repeat(64),
                "durability_scope": "cell_replicated",
                "eventual_shard_receipts": 1,
                "pending_debt_blake3": "c".repeat(64),
                "pending_eventual_shards": 2,
                "policy_committed": true,
                "policy_evidence_blake3": "a".repeat(64),
                "required_shard_receipts": 3
            },
            "object": object_response(),
            "upload": status_value(
                "committed",
                1,
                Some("02020202-0202-4202-8202-020202020202"),
                Some("05050505-0505-4505-8505-050505050505")
            )
        }))
        .map_err(|_| NativeUploadError::Failed)
    }

    fn abort_upload(
        &mut self,
        _context: FilesystemAccessContext,
        _upload_id: &str,
        _request: AbortUploadRequest,
    ) -> Result<AbortUploadResponse, NativeUploadError> {
        self.evidence.record("abort");
        status("aborted", 1, None, None)
    }
}

fn json_request(method: &str, uri: &str, value: &serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(AUTHORIZATION, "MeshSpan proof")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(value.to_string()))
        .expect("JSON request fixture must build")
}

fn read_request(uri: &str) -> Result<Request<Body>, axum::http::Error> {
    Request::builder()
        .uri(uri)
        .header(AUTHORIZATION, "MeshSpan proof")
        .body(Body::empty())
}

fn status(
    state: &str,
    sequence: u64,
    object_id: Option<&str>,
    version_id: Option<&str>,
) -> Result<UploadStatusResponse, NativeUploadError> {
    serde_json::from_value(status_value(state, sequence, object_id, version_id))
        .map_err(|_| NativeUploadError::Failed)
}

fn status_value(
    state: &str,
    sequence: u64,
    object_id: Option<&str>,
    version_id: Option<&str>,
) -> serde_json::Value {
    serde_json::json!({
        "checkpoint_sequence": sequence,
        "committed_object_id": object_id,
        "committed_version_id": version_id,
        "expires_at_epoch_micros": 1_800_000_000_000_000_i64,
        "logical_extent": if sequence == 0 { 0 } else { 4 },
        "maximum_bytes": 1024,
        "path": "reports/accounts.csv",
        "ranges_url": format!("/api/latest/uploads/{UPLOAD_ID}/ranges"),
        "stage_fence": 1,
        "state": state,
        "upload_id": UPLOAD_ID,
        "volume_id": VOLUME_ID
    })
}

fn object_response() -> serde_json::Value {
    serde_json::json!({
        "namespace_commit_id": "04040404-0404-4404-8404-040404040404",
        "object": {
            "entry_generation": 1,
            "file_version_id": "05050505-0505-4505-8505-050505050505",
            "kind": "file",
            "logical_length": 4,
            "name": "accounts.csv",
            "object_id": "02020202-0202-4202-8202-020202020202",
            "object_revision_id": "03030303-0303-4303-8303-030303030303"
        },
        "path": "reports/accounts.csv",
        "volume_id": VOLUME_ID
    })
}

fn versioned(seed: u8) -> [u8; 16] {
    let mut bytes = [seed; 16];
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes
}
