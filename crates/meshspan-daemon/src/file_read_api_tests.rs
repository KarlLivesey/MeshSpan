// SPDX-License-Identifier: GPL-2.0-only

//! Native specialised bounded-file boundary and handle-lifecycle proofs.

#![allow(
    clippy::expect_used,
    reason = "HTTP boundary fixtures must stop at the first invalid checked value"
)]

use std::sync::{Arc, Mutex};

use axum::body::{Body, to_bytes};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use meshspan_contracts::BoundedBytes;
use meshspan_domain::{
    AssuranceLevel, AuthenticationService, EntropyError, FileVersionId, NamespaceCommitId, NodeId,
    ObjectId, ObjectRevisionId, RandomSource, UnixMicros,
};
use meshspan_filesystem::{
    AdapterCloseFileRequest, AdapterOpenFileRequest, AdapterReadFileRequest, CloseHandleOutcome,
    CloseHandleReceipt, FilesystemAccessContext, FilesystemHandleCloseReceipt,
    FilesystemHandleReadReceipt, OpenHandleReceipt, PublicationDisposition,
};
use tower::ServiceExt;

use crate::{
    FileApiAuthenticationError, FileApiFailure, FileRangeReader, FileReadService,
    NativeFileApiAuthenticator, NativeFileRequestProtection, file_read_api_router,
};

const VOLUME_ID: &str = "01010101-0101-4101-8101-010101010101";

#[tokio::test]
async fn authenticated_client_receives_verified_bounded_bytes_and_version()
-> Result<(), Box<dyn std::error::Error>> {
    let evidence = Evidence::default();
    let service = service(evidence.clone(), ReadMode::Success);
    let response = file_read_api_router(service)?
        .oneshot(request(&format!(
            "/api/latest/volumes/{VOLUME_ID}/file-content?path=reports%2Faccounts.csv&offset=2&length=4"
        )))
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(CONTENT_TYPE),
        Some(&HeaderValue::from_static("application/octet-stream"))
    );
    assert_eq!(
        response.headers().get("meshspan-read-offset"),
        Some(&HeaderValue::from_static("2"))
    );
    assert_eq!(
        response.headers().get("meshspan-file-version"),
        Some(&HeaderValue::from_static(
            "05050505-0505-4505-8505-050505050505"
        ))
    );
    assert_eq!(&to_bytes(response.into_body(), 16).await?[..], b"safe");
    assert_eq!(evidence.authenticated(), 1);
    assert_eq!(evidence.operations(), vec!["open", "read", "close"]);
    Ok(())
}

#[tokio::test]
async fn hostile_ranges_are_rejected_before_authentication_or_handle_work()
-> Result<(), Box<dyn std::error::Error>> {
    let evidence = Evidence::default();
    for query in [
        "",
        "unknown=true",
        "path=reports%ZZprivate",
        "path=reports%2F..%2Fprivate",
        "path=reports%2Ffile&offset=01",
        "path=reports%2Ffile&offset=1&offset=2",
        "path=reports%2Ffile&offset=9007199254740992",
        "path=reports%2Ffile&length=0",
        "path=reports%2Ffile&length=8388609",
    ] {
        let response = file_read_api_router(service(evidence.clone(), ReadMode::Success))?
            .oneshot(request(&format!(
                "/api/latest/volumes/{VOLUME_ID}/file-content?{query}"
            )))
            .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "query: {query}");
    }
    assert_eq!(evidence.authenticated(), 0);
    assert!(evidence.operations().is_empty());
    Ok(())
}

#[tokio::test]
async fn failed_content_read_still_releases_the_temporary_handle()
-> Result<(), Box<dyn std::error::Error>> {
    let evidence = Evidence::default();
    let response = file_read_api_router(service(evidence.clone(), ReadMode::Unavailable))?
        .oneshot(request(&format!(
            "/api/latest/volumes/{VOLUME_ID}/file-content?path=reports%2Faccounts.csv&length=4"
        )))
        .await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(evidence.operations(), vec!["open", "read", "close"]);
    Ok(())
}

fn service(
    evidence: Evidence,
    mode: ReadMode,
) -> FileReadService<CountingAuthenticator, TestReader, fn(&TestError) -> FileApiFailure, TestRandom>
{
    FileReadService::new(
        CountingAuthenticator {
            evidence: evidence.clone(),
        },
        TestReader { evidence, mode },
        classify_test_error,
        TestRandom { next: 31 },
    )
}

fn request(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header(AUTHORIZATION, "MeshSpan proof")
        .body(Body::empty())
        .expect("request fixture must build")
}

#[derive(Clone, Default)]
struct Evidence {
    authenticated: Arc<Mutex<usize>>,
    operations: Arc<Mutex<Vec<&'static str>>>,
}

impl Evidence {
    fn authenticated(&self) -> usize {
        *self
            .authenticated
            .lock()
            .expect("evidence lock must remain live")
    }

    fn operations(&self) -> Vec<&'static str> {
        self.operations
            .lock()
            .expect("evidence lock must remain live")
            .clone()
    }
}

struct CountingAuthenticator {
    evidence: Evidence,
}

impl NativeFileApiAuthenticator for CountingAuthenticator {
    fn authenticate_file_request(
        &self,
        headers: &HeaderMap,
        _protection: NativeFileRequestProtection,
        now: UnixMicros,
    ) -> Result<FilesystemAccessContext, FileApiAuthenticationError> {
        *self
            .evidence
            .authenticated
            .lock()
            .map_err(|_| FileApiAuthenticationError::AuthorityUnavailable)? += 1;
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
}

#[derive(Clone, Copy)]
enum ReadMode {
    Success,
    Unavailable,
}

struct TestReader {
    evidence: Evidence,
    mode: ReadMode,
}

impl FileRangeReader for TestReader {
    type Error = TestError;

    fn open_file(
        &mut self,
        _context: FilesystemAccessContext,
        request: &AdapterOpenFileRequest,
    ) -> Result<OpenHandleReceipt, Self::Error> {
        self.record("open")?;
        Ok(OpenHandleReceipt {
            disposition: PublicationDisposition::Applied,
            operation_id: request.operation_id,
            handle_id: request.handle_id,
            request_digest: [1; 32],
            namespace_commit_id: NamespaceCommitId::from_bytes(versioned(2))
                .map_err(|_| TestError)?,
            object_id: ObjectId::from_bytes(versioned(3)).map_err(|_| TestError)?,
            object_revision_id: ObjectRevisionId::from_bytes(versioned(4))
                .map_err(|_| TestError)?,
            opened_version_id: file_version()?,
            opened_logical_length: 0,
            handle_fence: 1,
            truncate_on_first_write: false,
            result_digest: [2; 32],
        })
    }

    fn read_range(
        &mut self,
        _context: FilesystemAccessContext,
        _request: AdapterReadFileRequest,
    ) -> Result<FilesystemHandleReadReceipt, Self::Error> {
        self.record("read")?;
        if matches!(self.mode, ReadMode::Unavailable) {
            return Err(TestError);
        }
        Ok(FilesystemHandleReadReceipt {
            opened_version_id: file_version()?,
            checkpoint_sequence: 0,
            bytes: BoundedBytes::copy_from(b"safe", 4).map_err(|_| TestError)?,
        })
    }

    fn close_file(
        &mut self,
        _context: FilesystemAccessContext,
        request: AdapterCloseFileRequest,
    ) -> Result<FilesystemHandleCloseReceipt, Self::Error> {
        self.record("close")?;
        Ok(FilesystemHandleCloseReceipt {
            flush: None,
            delete: None,
            close: CloseHandleReceipt {
                disposition: PublicationDisposition::Applied,
                operation_id: request.operation_id,
                handle_id: request.handle_id,
                request_digest: [3; 32],
                handle_fence: request.handle_fence,
                outcome: CloseHandleOutcome::Closed,
                closed_at: request.observed_at,
                result_digest: [4; 32],
            },
        })
    }
}

impl TestReader {
    fn record(&self, operation: &'static str) -> Result<(), TestError> {
        self.evidence
            .operations
            .lock()
            .map_err(|_| TestError)?
            .push(operation);
        Ok(())
    }
}

#[derive(Debug)]
struct TestError;

const fn classify_test_error(_error: &TestError) -> FileApiFailure {
    FileApiFailure::Unavailable
}

struct TestRandom {
    next: u8,
}

impl RandomSource for TestRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        destination.fill(self.next);
        self.next = self.next.wrapping_add(1);
        Ok(())
    }
}

fn file_version() -> Result<FileVersionId, TestError> {
    FileVersionId::from_bytes(versioned(5)).map_err(|_| TestError)
}

const fn versioned(seed: u8) -> [u8; 16] {
    let mut bytes = [seed; 16];
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes
}
