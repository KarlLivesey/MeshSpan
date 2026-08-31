// SPDX-License-Identifier: GPL-2.0-only

//! Native specialised object-metadata boundary proofs.

#![allow(
    clippy::expect_used,
    reason = "HTTP boundary fixtures must stop at the first invalid checked value"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::{Body, to_bytes};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use meshspan_api_contract::GetObjectResponse;
use meshspan_domain::{
    AssuranceLevel, AuthenticationService, FileVersionId, NamespaceCommitId, NodeId, ObjectId,
    ObjectRevisionId, UnixMicros,
};
use meshspan_filesystem::{
    AdapterStatRequest, DirectoryEntryKind, FilesystemAccessContext, NamespaceComponent,
    NamespaceLimits, NamespaceObjectStat,
};
use tower::ServiceExt;

use crate::{
    FileApiAuthenticationError, FileApiAuthenticator, FileApiFailure, ObjectStatReader,
    ObjectStatService, object_stat_api_router,
};

const VOLUME_ID: &str = "01010101-0101-4101-8101-010101010101";

#[tokio::test]
async fn authenticated_client_receives_complete_immutable_object_metadata()
-> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let service = ObjectStatService::new(
        HeaderAuthenticator,
        StatReader {
            calls: Arc::clone(&calls),
        },
        classify_unit_error,
    );
    let response = object_stat_api_router(service)?
        .oneshot(request(&format!(
            "/api/latest/volumes/{VOLUME_ID}/objects?path=reports%2Faccounts.csv"
        )))
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body: GetObjectResponse =
        serde_json::from_slice(&to_bytes(response.into_body(), 16_384).await?)?;
    assert_eq!(body.path.as_str(), "reports/accounts.csv");
    assert_eq!(body.object.name, "accounts.csv");
    assert_eq!(body.object.logical_length, Some(1_024));
    assert!(body.object.file_version_id.is_some());
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    Ok(())
}

#[tokio::test]
async fn hostile_object_queries_are_rejected_before_authentication_or_filesystem_work()
-> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    for query in [
        "",
        "unknown=true",
        "path=one&path=two",
        "path=reports%ZZprivate",
        "path=reports%2F..%2Fprivate",
        "path=%2Fabsolute",
    ] {
        let service = ObjectStatService::new(
            HeaderAuthenticator,
            StatReader {
                calls: Arc::clone(&calls),
            },
            classify_unit_error,
        );
        let response = object_stat_api_router(service)?
            .oneshot(request(&format!(
                "/api/latest/volumes/{VOLUME_ID}/objects?{query}"
            )))
            .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "query: {query}");
    }
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    Ok(())
}

fn request(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header(AUTHORIZATION, "MeshSpan proof")
        .body(Body::empty())
        .expect("request fixture must build")
}

const fn classify_unit_error(_error: &TestStatError) -> FileApiFailure {
    FileApiFailure::Failed
}

enum TestStatError {
    Invalid,
}

struct HeaderAuthenticator;

impl FileApiAuthenticator for HeaderAuthenticator {
    fn authenticate_file_read(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<FilesystemAccessContext, FileApiAuthenticationError> {
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

struct StatReader {
    calls: Arc<AtomicUsize>,
}

impl ObjectStatReader for StatReader {
    type Error = TestStatError;

    fn stat_object(
        &self,
        _context: FilesystemAccessContext,
        request: &AdapterStatRequest,
    ) -> Result<NamespaceObjectStat, Self::Error> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if request.path.components().len() != 2 {
            return Err(TestStatError::Invalid);
        }
        Ok(NamespaceObjectStat {
            namespace_commit_id: NamespaceCommitId::from_bytes(versioned(2))
                .map_err(|_| TestStatError::Invalid)?,
            object_id: ObjectId::from_bytes(versioned(3)).map_err(|_| TestStatError::Invalid)?,
            object_revision_id: ObjectRevisionId::from_bytes(versioned(4))
                .map_err(|_| TestStatError::Invalid)?,
            name: NamespaceComponent::new("accounts.csv", NamespaceLimits::PORTABLE)
                .map_err(|_| TestStatError::Invalid)?,
            entry_generation: 1,
            kind: DirectoryEntryKind::File,
            file_version_id: Some(
                FileVersionId::from_bytes(versioned(5)).map_err(|_| TestStatError::Invalid)?,
            ),
            logical_length: Some(1_024),
        })
    }
}

const fn versioned(seed: u8) -> [u8; 16] {
    let mut bytes = [seed; 16];
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes
}
