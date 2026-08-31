// SPDX-License-Identifier: GPL-2.0-only

//! Native specialised file-API directory boundary proofs.

#![allow(
    clippy::expect_used,
    reason = "HTTP boundary fixtures must stop at the first invalid checked value"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::{Body, to_bytes};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use meshspan_api_contract::ListDirectoryResponse;
use meshspan_domain::{
    AssuranceLevel, AuthenticationService, NamespaceCommitId, NodeId, ObjectId, ObjectRevisionId,
    UnixMicros,
};
use meshspan_filesystem::{
    AdapterListRequest, DirectoryEntryKind, DirectoryListCursor, FilesystemAccessContext,
    NamespaceComponent, NamespaceLimits, NamespaceListEntry, NamespaceListPage,
};
use tower::ServiceExt;

use crate::{
    DirectoryLister, DirectoryListingFailure, DirectoryListingService, FileApiAuthenticationError,
    FileApiAuthenticator, directory_listing_api_router,
};

const VOLUME_ID: &str = "01010101-0101-4101-8101-010101010101";

#[tokio::test]
async fn authenticated_client_follows_complete_directory_pages_without_stat_requests()
-> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let service = DirectoryListingService::new(
        HeaderAuthenticator,
        PageLister {
            calls: Arc::clone(&calls),
        },
        classify_unit_error,
    );
    let router = directory_listing_api_router(service)?;

    let first = router
        .clone()
        .oneshot(request(&format!(
            "/api/latest/volumes/{VOLUME_ID}/directory-entries?path=reports%2F2026&limit=1"
        )))
        .await?;
    let first_status = first.status();
    let first_body = to_bytes(first.into_body(), 16_384).await?;
    assert_eq!(
        first_status,
        StatusCode::OK,
        "unexpected response: {}",
        String::from_utf8_lossy(&first_body)
    );
    let first: ListDirectoryResponse = serde_json::from_slice(&first_body)?;
    assert_eq!(first.entries.len(), 1);
    assert_eq!(first.entries[0].name, "accounts.csv");
    assert_eq!(first.entries[0].logical_length, Some(1_024));
    let next = first
        .next_page_url
        .as_deref()
        .expect("non-terminal page must provide a continuation URL");
    assert!(next.contains("path=reports%2F2026"));

    let second = router.oneshot(request(next)).await?;
    assert_eq!(second.status(), StatusCode::OK);
    let second: ListDirectoryResponse =
        serde_json::from_slice(&to_bytes(second.into_body(), 16_384).await?)?;
    assert_eq!(second.entries.len(), 1);
    assert_eq!(second.entries[0].name, "summary.txt");
    assert!(second.next_page_url.is_none());
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    Ok(())
}

#[tokio::test]
async fn missing_authentication_never_reaches_the_filesystem()
-> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let service = DirectoryListingService::new(
        HeaderAuthenticator,
        PageLister {
            calls: Arc::clone(&calls),
        },
        classify_unit_error,
    );
    let response = directory_listing_api_router(service)?
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/latest/volumes/{VOLUME_ID}/directory-entries?limit=1"
                ))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    Ok(())
}

#[tokio::test]
async fn hostile_query_shapes_are_rejected_before_auth_or_filesystem_work()
-> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    for query in [
        "unknown=true",
        "limit=1&limit=2",
        "limit=257",
        "path=reports%ZZ2026",
        "path=reports%2F..%2Fprivate",
        "cursor=contains%20spaces",
    ] {
        let service = DirectoryListingService::new(
            HeaderAuthenticator,
            PageLister {
                calls: Arc::clone(&calls),
            },
            classify_unit_error,
        );
        let response = directory_listing_api_router(service)?
            .oneshot(request(&format!(
                "/api/latest/volumes/{VOLUME_ID}/directory-entries?{query}"
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

const fn classify_unit_error(_error: &TestListerError) -> DirectoryListingFailure {
    DirectoryListingFailure::Failed
}

enum TestListerError {
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
            authentication_service: AuthenticationService::Https,
            credential_digest: [9; 32],
            required_assurance: AssuranceLevel::SingleFactor,
            gateway_node_id: NodeId::from_bytes(versioned(9))
                .map_err(|_| FileApiAuthenticationError::InvalidGateway)?,
            gateway_incarnation: 1,
            now,
        })
    }
}

struct PageLister {
    calls: Arc<AtomicUsize>,
}

impl DirectoryLister for PageLister {
    type Error = TestListerError;

    fn list_directory(
        &self,
        _context: FilesystemAccessContext,
        request: &AdapterListRequest,
    ) -> Result<NamespaceListPage, Self::Error> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let second = request.cursor.is_some();
        Ok(NamespaceListPage {
            namespace_commit_id: NamespaceCommitId::from_bytes(versioned(2))
                .map_err(|_| TestListerError::Invalid)?,
            directory_object_id: ObjectId::from_bytes(versioned(3))
                .map_err(|_| TestListerError::Invalid)?,
            directory_object_revision_id: ObjectRevisionId::from_bytes(versioned(4))
                .map_err(|_| TestListerError::Invalid)?,
            entries: vec![NamespaceListEntry {
                name: NamespaceComponent::new(
                    if second {
                        "summary.txt"
                    } else {
                        "accounts.csv"
                    },
                    NamespaceLimits::PORTABLE,
                )
                .map_err(|_| TestListerError::Invalid)?,
                object_id: ObjectId::from_bytes(versioned(if second { 10 } else { 5 }))
                    .map_err(|_| TestListerError::Invalid)?,
                object_revision_id: ObjectRevisionId::from_bytes(versioned(if second {
                    11
                } else {
                    6
                }))
                .map_err(|_| TestListerError::Invalid)?,
                entry_generation: 1,
                kind: DirectoryEntryKind::File,
                file_version_id: Some(
                    meshspan_domain::FileVersionId::from_bytes(versioned(if second {
                        12
                    } else {
                        7
                    }))
                    .map_err(|_| TestListerError::Invalid)?,
                ),
                logical_length: Some(if second { 512 } else { 1_024 }),
            }],
            next_cursor: (!second).then(|| DirectoryListCursor {
                namespace_commit_id: NamespaceCommitId::from_bytes(versioned(2))
                    .expect("fixture identifier must be valid"),
                directory_object_id: ObjectId::from_bytes(versioned(3))
                    .expect("fixture identifier must be valid"),
                directory_object_revision_id: ObjectRevisionId::from_bytes(versioned(4))
                    .expect("fixture identifier must be valid"),
                after_name_hash: [8; 32],
                after_name: NamespaceComponent::new("accounts.csv", NamespaceLimits::PORTABLE)
                    .expect("fixture name must be valid"),
            }),
        })
    }
}

fn versioned(value: u8) -> [u8; 16] {
    let mut bytes = [value; 16];
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes
}
