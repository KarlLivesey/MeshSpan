// SPDX-License-Identifier: GPL-2.0-only

//! Durable receiver boundary for authenticated federation history.

use std::future::Future;
use std::pin::Pin;

use meshspan_domain::UnixMicros;
use meshspan_filesystem::{
    NamespaceHistoryImmutableRecord, NamespaceHistoryPage, NamespaceHistoryReceiveCompletion,
    NamespaceHistoryReceiveRequest, NamespaceHistoryReceiveStatus, PublicationError,
    VersionPublicationStore,
};
use thiserror::Error;

use crate::FilesystemFederationHistorySource;

/// Owned future returned by a receiver which may dispatch blocking persistence work.
pub type FederationHistoryReceiveFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, FederationHistoryReceiveError>> + Send + 'a>>;

/// Persistence boundary required by the federation history convergence driver.
pub trait FederationHistoryReceiver: Send + Sync {
    /// Starts or resumes an exact durable receive transaction.
    fn begin(
        &self,
        request: NamespaceHistoryReceiveRequest,
    ) -> FederationHistoryReceiveFuture<'_, NamespaceHistoryReceiveStatus>;

    /// Persists one exact sequential authenticated page.
    fn accept_page(
        &self,
        session_id: [u8; 32],
        input_cursor: Vec<u8>,
        page: NamespaceHistoryPage,
        now: UnixMicros,
    ) -> FederationHistoryReceiveFuture<'_, NamespaceHistoryReceiveStatus>;

    /// Persists one independently authenticated advertised body.
    fn accept_object(
        &self,
        session_id: [u8; 32],
        record: NamespaceHistoryImmutableRecord,
        now: UnixMicros,
    ) -> FederationHistoryReceiveFuture<'_, NamespaceHistoryReceiveStatus>;

    /// Atomically validates and imports a terminal complete transaction.
    fn complete(
        &self,
        session_id: [u8; 32],
        now: UnixMicros,
    ) -> FederationHistoryReceiveFuture<'_, NamespaceHistoryReceiveCompletion>;
}

impl FederationHistoryReceiver for FilesystemFederationHistorySource {
    fn begin(
        &self,
        request: NamespaceHistoryReceiveRequest,
    ) -> FederationHistoryReceiveFuture<'_, NamespaceHistoryReceiveStatus> {
        let state_directory = self.state_directory().to_owned();
        blocking(move || {
            let mut store = VersionPublicationStore::open(&state_directory, request.now)?;
            store.begin_namespace_history_receive(&request)
        })
    }

    fn accept_page(
        &self,
        session_id: [u8; 32],
        input_cursor: Vec<u8>,
        page: NamespaceHistoryPage,
        now: UnixMicros,
    ) -> FederationHistoryReceiveFuture<'_, NamespaceHistoryReceiveStatus> {
        let state_directory = self.state_directory().to_owned();
        blocking(move || {
            let mut store = VersionPublicationStore::open(&state_directory, now)?;
            store.receive_namespace_history_page(session_id, &input_cursor, &page, now)
        })
    }

    fn accept_object(
        &self,
        session_id: [u8; 32],
        record: NamespaceHistoryImmutableRecord,
        now: UnixMicros,
    ) -> FederationHistoryReceiveFuture<'_, NamespaceHistoryReceiveStatus> {
        let state_directory = self.state_directory().to_owned();
        blocking(move || {
            let mut store = VersionPublicationStore::open(&state_directory, now)?;
            store.receive_namespace_history_object(session_id, &record, now)
        })
    }

    fn complete(
        &self,
        session_id: [u8; 32],
        now: UnixMicros,
    ) -> FederationHistoryReceiveFuture<'_, NamespaceHistoryReceiveCompletion> {
        let state_directory = self.state_directory().to_owned();
        blocking(move || {
            let mut store = VersionPublicationStore::open(&state_directory, now)?;
            store.complete_namespace_history_receive(session_id, now)
        })
    }
}

fn blocking<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T, PublicationError> + Send + 'static,
) -> FederationHistoryReceiveFuture<'static, T> {
    Box::pin(async move {
        tokio::task::spawn_blocking(operation)
            .await
            .map_err(|_| FederationHistoryReceiveError::Unavailable)?
            .map_err(Into::into)
    })
}

/// Closed failures from receiver persistence or its blocking worker.
#[derive(Debug, Error)]
pub enum FederationHistoryReceiveError {
    /// The blocking persistence worker exited without a result.
    #[error("federation history receiver is unavailable")]
    Unavailable,
    /// The durable filesystem receiver rejected or could not persist the transaction.
    #[error("federation history receiver rejected the transaction")]
    Publication(#[from] PublicationError),
}
