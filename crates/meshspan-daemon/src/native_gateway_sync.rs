// SPDX-License-Identifier: GPL-2.0-only

//! Same-swarm immutable namespace and content-layout convergence for native gateways.

mod receiver;
mod source;

use std::path::Path;

use meshspan_cluster::{ConsensusNetwork, PeerControlRequest};
use meshspan_domain::OperationId;
use meshspan_protocol::v1::control_envelope::Message;
use meshspan_protocol::v1::{ControlEnvelope, RequestHeader};
use thiserror::Error;

pub(crate) async fn handle(
    network: &ConsensusNetwork,
    state_directory: &Path,
    peer: &PeerControlRequest,
    operation_id: OperationId,
    request_header: &RequestHeader,
    message: &Message,
) -> Result<Option<ControlEnvelope>, NativeGatewaySyncError> {
    let response = match message {
        Message::FetchNamespaceHistoryPage(request) => {
            let state_directory = state_directory.to_path_buf();
            let request = request.clone();
            let requester = peer.from;
            tokio::task::spawn_blocking(move || {
                source::history_page(&state_directory, requester, request)
            })
            .await
            .map_err(|_| NativeGatewaySyncError::Unavailable)??
        }
        Message::FetchNamespaceHistoryObject(request) => {
            let state_directory = state_directory.to_path_buf();
            let request = request.clone();
            let requester = peer.from;
            tokio::task::spawn_blocking(move || {
                source::history_object(&state_directory, requester, request)
            })
            .await
            .map_err(|_| NativeGatewaySyncError::Unavailable)??
        }
        Message::FetchNativeContentLayout(request) => {
            let state_directory = state_directory.to_path_buf();
            let request = request.clone();
            tokio::task::spawn_blocking(move || source::content_layout(&state_directory, request))
                .await
                .map_err(|_| NativeGatewaySyncError::Unavailable)??
        }
        Message::PublishNamespaceHead(request) => {
            receiver::publish_head(
                network,
                state_directory,
                peer.from,
                operation_id,
                request_header.deadline_unix_micros,
                request,
            )
            .await?
        }
        _ => return Ok(None),
    };
    Ok(Some(ControlEnvelope {
        header: Some(network.control_header(operation_id, request_header.deadline_unix_micros)?),
        message: Some(response),
    }))
}

pub(super) fn identifier<const LENGTH: usize>(
    bytes: &[u8],
) -> Result<[u8; LENGTH], NativeGatewaySyncError> {
    bytes
        .try_into()
        .map_err(|_| NativeGatewaySyncError::Invalid)
}

#[derive(Debug, Error)]
pub(crate) enum NativeGatewaySyncError {
    #[error("native gateway convergence input is invalid")]
    Invalid,
    #[error("native gateway convergence is unavailable")]
    Unavailable,
}

impl From<meshspan_cluster::ConsensusNetworkError> for NativeGatewaySyncError {
    fn from(_: meshspan_cluster::ConsensusNetworkError) -> Self {
        Self::Unavailable
    }
}
