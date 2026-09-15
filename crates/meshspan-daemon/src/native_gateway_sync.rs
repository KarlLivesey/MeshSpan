// SPDX-License-Identifier: GPL-2.0-only

//! Same-swarm immutable namespace and content-layout convergence for native gateways.

mod convergence;
mod history;
mod receiver;
mod sender;
mod source;

pub(crate) use history::NativeGatewayHistory;
pub(crate) use sender::NamespaceDeliveryWorker;

#[cfg(test)]
pub(crate) use receiver::assert_fresh_repaired_import;

use meshspan_cluster::{ConsensusNetwork, PeerControlRequest};
use meshspan_domain::OperationId;
use meshspan_protocol::v1::control_envelope::Message;
use meshspan_protocol::v1::{ControlEnvelope, RequestHeader};
use thiserror::Error;

pub(crate) async fn handle(
    network: &ConsensusNetwork,
    history: &NativeGatewayHistory,
    peer: &PeerControlRequest,
    operation_id: OperationId,
    request_header: &RequestHeader,
    message: &Message,
) -> Result<Option<ControlEnvelope>, NativeGatewaySyncError> {
    let response = match message {
        Message::FetchNamespaceHistoryPage(request) => {
            let request = request.clone();
            let requester = peer.from;
            history
                .execute(move |store| source::history_page(store, requester, request))
                .await?
        }
        Message::FetchNamespaceHistoryObject(request) => {
            let request = request.clone();
            let requester = peer.from;
            history
                .execute(move |store| source::history_object(store, requester, &request))
                .await?
        }
        Message::FetchNativeContentLayout(request) => {
            let state_directory = history.state_directory.clone();
            let request = request.clone();
            tokio::task::spawn_blocking(move || source::content_layout(&state_directory, &request))
                .await
                .map_err(|_| NativeGatewaySyncError::Unavailable)??
        }
        Message::PublishNamespaceHead(request) => {
            receiver::publish_head(
                network,
                history,
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
