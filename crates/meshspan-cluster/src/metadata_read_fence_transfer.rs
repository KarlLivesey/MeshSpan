// SPDX-License-Identifier: GPL-2.0-only

//! Request-bound read frontiers; these never confer maintenance or user permissions.

use std::time::Duration;

use meshspan_domain::{NodeId, OperationId, PartitionId, Revision, UnixMicros};
use meshspan_protocol::{
    encode_control_frame,
    v1::{
        ControlEnvelope, ErrorCode, FetchMetadataReadFence, MetadataReadFenceResult, WireError,
        control_envelope::Message, metadata_read_fence_result::Outcome,
    },
};

use crate::{ConsensusNetwork, MetadataAuthorityRequestError as RequestError, MetadataReadFence};

const TRANSFER_TIMEOUT: Duration = Duration::from_secs(10);

impl ConsensusNetwork {
    /// Obtains a nonce-bound read frontier from one exact current voter candidate.
    ///
    /// The caller selects a voter from its trusted phase and supplies a fresh unpredictable
    /// nonce. The result is not a permission lease: catch up to and verify the exact frontier
    /// before checking current metadata for the particular operation.
    ///
    /// # Errors
    /// Rejects timeout, unavailable leaders, wrong identity/correlation and malformed results.
    pub async fn fetch_metadata_read_fence(
        &self,
        source: NodeId,
        operation: OperationId,
        nonce: [u8; 32],
        now: UnixMicros,
    ) -> Result<MetadataReadFence, RequestError> {
        let deadline = now
            .get()
            .checked_add(10_000_000)
            .ok_or(RequestError::Unavailable)?;
        let request = ControlEnvelope {
            header: Some(
                self.control_header(operation, deadline)
                    .map_err(|_| RequestError::Failed)?,
            ),
            message: Some(Message::FetchMetadataReadFence(FetchMetadataReadFence {
                nonce: nonce.to_vec(),
            })),
        };
        let response =
            tokio::time::timeout(TRANSFER_TIMEOUT, self.request_control(source, &request))
                .await
                .map_err(|_| RequestError::Unavailable)?
                .map_err(|_| RequestError::Unavailable)?;
        parse_response(&request, response.as_inner(), source)
    }
}

/// Encodes an already admitted and freshly confirmed read, or a typed rejection.
///
/// Caller admission must be checked before quorum work and again afterwards. This helper
/// only validates framing and correlation; it does not perform either authority check.
///
/// # Errors
/// Rejects malformed requests and a success attributed to another partition or leader.
pub fn metadata_read_fence_response(
    network: &ConsensusNetwork,
    request: &ControlEnvelope,
    result: Result<MetadataReadFence, ErrorCode>,
) -> Result<ControlEnvelope, RequestError> {
    encode_control_frame(request, network.wire_limits()).map_err(|_| RequestError::Rejected)?;
    let header = request.header.as_ref().ok_or(RequestError::Rejected)?;
    let Some(Message::FetchMetadataReadFence(query)) = &request.message else {
        return Err(RequestError::Rejected);
    };
    let operation = OperationId::from_bytes(
        header
            .operation_id
            .as_slice()
            .try_into()
            .map_err(|_| RequestError::Rejected)?,
    )
    .map_err(|_| RequestError::Rejected)?;
    let mut reply_header = network
        .control_header(operation, header.deadline_unix_micros)
        .map_err(|_| RequestError::Failed)?;
    if header.mesh_id != reply_header.mesh_id
        || header.partition_id != reply_header.partition_id
        || header.routing_epoch != reply_header.routing_epoch
    {
        return Err(RequestError::Rejected);
    }
    reply_header.request_id.clone_from(&header.request_id);
    reply_header.trace_id.clone_from(&header.trace_id);
    let outcome = match result {
        Ok(fence) => {
            if fence.partition_id != network.partition_id()
                || fence.leader_node_id != network.local_node_id()
            {
                return Err(RequestError::Failed);
            }
            Outcome::Fence(meshspan_protocol::v1::MetadataReadFence {
                partition_id: fence.partition_id.as_bytes().to_vec(),
                leader_node_id: fence.leader_node_id.as_bytes().to_vec(),
                term: fence.term,
                membership_epoch: fence.membership_epoch,
                plan_digest: fence.plan_digest.to_vec(),
                applied: Some(meshspan_protocol::v1::LogPosition {
                    term: fence.applied.term,
                    index: fence.applied.index,
                }),
                applied_digest: fence.applied_digest.to_vec(),
                revision: fence.revision.get(),
            })
        }
        Err(code) => Outcome::Rejection(WireError {
            code: code.into(),
            diagnostic_code: 1,
            retry_after_micros: None,
        }),
    };
    let response = ControlEnvelope {
        header: Some(reply_header),
        message: Some(Message::MetadataReadFenceResult(MetadataReadFenceResult {
            nonce: query.nonce.clone(),
            outcome: Some(outcome),
        })),
    };
    encode_control_frame(&response, network.wire_limits()).map_err(|_| RequestError::Failed)?;
    Ok(response)
}

fn parse_response(
    request: &ControlEnvelope,
    response: &ControlEnvelope,
    source: NodeId,
) -> Result<MetadataReadFence, RequestError> {
    let requested = request.header.as_ref().ok_or(RequestError::Failed)?;
    let received = response.header.as_ref().ok_or(RequestError::Failed)?;
    let Some(Message::FetchMetadataReadFence(query)) = &request.message else {
        return Err(RequestError::Failed);
    };
    let Some(Message::MetadataReadFenceResult(result)) = &response.message else {
        return Err(RequestError::Failed);
    };
    if received.mesh_id != requested.mesh_id
        || received.partition_id != requested.partition_id
        || received.routing_epoch != requested.routing_epoch
        || received.request_id != requested.request_id
        || received.operation_id != requested.operation_id
        || received.trace_id != requested.trace_id
        || received.deadline_unix_micros != requested.deadline_unix_micros
        || received.sender_node_id.as_slice() != source.as_bytes()
        || result.nonce != query.nonce
    {
        return Err(RequestError::Failed);
    }
    let fence = match result.outcome.as_ref().ok_or(RequestError::Failed)? {
        Outcome::Fence(fence) => fence,
        Outcome::Rejection(error) => {
            return Err(match ErrorCode::try_from(error.code) {
                Ok(ErrorCode::Unavailable | ErrorCode::Deadline) => RequestError::Unavailable,
                Ok(ErrorCode::Unauthorised | ErrorCode::Invalid | ErrorCode::Stale) => {
                    RequestError::Rejected
                }
                _ => RequestError::Failed,
            });
        }
    };
    if fence.partition_id != requested.partition_id
        || fence.leader_node_id.as_slice() != source.as_bytes()
    {
        return Err(RequestError::Failed);
    }
    let applied = fence.applied.as_ref().ok_or(RequestError::Failed)?;
    Ok(MetadataReadFence {
        partition_id: PartitionId::from_bytes(
            fence
                .partition_id
                .as_slice()
                .try_into()
                .map_err(|_| RequestError::Failed)?,
        )
        .map_err(|_| RequestError::Failed)?,
        leader_node_id: source,
        term: fence.term,
        membership_epoch: fence.membership_epoch,
        plan_digest: fence
            .plan_digest
            .as_slice()
            .try_into()
            .map_err(|_| RequestError::Failed)?,
        applied: meshspan_consensus::LogPosition {
            term: applied.term,
            index: applied.index,
        },
        applied_digest: fence
            .applied_digest
            .as_slice()
            .try_into()
            .map_err(|_| RequestError::Failed)?,
        revision: Revision::new(fence.revision),
    })
}

#[cfg(test)]
#[path = "metadata_read_fence_transfer_tests.rs"]
mod tests;
