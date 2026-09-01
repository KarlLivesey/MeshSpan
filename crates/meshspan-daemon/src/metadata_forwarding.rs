// SPDX-License-Identifier: GPL-2.0-only

//! Authenticated forwarding of exact root-metadata commands to the current leader.

use std::sync::Arc;
use std::time::Duration;

use meshspan_cluster::{ConsensusNetwork, MetadataAuthorityHandle, MetadataAuthorityRequestError};
use meshspan_domain::{NodeId, OperationId};
use meshspan_metadata::{
    AuthoritativeCommand, AuthoritativeRepository, CommandContext, CommandReceipt,
    METADATA_COMMAND_VERSION, decode_authoritative_command, encode_authoritative_command,
};
use meshspan_protocol::v1::control_envelope::Message;
use meshspan_protocol::v1::metadata_command::Command;
use meshspan_protocol::v1::{
    ControlEnvelope, MetadataCommand, OperationOutcome, OperationResult, OperationStatusResponse,
    VersionedPayload,
};

use crate::private_consensus_runtime::PrivateConsensusRuntime;

const FORWARD_TIMEOUT_MICROS: i64 = 30 * 1_000_000;
const LOCAL_APPLY_ATTEMPTS: usize = 200;

pub(crate) async fn forward(
    runtime: &Arc<PrivateConsensusRuntime>,
    reader: &AuthoritativeRepository,
    leader_id: NodeId,
    context: CommandContext,
    command: &AuthoritativeCommand,
) -> Result<CommandReceipt, MetadataAuthorityRequestError> {
    let network = runtime
        .network()
        .map_err(|()| MetadataAuthorityRequestError::Unavailable)?;
    let encoded = encode_authoritative_command(context, command).map_err(|error| match error {
        meshspan_metadata::MetadataCommandCodecError::Unsupported => {
            MetadataAuthorityRequestError::Unsupported
        }
        _ => MetadataAuthorityRequestError::Failed,
    })?;
    let request_digest = command.request_digest(context);
    let deadline = context
        .occurred_at
        .get()
        .checked_add(FORWARD_TIMEOUT_MICROS)
        .ok_or(MetadataAuthorityRequestError::Unavailable)?;
    let response = network
        .request_control(
            leader_id,
            &ControlEnvelope {
                header: Some(
                    network
                        .control_header(context.operation_id, deadline)
                        .map_err(|_| MetadataAuthorityRequestError::Unavailable)?,
                ),
                message: Some(Message::MetadataCommand(MetadataCommand {
                    expected_revision: context.expected_revision.map(|revision| revision.get()),
                    request_digest: request_digest.to_vec(),
                    command: Some(Command::ClusterControl(VersionedPayload {
                        format_version: u32::from(METADATA_COMMAND_VERSION),
                        canonical_bytes: encoded,
                    })),
                })),
            },
        )
        .await
        .map_err(|_| MetadataAuthorityRequestError::Unavailable)?;
    let Some(Message::OperationStatusResponse(status)) = response.as_inner().message.as_ref()
    else {
        return Err(MetadataAuthorityRequestError::Failed);
    };
    let result = status
        .result
        .as_ref()
        .ok_or(MetadataAuthorityRequestError::Failed)?;
    if result.outcome != i32::from(OperationOutcome::Durable) || result.result_digest.len() != 32 {
        return Err(MetadataAuthorityRequestError::Unavailable);
    }
    for _ in 0..LOCAL_APPLY_ATTEMPTS {
        let receipt = reader
            .resolve_operation(context.operation_id)
            .map_err(|_| MetadataAuthorityRequestError::Failed)?;
        if let Some(receipt) = receipt {
            return if receipt.request_digest == request_digest
                && receipt.result_digest.as_slice() == result.result_digest
            {
                Ok(receipt)
            } else {
                Err(MetadataAuthorityRequestError::Conflict)
            };
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Err(MetadataAuthorityRequestError::Unavailable)
}

pub(crate) async fn handle(
    network: &ConsensusNetwork,
    authority: &MetadataAuthorityHandle,
    operation_id: OperationId,
    request_deadline: i64,
    request: &MetadataCommand,
) -> Result<ControlEnvelope, MetadataAuthorityRequestError> {
    let payload = match request.command.as_ref() {
        Some(
            Command::Topology(payload)
            | Command::IdentityAccess(payload)
            | Command::Namespace(payload)
            | Command::Policy(payload)
            | Command::Lifecycle(payload)
            | Command::ClusterControl(payload),
        ) => payload,
        None => return Err(MetadataAuthorityRequestError::Rejected),
    };
    if payload.format_version != u32::from(METADATA_COMMAND_VERSION) {
        return Err(MetadataAuthorityRequestError::Unsupported);
    }
    let decoded = decode_authoritative_command(&payload.canonical_bytes)
        .map_err(|_| MetadataAuthorityRequestError::Rejected)?;
    let expected_digest = decoded.command.request_digest(decoded.context);
    if decoded.context.operation_id != operation_id
        || decoded
            .context
            .expected_revision
            .map(|revision| revision.get())
            != request.expected_revision
        || decoded.context.occurred_at.get() > request_deadline
        || request.request_digest.as_slice() != expected_digest
    {
        return Err(MetadataAuthorityRequestError::Rejected);
    }
    let receipt = authority
        .commit_or_resolve(decoded.context, decoded.command)
        .await?;
    Ok(ControlEnvelope {
        header: Some(
            network
                .control_header(operation_id, request_deadline)
                .map_err(|_| MetadataAuthorityRequestError::Failed)?,
        ),
        message: Some(Message::OperationStatusResponse(OperationStatusResponse {
            result: Some(OperationResult {
                outcome: OperationOutcome::Durable.into(),
                committed_revision: Some(receipt.committed_revision.get()),
                error: None,
                result: None,
                result_digest: receipt.result_digest.to_vec(),
            }),
        })),
    })
}
