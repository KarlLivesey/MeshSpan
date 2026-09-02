// SPDX-License-Identifier: GPL-2.0-only

//! Authenticated forwarding of exact root-metadata commands to the current leader.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use meshspan_cluster::{ConsensusNetwork, MetadataAuthorityHandle, MetadataAuthorityRequestError};
use meshspan_domain::{NodeId, OperationId, Revision};
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
const LEADER_HINT_GRACE: Duration = Duration::from_millis(250);
const CANDIDATE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(3);
const LEADER_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) async fn forward_to_authority(
    runtime: &Arc<PrivateConsensusRuntime>,
    reader: &AuthoritativeRepository,
    leader_hint: Option<NodeId>,
    context: CommandContext,
    command: &AuthoritativeCommand,
) -> Result<CommandReceipt, MetadataAuthorityRequestError> {
    let network = runtime
        .network()
        .map_err(|()| MetadataAuthorityRequestError::Unavailable)?;
    let plan = reader
        .load_active_consensus_quorum_plan()
        .map_err(|_| MetadataAuthorityRequestError::Failed)?
        .ok_or(MetadataAuthorityRequestError::Unavailable)?;
    let candidates = forwarding_candidates(network.local_node_id(), leader_hint, plan.voters());
    if candidates.is_empty() {
        return Err(MetadataAuthorityRequestError::NotLeader {
            leader_id: leader_hint,
        });
    }
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
    let request = ControlEnvelope {
        header: Some(
            network
                .control_header(context.operation_id, deadline)
                .map_err(|_| MetadataAuthorityRequestError::Unavailable)?,
        ),
        message: Some(Message::MetadataCommand(MetadataCommand {
            expected_revision: context.expected_revision.map(Revision::get),
            request_digest: request_digest.to_vec(),
            command: Some(Command::ClusterControl(VersionedPayload {
                format_version: u32::from(METADATA_COMMAND_VERSION),
                canonical_bytes: encoded,
            })),
        })),
    };
    let committed_digest =
        discover_durable_result(&network, leader_hint, candidates, &request).await?;
    resolve_local_receipt(reader, context, request_digest, committed_digest).await
}

async fn discover_durable_result(
    network: &ConsensusNetwork,
    leader_hint: Option<NodeId>,
    candidates: Vec<NodeId>,
    request: &ControlEnvelope,
) -> Result<[u8; 32], MetadataAuthorityRequestError> {
    let mut requests = tokio::task::JoinSet::new();
    let hinted = leader_hint.filter(|node_id| *node_id != network.local_node_id());
    let mut remaining = candidates.into_iter();
    if let Some(hinted) = hinted {
        let first = remaining.next();
        if first != Some(hinted) {
            return Err(MetadataAuthorityRequestError::Failed);
        }
        spawn_candidate_request(&mut requests, network, hinted, request);
        if let Ok(Some(result)) =
            tokio::time::timeout(LEADER_HINT_GRACE, requests.join_next()).await
            && let Some(digest) = candidate_result(&result)?
        {
            return Ok(digest);
        }
    }
    for candidate in remaining {
        spawn_candidate_request(&mut requests, network, candidate, request);
    }
    if requests.is_empty() {
        return Err(MetadataAuthorityRequestError::Unavailable);
    }
    tokio::time::timeout(LEADER_DISCOVERY_TIMEOUT, async move {
        while let Some(result) = requests.join_next().await {
            if let Some(digest) = candidate_result(&result)? {
                return Ok(digest);
            }
        }
        Err(MetadataAuthorityRequestError::Unavailable)
    })
    .await
    .unwrap_or(Err(MetadataAuthorityRequestError::Unavailable))
}

fn spawn_candidate_request(
    requests: &mut tokio::task::JoinSet<Result<[u8; 32], MetadataAuthorityRequestError>>,
    network: &ConsensusNetwork,
    candidate: NodeId,
    request: &ControlEnvelope,
) {
    let network = network.clone();
    let request = request.clone();
    requests.spawn(async move {
        tokio::time::timeout(
            CANDIDATE_RESPONSE_TIMEOUT,
            request_durable_result(&network, candidate, &request),
        )
        .await
        .unwrap_or(Err(MetadataAuthorityRequestError::Unavailable))
    });
}

fn candidate_result(
    result: &Result<Result<[u8; 32], MetadataAuthorityRequestError>, tokio::task::JoinError>,
) -> Result<Option<[u8; 32]>, MetadataAuthorityRequestError> {
    match result {
        Ok(Ok(digest)) => Ok(Some(*digest)),
        Ok(Err(MetadataAuthorityRequestError::Unavailable)) => Ok(None),
        Ok(Err(error)) => Err(*error),
        Err(_) => Err(MetadataAuthorityRequestError::Failed),
    }
}

async fn resolve_local_receipt(
    reader: &AuthoritativeRepository,
    context: CommandContext,
    request_digest: [u8; 32],
    committed_digest: [u8; 32],
) -> Result<CommandReceipt, MetadataAuthorityRequestError> {
    for _ in 0..LOCAL_APPLY_ATTEMPTS {
        let receipt = reader
            .resolve_operation(context.operation_id)
            .map_err(|_| MetadataAuthorityRequestError::Failed)?;
        if let Some(receipt) = receipt {
            return if receipt.request_digest == request_digest
                && receipt.result_digest == committed_digest
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

fn forwarding_candidates(
    local_node_id: NodeId,
    leader_hint: Option<NodeId>,
    voters: BTreeSet<NodeId>,
) -> Vec<NodeId> {
    let hinted = leader_hint.filter(|node_id| *node_id != local_node_id);
    hinted
        .into_iter()
        .chain(
            voters
                .into_iter()
                .filter(|node_id| *node_id != local_node_id && Some(*node_id) != hinted),
        )
        .collect()
}

async fn request_durable_result(
    network: &ConsensusNetwork,
    candidate: NodeId,
    request: &ControlEnvelope,
) -> Result<[u8; 32], MetadataAuthorityRequestError> {
    let response = network
        .request_control(candidate, request)
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
    if result.outcome != i32::from(OperationOutcome::Durable) {
        return Err(MetadataAuthorityRequestError::Unavailable);
    }
    result
        .result_digest
        .as_slice()
        .try_into()
        .map_err(|_| MetadataAuthorityRequestError::Failed)
}

pub(crate) async fn handle(
    network: &ConsensusNetwork,
    authority: &MetadataAuthorityHandle,
    operation_id: OperationId,
    request_deadline: i64,
    request: &MetadataCommand,
) -> Result<ControlEnvelope, MetadataAuthorityRequestError> {
    let Some(
        Command::Topology(payload)
        | Command::IdentityAccess(payload)
        | Command::Namespace(payload)
        | Command::Policy(payload)
        | Command::Lifecycle(payload)
        | Command::ClusterControl(payload),
    ) = request.command.as_ref()
    else {
        return Err(MetadataAuthorityRequestError::Rejected);
    };
    if payload.format_version != u32::from(METADATA_COMMAND_VERSION) {
        return Err(MetadataAuthorityRequestError::Unsupported);
    }
    let decoded = decode_authoritative_command(&payload.canonical_bytes)
        .map_err(|_| MetadataAuthorityRequestError::Rejected)?;
    let expected_digest = decoded.command.request_digest(decoded.context);
    if decoded.context.operation_id != operation_id
        || decoded.context.expected_revision.map(Revision::get) != request.expected_revision
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

#[cfg(test)]
mod forwarding_candidate_tests {
    use super::*;

    #[test]
    fn tries_authenticated_hint_then_each_other_voter_once()
    -> Result<(), Box<dyn std::error::Error>> {
        let local = node(1)?;
        let hinted = node(3)?;
        let candidates = forwarding_candidates(
            local,
            Some(hinted),
            BTreeSet::from([node(1)?, node(2)?, node(3)?, node(4)?]),
        );

        assert_eq!(candidates, vec![hinted, node(2)?, node(4)?]);
        Ok(())
    }

    #[test]
    fn discovers_voters_without_a_leader_hint() -> Result<(), Box<dyn std::error::Error>> {
        let candidates = forwarding_candidates(
            node(4)?,
            None,
            BTreeSet::from([node(1)?, node(2)?, node(3)?]),
        );

        assert_eq!(candidates, vec![node(1)?, node(2)?, node(3)?]);
        Ok(())
    }

    fn node(marker: u8) -> Result<NodeId, meshspan_domain::IdentifierError> {
        NodeId::from_bytes([marker; 16])
    }
}
