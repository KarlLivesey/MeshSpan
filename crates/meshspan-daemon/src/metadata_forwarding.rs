// SPDX-License-Identifier: GPL-2.0-only

//! Authenticated forwarding of exact root-metadata commands to the current leader.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use meshspan_cluster::{
    ConsensusNetwork, MetadataAuthorityHandle, MetadataAuthorityRequestError, PeerControlRequest,
};
use meshspan_domain::{Clock as _, NodeId, OperationId, Revision, UnixMicros};
use meshspan_metadata::{
    AuthoritativeCommand, AuthoritativeRepository, CommandContext, CommandReceipt,
    METADATA_COMMAND_VERSION, encode_authoritative_command,
};
use meshspan_protocol::v1::control_envelope::Message;
use meshspan_protocol::v1::metadata_command::Command;
use meshspan_protocol::v1::{
    ControlEnvelope, ErrorCode, MetadataCommand, OperationOutcome, OperationResult,
    OperationStatusResponse, VersionedPayload, WireError,
};

use crate::private_consensus_runtime::PrivateConsensusRuntime;

const FORWARD_TIMEOUT_MICROS: i64 = 30 * 1_000_000;
const LOCAL_APPLY_ATTEMPTS: usize = 200;

#[path = "metadata_authority_discovery.rs"]
pub(crate) mod discovery;

#[path = "metadata_command_admission.rs"]
pub(crate) mod admission;

pub(crate) async fn forward_to_authority(
    runtime: &Arc<PrivateConsensusRuntime>,
    reader: &AuthoritativeRepository,
    authority: &MetadataAuthorityHandle,
    context: CommandContext,
    command: &AuthoritativeCommand,
) -> Result<CommandReceipt, MetadataAuthorityRequestError> {
    forward(runtime, reader, Some(authority), context, command).await
}

/// A non-voting service forwards directly; it cannot win an election or submit locally.
pub(crate) async fn forward_from_replica(
    runtime: &Arc<PrivateConsensusRuntime>,
    reader: &AuthoritativeRepository,
    context: CommandContext,
    command: &AuthoritativeCommand,
) -> Result<CommandReceipt, MetadataAuthorityRequestError> {
    forward(runtime, reader, None, context, command).await
}

async fn forward(
    runtime: &Arc<PrivateConsensusRuntime>,
    reader: &AuthoritativeRepository,
    authority: Option<&MetadataAuthorityHandle>,
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
    let local_node = network.local_node_id();
    let leader_hint = match authority {
        Some(authority) => authority
            .observe()
            .await?
            .known_leader
            .filter(|id| *id != local_node),
        None => None,
    };
    let mut candidates = forwarding_candidates(local_node, leader_hint, plan.voters());
    // The forwarding gateway may itself win the election while remote requests are in flight.
    if authority.is_some() {
        candidates.push(local_node);
    }
    let request_digest = command.request_digest(context);
    let (metadata, deadline) =
        prepare_request(context, command, crate::OperatingSystemClock.now())?;
    let request = ControlEnvelope {
        header: Some(
            network
                .control_header(context.operation_id, deadline)
                .map_err(|_| MetadataAuthorityRequestError::Unavailable)?,
        ),
        message: Some(Message::MetadataCommand(metadata)),
    };
    let local = authority.cloned();
    let command = command.clone();
    let committed_digest = discovery::discover(candidates, leader_hint, move |candidate| {
        let network = network.clone();
        let request = request.clone();
        let local = local.clone();
        let command = command.clone();
        async move {
            if candidate == local_node {
                local
                    .ok_or(MetadataAuthorityRequestError::Unavailable)?
                    .commit_or_resolve(context, command)
                    .await
                    .map(|receipt| receipt.result_digest)
                    .map_err(|error| match error {
                        MetadataAuthorityRequestError::NotLeader { .. } => {
                            MetadataAuthorityRequestError::Unavailable
                        }
                        error => error,
                    })
            } else {
                request_durable_result(&network, candidate, &request).await
            }
        }
    })
    .await?;
    resolve_local_receipt(reader, context, request_digest, committed_digest).await
}

/// Prepare the immutable operation payload separately from its delivery lifetime.
fn prepare_request(
    context: CommandContext,
    command: &AuthoritativeCommand,
    now: UnixMicros,
) -> Result<(MetadataCommand, i64), MetadataAuthorityRequestError> {
    let encoded = encode_authoritative_command(context, command).map_err(|error| match error {
        meshspan_metadata::MetadataCommandCodecError::Unsupported => {
            MetadataAuthorityRequestError::Unsupported
        }
        _ => MetadataAuthorityRequestError::Failed,
    })?;
    // The durable timestamp/id/digest survive outages; only this delivery lifetime renews.
    let deadline = now
        .get()
        .checked_add(FORWARD_TIMEOUT_MICROS)
        .ok_or(MetadataAuthorityRequestError::Unavailable)?;
    Ok((
        MetadataCommand {
            expected_revision: context.expected_revision.map(Revision::get),
            request_digest: command.request_digest(context).to_vec(),
            command: Some(Command::ClusterControl(VersionedPayload {
                format_version: u32::from(METADATA_COMMAND_VERSION),
                canonical_bytes: encoded,
            })),
        },
        deadline,
    ))
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
        return Err(authority_response_error(result));
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
    request: &PeerControlRequest,
) -> Result<ControlEnvelope, MetadataAuthorityRequestError> {
    handle_owned(
        network,
        authority,
        request,
        #[cfg(test)]
        None,
    )
    .await
}

#[cfg(test)]
pub(crate) struct AdmissionGate {
    pub(crate) operation_id: OperationId,
    pub(crate) started: tokio::sync::oneshot::Sender<()>,
    pub(crate) released: std::sync::mpsc::Receiver<()>,
}

#[cfg(test)]
impl AdmissionGate {
    fn wait(self, operation: OperationId) -> Result<(), ErrorCode> {
        if self.operation_id != operation {
            return Err(ErrorCode::Invalid);
        }
        match self.started.send(()) {
            Ok(()) | Err(()) => {}
        }
        // Dropping the fixture's release sender also releases the worker after a failed assertion.
        match self.released.recv() {
            Ok(()) | Err(_) => {}
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) async fn handle_with_admission_gate(
    network: &ConsensusNetwork,
    authority: &MetadataAuthorityHandle,
    request: &PeerControlRequest,
    gate: AdmissionGate,
) -> Result<ControlEnvelope, MetadataAuthorityRequestError> {
    handle_owned(network, authority, request, Some(gate)).await
}

async fn handle_owned(
    network: &ConsensusNetwork,
    authority: &MetadataAuthorityHandle,
    request: &PeerControlRequest,
    #[cfg(test)] gate: Option<AdmissionGate>,
) -> Result<ControlEnvelope, MetadataAuthorityRequestError> {
    let envelope = request.envelope.as_inner().clone();
    let header = envelope
        .header
        .as_ref()
        .ok_or(MetadataAuthorityRequestError::Rejected)?;
    let operation_id = OperationId::from_bytes(
        header
            .operation_id
            .as_slice()
            .try_into()
            .map_err(|_| MetadataAuthorityRequestError::Rejected)?,
    )
    .map_err(|_| MetadataAuthorityRequestError::Rejected)?;
    let request_deadline = header.deadline_unix_micros;
    let peer = meshspan_transport::PeerBinding {
        node_id: request.from,
        incarnation: request.sender_incarnation,
        certificate_fingerprint: request.certificate_fingerprint,
    };
    #[cfg(test)]
    if let Some(gate) = gate {
        tokio::task::spawn_blocking(move || gate.wait(operation_id))
            .await
            .map_err(|_| MetadataAuthorityRequestError::Failed)?
            .map_err(|_| MetadataAuthorityRequestError::Rejected)?;
    }
    let admitted = match admission::prepare(authority, peer, envelope).await {
        Ok(decoded) => Ok(decoded),
        Err(admission::AdmissionError::Protocol(code)) => Err(code),
        Err(admission::AdmissionError::WorkerStopped) => {
            return Err(MetadataAuthorityRequestError::Failed);
        }
    };
    let result = match admitted {
        Ok(decoded) => match authority
            .commit_or_resolve(decoded.context, decoded.command)
            .await
        {
            Ok(receipt) => OperationResult {
                outcome: OperationOutcome::Durable.into(),
                committed_revision: Some(receipt.committed_revision.get()),
                error: None,
                result: None,
                result_digest: receipt.result_digest.to_vec(),
            },
            Err(error) => authority_error_result(error),
        },
        Err(code) => OperationResult {
            outcome: if code == ErrorCode::Unavailable {
                OperationOutcome::Failed
            } else {
                OperationOutcome::Rejected
            }
            .into(),
            committed_revision: None,
            error: Some(WireError {
                code: code.into(),
                diagnostic_code: 7,
                retry_after_micros: None,
            }),
            result: None,
            result_digest: Vec::new(),
        },
    };
    Ok(ControlEnvelope {
        header: Some(
            network
                .control_header(operation_id, request_deadline)
                .map_err(|_| MetadataAuthorityRequestError::Failed)?,
        ),
        message: Some(Message::OperationStatusResponse(OperationStatusResponse {
            result: Some(result),
        })),
    })
}

pub(crate) fn authority_error_result(error: MetadataAuthorityRequestError) -> OperationResult {
    let (outcome, code, diagnostic_code) = match error {
        MetadataAuthorityRequestError::NotLeader { .. } => {
            (OperationOutcome::Redirect, ErrorCode::Unavailable, 1)
        }
        MetadataAuthorityRequestError::Unavailable => {
            (OperationOutcome::Failed, ErrorCode::Unavailable, 2)
        }
        MetadataAuthorityRequestError::Conflict => {
            (OperationOutcome::Rejected, ErrorCode::Conflict, 3)
        }
        MetadataAuthorityRequestError::Rejected => {
            (OperationOutcome::Rejected, ErrorCode::Invalid, 4)
        }
        MetadataAuthorityRequestError::Unsupported => {
            (OperationOutcome::Rejected, ErrorCode::Unsupported, 5)
        }
        MetadataAuthorityRequestError::Failed => {
            (OperationOutcome::Failed, ErrorCode::InternalContract, 6)
        }
    };
    OperationResult {
        outcome: outcome.into(),
        committed_revision: None,
        error: Some(WireError {
            code: code.into(),
            diagnostic_code,
            retry_after_micros: None,
        }),
        result: None,
        result_digest: Vec::new(),
    }
}

pub(crate) fn authority_response_error(result: &OperationResult) -> MetadataAuthorityRequestError {
    match result
        .error
        .as_ref()
        .and_then(|error| ErrorCode::try_from(error.code).ok())
    {
        Some(ErrorCode::Unavailable) => MetadataAuthorityRequestError::Unavailable,
        Some(ErrorCode::Conflict) => MetadataAuthorityRequestError::Conflict,
        Some(ErrorCode::Invalid) => MetadataAuthorityRequestError::Rejected,
        Some(ErrorCode::Unsupported) => MetadataAuthorityRequestError::Unsupported,
        Some(
            ErrorCode::InternalContract
            | ErrorCode::Unauthorised
            | ErrorCode::Stale
            | ErrorCode::Exhausted
            | ErrorCode::Corrupt
            | ErrorCode::Deadline
            | ErrorCode::NotFound
            | ErrorCode::Unspecified,
        )
        | None => MetadataAuthorityRequestError::Failed,
    }
}

#[cfg(test)]
mod forwarding_candidate_tests {
    use super::*;

    #[test]
    fn forwarding_retry_renews_delivery_without_rewriting_the_durable_operation()
    -> Result<(), Box<dyn std::error::Error>> {
        use meshspan_domain::{AuditEventId, GroupId, PrincipalId};
        let context = CommandContext {
            operation_id: OperationId::from_bytes([1; 16])?,
            actor_principal_id: PrincipalId::from_bytes([2; 16])?,
            audit_event_id: AuditEventId::from_bytes([3; 16])?,
            occurred_at: UnixMicros::new(100),
            expected_revision: None,
        };
        let command = AuthoritativeCommand::CreateGroup(meshspan_metadata::CreateGroup {
            group_id: GroupId::from_bytes([4; 16])?,
            name: meshspan_metadata::RecordName::new("delayed group")?,
            activation_policy_id: None,
        });
        let (first, first_deadline) =
            prepare_request(context, &command, UnixMicros::new(60_000_000))?;
        let (retry, retry_deadline) =
            prepare_request(context, &command, UnixMicros::new(120_000_000))?;
        assert_eq!(first_deadline, 90_000_000);
        assert_eq!(retry_deadline, 150_000_000);
        assert_eq!(first, retry);
        let Some(Command::ClusterControl(payload)) = retry.command else {
            return Err("missing canonical command".into());
        };
        assert_eq!(
            meshspan_metadata::decode_authoritative_command(&payload.canonical_bytes)?.context,
            context
        );
        assert_eq!(
            prepare_request(context, &command, UnixMicros::new(i64::MAX)),
            Err(MetadataAuthorityRequestError::Unavailable)
        );
        Ok(())
    }

    #[test]
    fn lists_authenticated_hint_then_each_other_voter_without_duplicates()
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

    #[test]
    fn authority_failures_round_trip_as_typed_operation_results()
    -> Result<(), Box<dyn std::error::Error>> {
        let cases = [
            (
                MetadataAuthorityRequestError::NotLeader {
                    leader_id: Some(node(2)?),
                },
                MetadataAuthorityRequestError::Unavailable,
            ),
            (
                MetadataAuthorityRequestError::Unavailable,
                MetadataAuthorityRequestError::Unavailable,
            ),
            (
                MetadataAuthorityRequestError::Conflict,
                MetadataAuthorityRequestError::Conflict,
            ),
            (
                MetadataAuthorityRequestError::Rejected,
                MetadataAuthorityRequestError::Rejected,
            ),
            (
                MetadataAuthorityRequestError::Unsupported,
                MetadataAuthorityRequestError::Unsupported,
            ),
            (
                MetadataAuthorityRequestError::Failed,
                MetadataAuthorityRequestError::Failed,
            ),
        ];
        for (authority_error, expected_response) in cases {
            let result = authority_error_result(authority_error);
            assert_ne!(result.outcome, i32::from(OperationOutcome::Durable));
            assert_eq!(authority_response_error(&result), expected_response);
        }
        Ok(())
    }

    fn node(marker: u8) -> Result<NodeId, meshspan_domain::IdentifierError> {
        NodeId::from_bytes([marker; 16])
    }
}
