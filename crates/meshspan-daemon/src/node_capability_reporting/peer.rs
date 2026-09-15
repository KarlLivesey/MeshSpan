// SPDX-License-Identifier: GPL-2.0-only

//! Narrow mTLS ingress for node self-reports; no arbitrary node-authenticated commands.

use super::*;
use meshspan_cluster::PeerControlRequest;
use meshspan_metadata::{
    AuthoritativeCommandContext, METADATA_COMMAND_VERSION, decode_authoritative_entry_for_version,
    encode_authoritative_node_command,
};
use meshspan_protocol::v1::control_envelope::Message;
use meshspan_protocol::v1::{
    ControlEnvelope, NodeCapabilityReport, NodeCapabilityReportResult, OperationOutcome,
    OperationResult,
};
use meshspan_transport::PeerBinding;
use std::path::Path;

pub(crate) async fn handle(
    network: &ConsensusNetwork,
    authority: &MetadataAuthorityHandle,
    directory: &Path,
    request: &PeerControlRequest,
) -> Result<ControlEnvelope, Error> {
    let envelope = request.envelope.as_inner().clone();
    let header = envelope.header.as_ref().ok_or(Error::Rejected)?;
    let operation_id = OperationId::from_bytes(
        header
            .operation_id
            .as_slice()
            .try_into()
            .map_err(|_| Error::Rejected)?,
    )
    .map_err(|_| Error::Rejected)?;
    let deadline = header.deadline_unix_micros;
    let binding = PeerBinding {
        node_id: request.from,
        incarnation: request.sender_incarnation,
        certificate_fingerprint: request.certificate_fingerprint,
    };
    let capability_digest = request.capability_digest;
    let directory = directory.to_path_buf();
    let pending = tokio::task::spawn_blocking(move || {
        admit(&directory, binding, capability_digest, &envelope)
    })
    .await
    .map_err(|_| Error::Failed)??;
    let digest = AuthoritativeCommandContext::Node(pending.context).request_digest(
        &AuthoritativeCommand::RefreshNodeCapabilities(pending.command),
    );
    let remaining = deadline
        .checked_sub(crate::OperatingSystemClock.now().get())
        .and_then(|remaining| u64::try_from(remaining).ok())
        .filter(|remaining| *remaining > 0)
        .ok_or(Error::Unavailable)?;
    // Timing out loses only this response waiter; the authority still owns any queued commit.
    let outcome = tokio::time::timeout(
        Duration::from_micros(remaining),
        authority.commit_or_resolve_node(pending.context, pending.command),
    )
    .await
    .unwrap_or(Err(Error::Unavailable));
    let result = match outcome {
        Ok(receipt) => OperationResult {
            outcome: OperationOutcome::Durable.into(),
            committed_revision: Some(receipt.committed_revision.get()),
            error: None,
            result: None,
            result_digest: receipt.result_digest.to_vec(),
        },
        Err(error) => crate::metadata_forwarding::authority_error_result(error),
    };
    Ok(ControlEnvelope {
        header: Some(
            network
                .control_header(operation_id, deadline)
                .map_err(|_| Error::Failed)?,
        ),
        message: Some(Message::NodeCapabilityReportResult(
            NodeCapabilityReportResult {
                request_digest: digest.to_vec(),
                result: Some(result),
            },
        )),
    })
}

fn admit(
    directory: &Path,
    binding: PeerBinding,
    capability_digest: [u8; 32],
    envelope: &ControlEnvelope,
) -> Result<PendingReport, Error> {
    let header = envelope.header.as_ref().ok_or(Error::Rejected)?;
    let Some(Message::NodeCapabilityReport(report)) = envelope.message.as_ref() else {
        return Err(Error::Rejected);
    };
    let decoded = decode_authoritative_entry_for_version(
        u16::try_from(report.command_version).map_err(|_| Error::Rejected)?,
        &report.canonical_command,
    )
    .map_err(|_| Error::Rejected)?;
    let (
        AuthoritativeCommandContext::Node(context),
        AuthoritativeCommand::RefreshNodeCapabilities(command),
    ) = (decoded.context, decoded.command)
    else {
        return Err(Error::Rejected);
    };
    let now = crate::OperatingSystemClock.now();
    validate_identity(context, command, binding, capability_digest)?;
    if header.sender_node_id.as_slice() != binding.node_id.as_bytes()
        || header.sender_incarnation != binding.incarnation
        || header.operation_id.as_slice() != context.operation_id.as_bytes()
        || context.occurred_at > now
        || !header
            .deadline_unix_micros
            .checked_sub(now.get())
            .is_some_and(|remaining| (1..=30_000_000).contains(&remaining))
    {
        return Err(Error::Rejected);
    }
    let repository = crate::appliance_runtime::open_root_repository_at(directory, now)
        .map_err(|_| Error::Unavailable)?;
    let mesh = repository
        .local_mesh_id()
        .map_err(|_| Error::Failed)?
        .ok_or(Error::Unavailable)?;
    let certificate = repository
        .active_node_certificate(binding.node_id)
        .map_err(|_| Error::Failed)?
        .ok_or(Error::Rejected)?;
    if header.mesh_id.as_slice() != mesh.as_bytes()
        || header.partition_id.as_slice() != repository.partition_id().as_bytes()
        || certificate.incarnation != binding.incarnation
        || certificate.generation != command.certificate_generation
        || certificate.certificate_fingerprint != binding.certificate_fingerprint
        || certificate.valid_until <= now
    {
        return Err(Error::Rejected);
    }
    Ok(PendingReport { context, command })
}

fn validate_identity(
    context: NodeCommandContext,
    command: RefreshNodeCapabilities,
    binding: PeerBinding,
    capability_digest: [u8; 32],
) -> Result<(), Error> {
    if context.actor_node_id != binding.node_id
        || command.node_id != binding.node_id
        || command.incarnation != binding.incarnation
        || command.certificate_fingerprint != binding.certificate_fingerprint
        || command.capability_digest != capability_digest
    {
        return Err(Error::Rejected);
    }
    Ok(())
}

pub(super) async fn submit(
    network: &ConsensusNetwork,
    candidate: NodeId,
    pending: &PendingReport,
) -> Result<(), Error> {
    let command = AuthoritativeCommand::RefreshNodeCapabilities(pending.command);
    let digest = AuthoritativeCommandContext::Node(pending.context).request_digest(&command);
    let deadline = crate::OperatingSystemClock
        .now()
        .get()
        .checked_add(30_000_000)
        .ok_or(Error::Failed)?;
    let request = ControlEnvelope {
        header: Some(
            network
                .control_header(pending.context.operation_id, deadline)
                .map_err(|_| Error::Failed)?,
        ),
        message: Some(Message::NodeCapabilityReport(NodeCapabilityReport {
            command_version: u32::from(METADATA_COMMAND_VERSION),
            canonical_command: encode_authoritative_node_command(pending.context, &command)
                .map_err(|_| Error::Failed)?,
        })),
    };
    let response = network
        .request_control(candidate, &request)
        .await
        .map_err(|_| Error::Unavailable)?;
    let envelope = response.as_inner();
    let Some(Message::NodeCapabilityReportResult(report)) = &envelope.message else {
        return Err(Error::Unavailable);
    };
    if envelope.header.as_ref().is_none_or(|header| {
        header.operation_id.as_slice() != pending.context.operation_id.as_bytes()
    }) || report.request_digest.as_slice() != digest
    {
        return Err(Error::Rejected);
    }
    let result = report.result.as_ref().ok_or(Error::Rejected)?;
    if result.outcome != i32::from(OperationOutcome::Durable) {
        return Err(retry_leader(
            crate::metadata_forwarding::authority_response_error(result),
        ));
    }
    if result
        .committed_revision
        .is_none_or(|revision| revision == 0)
        || result.result_digest.len() != 32
    {
        return Err(Error::Rejected);
    }
    // A reply never populates capability authority or the local cache. The next pass must
    // observe the exact replicated presentation before treating this report as complete.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_identity_cannot_substitute_node_incarnation_certificate_or_hello()
    -> Result<(), Box<dyn std::error::Error>> {
        let node = NodeId::from_bytes([1; 16])?;
        let other = NodeId::from_bytes([2; 16])?;
        let context = context(node, UnixMicros::new(1))?;
        let binding = PeerBinding {
            node_id: node,
            incarnation: 1,
            certificate_fingerprint: [3; 32],
        };
        let command = RefreshNodeCapabilities {
            node_id: node,
            incarnation: 1,
            certificate_generation: 1,
            certificate_fingerprint: [3; 32],
            capability_digest: [4; 32],
            prior: NodeCapabilityPrior::InitialAdmittedCertificate {
                revision: meshspan_domain::Revision::new(1),
                generation: 1,
                certificate_fingerprint: [3; 32],
            },
        };
        validate_identity(context, command, binding, [4; 32])?;
        for changed in [
            RefreshNodeCapabilities {
                node_id: other,
                ..command
            },
            RefreshNodeCapabilities {
                incarnation: 2,
                ..command
            },
            RefreshNodeCapabilities {
                certificate_fingerprint: [5; 32],
                ..command
            },
            RefreshNodeCapabilities {
                capability_digest: [6; 32],
                ..command
            },
        ] {
            assert!(matches!(
                validate_identity(context, changed, binding, [4; 32]),
                Err(Error::Rejected)
            ));
        }
        assert!(matches!(
            validate_identity(
                NodeCommandContext {
                    actor_node_id: other,
                    ..context
                },
                command,
                binding,
                [4; 32]
            ),
            Err(Error::Rejected)
        ));
        Ok(())
    }
}
