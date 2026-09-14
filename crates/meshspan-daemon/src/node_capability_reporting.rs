// SPDX-License-Identifier: GPL-2.0-only

//! Automatically orders the configured transport presentation through root authority.

mod peer;

use crate::private_consensus_runtime::PrivateConsensusRuntime;
use meshspan_cluster::{
    ConsensusNetwork, LocalNodeCapabilityPresentation, MetadataAuthorityHandle,
    MetadataAuthorityRequestError as Error,
};
use meshspan_domain::{
    AuditEventId, Clock as _, NodeId, OperationId, RandomSource as _, UnixMicros, uuid_v8,
};
use meshspan_metadata::{
    AuthoritativeCommand, AuthoritativeRepository, NodeCapabilityPrior, NodeCommandContext,
    RefreshNodeCapabilities,
};
use std::{path::PathBuf, sync::Arc, time::Duration};

pub(crate) use peer::handle;

pub(crate) struct NodeCapabilityReporter {
    directory: PathBuf,
    runtime: Arc<PrivateConsensusRuntime>,
    authority: Option<MetadataAuthorityHandle>,
    pending: Option<PendingReport>,
}

#[derive(Clone)]
struct PendingReport {
    context: NodeCommandContext,
    command: RefreshNodeCapabilities,
}

struct PreparedReport {
    roles: Vec<meshspan_protocol::v1::NodeRole>,
    command: Option<RefreshNodeCapabilities>,
    voters: Vec<NodeId>,
    retained: Vec<(NodeId, u64, [u8; 32])>,
}

impl NodeCapabilityReporter {
    pub(crate) fn new(
        directory: PathBuf,
        runtime: Arc<PrivateConsensusRuntime>,
        authority: Option<MetadataAuthorityHandle>,
    ) -> Self {
        Self {
            directory,
            runtime,
            authority,
            pending: None,
        }
    }

    pub(crate) async fn run_until(
        mut self,
        mut stop: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), Error> {
        let mut ticks = tokio::time::interval(Duration::from_secs(1));
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            if *stop.borrow() {
                return Ok(());
            }
            tokio::select! {
                result = stop.changed() => { if result.is_err() { return Ok(()); } }
                _ = ticks.tick() => {
                    // Each step owns its blocking reader and bounded remote requests through
                    // completion. Dropping a future is never treated as undoing its metadata write.
                    match self.step().await {
                        Ok(()) | Err(Error::Unavailable | Error::NotLeader { .. } | Error::Conflict | Error::Rejected) => {}
                        Err(error @ (Error::Failed | Error::Unsupported)) => return Err(error),
                    }
                }
            }
        }
    }

    async fn step(&mut self) -> Result<(), Error> {
        let network = self.runtime.network().map_err(|()| Error::Unavailable)?;
        let local = network
            .local_capability_presentation()
            .map_err(|_| Error::Failed)?;
        let peers = network.peer_routes().map_err(|_| Error::Failed)?;
        let directory = self.directory.clone();
        let prepared = tokio::task::spawn_blocking(move || {
            let repository = crate::appliance_runtime::open_root_repository_at(
                &directory,
                crate::OperatingSystemClock.now(),
            )
            .map_err(|_| Error::Unavailable)?;
            prepare(
                &repository,
                &local,
                peers.into_iter().map(|peer| peer.node_id),
            )
        })
        .await
        .map_err(|_| Error::Failed)??;
        if network
            .replace_local_roles(&prepared.roles)
            .map_err(|_| Error::Failed)?
        {
            // The prepared command describes the previous Hello. Re-read configured transport
            // state on the next tick after connections advertising old roles are invalidated.
            return Err(Error::Unavailable);
        }
        // Prune even during a quorum outage. Only the committed digest and newest candidate
        // survive; pruning is cache housekeeping and never grants transport permission.
        for (node, incarnation, digest) in prepared.retained {
            network
                .retain_capability_preimages(node, incarnation, digest)
                .await
                .map_err(|_| Error::Failed)?;
        }
        let Some(command) = prepared.command else {
            self.pending = None;
            return Ok(());
        };
        let pending = match self.pending.as_ref() {
            Some(pending) if pending.command == command => pending.clone(),
            Some(_) | None => PendingReport {
                context: context(command.node_id, crate::OperatingSystemClock.now())?,
                command,
            },
        };
        self.pending = Some(pending.clone());
        let authority = self.authority.clone();
        crate::metadata_forwarding::discovery::discover(prepared.voters, None, move |candidate| {
            let network = network.clone();
            let authority = authority.clone();
            let pending = pending.clone();
            async move { submit(&network, authority.as_ref(), candidate, &pending).await }
        })
        .await
    }
}

fn prepare(
    repository: &AuthoritativeRepository,
    local: &LocalNodeCapabilityPresentation,
    peers: impl Iterator<Item = NodeId>,
) -> Result<PreparedReport, Error> {
    let plan = repository
        .load_active_consensus_quorum_plan()
        .map_err(|_| Error::Failed)?
        .ok_or(Error::Unavailable)?;
    let certificate = repository
        .active_node_certificate(local.binding.node_id)
        .map_err(|_| Error::Failed)?
        .ok_or(Error::Unavailable)?;
    let roles = crate::private_consensus_runtime::advertised_node_roles(
        local.binding.node_id,
        certificate.roles,
        &plan,
    )
    .map_err(|()| Error::Failed)?;
    let command = prepare_local(repository, local)?;
    let mut retained = Vec::new();
    for node in peers {
        let Some(certificate) = repository
            .active_node_certificate(node)
            .map_err(|_| Error::Failed)?
        else {
            continue;
        };
        if certificate.valid_until <= crate::OperatingSystemClock.now() {
            continue;
        }
        if let Some(presentation) = repository
            .node_capability_presentation(node)
            .map_err(|_| Error::Failed)?
        {
            if presentation.incarnation == certificate.incarnation
                && presentation.certificate_generation == certificate.generation
                && presentation.certificate_fingerprint == certificate.certificate_fingerprint
            {
                retained.push((
                    node,
                    presentation.incarnation,
                    presentation.capability_digest,
                ));
            }
        } else if let Some(activation) = repository
            .node_activation(node)
            .map_err(|_| Error::Failed)?
            && activation.incarnation == certificate.incarnation
        {
            retained.push((node, activation.incarnation, activation.capability_digest));
        }
    }
    Ok(PreparedReport {
        roles,
        command,
        voters: plan.voters().into_iter().collect(),
        retained,
    })
}

fn prepare_local(
    repository: &AuthoritativeRepository,
    local: &LocalNodeCapabilityPresentation,
) -> Result<Option<RefreshNodeCapabilities>, Error> {
    let node = local.binding.node_id;
    let certificate = repository
        .active_node_certificate(node)
        .map_err(|_| Error::Failed)?
        .ok_or(Error::Unavailable)?;
    if certificate.incarnation != local.binding.incarnation
        || certificate.generation != local.certificate_generation
        || certificate.certificate_fingerprint != local.binding.certificate_fingerprint
        || certificate.valid_until <= crate::OperatingSystemClock.now()
    {
        return Err(Error::Unavailable);
    }
    let prior = if let Some(current) = repository
        .node_capability_presentation(node)
        .map_err(|_| Error::Failed)?
    {
        if current.incarnation == local.binding.incarnation
            && current.certificate_generation == local.certificate_generation
            && current.certificate_fingerprint == local.binding.certificate_fingerprint
            && current.capability_digest == local.observed.capability_digest
        {
            return Ok(None);
        }
        NodeCapabilityPrior::ExistingPresentation {
            revision: current.revision,
            capability_digest: current.capability_digest,
        }
    } else if let Some(activation) = repository
        .node_activation(node)
        .map_err(|_| Error::Failed)?
    {
        NodeCapabilityPrior::InitialActivation {
            revision: activation.revision,
            capability_digest: activation.capability_digest,
        }
    } else {
        NodeCapabilityPrior::InitialAdmittedCertificate {
            revision: certificate.revision,
            generation: certificate.generation,
            certificate_fingerprint: certificate.certificate_fingerprint,
        }
    };
    Ok(Some(RefreshNodeCapabilities {
        node_id: node,
        incarnation: local.binding.incarnation,
        certificate_generation: local.certificate_generation,
        certificate_fingerprint: local.binding.certificate_fingerprint,
        capability_digest: local.observed.capability_digest,
        prior,
    }))
}

fn context(node: NodeId, now: UnixMicros) -> Result<NodeCommandContext, Error> {
    let mut operation = [0; 16];
    let mut audit = [0; 16];
    crate::OperatingSystemRandom
        .fill_bytes(&mut operation)
        .map_err(|_| Error::Failed)?;
    crate::OperatingSystemRandom
        .fill_bytes(&mut audit)
        .map_err(|_| Error::Failed)?;
    Ok(NodeCommandContext {
        operation_id: OperationId::from_bytes(uuid_v8(operation)).map_err(|_| Error::Failed)?,
        actor_node_id: node,
        audit_event_id: AuditEventId::from_bytes(uuid_v8(audit)).map_err(|_| Error::Failed)?,
        occurred_at: now,
        expected_revision: None,
    })
}

async fn submit(
    network: &ConsensusNetwork,
    authority: Option<&MetadataAuthorityHandle>,
    candidate: NodeId,
    pending: &PendingReport,
) -> Result<(), Error> {
    if candidate != network.local_node_id() {
        return peer::submit(network, candidate, pending).await;
    }
    let authority = authority.ok_or(Error::Unavailable)?;
    // Rebind immediately before enqueueing; a concurrent local certificate/role change
    // cannot submit an old Hello merely because preparation once matched it.
    let current = network
        .local_capability_presentation()
        .map_err(|_| Error::Failed)?;
    if current.binding.incarnation != pending.command.incarnation
        || current.binding.certificate_fingerprint != pending.command.certificate_fingerprint
        || current.certificate_generation != pending.command.certificate_generation
        || current.observed.capability_digest != pending.command.capability_digest
    {
        return Err(Error::Rejected);
    }
    tokio::time::timeout(
        Duration::from_secs(30),
        authority.commit_or_resolve_node(pending.context, pending.command),
    )
    .await
    .map_err(|_| Error::Unavailable)?
    .map(|_| ())
    .map_err(retry_leader)
}

fn retry_leader(error: Error) -> Error {
    match error {
        Error::NotLeader { .. } | Error::Unsupported => Error::Unavailable,
        Error::Unavailable | Error::Conflict | Error::Rejected | Error::Failed => error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_report_endpoint_remains_retryable() {
        assert!(matches!(
            retry_leader(Error::Unsupported),
            Error::Unavailable
        ));
        assert!(matches!(retry_leader(Error::Rejected), Error::Rejected));
    }
}
