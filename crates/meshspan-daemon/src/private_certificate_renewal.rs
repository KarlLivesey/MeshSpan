// SPDX-License-Identifier: GPL-2.0-only

//! Automatic private identity maintenance, independently scheduled from public ACME.

use std::{future::Future, sync::Arc, time::Duration};

use meshspan_certificates::{NodeCertificateRequest, NodeIdentityKey, NodePublicIdentity};
use meshspan_cluster::{ConsensusNetwork, MetadataAuthorityRequestError};
use meshspan_domain::{
    AuditEventId, Clock as _, NodeId, OperationId, PrincipalId, RandomSource as _, UnixMicros,
    uuid_v8,
};
use meshspan_metadata::{
    AcknowledgeNodeCertificateInstallation, AuthoritativeCommand, CommandContext,
    NodeCertificateRotation, NodeCertificateRotationState, PageLimit, RetireNodeCertificate,
    StageNodeCertificate, TopologyNodeCursor,
};
use meshspan_transport::NodeCredentials;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use thiserror::Error;

use crate::private_consensus_runtime::PrivateConsensusRuntime;
use crate::{
    ConsensusAuthenticationAuthority, LocalWrappingKey, OnlineAuthorityLoadingError,
    OnlineAuthorityLoadingService, OperatingSystemClock, OperatingSystemRandom,
};

const SECOND: i64 = 1_000_000;
const RENEWAL_LEAD: i64 = 7 * 86_400 * SECOND;

pub(crate) struct PrivateCertificateRenewal {
    authority: ConsensusAuthenticationAuthority,
    issuer: OnlineAuthorityLoadingService<ConsensusAuthenticationAuthority, LocalWrappingKey>,
    identity: NodeIdentityKey,
    network: Arc<PrivateConsensusRuntime>,
    after: Option<TopologyNodeCursor>,
    pending: Option<(CommandContext, AuthoritativeCommand)>,
}

impl PrivateCertificateRenewal {
    pub(crate) const fn new(
        authority: ConsensusAuthenticationAuthority,
        issuer: OnlineAuthorityLoadingService<ConsensusAuthenticationAuthority, LocalWrappingKey>,
        identity: NodeIdentityKey,
        network: Arc<PrivateConsensusRuntime>,
    ) -> Self {
        Self {
            authority,
            issuer,
            identity,
            network,
            after: None,
            pending: None,
        }
    }

    /// Runs bounded renewal work on an owned blocking job; public CA delays do not hold it.
    pub(crate) async fn run_until<F>(
        mut self,
        shutdown: F,
    ) -> Result<(), PrivateCertificateRenewalError>
    where
        F: Future<Output = ()> + Send,
    {
        tokio::pin!(shutdown);
        loop {
            let (returned, outcome) = tokio::task::spawn_blocking(move || {
                let outcome = self.run_once(OperatingSystemClock.now());
                (self, outcome)
            })
            .await
            .map_err(|_| PrivateCertificateRenewalError::WorkerStopped)?;
            self = returned;
            let changed = outcome?;
            let delay = if changed {
                Duration::from_millis(250)
            } else {
                Duration::from_secs(5)
            };
            tokio::select! {
                () = &mut shutdown => return Ok(()),
                () = tokio::time::sleep(delay) => {}
            }
        }
    }

    fn run_once(&mut self, now: UnixMicros) -> Result<bool, PrivateCertificateRenewalError> {
        let Ok(network) = self.network.network() else {
            return Ok(false);
        };
        if self.pending.is_some() {
            return self.commit_pending();
        }
        let Some(registration) = self
            .authority
            .reader()
            .storage_target_registration_context(network.local_node_id(), now)?
        else {
            return Ok(false);
        };
        let actor = registration.actor_principal_id;
        if let Some(rotation) = self
            .authority
            .reader()
            .node_certificate_rotation(network.local_node_id())?
            && rotation.state == NodeCertificateRotationState::Staged
            && rotation.valid_until > now
            && rotation.incarnation == network.local_incarnation()
        {
            let acknowledgement = self.install(&network, &rotation)?;
            return self.submit(
                actor,
                now,
                AuthoritativeCommand::AcknowledgeNodeCertificateInstallation(acknowledgement),
            );
        }
        let page = self
            .authority
            .reader()
            .topology_nodes(self.after.as_ref(), PageLimit::new(32)?)?;
        self.after = page.next;
        for node in page.items {
            if node.state != 2 {
                continue;
            }
            if let Some(command) = self.next_mutation(node.node_id, node.incarnation, now)? {
                return self.submit(actor, now, command);
            }
        }
        Ok(false)
    }

    fn next_mutation(
        &self,
        node: NodeId,
        incarnation: u64,
        now: UnixMicros,
    ) -> Result<Option<AuthoritativeCommand>, PrivateCertificateRenewalError> {
        let rotation = self.authority.reader().node_certificate_rotation(node)?;
        if let Some(rotation) = &rotation {
            let retire = match rotation.state {
                NodeCertificateRotationState::Staged => rotation.valid_until <= now,
                NodeCertificateRotationState::Installed => rotation
                    .retire_after
                    .is_some_and(|deadline| deadline <= now),
                NodeCertificateRotationState::Retired | NodeCertificateRotationState::Abandoned => {
                    false
                }
            };
            if retire && rotation.incarnation == incarnation {
                return Ok(Some(AuthoritativeCommand::RetireNodeCertificate(
                    RetireNodeCertificate {
                        node_id: node,
                        incarnation,
                        generation: rotation.generation,
                    },
                )));
            }
            if matches!(
                rotation.state,
                NodeCertificateRotationState::Staged | NodeCertificateRotationState::Installed
            ) {
                return Ok(None);
            }
        }
        let Some(current) = self.authority.reader().active_node_certificate(node)? else {
            return Ok(None);
        };
        if current.valid_until.get().saturating_sub(now.get()) > RENEWAL_LEAD {
            return Ok(None);
        }
        let (mesh, issuer) = match self.issuer.load_latest() {
            Ok(value) => value,
            Err(
                OnlineAuthorityLoadingError::NotFound
                | OnlineAuthorityLoadingError::NotRecipient
                | OnlineAuthorityLoadingError::Unavailable,
            ) => return Ok(None),
            Err(error @ OnlineAuthorityLoadingError::Failed) => return Err(error.into()),
        };
        let issuer_record = self
            .authority
            .reader()
            .online_certificate_authority(mesh)?
            .filter(|record| record.certificate_der == issuer.certificate_der())
            .ok_or(PrivateCertificateRenewalError::InvalidState)?;
        let generation = rotation
            .map_or(current.generation, |value| value.generation)
            .checked_add(1)
            .ok_or(PrivateCertificateRenewalError::InvalidState)?;
        let from = now
            .get()
            .checked_div(SECOND)
            .and_then(|seconds| seconds.checked_sub(300))
            .filter(|seconds| *seconds >= 0)
            .ok_or(PrivateCertificateRenewalError::InvalidState)?;
        let until = from
            .checked_add(30 * 86_400)
            .ok_or(PrivateCertificateRenewalError::InvalidState)?;
        let name = crate::private_consensus_runtime::certificate_name(node);
        let public = NodePublicIdentity::from_certificate(&current.certificate_der)?;
        let der = issuer.renew_node_certificate(
            &public,
            NodeCertificateRequest {
                dns_name: &name,
                generation,
                not_before: from,
                not_after: until,
            },
        )?;
        Ok(Some(AuthoritativeCommand::StageNodeCertificate(
            StageNodeCertificate {
                node_id: node,
                incarnation,
                previous_generation: current.generation,
                generation,
                issuer_generation: issuer_record.generation,
                certificate_der: der,
                valid_from: UnixMicros::new(
                    from.checked_mul(SECOND)
                        .ok_or(PrivateCertificateRenewalError::InvalidState)?,
                ),
                valid_until: UnixMicros::new(
                    until
                        .checked_mul(SECOND)
                        .ok_or(PrivateCertificateRenewalError::InvalidState)?,
                ),
            },
        )))
    }

    fn install(
        &self,
        network: &ConsensusNetwork,
        rotation: &NodeCertificateRotation,
    ) -> Result<AcknowledgeNodeCertificateInstallation, PrivateCertificateRenewalError> {
        let installed = network.install_local_certificate(
            rotation.generation,
            NodeCredentials::new(
                vec![
                    CertificateDer::from(rotation.certificate_der.clone()),
                    CertificateDer::from(rotation.issuer_certificate_der.clone()),
                ],
                PrivatePkcs8KeyDer::from(self.identity.private_key_pkcs8().to_vec()).into(),
            )?,
        )?;
        let mut acknowledgement = AcknowledgeNodeCertificateInstallation {
            node_id: network.local_node_id(),
            incarnation: network.local_incarnation(),
            generation: installed.generation,
            certificate_fingerprint: installed.certificate_fingerprint,
            staged_revision: rotation.staged_revision,
            signature: Vec::new(),
        };
        acknowledgement.signature = self
            .identity
            .sign_enrolment_transcript(&acknowledgement.signing_transcript())?;
        Ok(acknowledgement)
    }

    fn submit(
        &mut self,
        actor: PrincipalId,
        now: UnixMicros,
        command: AuthoritativeCommand,
    ) -> Result<bool, PrivateCertificateRenewalError> {
        let mut operation = [0; 16];
        let mut audit = [0; 16];
        OperatingSystemRandom
            .fill_bytes(&mut operation)
            .map_err(|_| PrivateCertificateRenewalError::InvalidState)?;
        OperatingSystemRandom
            .fill_bytes(&mut audit)
            .map_err(|_| PrivateCertificateRenewalError::InvalidState)?;
        let context = CommandContext {
            operation_id: OperationId::from_bytes(uuid_v8(operation))?,
            actor_principal_id: actor,
            audit_event_id: AuditEventId::from_bytes(uuid_v8(audit))?,
            occurred_at: now,
            expected_revision: None,
        };
        self.pending = Some((context, command));
        self.commit_pending()
    }

    fn commit_pending(&mut self) -> Result<bool, PrivateCertificateRenewalError> {
        let Some((context, command)) = self.pending.as_ref() else {
            return Ok(false);
        };
        match self.authority.commit_authoritative(*context, command) {
            Ok(receipt)
                if receipt.operation_id == context.operation_id
                    && receipt.request_digest == command.request_digest(*context)
                    && receipt.committed_revision.get() > 0 =>
            {
                self.pending = None;
                Ok(true)
            }
            Err(
                MetadataAuthorityRequestError::NotLeader { .. }
                | MetadataAuthorityRequestError::Unavailable,
            ) => Ok(false),
            // Concurrent eligible workers can stage or retire the same node. The next tick
            // reloads the committed state; never retry a rejected command with changed bytes.
            Err(MetadataAuthorityRequestError::Rejected) => {
                self.pending = None;
                Ok(false)
            }
            Ok(_)
            | Err(
                MetadataAuthorityRequestError::Conflict
                | MetadataAuthorityRequestError::Unsupported
                | MetadataAuthorityRequestError::Failed,
            ) => Err(PrivateCertificateRenewalError::InvalidState),
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum PrivateCertificateRenewalError {
    #[error("private certificate rotation state is invalid")]
    InvalidState,
    #[error("private certificate worker stopped unexpectedly")]
    WorkerStopped,
    #[error("private certificate metadata is unavailable")]
    Metadata(#[from] meshspan_metadata::RepositoryError),
    #[error("private certificate identity is invalid")]
    Certificate(#[from] meshspan_certificates::CertificateError),
    #[error("private certificate signing authority is unavailable")]
    Issuer(#[from] OnlineAuthorityLoadingError),
    #[error("private certificate transport rejected installation")]
    Transport(#[from] meshspan_transport::TransportError),
    #[error("private certificate network rejected installation")]
    Network(#[from] meshspan_cluster::ConsensusNetworkError),
    #[error("private certificate identifier is invalid")]
    Domain(#[from] meshspan_domain::IdentifierError),
}
