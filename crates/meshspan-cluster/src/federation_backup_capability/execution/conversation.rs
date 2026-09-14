// SPDX-License-Identifier: GPL-2.0-only

//! Authority and reply routing vary by hop; provider IO and completion stay in one state machine.

use super::{FederationBackupOwnerStreamContext, execute};
use crate::{
    AuthorisedFederatedBackup, FederationBackupCapabilityError, FederationBackupCapabilityService,
    authorise_forwarded_backup,
};
use meshspan_contracts::{BackupProvider, ContractError};
use meshspan_domain::{NodeId, UnixMicros};
use meshspan_metadata::AuthoritativeRepository;
use meshspan_protocol::{
    WireLimits,
    v1::{
        DataControlEnvelope, ForwardFederatedBackupReady, ForwardFederatedBackupResult,
        data_control_envelope::Message as DataMessage, federation_envelope::Message,
    },
};
use meshspan_transport::{
    AcceptedStream, AuthenticatedFederationBackupRelay, AuthenticatedFederationBackupRequest,
    StreamKind, TransportError, federation_backup_relay_digest, send_data_control, send_federation,
    signed_federation_backup_message,
};

/// Owner-only execution environment. It neither owns nor borrows a gateway's federation secrets.
pub struct FederationBackupOwnerService<'a> {
    repository: &'a AuthoritativeRepository,
    node: NodeId,
    routing_epoch: u64,
}

impl<'a> FederationBackupOwnerService<'a> {
    /// Binds current authority and the receiving process's active private-network route.
    #[must_use]
    pub const fn new(
        repository: &'a AuthoritativeRepository,
        node: NodeId,
        routing_epoch: u64,
    ) -> Self {
        Self {
            repository,
            node,
            routing_epoch,
        }
    }

    /// Executes the exact relayed operation through the owner-supplied namespace provider.
    ///
    /// Invoke only on an owned blocking worker. The provider must be bound to the admitted
    /// allocation/target. Store admission precedes readiness; original byte length/digest and
    /// clean FIN precede publication. Authority is rechecked during IO and before final reply.
    ///
    /// # Errors
    /// Rejects wrong stream, current authority, framing, expired lifetime or provider failure.
    /// Losing any reply means unknown outcome, never rollback or permission to reroute.
    pub fn execute_stream(
        &self,
        relay: &AuthenticatedFederationBackupRelay,
        provider: &mut dyn BackupProvider,
        stream: AcceptedStream,
        context: FederationBackupOwnerStreamContext<'_>,
    ) -> Result<(), FederationBackupCapabilityError> {
        if stream.kind != StreamKind::Data {
            return Err(ContractError::InvalidInput.into());
        }
        let digest = federation_backup_relay_digest(relay.forwarded(), context.limits)?;
        let maximum = usize::try_from(relay.forwarded().maximum_frame_bytes)
            .map_err(|_| ContractError::InvalidInput)?;
        let limits = WireLimits::new(
            context.limits.maximum_control_bytes(),
            maximum.min(context.limits.maximum_data_frame_bytes()),
            context.limits.maximum_items(),
            context.limits.maximum_text_bytes(),
        )
        .map_err(TransportError::from)?;
        execute(
            Conversation::Owner {
                service: self,
                relay,
                digest,
            },
            provider,
            stream,
            FederationBackupOwnerStreamContext { limits, ..context },
        )
    }
}

pub(super) enum Conversation<'a, 'identity> {
    Direct {
        service: &'a FederationBackupCapabilityService<'a, 'identity>,
        authenticated: &'a AuthenticatedFederationBackupRequest,
        ready_nonce: [u8; 32],
        result_nonce: [u8; 32],
    },
    Owner {
        service: &'a FederationBackupOwnerService<'a>,
        relay: &'a AuthenticatedFederationBackupRelay,
        digest: [u8; 32],
    },
}

impl Conversation<'_, '_> {
    pub(super) fn authorise(
        &self,
        now: UnixMicros,
    ) -> Result<AuthorisedFederatedBackup, FederationBackupCapabilityError> {
        match self {
            Self::Direct {
                service,
                authenticated,
                ..
            } => service.authorise(authenticated, now),
            Self::Owner { service, relay, .. } => authorise_forwarded_backup(
                service.repository,
                service.node,
                service.routing_epoch,
                relay,
                now,
            ),
        }
    }

    pub(super) fn deadline(&self, expires: UnixMicros) -> UnixMicros {
        match self {
            Self::Direct { .. } => expires,
            Self::Owner { relay, .. } => relay
                .forwarded()
                .header
                .as_ref()
                .map_or(UnixMicros::new(0), |header| {
                    expires.min(UnixMicros::new(header.deadline_unix_micros))
                }),
        }
    }

    pub(super) async fn send(
        &self,
        stream: &mut quinn::SendStream,
        message: Message,
        limits: WireLimits,
        now: UnixMicros,
    ) -> Result<(), TransportError> {
        match self {
            Self::Direct {
                service,
                authenticated,
                ready_nonce,
                result_nonce,
            } => {
                let nonce = match &message {
                    Message::BackupReady(_) => *ready_nonce,
                    Message::BackupResult(_) => *result_nonce,
                    _ => return Err(TransportError::InvalidConfiguration),
                };
                let signed = signed_federation_backup_message(
                    service.identity,
                    authenticated.response_context(nonce)?,
                    message,
                    limits,
                    now,
                )?;
                send_federation(stream, signed.envelope(), limits).await
            }
            Self::Owner { digest, .. } => {
                let message = match message {
                    Message::BackupReady(ready) => {
                        DataMessage::ForwardFederatedBackupReady(ForwardFederatedBackupReady {
                            request_digest: digest.to_vec(),
                            ready: Some(ready),
                        })
                    }
                    Message::BackupResult(result) => {
                        DataMessage::ForwardFederatedBackupResult(ForwardFederatedBackupResult {
                            request_digest: digest.to_vec(),
                            result: Some(result),
                        })
                    }
                    _ => return Err(TransportError::InvalidConfiguration),
                };
                send_data_control(
                    stream,
                    &DataControlEnvelope {
                        message: Some(message),
                    },
                    limits,
                )
                .await
            }
        }
    }
}
