// SPDX-License-Identifier: GPL-2.0-only

//! Gateway forwarding preserves owner admission and authenticates each returned receipt.

mod bytes;

use super::{
    FederationBackupCapabilityError as Error, FederationBackupCapabilityService,
    FederationBackupStreamContext,
};
use meshspan_contracts::{ContractError, FederatedBackupRequest};
use meshspan_domain::{NodeId, UnixMicros};
use meshspan_protocol::{
    WireLimits, encode_federation_frame,
    v1::{
        DataControlEnvelope, ForwardFederatedBackupRequest, RequestHeader,
        data_control_envelope::Message as DataMessage, federation_envelope::Message,
    },
};
use meshspan_transport::{
    AcceptedStream, AuthenticatedFederationBackupRequest, AuthenticatedPeer,
    FederationBackupOwnerResponseExpectation, PeerBinding, PeerRegistry, StreamKind,
    TransportError, open_stream, receive_data_control, send_data_control, send_federation,
    signed_federation_backup_message,
};

/// Gateway IO and its already-connected private owner route. The service verifies that
/// connection against current node certificates; routing headers come from the local network.
pub struct FederationBackupForwardContext<'a> {
    /// External conversation runtime, clock, framing and distinct response nonces.
    pub io: FederationBackupStreamContext<'a>,
    /// Same-swarm mTLS connection to the requested owner, never a foreign federation connection.
    pub connection: &'a quinn::Connection,
    /// Locally configured partition/epoch/sender route. Original request correlation is preserved.
    pub header: RequestHeader,
    /// Bounds negotiated with the owner.
    pub limits: WireLimits,
}

impl FederationBackupCapabilityService<'_, '_> {
    /// Forwards an admitted consumer stream to its exact current storage owner.
    ///
    /// Run on the owned blocking bulk worker. Successful readiness comes only from owner
    /// capacity admission. No owner or byte error is converted into an invented success;
    /// connection loss leaves the outcome unknown and does not permit rerouting.
    ///
    /// # Errors
    /// Rejects stale authority/owner certificates, malformed or substituted replies, incorrect
    /// byte length/digest/FIN, invalid routing and deadline/transport failure.
    pub fn forward_stream(
        &self,
        authenticated: &AuthenticatedFederationBackupRequest,
        mut stream: AcceptedStream,
        context: &FederationBackupForwardContext<'_>,
    ) -> Result<(), Error> {
        if stream.kind != StreamKind::Federation
            || context.io.ready_nonce == context.io.result_nonce
        {
            return Err(ContractError::InvalidInput.into());
        }
        let now = context.io.clock.now();
        let admitted = self.authorise_gateway(authenticated, now)?;
        let owner = admitted.scope().provider_node_id;
        let peer = self.backup_owner_peer(context.connection, owner, now)?;
        let request = self.forwarded_request(authenticated, context, admitted.permit())?;
        let deadline = request
            .header
            .as_ref()
            .ok_or(ContractError::InvalidInput)?
            .deadline_unix_micros;
        let remaining = u64::try_from(
            deadline
                .checked_sub(now.get())
                .ok_or(ContractError::DeadlineExceeded)?,
        )
        .map_err(|_| ContractError::DeadlineExceeded)?;
        let mut transfer = Forwarding {
            service: self,
            authenticated,
            context,
            peer,
            expected: FederationBackupOwnerResponseExpectation::new(&request, context.limits)?,
        };
        context.io.runtime.block_on(async {
            tokio::time::timeout(
                std::time::Duration::from_micros(remaining),
                transfer.execute(&mut stream, request, admitted.request()),
            )
            .await
            .map_err(|_| ContractError::DeadlineExceeded)?
        })
    }

    fn backup_owner_peer(
        &self,
        connection: &quinn::Connection,
        owner: NodeId,
        now: UnixMicros,
    ) -> Result<AuthenticatedPeer, Error> {
        let certificate = self
            .repository
            .active_node_certificate(owner)
            .map_err(|_| ContractError::Unavailable)?
            .ok_or(ContractError::Unauthorized)?;
        if certificate.valid_until <= now {
            return Err(ContractError::Unauthorized.into());
        }
        Ok(PeerRegistry::new([PeerBinding {
            node_id: owner,
            incarnation: certificate.incarnation,
            certificate_fingerprint: certificate.certificate_fingerprint,
        }])?
        .authenticate_connection(connection)?)
    }

    fn forwarded_request(
        &self,
        authenticated: &AuthenticatedFederationBackupRequest,
        context: &FederationBackupForwardContext<'_>,
        permit: &meshspan_contracts::FederatedBackupPermit,
    ) -> Result<ForwardFederatedBackupRequest, Error> {
        let mut header = context.header.clone();
        if header.sender_node_id != self.node_id.as_bytes()
            || header.mesh_id != permit.scope.provider_mesh_id.as_bytes()
            || header.partition_id != self.repository.partition_id().as_bytes()
        {
            return Err(ContractError::Unauthorized.into());
        }
        let original = authenticated.response_context(context.io.ready_nonce)?;
        header.request_id = original.request_id.to_vec();
        header.operation_id = original.operation_id.to_vec();
        header.trace_id = original.trace_id.to_vec();
        header.deadline_unix_micros = header.deadline_unix_micros.min(permit.expires_at.get());
        Ok(ForwardFederatedBackupRequest {
            header: Some(header),
            provider_node_id: permit.scope.provider_node_id.as_bytes().to_vec(),
            request: encode_federation_frame(&authenticated.signed_envelope(), context.limits)
                .map_err(TransportError::from)?,
            maximum_frame_bytes: context
                .limits
                .maximum_data_frame_bytes()
                .min(context.io.limits.maximum_data_frame_bytes())
                as u64,
        })
    }
}

struct Forwarding<'a, 'identity> {
    service: &'a FederationBackupCapabilityService<'a, 'identity>,
    authenticated: &'a AuthenticatedFederationBackupRequest,
    context: &'a FederationBackupForwardContext<'a>,
    peer: AuthenticatedPeer,
    expected: FederationBackupOwnerResponseExpectation,
}

impl Forwarding<'_, '_> {
    async fn execute(
        &mut self,
        client: &mut AcceptedStream,
        request: ForwardFederatedBackupRequest,
        operation: &FederatedBackupRequest,
    ) -> Result<(), Error> {
        self.check()?;
        let (mut send, mut receive) =
            open_stream(self.context.connection, StreamKind::Data).await?;
        send_data_control(
            &mut send,
            &DataControlEnvelope {
                message: Some(DataMessage::ForwardFederatedBackupRequest(request)),
            },
            self.context.limits,
        )
        .await?;
        let ready = self.response(&mut receive).await?;
        let Message::BackupReady(payload) = &ready else {
            return Err(ContractError::InvalidInput.into());
        };
        let rejected = payload.rejection.is_some();
        let maximum = usize::try_from(payload.maximum_frame_bytes)
            .map_err(|_| ContractError::InvalidInput)?;
        if rejected {
            self.clean_end(&mut receive).await?;
        }
        self.reply(&mut client.send, ready, self.context.io.ready_nonce)
            .await?;
        if !rejected {
            match operation {
                FederatedBackupRequest::Store(_) => {
                    self.copy_bytes(&mut client.receive, &mut send, operation.object(), maximum)
                        .await?;
                    self.clean_end(&mut client.receive).await?;
                    send.finish().map_err(TransportError::from)?;
                }
                FederatedBackupRequest::Read(_) => {
                    send.finish().map_err(TransportError::from)?;
                    self.copy_bytes(&mut receive, &mut client.send, operation.object(), maximum)
                        .await?;
                }
                FederatedBackupRequest::Lookup(_)
                | FederatedBackupRequest::Verify(_)
                | FederatedBackupRequest::Delete(_) => {
                    send.finish().map_err(TransportError::from)?;
                }
            }
            let result = self.response(&mut receive).await?;
            self.clean_end(&mut receive).await?;
            self.reply(&mut client.send, result, self.context.io.result_nonce)
                .await?;
        }
        client.send.finish().map_err(TransportError::from)?;
        Ok(())
    }

    fn check(&self) -> Result<(), Error> {
        let now = self.context.io.clock.now();
        let admitted = self.service.authorise_gateway(self.authenticated, now)?;
        if self.service.backup_owner_peer(
            self.context.connection,
            admitted.scope().provider_node_id,
            now,
        )? != self.peer
        {
            return Err(ContractError::Stale.into());
        }
        Ok(())
    }

    async fn response(&mut self, receive: &mut quinn::RecvStream) -> Result<Message, Error> {
        let response = receive_data_control(receive, self.context.limits).await?;
        self.check()?;
        Ok(self
            .expected
            .accept(&response, self.context.io.clock.now())?)
    }

    async fn reply(
        &self,
        send: &mut quinn::SendStream,
        message: Message,
        nonce: [u8; 32],
    ) -> Result<(), Error> {
        self.check()?;
        let response = signed_federation_backup_message(
            self.service.identity,
            self.authenticated.response_context(nonce)?,
            message,
            self.context.io.limits,
            self.context.io.clock.now(),
        )?;
        Ok(send_federation(send, response.envelope(), self.context.io.limits).await?)
    }
}
