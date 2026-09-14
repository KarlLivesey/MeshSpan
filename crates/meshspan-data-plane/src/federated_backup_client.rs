// SPDX-License-Identifier: GPL-2.0-only

//! Consumer conversations on an already negotiated, currently trusted federation session.

mod bytes;
mod upload;
pub use upload::PreparedFederatedBackupUpload;

use meshspan_contracts::{
    BackupDeleteReceipt, BackupObjectReceipt, BackupReadReceipt, FederatedBackupRequest,
    FederatedBackupScope,
};
use meshspan_domain::{Clock, DurationMicros, RandomSource, UnixMicros};
use meshspan_protocol::{
    WireLimits,
    v1::{
        ExecuteFederatedBackup, ProtocolVersion, federated_backup_result::Outcome,
        federation_envelope::Message,
    },
};
use meshspan_transport::{
    AuthenticatedFederationBackupResponse, FederationBackupResponseExpectation,
    FederationExchangeContext, FederationLocalIdentity, FederationPeerRegistry,
    FederationReplayGuard, OutboundFederationBackupMessage, StreamKind, TransportError,
    open_stream, receive_federation, send_federation, signed_federation_backup_message,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

use crate::{BackupPlaneError as Error, backup_wire};

/// Byte direction for an exact operation. Metadata-only operations cannot accept byte streams.
pub enum FederatedBackupIo<'a> {
    /// Encrypted source; both its exact length and digest are checked before completion.
    Upload(&'a mut (dyn AsyncRead + Unpin)),
    /// Encrypted output; partial bytes on error are not a successful backup read.
    Download(&'a mut (dyn AsyncWrite + Unpin)),
    /// Verification or retirement with no bulk bytes.
    None,
}

/// A signed, correlated provider result, not a consumer metadata-commit acknowledgement.
#[derive(Debug, Eq, PartialEq)]
pub enum FederatedBackupReceipt {
    /// Retained catalogue evidence, not a current object-byte verification.
    LookedUp(BackupObjectReceipt),
    /// Exact storage acknowledgement.
    Stored(BackupObjectReceipt),
    /// Measured exact read completion.
    Read(BackupReadReceipt),
    /// Exact verification acknowledgement.
    Verified(BackupObjectReceipt),
    /// Exact retirement acknowledgement.
    Deleted(BackupDeleteReceipt),
}

/// Bounded client for an existing federation connection; does not select or mutate authority.
///
/// The daemon supplies current peer trust. Direct execution uses an already persisted route;
/// upload preparation admits capacity before that route is committed, without sending bytes.
/// Retrying an unknown result retains the operation/object/route with a fresh capability.
pub struct FederatedBackupClient<'a, 'identity> {
    connection: &'a quinn::Connection,
    identity: &'a FederationLocalIdentity<'identity>,
    peers: &'a FederationPeerRegistry,
    limits: WireLimits,
    clock: &'a dyn Clock,
    replay: FederationReplayGuard,
}

/// Authenticated ready/result streams before any object bytes cross the boundary.
struct ReadyTransfer {
    send: quinn::SendStream,
    receive: quinn::RecvStream,
    expected: FederationBackupResponseExpectation,
    frame_bytes: usize,
}

impl<'a, 'identity> FederatedBackupClient<'a, 'identity> {
    /// Binds negotiated framing and trust without opening another connection or doing IO.
    /// # Errors
    /// Rejects invalid replay protection configuration.
    pub fn new(
        connection: &'a quinn::Connection,
        identity: &'a FederationLocalIdentity<'identity>,
        peers: &'a FederationPeerRegistry,
        limits: WireLimits,
        clock: &'a dyn Clock,
    ) -> Result<Self, Error> {
        Ok(Self {
            connection,
            identity,
            peers,
            limits,
            clock,
            replay: FederationReplayGuard::new(
                256,
                DurationMicros::new(
                    meshspan_contracts::MAXIMUM_FEDERATED_BACKUP_PERMIT_LIFETIME_MICROS
                        .unsigned_abs(),
                ),
            )?,
        })
    }

    /// Obtains a fresh signed capability, transfers bounded encrypted frames and checks its result.
    ///
    /// All waits share the request deadline; execution is further limited by permit expiry.
    /// Cancellation or a lost response means an unknown remote outcome, never rollback.
    /// # Errors
    /// Rejects the wrong IO direction, source/response drift, revoked or expired trust, replay,
    /// typed provider rejection, invalid framing, local IO failure or an elapsed deadline.
    pub async fn execute(
        &mut self,
        scope: FederatedBackupScope,
        request: &FederatedBackupRequest,
        io: FederatedBackupIo<'_>,
        random: &mut dyn RandomSource,
    ) -> Result<FederatedBackupReceipt, Error> {
        match (request, &io) {
            (FederatedBackupRequest::Store(_), FederatedBackupIo::Upload(_))
            | (FederatedBackupRequest::Read(_), FederatedBackupIo::Download(_))
            | (
                FederatedBackupRequest::Lookup(_)
                | FederatedBackupRequest::Verify(_)
                | FederatedBackupRequest::Delete(_),
                FederatedBackupIo::None,
            ) => {}
            _ => return Err(Error::InvalidMessage),
        }
        let deadline = deadline_at(request.context().deadline, self.clock.now())?;
        tokio::time::timeout_at(deadline, async {
            let outbound = self.capability(scope, request, random).await?;
            let Message::ExecuteBackup(execution) = outbound
                .envelope()
                .message
                .as_ref()
                .ok_or(Error::InvalidMessage)?
            else {
                return Err(Error::InvalidMessage);
            };
            let permit = execution.permit.as_ref().ok_or(Error::InvalidMessage)?;
            let permit_deadline = deadline_at(
                UnixMicros::new(permit.expires_at_unix_micros),
                self.clock.now(),
            )?
            .min(deadline);
            tokio::time::timeout_at(permit_deadline, self.transfer(&outbound, request, io))
                .await
                .map_err(|_| timed_out())?
        })
        .await
        .map_err(|_| timed_out())?
    }

    async fn capability(
        &mut self,
        scope: FederatedBackupScope,
        request: &FederatedBackupRequest,
        random: &mut dyn RandomSource,
    ) -> Result<OutboundFederationBackupMessage, Error> {
        let wire = crate::encode_federated_backup_request(scope, request, self.clock.now())
            .map_err(|_| Error::InvalidMessage)?;
        let outbound = self.sign(Message::RequestBackupCapability(wire), request, random)?;
        let (mut send, mut receive) = open_stream(self.connection, StreamKind::Federation).await?;
        send_federation(&mut send, outbound.envelope(), self.limits).await?;
        send.finish().map_err(TransportError::from)?;
        let response = self
            .response(&mut receive, &outbound.expectation()?)
            .await?;
        let Message::BackupCapability(value) = response.message() else {
            return Err(Error::InvalidMessage);
        };
        if let Some(rejection) = &value.rejection {
            return Err(backup_wire::remote_rejection(rejection)?);
        }
        let permit = value.permit.clone().ok_or(Error::InvalidMessage)?;
        crate::decode_federated_backup_permit(&permit, self.clock.now())
            .map_err(|_| Error::InvalidMessage)?;
        require_end(&mut receive).await?;
        self.sign(
            Message::ExecuteBackup(ExecuteFederatedBackup {
                permit: Some(permit),
                signature: Vec::new(),
            }),
            request,
            random,
        )
    }

    async fn transfer(
        &mut self,
        outbound: &OutboundFederationBackupMessage,
        request: &FederatedBackupRequest,
        io: FederatedBackupIo<'_>,
    ) -> Result<FederatedBackupReceipt, Error> {
        let mut ready = self
            .admit(outbound, matches!(io, FederatedBackupIo::Upload(_)))
            .await?;
        match io {
            FederatedBackupIo::Upload(source) => {
                bytes::upload(
                    &mut ready.send,
                    source,
                    request.object(),
                    ready.frame_bytes,
                    self.limits,
                )
                .await?;
                ready.send.finish().map_err(TransportError::from)?;
            }
            FederatedBackupIo::Download(destination) => {
                bytes::download(
                    &mut ready.receive,
                    destination,
                    request.object(),
                    ready.frame_bytes,
                    self.limits,
                )
                .await?;
            }
            FederatedBackupIo::None => {}
        }
        self.complete(ready).await
    }

    async fn admit(
        &mut self,
        outbound: &OutboundFederationBackupMessage,
        upload: bool,
    ) -> Result<ReadyTransfer, Error> {
        let (mut send, mut receive) = open_stream(self.connection, StreamKind::Federation).await?;
        send_federation(&mut send, outbound.envelope(), self.limits).await?;
        if !upload {
            send.finish().map_err(TransportError::from)?;
        }
        let ready = self
            .response(&mut receive, &outbound.expectation()?)
            .await?;
        let Message::BackupReady(value) = ready.message() else {
            return Err(Error::InvalidMessage);
        };
        if let Some(rejection) = &value.rejection {
            return Err(backup_wire::remote_rejection(rejection)?);
        }
        let frame_bytes =
            usize::try_from(value.maximum_frame_bytes).map_err(|_| Error::InvalidMessage)?;
        if frame_bytes == 0 || frame_bytes > self.limits.maximum_data_frame_bytes() {
            return Err(Error::InvalidMessage);
        }
        let expected = ready.result_expectation()?;
        Ok(ReadyTransfer {
            send,
            receive,
            expected,
            frame_bytes,
        })
    }

    async fn complete(
        &mut self,
        mut ready: ReadyTransfer,
    ) -> Result<FederatedBackupReceipt, Error> {
        let result = self.response(&mut ready.receive, &ready.expected).await?;
        let Message::BackupResult(result) = result.message() else {
            return Err(Error::InvalidMessage);
        };
        let receipt = receipt(result.outcome.as_ref().ok_or(Error::InvalidMessage)?)?;
        require_end(&mut ready.receive).await?;
        Ok(receipt)
    }

    async fn response(
        &mut self,
        receive: &mut quinn::RecvStream,
        expected: &FederationBackupResponseExpectation,
    ) -> Result<AuthenticatedFederationBackupResponse, Error> {
        let envelope = receive_federation(receive, self.limits).await?;
        Ok(self.peers.authenticate_backup_response(
            self.connection,
            &envelope,
            expected,
            self.clock.now(),
            &mut self.replay,
        )?)
    }

    fn sign(
        &self,
        message: Message,
        request: &FederatedBackupRequest,
        random: &mut dyn RandomSource,
    ) -> Result<OutboundFederationBackupMessage, Error> {
        let mut nonce = [0; 32];
        let mut request_id = [0; 16];
        random.fill_bytes(&mut nonce).map_err(|_| Error::Worker)?;
        random
            .fill_bytes(&mut request_id)
            .map_err(|_| Error::Worker)?;
        let context = request.context();
        let now = self.clock.now();
        // The operation's deadline remains in its signed payload. Each attempt's
        // envelope is shorter, bounded by the existing capability lifetime.
        let message_deadline = context.deadline.min(
            now.checked_add(DurationMicros::new(
                meshspan_contracts::MAXIMUM_FEDERATED_BACKUP_PERMIT_LIFETIME_MICROS.unsigned_abs(),
            ))
            .ok_or(Error::InvalidMessage)?,
        );
        Ok(signed_federation_backup_message(
            self.identity,
            FederationExchangeContext::new(
                ProtocolVersion { major: 1, minor: 0 },
                request_id,
                context.operation_id.as_bytes(),
                context.operation_id.as_bytes(),
                message_deadline,
                nonce,
            )?,
            message,
            self.limits,
            now,
        )?)
    }
}

fn receipt(outcome: &Outcome) -> Result<FederatedBackupReceipt, Error> {
    Ok(match outcome {
        Outcome::Stored(value) => {
            FederatedBackupReceipt::Stored(backup_wire::object_receipt(value)?)
        }
        Outcome::LookedUp(value) => {
            FederatedBackupReceipt::LookedUp(backup_wire::object_receipt(value)?)
        }
        Outcome::Read(value) => FederatedBackupReceipt::Read(backup_wire::read_receipt(value)?),
        Outcome::Verified(value) => {
            FederatedBackupReceipt::Verified(backup_wire::object_receipt(value)?)
        }
        Outcome::Deleted(value) => {
            FederatedBackupReceipt::Deleted(backup_wire::delete_receipt(value)?)
        }
        Outcome::Rejection(value) => return Err(backup_wire::remote_rejection(value)?),
    })
}

fn deadline_at(at: UnixMicros, now: UnixMicros) -> Result<tokio::time::Instant, Error> {
    let micros = at
        .get()
        .checked_sub(now.get())
        .and_then(|value| u64::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or_else(timed_out)?;
    tokio::time::Instant::now()
        .checked_add(std::time::Duration::from_micros(micros))
        .ok_or(Error::InvalidMessage)
}

fn timed_out() -> Error {
    Error::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "federated backup deadline elapsed; remote outcome may be unknown",
    ))
}

async fn require_end(receive: &mut quinn::RecvStream) -> Result<(), Error> {
    let mut byte = [0; 1];
    if AsyncReadExt::read(receive, &mut byte).await? != 0 {
        Err(Error::InvalidMessage)
    } else {
        Ok(())
    }
}
