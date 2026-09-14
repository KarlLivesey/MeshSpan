// SPDX-License-Identifier: GPL-2.0-only

//! Capacity admission before consumer route commitment, then exact byte publication.

use super::{
    Error, FederatedBackupClient, FederatedBackupReceipt, ReadyTransfer, bytes, deadline_at,
    timed_out,
};
use meshspan_contracts::{
    BackupObjectReceipt, BackupStoreRequest, FederatedBackupRequest, FederatedBackupScope,
};
use meshspan_domain::{RandomSource, UnixMicros};
use meshspan_protocol::{WireLimits, v1::federation_envelope::Message};
use meshspan_transport::TransportError;
use tokio::io::AsyncRead;

/// Provider-admitted capacity with no uploaded bytes. Dropping closes this attempt's streams.
/// The consumer commits the exact route while holding this value, then finishes the same
/// operation. This is not a stored receipt and cannot outlive its signed permit deadline.
pub struct PreparedFederatedBackupUpload {
    request: BackupStoreRequest,
    scope: FederatedBackupScope,
    connection_id: usize,
    limits: WireLimits,
    deadline: tokio::time::Instant,
    transfer: ReadyTransfer,
}

impl PreparedFederatedBackupUpload {
    /// Exact store operation for which the provider admitted capacity.
    #[must_use]
    pub const fn request(&self) -> BackupStoreRequest {
        self.request
    }

    /// Exact admitted route; selection cannot change it before uploading.
    #[must_use]
    pub const fn scope(&self) -> FederatedBackupScope {
        self.scope
    }
}

impl FederatedBackupClient<'_, '_> {
    /// Obtains a permit and signed capacity admission without accepting a source stream.
    /// # Errors
    /// Rejects capacity/authority failures, wrong peers or framing, and elapsed deadlines.
    /// No object bytes can be sent here, including after a lost ready response.
    pub async fn prepare_upload(
        &mut self,
        scope: FederatedBackupScope,
        request: BackupStoreRequest,
        random: &mut dyn RandomSource,
    ) -> Result<PreparedFederatedBackupUpload, Error> {
        let deadline = deadline_at(request.context.deadline, self.clock.now())?;
        tokio::time::timeout_at(deadline, async {
            let outbound = self
                .capability(scope, &FederatedBackupRequest::Store(request), random)
                .await?;
            let Message::ExecuteBackup(execution) = outbound
                .envelope()
                .message
                .as_ref()
                .ok_or(Error::InvalidMessage)?
            else {
                return Err(Error::InvalidMessage);
            };
            let permit = execution.permit.as_ref().ok_or(Error::InvalidMessage)?;
            let deadline = deadline_at(
                UnixMicros::new(permit.expires_at_unix_micros),
                self.clock.now(),
            )?
            .min(deadline);
            let transfer = tokio::time::timeout_at(deadline, self.admit(&outbound, true))
                .await
                .map_err(|_| timed_out())??;
            Ok(PreparedFederatedBackupUpload {
                request,
                scope,
                connection_id: self.connection.stable_id(),
                limits: self.limits,
                deadline,
                transfer,
            })
        })
        .await
        .map_err(|_| timed_out())?
    }

    /// Sends exact source bytes after its caller commits the admitted route.
    /// # Errors
    /// Rejects a replaced connection, changed bounds, expiry, invalid bytes or mismatched
    /// result. A failure after bytes were sent leaves the remote outcome unknown.
    pub async fn finish_upload(
        &mut self,
        mut prepared: PreparedFederatedBackupUpload,
        source: &mut (dyn AsyncRead + Unpin),
    ) -> Result<BackupObjectReceipt, Error> {
        if prepared.connection_id != self.connection.stable_id() || prepared.limits != self.limits {
            return Err(Error::InvalidMessage);
        }
        self.peers
            .authenticate_connection(self.connection, self.clock.now())?;
        let deadline = deadline_at(prepared.request.context.deadline, self.clock.now())?
            .min(prepared.deadline);
        tokio::time::timeout_at(deadline, async {
            bytes::upload(
                &mut prepared.transfer.send,
                source,
                prepared.request.object,
                prepared.transfer.frame_bytes,
                self.limits,
            )
            .await?;
            prepared
                .transfer
                .send
                .finish()
                .map_err(TransportError::from)?;
            match self.complete(prepared.transfer).await? {
                FederatedBackupReceipt::Stored(receipt) => Ok(receipt),
                _ => Err(Error::InvalidMessage),
            }
        })
        .await
        .map_err(|_| timed_out())?
    }
}
