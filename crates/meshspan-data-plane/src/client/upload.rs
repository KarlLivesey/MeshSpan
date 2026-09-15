// SPDX-License-Identifier: GPL-2.0-only

//! Owned admission/persistence/upload boundary for durable native repair attempts.

use meshspan_contracts::{
    BoundedBytes, ContractError, ShardPutIdentity, ShardReceipt, ShardWritePermit,
};
use meshspan_domain::{Clock, UnixMicros};
use meshspan_protocol::{WireLimits, v1::RequestHeader};

use super::{DataPlaneError, ReadyShardUpload, admit_native_upload};

/// Native upload client with an explicit operation clock and bounded connection lifetime.
pub struct ShardUploadClient<'a> {
    connection: &'a quinn::Connection,
    limits: WireLimits,
    clock: &'a dyn Clock,
}

/// Provider admission with no transmitted shard bytes. Persist its identity before finishing.
/// Dropping closes the streams; it does not imply cancellation of the capacity reservation.
pub struct PreparedShardUpload {
    transfer: ReadyShardUpload,
    deadline: tokio::time::Instant,
}

impl PreparedShardUpload {
    /// Original provider identity, including its actual reservation and original request context.
    #[must_use]
    pub const fn identity(&self) -> ShardPutIdentity {
        self.transfer.identity
    }
}

impl<'a> ShardUploadClient<'a> {
    /// Binds an authenticated connection, negotiated limits and the caller's current clock.
    #[must_use]
    pub const fn new(
        connection: &'a quinn::Connection,
        limits: WireLimits,
        clock: &'a dyn Clock,
    ) -> Self {
        Self {
            connection,
            limits,
            clock,
        }
    }

    /// Resolves retained admission under fresh authority without uploading any bytes.
    /// # Errors
    /// Rejects expired requests, altered original identity, corrupt evidence and transport failure.
    pub async fn resolve_upload(
        &self,
        header: RequestHeader,
        original: ShardPutIdentity,
        authority: ShardWritePermit,
    ) -> Result<meshspan_contracts::ShardPutResolution, DataPlaneError> {
        let deadline = deadline_at(
            UnixMicros::new(header.deadline_unix_micros),
            self.clock.now(),
        )?;
        tokio::time::timeout_at(
            deadline,
            crate::put_resolution_client::resolve_shard_put(
                self.connection,
                header,
                original,
                authority,
                self.limits,
            ),
        )
        .await
        .map_err(|_| expired())?
    }

    /// Obtains and validates the provider's reservation without sending shard bytes.
    /// # Errors
    /// Rejects expired requests, contradictory admission, remote rejection and transport failure.
    pub async fn prepare_upload(
        &self,
        header: RequestHeader,
        authority: ShardWritePermit,
        bytes: &BoundedBytes,
    ) -> Result<PreparedShardUpload, DataPlaneError> {
        let deadline = deadline_at(
            UnixMicros::new(header.deadline_unix_micros),
            self.clock.now(),
        )?;
        if header.deadline_unix_micros > authority.expires_at.get() {
            return Err(DataPlaneError::InvalidMessage);
        }
        let transfer = tokio::time::timeout_at(
            deadline,
            admit_native_upload(self.connection, header, authority, bytes, self.limits),
        )
        .await
        .map_err(|_| expired())??;
        Ok(PreparedShardUpload { transfer, deadline })
    }

    /// Sends bytes only after the caller has durably retained the original admission.
    /// # Errors
    /// Rejects changed bytes, connection replacement and elapsed authority. A lost result after
    /// bytes are sent remains unknown and must be resolved using the retained original identity.
    pub async fn finish_upload(
        &self,
        prepared: PreparedShardUpload,
        bytes: &BoundedBytes,
    ) -> Result<ShardReceipt, DataPlaneError> {
        if prepared.transfer.connection_id != self.connection.stable_id()
            || prepared.transfer.limits != self.limits
        {
            return Err(DataPlaneError::InvalidMessage);
        }
        let deadline = deadline_at(prepared.identity().context.deadline, self.clock.now())?
            .min(prepared.deadline);
        tokio::time::timeout_at(deadline, prepared.transfer.finish(bytes))
            .await
            .map_err(|_| expired())?
    }
}

fn deadline_at(at: UnixMicros, now: UnixMicros) -> Result<tokio::time::Instant, DataPlaneError> {
    let micros = at
        .get()
        .checked_sub(now.get())
        .filter(|value| *value > 0)
        .ok_or_else(expired)?;
    let duration = std::time::Duration::from_micros(u64::try_from(micros).map_err(|_| expired())?);
    tokio::time::Instant::now()
        .checked_add(duration)
        .ok_or_else(expired)
}

fn expired() -> DataPlaneError {
    DataPlaneError::Contract(ContractError::DeadlineExceeded)
}
