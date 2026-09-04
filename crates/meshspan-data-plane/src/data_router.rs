// SPDX-License-Identifier: GPL-2.0-only

//! Single-read dispatch across every private data-stream protocol family.

use meshspan_contracts::{BackupProvider, StorageProvider};
use meshspan_domain::UnixMicros;
use meshspan_protocol::WireLimits;
use meshspan_protocol::v1::data_control_envelope::Message;
use meshspan_transport::{AcceptedStream, AuthenticatedPeer, StreamKind, receive_data_control};
use thiserror::Error;

use crate::{
    BackupPlaneError, DataPlaneError, RemoteBackupAuthority, RemoteBackupRouter, RemoteShardRouter,
};

/// One bounded dispatcher which consumes the first envelope exactly once.
pub struct RemoteDataRouter<ShardProvider, BackupProviderImpl, Authority> {
    shards: Option<RemoteShardRouter<ShardProvider>>,
    backups: Option<RemoteBackupRouter<BackupProviderImpl, Authority>>,
}

impl<ShardProvider, BackupProviderImpl, Authority>
    RemoteDataRouter<ShardProvider, BackupProviderImpl, Authority>
where
    ShardProvider: StorageProvider,
    BackupProviderImpl: BackupProvider + Send + 'static,
    Authority: RemoteBackupAuthority + Clone + Send + 'static,
{
    /// Composes available protocol families while requiring at least one live route.
    ///
    /// # Errors
    ///
    /// Rejects an empty daemon data plane.
    pub fn new(
        shards: Option<RemoteShardRouter<ShardProvider>>,
        backups: Option<RemoteBackupRouter<BackupProviderImpl, Authority>>,
    ) -> Result<Self, RemoteDataRouterError> {
        if shards.is_none() && backups.is_none() {
            Err(RemoteDataRouterError::InvalidConfiguration)
        } else {
            Ok(Self { shards, backups })
        }
    }

    /// Routes one authenticated data stream without speculative parsing or broadcast.
    ///
    /// # Errors
    ///
    /// Rejects malformed, unsupported or unavailable protocol routes before provider IO.
    pub async fn serve_stream(
        &mut self,
        mut stream: AcceptedStream,
        peer: AuthenticatedPeer,
        limits: WireLimits,
        observed_at: UnixMicros,
    ) -> Result<(), RemoteDataRouterError> {
        if stream.kind != StreamKind::Data {
            return Err(RemoteDataRouterError::InvalidMessage);
        }
        let envelope = receive_data_control(&mut stream.receive, limits)
            .await?
            .into_inner();
        let message = envelope
            .message
            .ok_or(RemoteDataRouterError::InvalidMessage)?;
        match family(&message)? {
            DataFamily::Shard => self
                .shards
                .as_mut()
                .ok_or(RemoteDataRouterError::Unavailable)?
                .serve_message(stream, peer, limits, observed_at, message)
                .await
                .map_err(Into::into),
            DataFamily::Backup => self
                .backups
                .as_ref()
                .ok_or(RemoteDataRouterError::Unavailable)?
                .serve_message(stream, peer, limits, observed_at, message)
                .await
                .map_err(Into::into),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DataFamily {
    Shard,
    Backup,
}

fn family(message: &Message) -> Result<DataFamily, RemoteDataRouterError> {
    match message {
        Message::PutShardBegin(_)
        | Message::GetShardRequest(_)
        | Message::DeleteShardRequest(_)
        | Message::ReclaimShardRequest(_) => Ok(DataFamily::Shard),
        Message::StoreBackupBegin(_)
        | Message::ReadBackupRequest(_)
        | Message::VerifyBackupRequest(_)
        | Message::DeleteBackupRequest(_) => Ok(DataFamily::Backup),
        _ => Err(RemoteDataRouterError::InvalidMessage),
    }
}

/// Stable top-level failure from one private data-stream dispatch.
#[derive(Debug, Error)]
pub enum RemoteDataRouterError {
    /// No protocol family was configured.
    #[error("private data router configuration is invalid")]
    InvalidConfiguration,
    /// The first message does not identify a supported request family.
    #[error("private data stream request is invalid")]
    InvalidMessage,
    /// The requested family has no live local route.
    #[error("private data stream route is unavailable")]
    Unavailable,
    /// Shard protocol handling failed.
    #[error("private shard stream failed")]
    Shard(#[from] DataPlaneError),
    /// Backup protocol handling failed.
    #[error("private backup stream failed")]
    Backup(#[from] BackupPlaneError),
    /// Initial authenticated framing failed.
    #[error("private data stream framing failed")]
    Transport(#[from] meshspan_transport::TransportError),
}

#[cfg(test)]
mod tests {
    use meshspan_protocol::v1::data_control_envelope::Message;
    use meshspan_protocol::v1::{GetShardRequest, StoreBackupBegin, StoreBackupFinish};

    use super::{DataFamily, family};

    #[test]
    fn request_family_is_closed_and_unambiguous() {
        assert_eq!(
            family(&Message::GetShardRequest(GetShardRequest::default())).ok(),
            Some(DataFamily::Shard)
        );
        assert_eq!(
            family(&Message::StoreBackupBegin(StoreBackupBegin::default())).ok(),
            Some(DataFamily::Backup)
        );
        assert!(family(&Message::StoreBackupFinish(StoreBackupFinish::default())).is_err());
    }
}
