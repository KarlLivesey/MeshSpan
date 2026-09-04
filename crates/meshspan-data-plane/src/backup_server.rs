// SPDX-License-Identifier: GPL-2.0-only

//! Provider-neutral server for authenticated remote metadata-backup streams.

mod mutation;
mod preparation;
mod read;
mod store;

use std::sync::{Arc, Mutex};

use meshspan_contracts::{
    BackupDeleteRequest, BackupProvider, BackupReadRequest, BackupStoreRequest,
    BackupVerifyRequest, ContractError,
};
use meshspan_domain::{BackupDestinationId, MeshId, UnixMicros};
use meshspan_protocol::WireLimits;
use meshspan_protocol::v1::data_control_envelope::Message;
use meshspan_transport::{AcceptedStream, AuthenticatedPeer, StreamKind, receive_data_control};

use crate::BackupPlaneError;

/// Exact provider operation presented to current replicated backup authority.
#[derive(Clone, Copy, Debug)]
pub enum RemoteBackupAuthorisation<'a> {
    /// Persist one exact encrypted generation.
    Store(&'a BackupStoreRequest),
    /// Read one exact encrypted generation.
    Read(&'a BackupReadRequest),
    /// Verify one exact encrypted generation without returning bytes.
    Verify(&'a BackupVerifyRequest),
    /// Delete one exact retired encrypted generation.
    Delete(&'a BackupDeleteRequest),
}

/// Current metadata authority required before remote backup-provider IO.
pub trait RemoteBackupAuthority {
    /// Revalidates the authenticated worker, exact destination and current revision.
    ///
    /// # Errors
    ///
    /// Rejects an inactive destination, stale worker claim, revision mismatch or operation that
    /// current replicated metadata does not authorise.
    fn authorise(
        &self,
        peer: AuthenticatedPeer,
        request: RemoteBackupAuthorisation<'_>,
        observed_at: UnixMicros,
    ) -> Result<(), ContractError>;
}

/// One exact destination-generation adapter over any conforming backup provider.
pub struct RemoteBackupService<Provider, Authority> {
    pub(super) provider: Arc<Mutex<Provider>>,
    pub(super) authority: Authority,
    pub(super) mesh_id: MeshId,
    pub(super) destination_id: BackupDestinationId,
    pub(super) provider_generation: u64,
}

impl<Provider, Authority> Clone for RemoteBackupService<Provider, Authority>
where
    Authority: Clone,
{
    fn clone(&self) -> Self {
        Self {
            provider: Arc::clone(&self.provider),
            authority: self.authority.clone(),
            mesh_id: self.mesh_id,
            destination_id: self.destination_id,
            provider_generation: self.provider_generation,
        }
    }
}

enum OwnedRemoteBackupAuthorisation {
    Store(BackupStoreRequest),
    Read(BackupReadRequest),
    Verify(BackupVerifyRequest),
    Delete(BackupDeleteRequest),
}

impl<Provider, Authority> RemoteBackupService<Provider, Authority>
where
    Provider: BackupProvider + Send + 'static,
    Authority: RemoteBackupAuthority + Clone + Send + 'static,
{
    /// Binds a provider and authority to one exact destination incarnation.
    ///
    /// # Errors
    ///
    /// Rejects a zero provider generation.
    pub fn new(
        provider: Provider,
        authority: Authority,
        mesh_id: MeshId,
        destination_id: BackupDestinationId,
        provider_generation: u64,
    ) -> Result<Self, BackupPlaneError> {
        if provider_generation == 0 {
            return Err(BackupPlaneError::InvalidConfiguration);
        }
        Ok(Self {
            provider: Arc::new(Mutex::new(provider)),
            authority,
            mesh_id,
            destination_id,
            provider_generation,
        })
    }

    /// Serves one already-mTLS-authenticated backup-provider stream.
    ///
    /// # Errors
    ///
    /// Rejects the wrong stream class, malformed sequence, sender substitution, stale authority,
    /// transport failure or a provider worker failure.
    pub async fn serve_stream(
        &self,
        mut stream: AcceptedStream,
        peer: AuthenticatedPeer,
        limits: WireLimits,
        observed_at: UnixMicros,
    ) -> Result<(), BackupPlaneError> {
        if stream.kind != StreamKind::Data {
            return Err(BackupPlaneError::InvalidMessage);
        }
        let envelope = receive_data_control(&mut stream.receive, limits)
            .await?
            .into_inner();
        self.serve_message(
            stream,
            peer,
            limits,
            observed_at,
            envelope.message.ok_or(BackupPlaneError::InvalidMessage)?,
        )
        .await
    }

    pub(crate) const fn route(&self) -> (BackupDestinationId, u64) {
        (self.destination_id, self.provider_generation)
    }

    pub(crate) async fn serve_message(
        &self,
        mut stream: AcceptedStream,
        peer: AuthenticatedPeer,
        limits: WireLimits,
        observed_at: UnixMicros,
        message: Message,
    ) -> Result<(), BackupPlaneError> {
        match message {
            Message::StoreBackupBegin(value) => {
                self.serve_store(&mut stream, peer, limits, observed_at, value)
                    .await
            }
            Message::ReadBackupRequest(value) => {
                self.serve_read(&mut stream, peer, limits, observed_at, value)
                    .await
            }
            Message::VerifyBackupRequest(value) => {
                self.serve_verify(&mut stream, peer, limits, observed_at, value)
                    .await
            }
            Message::DeleteBackupRequest(value) => {
                self.serve_delete(&mut stream, peer, limits, observed_at, value)
                    .await
            }
            _ => Err(BackupPlaneError::InvalidMessage),
        }
    }

    async fn authorise(
        &self,
        peer: AuthenticatedPeer,
        request: OwnedRemoteBackupAuthorisation,
        observed_at: UnixMicros,
    ) -> Result<(), ContractError> {
        let authority = self.authority.clone();
        tokio::task::spawn_blocking(move || {
            let borrowed = match &request {
                OwnedRemoteBackupAuthorisation::Store(value) => {
                    RemoteBackupAuthorisation::Store(value)
                }
                OwnedRemoteBackupAuthorisation::Read(value) => {
                    RemoteBackupAuthorisation::Read(value)
                }
                OwnedRemoteBackupAuthorisation::Verify(value) => {
                    RemoteBackupAuthorisation::Verify(value)
                }
                OwnedRemoteBackupAuthorisation::Delete(value) => {
                    RemoteBackupAuthorisation::Delete(value)
                }
            };
            authority.authorise(peer, borrowed, observed_at)
        })
        .await
        .map_err(|_| ContractError::InternalContract)?
    }
}
