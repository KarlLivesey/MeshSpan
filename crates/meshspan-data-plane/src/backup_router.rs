// SPDX-License-Identifier: GPL-2.0-only

//! Bounded exact routing across daemon-local remote backup-provider services.

use std::collections::BTreeMap;

use meshspan_contracts::BackupProvider;
use meshspan_domain::{BackupDestinationId, UnixMicros};
use meshspan_protocol::WireLimits;
use meshspan_protocol::v1::data_control_envelope::Message;
use meshspan_transport::{AcceptedStream, AuthenticatedPeer, StreamKind, receive_data_control};

use crate::{BackupPlaneError, RemoteBackupAuthority, RemoteBackupService};

/// Target-generation router for a bounded set of local backup providers.
pub struct RemoteBackupRouter<Provider, Authority> {
    services: BTreeMap<(BackupDestinationId, u64), RemoteBackupService<Provider, Authority>>,
}

impl<Provider, Authority> Clone for RemoteBackupRouter<Provider, Authority>
where
    Authority: Clone,
{
    fn clone(&self) -> Self {
        Self {
            services: self.services.clone(),
        }
    }
}

impl<Provider, Authority> RemoteBackupRouter<Provider, Authority>
where
    Provider: BackupProvider + Send + 'static,
    Authority: RemoteBackupAuthority + Clone + Send + 'static,
{
    /// Builds a bounded router and rejects empty, excessive or duplicate route sets.
    ///
    /// # Errors
    ///
    /// Rejects a zero bound, no services, excess services or duplicate destination generations.
    pub fn new(
        services: impl IntoIterator<Item = RemoteBackupService<Provider, Authority>>,
        maximum_destinations: usize,
    ) -> Result<Self, BackupPlaneError> {
        if maximum_destinations == 0 {
            return Err(BackupPlaneError::InvalidConfiguration);
        }
        let mut routes = BTreeMap::new();
        for service in services
            .into_iter()
            .take(maximum_destinations.saturating_add(1))
        {
            if routes.len() == maximum_destinations
                || routes.insert(service.route(), service).is_some()
            {
                return Err(BackupPlaneError::InvalidConfiguration);
            }
        }
        if routes.is_empty() {
            Err(BackupPlaneError::InvalidConfiguration)
        } else {
            Ok(Self { services: routes })
        }
    }

    /// Routes one authenticated stream by exact destination identity and generation.
    ///
    /// # Errors
    ///
    /// Rejects malformed, unknown or stale routes before provider or authority IO.
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
        let message = envelope.message.ok_or(BackupPlaneError::InvalidMessage)?;
        self.serve_message(stream, peer, limits, observed_at, message)
            .await
    }

    pub(crate) async fn serve_message(
        &self,
        stream: AcceptedStream,
        peer: AuthenticatedPeer,
        limits: WireLimits,
        observed_at: UnixMicros,
        message: Message,
    ) -> Result<(), BackupPlaneError> {
        let route = message_route(&message)?;
        self.services
            .get(&route)
            .ok_or(BackupPlaneError::InvalidMessage)?
            .serve_message(stream, peer, limits, observed_at, message)
            .await
    }

    /// Number of independently fenced provider generations exposed by this router.
    #[must_use]
    pub fn destination_count(&self) -> usize {
        self.services.len()
    }
}

fn message_route(message: &Message) -> Result<(BackupDestinationId, u64), BackupPlaneError> {
    let object = match message {
        Message::StoreBackupBegin(value) => value.object.as_ref(),
        Message::ReadBackupRequest(value) => value.object.as_ref(),
        Message::VerifyBackupRequest(value) => value.object.as_ref(),
        Message::DeleteBackupRequest(value) => value.object.as_ref(),
        _ => return Err(BackupPlaneError::InvalidMessage),
    }
    .ok_or(BackupPlaneError::InvalidMessage)?;
    if object.provider_generation == 0 {
        return Err(BackupPlaneError::InvalidMessage);
    }
    let identifier: [u8; 16] = object
        .destination_id
        .as_slice()
        .try_into()
        .map_err(|_| BackupPlaneError::InvalidMessage)?;
    let destination = BackupDestinationId::from_bytes(identifier)
        .map_err(|_| BackupPlaneError::InvalidMessage)?;
    Ok((destination, object.provider_generation))
}
