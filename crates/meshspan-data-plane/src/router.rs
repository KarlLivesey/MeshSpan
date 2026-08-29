// SPDX-License-Identifier: GPL-2.0-only

//! Bounded routing from one daemon data connection to several folder-provider targets.

use std::collections::BTreeMap;

use meshspan_contracts::StorageProvider;
use meshspan_domain::{TargetId, UnixMicros};
use meshspan_protocol::WireLimits;
use meshspan_protocol::v1::data_control_envelope::Message;
use meshspan_transport::{AcceptedStream, StreamKind, receive_data_control};

use crate::{DataPlaneError, RemoteShardService};

/// One daemon-local, target-incarnation-exact router for multiple storage providers.
pub struct RemoteShardRouter<Provider> {
    services: BTreeMap<(TargetId, u64), RemoteShardService<Provider>>,
}

impl<Provider: StorageProvider> RemoteShardRouter<Provider> {
    /// Builds a bounded router and rejects duplicate target incarnations.
    ///
    /// # Errors
    ///
    /// Rejects an empty service set, a zero bound, excess services or duplicate routes.
    pub fn new(
        services: impl IntoIterator<Item = RemoteShardService<Provider>>,
        maximum_targets: usize,
    ) -> Result<Self, DataPlaneError> {
        if maximum_targets == 0 {
            return Err(DataPlaneError::InvalidConfiguration);
        }
        let mut routes = BTreeMap::new();
        for service in services.into_iter().take(maximum_targets.saturating_add(1)) {
            if routes.len() == maximum_targets || routes.insert(service.route(), service).is_some()
            {
                return Err(DataPlaneError::InvalidConfiguration);
            }
        }
        if routes.is_empty() {
            Err(DataPlaneError::InvalidConfiguration)
        } else {
            Ok(Self { services: routes })
        }
    }

    /// Routes and serves exactly one authenticated data stream by explicit target incarnation.
    ///
    /// # Errors
    ///
    /// Rejects malformed, unknown or stale target routes before invoking any provider.
    pub async fn serve_stream(
        &mut self,
        mut stream: AcceptedStream,
        limits: WireLimits,
        observed_at: UnixMicros,
    ) -> Result<(), DataPlaneError> {
        if stream.kind != StreamKind::Data {
            return Err(DataPlaneError::InvalidMessage);
        }
        let envelope = receive_data_control(&mut stream.receive, limits)
            .await?
            .into_inner();
        let message = envelope.message.ok_or(DataPlaneError::InvalidMessage)?;
        let route = message_route(&message)?;
        let service = self
            .services
            .get_mut(&route)
            .ok_or(DataPlaneError::InvalidMessage)?;
        service
            .serve_message(stream, limits, observed_at, message)
            .await
    }

    /// Number of independently fenced storage targets available through this router.
    #[must_use]
    pub fn target_count(&self) -> usize {
        self.services.len()
    }
}

fn message_route(message: &Message) -> Result<(TargetId, u64), DataPlaneError> {
    let (bytes, generation) = match message {
        Message::PutShardBegin(value) => (&value.target_id, value.target_generation),
        Message::GetShardRequest(value) => (&value.target_id, value.target_generation),
        Message::DeleteShardRequest(value) => (&value.target_id, value.target_generation),
        Message::ReclaimShardRequest(value) => (&value.target_id, value.target_generation),
        _ => return Err(DataPlaneError::InvalidMessage),
    };
    if generation == 0 {
        return Err(DataPlaneError::InvalidMessage);
    }
    let identifier: [u8; 16] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| DataPlaneError::InvalidMessage)?;
    let target = TargetId::from_bytes(identifier).map_err(|_| DataPlaneError::InvalidMessage)?;
    Ok((target, generation))
}
