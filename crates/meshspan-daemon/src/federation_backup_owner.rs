// SPDX-License-Identifier: GPL-2.0-only

//! Same-swarm backup ingress shares the native provider owner, replay window and bulk budget.

use super::{FederationSessionRuntimeError as Error, FederationSessions};
use meshspan_cluster::{
    FederationBackupOwnerService, FederationBackupOwnerStreamContext, PeerDataStream,
    authorise_forwarded_backup, federation_connection_authority,
};
use meshspan_domain::FederationRelationshipId;
use meshspan_protocol::{ValidatedDataControlEnvelope, v1::data_control_envelope::Message};
use meshspan_transport::FederationPeerRegistry;
use std::sync::{Arc, OnceLock, Weak};

/// Listener-cycle binding; neither the data router nor a stopped cycle owns a second catalogue.
#[derive(Clone, Default)]
pub(crate) struct FederationBackupOwner(Arc<OnceLock<Weak<FederationSessions>>>);

impl FederationBackupOwner {
    pub(crate) fn attach(&self, sessions: &Arc<FederationSessions>) -> Result<(), Error> {
        self.0
            .set(Arc::downgrade(sessions))
            .map_err(|_| Error::Unavailable)
    }

    /// The caller owns this future through completion, including cycle shutdown. The worker
    /// observes the bounded permit deadline; dropping its join handle is not cancellation.
    pub(crate) async fn serve(
        &self,
        stream: PeerDataStream,
        envelope: ValidatedDataControlEnvelope,
    ) -> Result<(), Error> {
        let sessions = self
            .0
            .get()
            .and_then(Weak::upgrade)
            .ok_or(Error::Unavailable)?;
        let permit = Arc::clone(&sessions.backup_admission)
            .try_acquire_owned()
            .map_err(|_| Error::Unavailable)?;
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            sessions.bulk_readers.with_reader(|reader| {
                let now = crate::api_http::current_time().ok_or(Error::Unavailable)?;
                let Some(Message::ForwardFederatedBackupRequest(request)) =
                    envelope.as_inner().message.as_ref()
                else {
                    return Err(Error::Unavailable);
                };
                let original =
                    meshspan_protocol::decode_federation_frame(&request.request, stream.limits)
                        .map_err(meshspan_transport::TransportError::from)?;
                let header = original
                    .as_inner()
                    .header
                    .as_ref()
                    .ok_or(Error::Unavailable)?;
                let relationship = FederationRelationshipId::from_bytes(
                    header
                        .relationship_id
                        .as_slice()
                        .try_into()
                        .map_err(|_| Error::Unavailable)?,
                )
                .map_err(|_| Error::Unavailable)?;
                let current = federation_connection_authority(reader, relationship, now)?
                    .ok_or(Error::Unavailable)?;
                let relay = sessions.replay.authenticate_forwarded_backup_request(
                    &FederationPeerRegistry::new([current.peer])?,
                    stream.peer,
                    &envelope,
                    stream.limits,
                    now,
                )?;
                wait_for_permission_revision(reader, &relay)?;
                let now = crate::api_http::current_time().ok_or(Error::Unavailable)?;
                let admitted = authorise_forwarded_backup(
                    reader,
                    sessions.node,
                    stream.routing_epoch,
                    &relay,
                    now,
                )?;
                let mut provider = sessions
                    .backup_providers
                    .bind(admitted.scope(), admitted.request().object())?;
                let outcome =
                    FederationBackupOwnerService::new(reader, sessions.node, stream.routing_epoch)
                        .execute_stream(
                            &relay,
                            &mut provider,
                            stream.stream,
                            FederationBackupOwnerStreamContext {
                                runtime: &runtime,
                                clock: &crate::OperatingSystemClock,
                                limits: stream.limits,
                            },
                        )
                        .map_err(Into::into);
                #[cfg(test)]
                if outcome.is_ok() {
                    // The real terminal result and FIN precede this pause; physical
                    // provider ownership has already ended before the client sees them.
                    sessions
                        .backup_providers
                        .pause_completed_transfer(admitted.scope(), admitted.request().object())?;
                }
                outcome
            })
        })
        .await
        .map_err(|_| Error::Unavailable)?
    }
}

/// The gateway may know a just-committed permission before this storage replica
/// has applied it. Wait only for the signed provider revisions, never a consumer
/// catalogue revision, and then perform the complete current-authority check.
/// This runs on the already admitted blocking worker without a SQL transaction,
/// provider lock, network polling or another bulk slot. Expiry is not admission.
fn wait_for_permission_revision(
    reader: &meshspan_metadata::AuthoritativeRepository,
    relay: &meshspan_transport::AuthenticatedFederationBackupRelay,
) -> Result<(), Error> {
    let meshspan_protocol::v1::federation_envelope::Message::ExecuteBackup(execution) =
        relay.consumer().message()
    else {
        return Err(Error::Unavailable);
    };
    let permit = execution.permit.as_ref().ok_or(Error::Unavailable)?;
    let scope = permit.scope.as_ref().ok_or(Error::Unavailable)?;
    let revision = scope.grant_revision.max(scope.allocation_revision);
    let expires = relay
        .forwarded()
        .header
        .as_ref()
        .ok_or(Error::Unavailable)?
        .deadline_unix_micros
        .min(permit.expires_at_unix_micros);
    let now = crate::api_http::current_time().ok_or(Error::Unavailable)?;
    let remaining = expires
        .checked_sub(now.get())
        .and_then(|micros| u64::try_from(micros).ok())
        .filter(|micros| *micros > 0)
        .ok_or(Error::Unavailable)?;
    let deadline = std::time::Instant::now()
        .checked_add(std::time::Duration::from_micros(remaining))
        .ok_or(Error::Unavailable)?;
    let mut delay = std::time::Duration::from_millis(10);
    loop {
        if std::time::Instant::now() >= deadline {
            return Err(Error::Unavailable);
        }
        if reader
            .current_revision()
            .map_err(|_| Error::Unavailable)?
            .get()
            >= revision
        {
            return Ok(());
        }
        std::thread::sleep(
            delay.min(deadline.saturating_duration_since(std::time::Instant::now())),
        );
        delay = (delay * 2).min(std::time::Duration::from_millis(100));
    }
}
