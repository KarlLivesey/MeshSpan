// SPDX-License-Identifier: GPL-2.0-only

//! Authenticated catalogue-only receipt recovery, independent of object-byte verification.

use super::{OwnedRemoteBackupAuthorisation, RemoteBackupAuthority, RemoteBackupService};
use crate::BackupPlaneError;
use crate::backup_wire::{durable_result, rejected_result, wire_object_receipt};
use meshspan_contracts::{BackupProvider, ContractError};
use meshspan_domain::UnixMicros;
use meshspan_protocol::{
    WireLimits,
    v1::{
        DataControlEnvelope, LookupBackupRequest, LookupBackupResult,
        data_control_envelope::Message,
    },
};
use meshspan_transport::{AcceptedStream, AuthenticatedPeer, send_data_control};

impl<Provider, Authority> RemoteBackupService<Provider, Authority>
where
    Provider: BackupProvider + Send + 'static,
    Authority: RemoteBackupAuthority + Clone + Send + 'static,
{
    pub(super) async fn serve_lookup(
        &self,
        stream: &mut AcceptedStream,
        peer: AuthenticatedPeer,
        limits: WireLimits,
        observed_at: UnixMicros,
        value: LookupBackupRequest,
    ) -> Result<(), BackupPlaneError> {
        let result = self.lookup(peer, value, observed_at).await;
        let (result, receipt) = match result {
            Ok(receipt) => (durable_result(), Some(wire_object_receipt(&receipt))),
            Err(error) => (rejected_result(error), None),
        };
        send_data_control(
            &mut stream.send,
            &DataControlEnvelope {
                message: Some(Message::LookupBackupResult(LookupBackupResult {
                    result: Some(result),
                    receipt,
                })),
            },
            limits,
        )
        .await?;
        stream
            .send
            .finish()
            .map_err(meshspan_transport::TransportError::from)?;
        Ok(())
    }

    async fn lookup(
        &self,
        peer: AuthenticatedPeer,
        value: LookupBackupRequest,
        observed_at: UnixMicros,
    ) -> Result<meshspan_contracts::BackupObjectReceipt, ContractError> {
        let request = self.prepare_lookup(peer, &value, observed_at)?;
        self.authorise(
            peer,
            OwnedRemoteBackupAuthorisation::Lookup(request),
            observed_at,
        )
        .await?;
        let provider = self.provider.clone();
        tokio::task::spawn_blocking(move || {
            provider
                .lock()
                .map_err(|_| ContractError::InternalContract)?
                .lookup_exact(&request, observed_at)
        })
        .await
        .map_err(|_| ContractError::InternalContract)?
    }
}
