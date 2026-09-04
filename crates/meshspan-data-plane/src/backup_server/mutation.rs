// SPDX-License-Identifier: GPL-2.0-only

//! Remote backup verification and exact retirement conversations.

use meshspan_contracts::{BackupDeleteReceipt, BackupObjectReceipt, BackupProvider, ContractError};
use meshspan_domain::UnixMicros;
use meshspan_protocol::WireLimits;
use meshspan_protocol::v1::data_control_envelope::Message;
use meshspan_protocol::v1::{
    DataControlEnvelope, DeleteBackupRequest, DeleteBackupResult, VerifyBackupRequest,
    VerifyBackupResult,
};
use meshspan_transport::{AcceptedStream, AuthenticatedPeer, send_data_control};

use super::{RemoteBackupAuthority, RemoteBackupService};
use crate::BackupPlaneError;
use crate::backup_wire::{
    durable_result, rejected_result, wire_delete_receipt, wire_object_receipt,
};

impl<Provider, Authority> RemoteBackupService<Provider, Authority>
where
    Provider: BackupProvider + Send + 'static,
    Authority: RemoteBackupAuthority,
{
    pub(super) async fn serve_verify(
        &self,
        stream: &mut AcceptedStream,
        peer: AuthenticatedPeer,
        limits: WireLimits,
        observed_at: UnixMicros,
        value: VerifyBackupRequest,
    ) -> Result<(), BackupPlaneError> {
        let request = match self.prepare_verify(peer, &value, observed_at) {
            Ok(request) => request,
            Err(error) => return send_verify_result(stream, limits, Err(error)).await,
        };
        let provider = self.provider.clone();
        let result = tokio::task::spawn_blocking(move || {
            provider
                .lock()
                .map_err(|_| ContractError::InternalContract)?
                .verify_exact(&request, observed_at)
        })
        .await
        .map_err(|_| BackupPlaneError::Worker)?;
        send_verify_result(stream, limits, result).await
    }

    pub(super) async fn serve_delete(
        &self,
        stream: &mut AcceptedStream,
        peer: AuthenticatedPeer,
        limits: WireLimits,
        observed_at: UnixMicros,
        value: DeleteBackupRequest,
    ) -> Result<(), BackupPlaneError> {
        let request = match self.prepare_delete(peer, &value, observed_at) {
            Ok(request) => request,
            Err(error) => return send_delete_result(stream, limits, Err(error)).await,
        };
        let provider = self.provider.clone();
        let result = tokio::task::spawn_blocking(move || {
            provider
                .lock()
                .map_err(|_| ContractError::InternalContract)?
                .delete_exact(&request, observed_at)
        })
        .await
        .map_err(|_| BackupPlaneError::Worker)?;
        send_delete_result(stream, limits, result).await
    }
}

async fn send_verify_result(
    stream: &mut AcceptedStream,
    limits: WireLimits,
    result: Result<BackupObjectReceipt, ContractError>,
) -> Result<(), BackupPlaneError> {
    let (result, receipt) = match result {
        Ok(receipt) => (durable_result(), Some(wire_object_receipt(&receipt))),
        Err(error) => (rejected_result(error), None),
    };
    send_data_control(
        &mut stream.send,
        &DataControlEnvelope {
            message: Some(Message::VerifyBackupResult(VerifyBackupResult {
                result: Some(result),
                receipt,
            })),
        },
        limits,
    )
    .await?;
    finish(stream)
}

async fn send_delete_result(
    stream: &mut AcceptedStream,
    limits: WireLimits,
    result: Result<BackupDeleteReceipt, ContractError>,
) -> Result<(), BackupPlaneError> {
    let (result, receipt) = match result {
        Ok(receipt) => (durable_result(), Some(wire_delete_receipt(receipt))),
        Err(error) => (rejected_result(error), None),
    };
    send_data_control(
        &mut stream.send,
        &DataControlEnvelope {
            message: Some(Message::DeleteBackupResult(DeleteBackupResult {
                result: Some(result),
                receipt,
            })),
        },
        limits,
    )
    .await?;
    finish(stream)
}

fn finish(stream: &mut AcceptedStream) -> Result<(), BackupPlaneError> {
    stream
        .send
        .finish()
        .map_err(meshspan_transport::TransportError::from)?;
    Ok(())
}
