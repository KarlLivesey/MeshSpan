// SPDX-License-Identifier: GPL-2.0-only

//! Bounded remote metadata-backup store conversation.

use meshspan_contracts::{BackupObjectReceipt, BackupProvider, ContractError};
use meshspan_domain::UnixMicros;
use meshspan_protocol::WireLimits;
use meshspan_protocol::v1::data_control_envelope::Message;
use meshspan_protocol::v1::{
    DataControlEnvelope, StoreBackupBegin, StoreBackupReady, StoreBackupResult,
};
use meshspan_transport::{
    AcceptedStream, AuthenticatedPeer, receive_data_control, receive_data_frame, send_data_control,
};
use sha2::{Digest, Sha256};

use super::{OwnedRemoteBackupAuthorisation, RemoteBackupAuthority, RemoteBackupService};
use crate::BackupPlaneError;
use crate::backup_bridge::ProviderReader;
use crate::backup_wire::{durable_result, rejected_result, wire_error, wire_object_receipt};

const PROVIDER_CHANNEL_FRAMES: usize = 2;

impl<Provider, Authority> RemoteBackupService<Provider, Authority>
where
    Provider: BackupProvider + Send + 'static,
    Authority: RemoteBackupAuthority + Clone + Send + 'static,
{
    pub(super) async fn serve_store(
        &self,
        stream: &mut AcceptedStream,
        peer: AuthenticatedPeer,
        limits: WireLimits,
        observed_at: UnixMicros,
        begin: StoreBackupBegin,
    ) -> Result<(), BackupPlaneError> {
        let request = match self.prepare_store(peer, &begin, observed_at) {
            Ok(request) => request,
            Err(error) => return reject_store(stream, limits, error).await,
        };
        if let Err(error) = self
            .authorise(
                peer,
                OwnedRemoteBackupAuthorisation::Store(request),
                observed_at,
            )
            .await
        {
            return reject_store(stream, limits, error).await;
        }
        send_store_ready(stream, limits, &begin).await?;
        let (sender, receiver) = tokio::sync::mpsc::channel(PROVIDER_CHANNEL_FRAMES);
        let provider = self.provider.clone();
        let worker = tokio::task::spawn_blocking(move || {
            let mut source = ProviderReader::new(receiver);
            provider
                .lock()
                .map_err(|_| ContractError::InternalContract)?
                .store_exact(request, &mut source, observed_at)
        });
        let transfer = receive_exact_source(stream, limits, &begin, sender).await;
        let provider_result = worker.await.map_err(|_| BackupPlaneError::Worker)?;
        transfer?;
        send_store_result(stream, limits, provider_result).await
    }
}

async fn send_store_ready(
    stream: &mut AcceptedStream,
    limits: WireLimits,
    begin: &StoreBackupBegin,
) -> Result<(), BackupPlaneError> {
    let reservation = begin
        .header
        .as_ref()
        .ok_or(BackupPlaneError::InvalidMessage)?
        .request_id
        .clone();
    send_data_control(
        &mut stream.send,
        &DataControlEnvelope {
            message: Some(Message::StoreBackupReady(StoreBackupReady {
                reservation,
                maximum_frame_bytes: limits.maximum_data_frame_bytes() as u64,
                rejection: None,
            })),
        },
        limits,
    )
    .await?;
    Ok(())
}

async fn receive_exact_source(
    stream: &mut AcceptedStream,
    limits: WireLimits,
    begin: &StoreBackupBegin,
    sender: tokio::sync::mpsc::Sender<Vec<u8>>,
) -> Result<(), BackupPlaneError> {
    let mut received = 0_u64;
    let mut digest = Sha256::new();
    let mut provider_open = true;
    while received < required_length(begin)? {
        let frame = receive_data_frame(&mut stream.receive, limits)
            .await?
            .into_inner();
        if frame.offset != received {
            return Err(BackupPlaneError::InvalidMessage);
        }
        received = received
            .checked_add(frame.bytes.len() as u64)
            .ok_or(BackupPlaneError::InvalidMessage)?;
        if received > required_length(begin)? {
            return Err(BackupPlaneError::InvalidMessage);
        }
        digest.update(&frame.bytes);
        if provider_open && sender.send(frame.bytes).await.is_err() {
            provider_open = false;
        }
    }
    drop(sender);
    let finish = receive_data_control(&mut stream.receive, limits)
        .await?
        .into_inner();
    let Message::StoreBackupFinish(finish) =
        finish.message.ok_or(BackupPlaneError::InvalidMessage)?
    else {
        return Err(BackupPlaneError::InvalidMessage);
    };
    let actual_digest: [u8; 32] = digest.finalize().into();
    let expected_digest = required_digest(begin)?;
    if finish.final_length != received
        || finish.final_digest.as_slice() != actual_digest
        || received != required_length(begin)?
        || actual_digest != expected_digest
    {
        Err(BackupPlaneError::InvalidMessage)
    } else {
        Ok(())
    }
}

fn required_length(begin: &StoreBackupBegin) -> Result<u64, BackupPlaneError> {
    Ok(begin
        .object
        .as_ref()
        .ok_or(BackupPlaneError::InvalidMessage)?
        .byte_length)
}

fn required_digest(begin: &StoreBackupBegin) -> Result<[u8; 32], BackupPlaneError> {
    begin
        .object
        .as_ref()
        .ok_or(BackupPlaneError::InvalidMessage)?
        .digest
        .as_slice()
        .try_into()
        .map_err(|_| BackupPlaneError::InvalidMessage)
}

async fn reject_store(
    stream: &mut AcceptedStream,
    limits: WireLimits,
    error: ContractError,
) -> Result<(), BackupPlaneError> {
    send_data_control(
        &mut stream.send,
        &DataControlEnvelope {
            message: Some(Message::StoreBackupReady(StoreBackupReady {
                reservation: Vec::new(),
                maximum_frame_bytes: 0,
                rejection: Some(wire_error(error)),
            })),
        },
        limits,
    )
    .await?;
    finish(stream)
}

async fn send_store_result(
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
            message: Some(Message::StoreBackupResult(StoreBackupResult {
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
