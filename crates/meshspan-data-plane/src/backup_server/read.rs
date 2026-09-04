// SPDX-License-Identifier: GPL-2.0-only

//! Bounded remote metadata-backup read conversation.

use meshspan_contracts::{BackupProvider, BackupReadReceipt, ContractError};
use meshspan_domain::UnixMicros;
use meshspan_protocol::WireLimits;
use meshspan_protocol::v1::data_control_envelope::Message;
use meshspan_protocol::v1::{
    DataControlEnvelope, DataFrame, ReadBackupHeader, ReadBackupRequest, ReadBackupResult,
};
use meshspan_transport::{AcceptedStream, AuthenticatedPeer, send_data_control, send_data_frame};
use sha2::{Digest, Sha256};

use super::{OwnedRemoteBackupAuthorisation, RemoteBackupAuthority, RemoteBackupService};
use crate::BackupPlaneError;
use crate::backup_bridge::ProviderWriter;
use crate::backup_wire::{durable_result, rejected_result, wire_error, wire_read_receipt};

const PROVIDER_CHANNEL_FRAMES: usize = 2;

impl<Provider, Authority> RemoteBackupService<Provider, Authority>
where
    Provider: BackupProvider + Send + 'static,
    Authority: RemoteBackupAuthority + Clone + Send + 'static,
{
    pub(super) async fn serve_read(
        &self,
        stream: &mut AcceptedStream,
        peer: AuthenticatedPeer,
        limits: WireLimits,
        observed_at: UnixMicros,
        value: ReadBackupRequest,
    ) -> Result<(), BackupPlaneError> {
        let request = match self.prepare_read(peer, &value, observed_at) {
            Ok(request) => request,
            Err(error) => return reject_read(stream, limits, error).await,
        };
        if let Err(error) = self
            .authorise(
                peer,
                OwnedRemoteBackupAuthorisation::Read(request.clone()),
                observed_at,
            )
            .await
        {
            return reject_read(stream, limits, error).await;
        }
        let expected = request.object;
        let (chunk_sender, mut chunk_receiver) =
            tokio::sync::mpsc::channel(PROVIDER_CHANNEL_FRAMES);
        let (result_sender, result_receiver) = tokio::sync::oneshot::channel();
        let provider = self.provider.clone();
        tokio::task::spawn_blocking(move || {
            let mut destination =
                ProviderWriter::new(chunk_sender, limits.maximum_data_frame_bytes());
            let result = provider
                .lock()
                .map_err(|_| ContractError::InternalContract)
                .and_then(|provider| provider.read_exact(&request, &mut destination, observed_at));
            let _ignored = result_sender.send(result);
        });

        let Some(first) = chunk_receiver.recv().await else {
            let error = result_receiver
                .await
                .map_err(|_| BackupPlaneError::Worker)?
                .err()
                .unwrap_or(ContractError::InternalContract);
            return reject_read(stream, limits, error).await;
        };
        send_read_header(stream, limits, expected).await?;
        let mut transfer = ReadTransfer::new(expected);
        transfer.send(stream, limits, first).await?;
        while let Some(chunk) = chunk_receiver.recv().await {
            transfer.send(stream, limits, chunk).await?;
        }
        let provider_result = result_receiver
            .await
            .map_err(|_| BackupPlaneError::Worker)?;
        let result = transfer.validate(provider_result);
        send_read_result(stream, limits, result).await
    }
}

struct ReadTransfer {
    expected: meshspan_contracts::BackupObjectIdentity,
    sent: u64,
    digest: Sha256,
}

impl ReadTransfer {
    fn new(expected: meshspan_contracts::BackupObjectIdentity) -> Self {
        Self {
            expected,
            sent: 0,
            digest: Sha256::new(),
        }
    }

    async fn send(
        &mut self,
        stream: &mut AcceptedStream,
        limits: WireLimits,
        bytes: Vec<u8>,
    ) -> Result<(), BackupPlaneError> {
        let new_length = self
            .sent
            .checked_add(bytes.len() as u64)
            .ok_or(BackupPlaneError::InvalidMessage)?;
        if bytes.is_empty() || new_length > self.expected.byte_length {
            return Err(BackupPlaneError::InvalidMessage);
        }
        send_data_frame(
            &mut stream.send,
            &DataFrame {
                offset: self.sent,
                bytes: bytes.clone(),
            },
            limits,
        )
        .await?;
        self.digest.update(bytes);
        self.sent = new_length;
        Ok(())
    }

    fn validate(
        self,
        result: Result<BackupReadReceipt, ContractError>,
    ) -> Result<BackupReadReceipt, ContractError> {
        let receipt = result?;
        let digest: [u8; 32] = self.digest.finalize().into();
        if self.sent == self.expected.byte_length
            && digest == self.expected.digest
            && receipt.byte_length == self.expected.byte_length
            && receipt.digest == self.expected.digest
        {
            Ok(receipt)
        } else {
            Err(ContractError::InternalContract)
        }
    }
}

async fn send_read_header(
    stream: &mut AcceptedStream,
    limits: WireLimits,
    object: meshspan_contracts::BackupObjectIdentity,
) -> Result<(), BackupPlaneError> {
    send_data_control(
        &mut stream.send,
        &DataControlEnvelope {
            message: Some(Message::ReadBackupHeader(ReadBackupHeader {
                byte_length: object.byte_length,
                digest: object.digest.to_vec(),
                maximum_frame_bytes: limits.maximum_data_frame_bytes() as u64,
                rejection: None,
            })),
        },
        limits,
    )
    .await?;
    Ok(())
}

async fn reject_read(
    stream: &mut AcceptedStream,
    limits: WireLimits,
    error: ContractError,
) -> Result<(), BackupPlaneError> {
    send_data_control(
        &mut stream.send,
        &DataControlEnvelope {
            message: Some(Message::ReadBackupHeader(ReadBackupHeader {
                byte_length: 0,
                digest: Vec::new(),
                maximum_frame_bytes: 0,
                rejection: Some(wire_error(error)),
            })),
        },
        limits,
    )
    .await?;
    finish(stream)
}

async fn send_read_result(
    stream: &mut AcceptedStream,
    limits: WireLimits,
    result: Result<BackupReadReceipt, ContractError>,
) -> Result<(), BackupPlaneError> {
    let (result, receipt) = match result {
        Ok(receipt) => (durable_result(), Some(wire_read_receipt(receipt))),
        Err(error) => (rejected_result(error), None),
    };
    send_data_control(
        &mut stream.send,
        &DataControlEnvelope {
            message: Some(Message::ReadBackupResult(ReadBackupResult {
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
