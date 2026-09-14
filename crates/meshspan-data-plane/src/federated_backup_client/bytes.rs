// SPDX-License-Identifier: GPL-2.0-only

//! Exact encrypted byte transfer; memory depends on negotiated frames, never object size.

use crate::BackupPlaneError as Error;
use meshspan_contracts::BackupObjectIdentity;
use meshspan_protocol::{WireLimits, v1::DataFrame};
use meshspan_transport::{receive_data_frame, send_data_frame};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(super) async fn upload(
    send: &mut quinn::SendStream,
    source: &mut (dyn AsyncRead + Unpin),
    object: BackupObjectIdentity,
    frame_bytes: usize,
    limits: WireLimits,
) -> Result<(), Error> {
    let mut buffer = vec![0; frame_bytes];
    let mut offset = 0_u64;
    let mut digest = Sha256::new();
    while offset < object.byte_length {
        let remaining = usize::try_from(object.byte_length - offset)
            .unwrap_or(usize::MAX)
            .min(frame_bytes);
        let read = source.read(&mut buffer[..remaining]).await?;
        if read == 0 {
            return Err(Error::InvalidMessage);
        }
        digest.update(&buffer[..read]);
        send_data_frame(
            send,
            &DataFrame {
                offset,
                bytes: buffer[..read].to_vec(),
            },
            limits,
        )
        .await?;
        offset = offset
            .checked_add(read as u64)
            .ok_or(Error::InvalidMessage)?;
    }
    let mut excess = [0; 1];
    let measured: [u8; 32] = digest.finalize().into();
    if source.read(&mut excess).await? != 0 || measured != object.digest {
        return Err(Error::InvalidMessage);
    }
    Ok(())
}

pub(super) async fn download(
    receive: &mut quinn::RecvStream,
    destination: &mut (dyn AsyncWrite + Unpin),
    object: BackupObjectIdentity,
    frame_bytes: usize,
    limits: WireLimits,
) -> Result<(), Error> {
    let mut offset = 0_u64;
    let mut digest = Sha256::new();
    while offset < object.byte_length {
        let frame = receive_data_frame(receive, limits).await?.into_inner();
        let next = offset
            .checked_add(frame.bytes.len() as u64)
            .ok_or(Error::InvalidMessage)?;
        if frame.offset != offset
            || frame.bytes.is_empty()
            || frame.bytes.len() > frame_bytes
            || next > object.byte_length
        {
            return Err(Error::InvalidMessage);
        }
        digest.update(&frame.bytes);
        destination.write_all(&frame.bytes).await?;
        offset = next;
    }
    let measured: [u8; 32] = digest.finalize().into();
    if measured != object.digest {
        return Err(Error::InvalidMessage);
    }
    destination.flush().await?;
    Ok(())
}
