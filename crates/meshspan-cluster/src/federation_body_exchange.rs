// SPDX-License-Identifier: GPL-2.0-only

//! Shared bounded framing for authenticated federation bodies carried after signed headers.

use meshspan_contracts::BoundedBytes;
use meshspan_protocol::WireLimits;
use meshspan_protocol::v1::DataFrame;
use meshspan_transport::{receive_data_frame, send_data_frame};

use crate::FederationSessionError;

pub(crate) async fn send_exact_body(
    send: &mut quinn::SendStream,
    bytes: &[u8],
    maximum_frame_bytes: usize,
    limits: WireLimits,
) -> Result<usize, FederationSessionError> {
    if bytes.is_empty()
        || maximum_frame_bytes == 0
        || maximum_frame_bytes > limits.maximum_data_frame_bytes()
    {
        return Err(FederationSessionError::InvalidEnvelope);
    }
    for (index, chunk) in bytes.chunks(maximum_frame_bytes).enumerate() {
        let offset = index
            .checked_mul(maximum_frame_bytes)
            .and_then(|value| u64::try_from(value).ok())
            .ok_or(FederationSessionError::InvalidEnvelope)?;
        send_data_frame(
            send,
            &DataFrame {
                offset,
                bytes: chunk.to_vec(),
            },
            limits,
        )
        .await?;
    }
    Ok(bytes.len().div_ceil(maximum_frame_bytes))
}

pub(crate) async fn receive_exact_body(
    receive: &mut quinn::RecvStream,
    declared_length: u64,
    maximum_frame_bytes: u64,
    maximum_total_bytes: usize,
    expected_digest: [u8; 32],
    limits: WireLimits,
) -> Result<BoundedBytes, FederationSessionError> {
    let length =
        usize::try_from(declared_length).map_err(|_| FederationSessionError::InvalidEnvelope)?;
    let frame_limit = usize::try_from(maximum_frame_bytes)
        .map_err(|_| FederationSessionError::InvalidEnvelope)?;
    if length == 0
        || length > maximum_total_bytes
        || frame_limit == 0
        || frame_limit > limits.maximum_data_frame_bytes()
    {
        return Err(FederationSessionError::InvalidEnvelope);
    }
    let mut bytes = Vec::with_capacity(length);
    while bytes.len() < length {
        let frame = receive_data_frame(receive, limits).await?.into_inner();
        let expected_offset =
            u64::try_from(bytes.len()).map_err(|_| FederationSessionError::InvalidEnvelope)?;
        let next = bytes
            .len()
            .checked_add(frame.bytes.len())
            .ok_or(FederationSessionError::InvalidEnvelope)?;
        if frame.offset != expected_offset
            || frame.bytes.is_empty()
            || frame.bytes.len() > frame_limit
            || next > length
        {
            return Err(FederationSessionError::InvalidEnvelope);
        }
        bytes.extend_from_slice(&frame.bytes);
    }
    if blake3::hash(&bytes).as_bytes() != &expected_digest {
        return Err(FederationSessionError::InvalidEnvelope);
    }
    BoundedBytes::from_vec(bytes, maximum_total_bytes)
        .map_err(|_| FederationSessionError::InvalidEnvelope)
}
