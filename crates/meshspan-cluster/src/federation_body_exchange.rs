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
    let mut body = ExactBodyReceiver::new(
        declared_length,
        maximum_frame_bytes,
        maximum_total_bytes,
        expected_digest,
        limits,
    )?;
    while !body.is_complete() {
        let frame = receive_data_frame(receive, limits).await?.into_inner();
        body.push(&frame)?;
    }
    body.finish()
}

struct ExactBodyReceiver {
    bytes: Vec<u8>,
    declared_length: usize,
    maximum_frame_bytes: usize,
    maximum_total_bytes: usize,
    expected_digest: [u8; 32],
}

impl ExactBodyReceiver {
    fn new(
        declared_length: u64,
        maximum_frame_bytes: u64,
        maximum_total_bytes: usize,
        expected_digest: [u8; 32],
        limits: WireLimits,
    ) -> Result<Self, FederationSessionError> {
        let declared_length = usize::try_from(declared_length)
            .map_err(|_| FederationSessionError::InvalidEnvelope)?;
        let maximum_frame_bytes = usize::try_from(maximum_frame_bytes)
            .map_err(|_| FederationSessionError::InvalidEnvelope)?;
        if declared_length == 0
            || declared_length > maximum_total_bytes
            || maximum_frame_bytes == 0
            || maximum_frame_bytes > limits.maximum_data_frame_bytes()
        {
            return Err(FederationSessionError::InvalidEnvelope);
        }
        Ok(Self {
            bytes: Vec::with_capacity(declared_length),
            declared_length,
            maximum_frame_bytes,
            maximum_total_bytes,
            expected_digest,
        })
    }

    const fn is_complete(&self) -> bool {
        self.bytes.len() == self.declared_length
    }

    fn push(&mut self, frame: &DataFrame) -> Result<(), FederationSessionError> {
        let expected_offset =
            u64::try_from(self.bytes.len()).map_err(|_| FederationSessionError::InvalidEnvelope)?;
        let next = self
            .bytes
            .len()
            .checked_add(frame.bytes.len())
            .ok_or(FederationSessionError::InvalidEnvelope)?;
        if frame.offset != expected_offset
            || frame.bytes.is_empty()
            || frame.bytes.len() > self.maximum_frame_bytes
            || next > self.declared_length
        {
            return Err(FederationSessionError::InvalidEnvelope);
        }
        self.bytes.extend_from_slice(&frame.bytes);
        Ok(())
    }

    fn finish(self) -> Result<BoundedBytes, FederationSessionError> {
        if !self.is_complete() || blake3::hash(&self.bytes).as_bytes() != &self.expected_digest {
            return Err(FederationSessionError::InvalidEnvelope);
        }
        BoundedBytes::from_vec(self.bytes, self.maximum_total_bytes)
            .map_err(|_| FederationSessionError::InvalidEnvelope)
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use meshspan_protocol::WireLimits;
    use meshspan_protocol::v1::DataFrame;

    use super::ExactBodyReceiver;

    #[test]
    fn exact_body_rejects_excess_before_allocation_and_every_frame_lie()
    -> Result<(), Box<dyn Error>> {
        let limits = WireLimits::new(4_096, 4, 32, 64)?;
        let digest = *blake3::hash(b"abcdefgh").as_bytes();
        assert!(ExactBodyReceiver::new(65, 4, 64, digest, limits).is_err());
        assert!(ExactBodyReceiver::new(8, 5, 64, digest, limits).is_err());

        let mut offset = receiver(digest, limits)?;
        assert!(offset.push(&frame(1, b"abcd")).is_err());
        let mut empty = receiver(digest, limits)?;
        assert!(empty.push(&frame(0, b"")).is_err());
        let mut oversized = receiver(digest, limits)?;
        assert!(oversized.push(&frame(0, b"abcde")).is_err());
        let mut overrun = receiver(digest, limits)?;
        overrun.push(&frame(0, b"abcd"))?;
        assert!(overrun.push(&frame(4, b"abcde")).is_err());
        Ok(())
    }

    #[test]
    fn exact_body_rejects_truncation_and_corruption_but_accepts_exact_bytes()
    -> Result<(), Box<dyn Error>> {
        let limits = WireLimits::new(4_096, 4, 32, 64)?;
        let digest = *blake3::hash(b"abcdefgh").as_bytes();
        let mut truncated = receiver(digest, limits)?;
        truncated.push(&frame(0, b"abcd"))?;
        assert!(truncated.finish().is_err());

        let mut corrupt = receiver(digest, limits)?;
        corrupt.push(&frame(0, b"abcd"))?;
        corrupt.push(&frame(4, b"efgi"))?;
        assert!(corrupt.finish().is_err());

        let mut exact = receiver(digest, limits)?;
        exact.push(&frame(0, b"abcd"))?;
        exact.push(&frame(4, b"efgh"))?;
        assert_eq!(exact.finish()?.as_slice(), b"abcdefgh");
        Ok(())
    }

    fn receiver(
        digest: [u8; 32],
        limits: WireLimits,
    ) -> Result<ExactBodyReceiver, crate::FederationSessionError> {
        ExactBodyReceiver::new(8, 4, 64, digest, limits)
    }

    fn frame(offset: u64, bytes: &[u8]) -> DataFrame {
        DataFrame {
            offset,
            bytes: bytes.to_vec(),
        }
    }
}
