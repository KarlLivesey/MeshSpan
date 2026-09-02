// SPDX-License-Identifier: GPL-2.0-only

//! Bounded SMB Direct TCP framing.

const HEADER_LENGTH: usize = 4;
const MAX_WIRE_PAYLOAD_LENGTH: usize = 0x00ff_ffff;

/// A validated Direct TCP frame header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectTcpFrameHeader {
    payload_length: usize,
}

impl DirectTcpFrameHeader {
    /// Parses a complete four-byte Direct TCP header against a caller-owned limit.
    ///
    /// # Errors
    ///
    /// Returns an error when the reserved byte is non-zero, the payload is empty,
    /// or the declared payload exceeds `maximum_payload_length`.
    pub fn parse(
        bytes: [u8; HEADER_LENGTH],
        maximum_payload_length: usize,
    ) -> Result<Self, DirectTcpFrameError> {
        validate_maximum(maximum_payload_length)?;
        if bytes[0] != 0 {
            return Err(DirectTcpFrameError::InvalidReservedByte);
        }
        let payload_length =
            usize::from(bytes[1]) << 16 | usize::from(bytes[2]) << 8 | usize::from(bytes[3]);
        if payload_length == 0 {
            return Err(DirectTcpFrameError::EmptyPayload);
        }
        if payload_length > maximum_payload_length {
            return Err(DirectTcpFrameError::PayloadTooLarge);
        }
        Ok(Self { payload_length })
    }

    /// Returns the exact enclosed SMB message length.
    #[must_use]
    pub const fn payload_length(self) -> usize {
        self.payload_length
    }
}

/// One complete borrowed Direct TCP frame and the remaining stream bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectTcpFrame<'a> {
    /// Exact SMB message bytes, excluding the Direct TCP header.
    pub payload: &'a [u8],
    /// Bytes following this frame, which may contain another frame or a partial header.
    pub remaining: &'a [u8],
}

impl<'a> DirectTcpFrame<'a> {
    /// Decodes at most one frame without allocating or consuming an incomplete frame.
    ///
    /// `Ok(None)` means more transport bytes are required.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid header or a declared payload beyond the
    /// caller's resource limit.
    pub fn decode(
        bytes: &'a [u8],
        maximum_payload_length: usize,
    ) -> Result<Option<Self>, DirectTcpFrameError> {
        validate_maximum(maximum_payload_length)?;
        let Some(header_bytes) = bytes.get(..HEADER_LENGTH) else {
            return Ok(None);
        };
        let header = DirectTcpFrameHeader::parse(
            header_bytes
                .try_into()
                .map_err(|_| DirectTcpFrameError::IncompleteHeader)?,
            maximum_payload_length,
        )?;
        let frame_length = HEADER_LENGTH
            .checked_add(header.payload_length())
            .ok_or(DirectTcpFrameError::PayloadTooLarge)?;
        if bytes.len() < frame_length {
            return Ok(None);
        }
        Ok(Some(Self {
            payload: &bytes[HEADER_LENGTH..frame_length],
            remaining: &bytes[frame_length..],
        }))
    }
}

/// Encodes one Direct TCP header for a previously bounded payload.
///
/// # Errors
///
/// Returns an error when the payload is empty or exceeds the 24-bit wire limit.
pub fn encode_direct_tcp_header(
    payload_length: usize,
) -> Result<[u8; HEADER_LENGTH], DirectTcpFrameError> {
    if payload_length == 0 {
        return Err(DirectTcpFrameError::EmptyPayload);
    }
    if payload_length > MAX_WIRE_PAYLOAD_LENGTH {
        return Err(DirectTcpFrameError::PayloadTooLarge);
    }
    let length = u32::try_from(payload_length).map_err(|_| DirectTcpFrameError::PayloadTooLarge)?;
    let encoded = length.to_be_bytes();
    Ok([0, encoded[1], encoded[2], encoded[3]])
}

fn validate_maximum(maximum_payload_length: usize) -> Result<(), DirectTcpFrameError> {
    if maximum_payload_length == 0 || maximum_payload_length > MAX_WIRE_PAYLOAD_LENGTH {
        Err(DirectTcpFrameError::InvalidMaximum)
    } else {
        Ok(())
    }
}

/// Invalid or incomplete Direct TCP framing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DirectTcpFrameError {
    /// The configured maximum cannot be represented safely by the wire format.
    #[error("Direct TCP payload maximum is invalid")]
    InvalidMaximum,
    /// Fewer than four bytes were supplied where a complete header was required.
    #[error("Direct TCP header is incomplete")]
    IncompleteHeader,
    /// The first Direct TCP header byte was not zero.
    #[error("Direct TCP reserved byte is invalid")]
    InvalidReservedByte,
    /// SMB messages cannot be empty.
    #[error("Direct TCP payload is empty")]
    EmptyPayload,
    /// The declared or encoded payload exceeds a configured or wire bound.
    #[error("Direct TCP payload exceeds its limit")]
    PayloadTooLarge,
}

#[cfg(test)]
mod tests {
    use super::{
        DirectTcpFrame, DirectTcpFrameError, DirectTcpFrameHeader, encode_direct_tcp_header,
    };

    #[test]
    fn complete_and_coalesced_frames_decode_without_copying() -> Result<(), DirectTcpFrameError> {
        let bytes = [0, 0, 0, 3, 0xfe, b'S', b'M', 0, 0, 0, 1, 9];
        let first =
            DirectTcpFrame::decode(&bytes, 1024)?.ok_or(DirectTcpFrameError::EmptyPayload)?;
        assert_eq!(first.payload, &[0xfe, b'S', b'M']);
        let second = DirectTcpFrame::decode(first.remaining, 1024)?
            .ok_or(DirectTcpFrameError::EmptyPayload)?;
        assert_eq!(second.payload, &[9]);
        assert!(second.remaining.is_empty());
        Ok(())
    }

    #[test]
    fn partial_frames_wait_without_accepting_invalid_headers() -> Result<(), DirectTcpFrameError> {
        assert_eq!(DirectTcpFrame::decode(&[0, 0, 0], 16)?, None);
        assert_eq!(DirectTcpFrame::decode(&[0, 0, 0, 4, 1, 2], 16)?, None);
        assert_eq!(
            DirectTcpFrame::decode(&[1, 0, 0, 1, 9], 16),
            Err(DirectTcpFrameError::InvalidReservedByte)
        );
        assert_eq!(
            DirectTcpFrameHeader::parse([0, 0, 1, 0], 255),
            Err(DirectTcpFrameError::PayloadTooLarge)
        );
        Ok(())
    }

    #[test]
    fn encoded_lengths_are_canonical_and_bounded() -> Result<(), DirectTcpFrameError> {
        assert_eq!(encode_direct_tcp_header(0x01_0203)?, [0, 1, 2, 3]);
        assert_eq!(
            encode_direct_tcp_header(0),
            Err(DirectTcpFrameError::EmptyPayload)
        );
        assert_eq!(
            encode_direct_tcp_header(0x0100_0000),
            Err(DirectTcpFrameError::PayloadTooLarge)
        );
        Ok(())
    }
}
