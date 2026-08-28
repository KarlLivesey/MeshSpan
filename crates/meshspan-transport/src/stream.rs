// SPDX-License-Identifier: GPL-2.0-only

//! Independent typed QUIC streams and allocation-safe control framing.

use meshspan_protocol::v1::{ControlEnvelope, DataControlEnvelope, DataFrame};
use meshspan_protocol::{
    ValidatedControlEnvelope, ValidatedDataControlEnvelope, ValidatedDataFrame, WireLimits,
    decode_control_frame, decode_data_control_frame, decode_data_frame, encode_control_frame,
    encode_data_control_frame, encode_data_frame,
};
use quinn::{Connection, RecvStream, SendStream};

use crate::TransportError;

const FRAME_PREFIX_BYTES: usize = 4;

/// First byte on every bidirectional stream; stream flow control remains independent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum StreamKind {
    /// Elections, append traffic and read barriers; highest scheduling priority.
    Consensus = 1,
    /// Typed metadata commands, queries, routes and status.
    Metadata = 2,
    /// Snapshot negotiation and chunks.
    Snapshot = 3,
    /// Bulk-data control; bytes themselves use separately bounded frames.
    Data = 4,
}

impl StreamKind {
    const fn priority(self) -> i32 {
        match self {
            Self::Consensus => 100,
            Self::Metadata => 50,
            Self::Snapshot => 10,
            Self::Data => 0,
        }
    }

    const fn from_byte(value: u8) -> Result<Self, TransportError> {
        match value {
            1 => Ok(Self::Consensus),
            2 => Ok(Self::Metadata),
            3 => Ok(Self::Snapshot),
            4 => Ok(Self::Data),
            _ => Err(TransportError::InvalidFrame),
        }
    }
}

/// One accepted stream after its kind prefix passed validation.
pub struct AcceptedStream {
    /// Validated stream class.
    pub kind: StreamKind,
    /// Response direction.
    pub send: SendStream,
    /// Request direction after the kind byte.
    pub receive: RecvStream,
}

/// Opens one independent typed bidirectional stream and writes its kind prefix.
///
/// # Errors
///
/// Reports connection closure or inability to write the stream prefix/priority.
pub async fn open_stream(
    connection: &Connection,
    kind: StreamKind,
) -> Result<(SendStream, RecvStream), TransportError> {
    let (mut send, receive) = connection.open_bi().await?;
    send.set_priority(kind.priority())?;
    send.write_all(&[kind as u8]).await?;
    Ok((send, receive))
}

/// Accepts one typed bidirectional stream without reading its first frame.
///
/// # Errors
///
/// Rejects closed streams and unknown stream-kind bytes.
pub async fn accept_stream(connection: &Connection) -> Result<AcceptedStream, TransportError> {
    let (send, mut receive) = connection.accept_bi().await?;
    let mut kind = [0_u8; 1];
    receive.read_exact(&mut kind).await?;
    Ok(AcceptedStream {
        kind: StreamKind::from_byte(kind[0])?,
        send,
        receive,
    })
}

/// Encodes and writes one fully validated control envelope, leaving the stream open.
///
/// # Errors
///
/// Rejects semantic/wire limits before writing or reports stream failure.
pub async fn send_control(
    send: &mut SendStream,
    envelope: &ControlEnvelope,
    limits: WireLimits,
) -> Result<(), TransportError> {
    let frame = encode_control_frame(envelope, limits)?;
    send.write_all(&frame).await?;
    Ok(())
}

/// Reads exactly one length-prefixed frame with a pre-allocation bound, then validates Protobuf.
///
/// # Errors
///
/// Rejects truncation, excess, malformed Protobuf and every failed semantic invariant.
pub async fn receive_control(
    receive: &mut RecvStream,
    limits: WireLimits,
) -> Result<ValidatedControlEnvelope, TransportError> {
    let frame = receive_prefixed(receive, limits.maximum_control_bytes()).await?;
    decode_control_frame(&frame, limits).map_err(Into::into)
}

/// Encodes and writes one validated data-stream control envelope.
///
/// # Errors
///
/// Rejects invalid control fields and negotiated-limit violations before writing.
pub async fn send_data_control(
    send: &mut SendStream,
    envelope: &DataControlEnvelope,
    limits: WireLimits,
) -> Result<(), TransportError> {
    let frame = encode_data_control_frame(envelope, limits)?;
    send.write_all(&frame).await?;
    Ok(())
}

/// Reads one bounded and semantically validated data-stream control envelope.
///
/// # Errors
///
/// Rejects truncation, excess, malformed Protobuf and invalid fields.
pub async fn receive_data_control(
    receive: &mut RecvStream,
    limits: WireLimits,
) -> Result<ValidatedDataControlEnvelope, TransportError> {
    let frame = receive_prefixed(receive, limits.maximum_control_bytes()).await?;
    decode_data_control_frame(&frame, limits).map_err(Into::into)
}

/// Encodes and writes one independently bounded bulk data frame.
///
/// # Errors
///
/// Rejects empty/excessive bytes or reports stream failure.
pub async fn send_data_frame(
    send: &mut SendStream,
    frame: &DataFrame,
    limits: WireLimits,
) -> Result<(), TransportError> {
    let encoded = encode_data_frame(frame, limits)?;
    send.write_all(&encoded).await?;
    Ok(())
}

/// Reads one independently bounded and validated bulk data frame.
///
/// # Errors
///
/// Rejects declared sizes before allocation, truncation and malformed/invalid bytes.
pub async fn receive_data_frame(
    receive: &mut RecvStream,
    limits: WireLimits,
) -> Result<ValidatedDataFrame, TransportError> {
    let maximum_encoded = limits
        .maximum_data_frame_bytes()
        .checked_add(32)
        .ok_or(TransportError::InvalidFrame)?;
    let frame = receive_prefixed(receive, maximum_encoded).await?;
    decode_data_frame(&frame, limits).map_err(Into::into)
}

async fn receive_prefixed(
    receive: &mut RecvStream,
    maximum_payload_bytes: usize,
) -> Result<Vec<u8>, TransportError> {
    let mut prefix = [0_u8; FRAME_PREFIX_BYTES];
    receive.read_exact(&mut prefix).await?;
    let payload_length =
        usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| TransportError::InvalidFrame)?;
    if payload_length == 0 || payload_length > maximum_payload_bytes {
        return Err(TransportError::InvalidFrame);
    }
    let frame_length = payload_length
        .checked_add(FRAME_PREFIX_BYTES)
        .ok_or(TransportError::InvalidFrame)?;
    let mut frame = vec![0_u8; frame_length];
    frame[..FRAME_PREFIX_BYTES].copy_from_slice(&prefix);
    receive.read_exact(&mut frame[FRAME_PREFIX_BYTES..]).await?;
    Ok(frame)
}
