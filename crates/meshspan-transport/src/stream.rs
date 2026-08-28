// SPDX-License-Identifier: GPL-2.0-only

//! Independent typed QUIC streams and allocation-safe control framing.

use meshspan_protocol::v1::ControlEnvelope;
use meshspan_protocol::{
    ValidatedControlEnvelope, WireLimits, decode_control_frame, encode_control_frame,
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
    let mut prefix = [0_u8; FRAME_PREFIX_BYTES];
    receive.read_exact(&mut prefix).await?;
    let payload_length =
        usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| TransportError::InvalidFrame)?;
    if payload_length == 0 || payload_length > limits.maximum_control_bytes() {
        return Err(TransportError::InvalidFrame);
    }
    let frame_length = payload_length
        .checked_add(FRAME_PREFIX_BYTES)
        .ok_or(TransportError::InvalidFrame)?;
    let mut frame = vec![0_u8; frame_length];
    frame[..FRAME_PREFIX_BYTES].copy_from_slice(&prefix);
    receive.read_exact(&mut frame[FRAME_PREFIX_BYTES..]).await?;
    decode_control_frame(&frame, limits).map_err(Into::into)
}
