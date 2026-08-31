// SPDX-License-Identifier: GPL-2.0-only

//! Protocol Buffers field keys and wire types.

use crate::{DecodeError, DecodeErrorKind};

/// The six field representations defined by the Protocol Buffers wire format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum WireType {
    /// Variable-width integer.
    Varint = 0,
    /// Little-endian 64-bit value.
    Fixed64 = 1,
    /// Varint length followed by bytes.
    LengthDelimited = 2,
    /// Deprecated group start.
    StartGroup = 3,
    /// Deprecated group end.
    EndGroup = 4,
    /// Little-endian 32-bit value.
    Fixed32 = 5,
}

impl WireType {
    pub(crate) fn from_key(value: u64, offset: usize) -> Result<Self, DecodeError> {
        match value & 0b111 {
            0 => Ok(Self::Varint),
            1 => Ok(Self::Fixed64),
            2 => Ok(Self::LengthDelimited),
            3 => Ok(Self::StartGroup),
            4 => Ok(Self::EndGroup),
            5 => Ok(Self::Fixed32),
            _ => Err(DecodeError::new(DecodeErrorKind::InvalidKey, offset)),
        }
    }
}
