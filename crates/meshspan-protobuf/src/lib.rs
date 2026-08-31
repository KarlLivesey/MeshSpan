// SPDX-License-Identifier: GPL-2.0-only

//! Bounded, dependency-free Protocol Buffers encoding and decoding.

mod decode;
pub mod encode;
mod error;
mod limits;
mod wire;

pub use decode::{DecodeState, Decoder};
pub use encode::{EncodedLength, Encoder};
pub use error::{DecodeError, DecodeErrorKind, EncodeError};
pub use limits::DecodeLimits;
pub use wire::WireType;

/// A generated Protocol Buffers message with bounded decoding.
pub trait Message: Default + Sized {
    /// Adds this message's exact encoded length to an accumulator.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError::LengthOverflow`] when the message cannot be
    /// represented by an addressable Rust buffer.
    fn encoded_len(&self, length: &mut EncodedLength) -> Result<(), EncodeError>;

    /// Writes fields after the caller has reserved the exact encoded length.
    ///
    /// # Errors
    ///
    /// Returns an error if nested length calculation discovers an overflow or
    /// generated length and field logic disagree.
    fn encode_fields(&self, encoder: &mut Encoder<'_>) -> Result<(), EncodeError>;

    /// Merges one decoded field into this message.
    ///
    /// # Errors
    ///
    /// Returns a bounded decoding error for malformed input or exceeded limits.
    fn merge_field(
        &mut self,
        field_number: u32,
        wire_type: WireType,
        decoder: &mut Decoder<'_>,
        state: &mut DecodeState,
        depth: usize,
    ) -> Result<(), DecodeError>;

    /// Returns the exact encoded byte length.
    ///
    /// # Errors
    ///
    /// Returns an error when length arithmetic overflows.
    fn encoded_length(&self) -> Result<usize, EncodeError> {
        let mut length = EncodedLength::new();
        self.encoded_len(&mut length)?;
        Ok(length.get())
    }

    /// Encodes this message into a new exactly reserved byte vector.
    ///
    /// # Errors
    ///
    /// Returns an error for length overflow or failed allocation.
    fn encode_to_vec(&self) -> Result<Vec<u8>, EncodeError> {
        let encoded_length = self.encoded_length()?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(encoded_length)
            .map_err(|_| EncodeError::AllocationFailed)?;
        self.encode_fields(&mut Encoder::new(&mut output))?;
        if output.len() != encoded_length {
            return Err(EncodeError::LengthMismatch);
        }
        Ok(output)
    }

    /// Decodes with conservative hostile-input defaults.
    ///
    /// # Errors
    ///
    /// Returns a bounded decoding error for malformed input or exceeded limits.
    fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        Self::decode_with_limits(input, DecodeLimits::default())
    }

    /// Decodes with caller-selected hostile-input limits.
    ///
    /// # Errors
    ///
    /// Returns a bounded decoding error for malformed input or exceeded limits.
    fn decode_with_limits(input: &[u8], limits: DecodeLimits) -> Result<Self, DecodeError> {
        let mut state = DecodeState::new(limits, input.len())?;
        let mut decoder = Decoder::new(input);
        let mut message = Self::default();
        decoder.merge_message(&mut message, &mut state, 0)?;
        Ok(message)
    }
}
