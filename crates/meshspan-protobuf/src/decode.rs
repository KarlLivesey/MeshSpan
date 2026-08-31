// SPDX-License-Identifier: GPL-2.0-only

//! Bounded Protocol Buffers decoding primitives.

use crate::{DecodeError, DecodeErrorKind, DecodeLimits, Message, WireType};

const MAXIMUM_FIELD_NUMBER: u32 = (1 << 29) - 1;

/// Mutable work accounting shared by one complete decode operation.
#[derive(Debug)]
pub struct DecodeState {
    limits: DecodeLimits,
    fields: usize,
}

impl DecodeState {
    /// Creates accounting state and rejects an oversized complete message.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeErrorKind::MessageTooLarge`] before parsing begins.
    pub fn new(limits: DecodeLimits, input_length: usize) -> Result<Self, DecodeError> {
        if input_length > limits.maximum_message_bytes {
            return Err(DecodeError::new(DecodeErrorKind::MessageTooLarge, 0));
        }
        Ok(Self { limits, fields: 0 })
    }

    /// Records one repeated value before its destination vector grows.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeErrorKind::TooManyItems`] at the configured bound.
    pub fn repeated_item(&self, current_length: usize, offset: usize) -> Result<(), DecodeError> {
        if current_length >= self.limits.maximum_repeated_items {
            return Err(DecodeError::new(DecodeErrorKind::TooManyItems, offset));
        }
        Ok(())
    }

    fn field(&mut self, offset: usize) -> Result<(), DecodeError> {
        self.fields = self
            .fields
            .checked_add(1)
            .ok_or_else(|| DecodeError::new(DecodeErrorKind::LengthOverflow, offset))?;
        if self.fields > self.limits.maximum_fields {
            return Err(DecodeError::new(DecodeErrorKind::TooManyFields, offset));
        }
        Ok(())
    }

    fn length_delimited(&self, length: usize, offset: usize) -> Result<(), DecodeError> {
        if length > self.limits.maximum_field_bytes {
            return Err(DecodeError::new(DecodeErrorKind::FieldTooLarge, offset));
        }
        Ok(())
    }

    fn depth(&self, depth: usize, offset: usize) -> Result<(), DecodeError> {
        if depth > self.limits.maximum_depth {
            return Err(DecodeError::new(DecodeErrorKind::RecursionLimit, offset));
        }
        Ok(())
    }
}

/// A cursor over one encoded message or embedded length-delimited region.
#[derive(Debug)]
pub struct Decoder<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    /// Creates a cursor over already size-bounded input.
    #[must_use]
    pub const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    /// Returns the current byte offset within this region.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.position
    }

    /// Returns whether the region has been consumed exactly.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.position == self.input.len()
    }

    /// Merges this complete region into a generated message.
    ///
    /// # Errors
    ///
    /// Returns a bounded decoding error for malformed input or exceeded limits.
    pub fn merge_message<M: Message>(
        &mut self,
        message: &mut M,
        state: &mut DecodeState,
        depth: usize,
    ) -> Result<(), DecodeError> {
        state.depth(depth, self.position)?;
        while !self.is_empty() {
            let key_offset = self.position;
            let key = self.varint()?;
            let field_number = u32::try_from(key >> 3)
                .map_err(|_| DecodeError::new(DecodeErrorKind::InvalidKey, key_offset))?;
            if field_number == 0 || field_number > MAXIMUM_FIELD_NUMBER {
                return Err(DecodeError::new(DecodeErrorKind::InvalidKey, key_offset));
            }
            let wire_type = WireType::from_key(key, key_offset)?;
            if wire_type == WireType::EndGroup {
                return Err(DecodeError::new(DecodeErrorKind::InvalidKey, key_offset));
            }
            state.field(key_offset)?;
            message.merge_field(field_number, wire_type, self, state, depth)?;
        }
        Ok(())
    }

    /// Reads an unsigned varint.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeErrorKind::InvalidVarint`] for truncation or overflow.
    pub fn varint(&mut self) -> Result<u64, DecodeError> {
        let start = self.position;
        let mut value = 0_u64;
        for shift in (0..70).step_by(7) {
            let byte = self
                .take_byte()
                .map_err(|_| DecodeError::new(DecodeErrorKind::InvalidVarint, start))?;
            if shift == 63 && byte > 1 {
                return Err(DecodeError::new(DecodeErrorKind::InvalidVarint, start));
            }
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(DecodeError::new(DecodeErrorKind::InvalidVarint, start))
    }

    /// Reads a zig-zag signed 64-bit integer.
    ///
    /// # Errors
    ///
    /// Returns an invalid-varint error for malformed input.
    pub fn sint64(&mut self) -> Result<i64, DecodeError> {
        let value = self.varint()?;
        Ok((value >> 1).cast_signed() ^ -(value & 1).cast_signed())
    }

    /// Reads a bounded unsigned 32-bit varint.
    ///
    /// # Errors
    ///
    /// Returns an invalid-varint error when the encoded value exceeds u32.
    pub fn uint32(&mut self) -> Result<u32, DecodeError> {
        let start = self.position;
        u32::try_from(self.varint()?)
            .map_err(|_| DecodeError::new(DecodeErrorKind::InvalidVarint, start))
    }

    /// Reads a Protocol Buffers enum/int32 value.
    ///
    /// # Errors
    ///
    /// Returns an invalid-varint error for malformed input.
    pub fn int32(&mut self) -> Result<i32, DecodeError> {
        let bytes = self.varint()?.to_le_bytes();
        Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Reads a Protocol Buffers Boolean, where any non-zero varint is true.
    ///
    /// # Errors
    ///
    /// Returns an invalid-varint error for malformed input.
    pub fn boolean(&mut self) -> Result<bool, DecodeError> {
        Ok(self.varint()? != 0)
    }

    /// Reads a little-endian fixed-width 64-bit integer.
    ///
    /// # Errors
    ///
    /// Returns a truncation error when eight bytes are unavailable.
    pub fn fixed64(&mut self) -> Result<u64, DecodeError> {
        let start = self.position;
        let bytes = self.take(8)?;
        let array = <[u8; 8]>::try_from(bytes)
            .map_err(|_| DecodeError::new(DecodeErrorKind::Truncated, start))?;
        Ok(u64::from_le_bytes(array))
    }

    /// Borrows one checked length-delimited value.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid length, configured excess or truncation.
    pub fn bytes(&mut self, state: &DecodeState) -> Result<&'a [u8], DecodeError> {
        let start = self.position;
        let encoded_length = self.varint()?;
        let length = usize::try_from(encoded_length)
            .map_err(|_| DecodeError::new(DecodeErrorKind::LengthOverflow, start))?;
        state.length_delimited(length, start)?;
        self.take(length)
    }

    /// Copies one checked byte field.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid length, configured excess or truncation.
    pub fn byte_vector(&mut self, state: &DecodeState) -> Result<Vec<u8>, DecodeError> {
        Ok(self.bytes(state)?.to_vec())
    }

    /// Decodes one checked UTF-8 string field.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid length, truncation or invalid UTF-8.
    pub fn string(&mut self, state: &DecodeState) -> Result<String, DecodeError> {
        let start = self.position;
        let bytes = self.bytes(state)?;
        let value = core::str::from_utf8(bytes)
            .map_err(|_| DecodeError::new(DecodeErrorKind::InvalidUtf8, start))?;
        Ok(value.to_owned())
    }

    /// Merges one embedded message into an optional destination.
    ///
    /// # Errors
    ///
    /// Returns a bounded decoding error for malformed input or exceeded limits.
    pub fn embedded<M: Message>(
        &mut self,
        destination: &mut Option<M>,
        state: &mut DecodeState,
        depth: usize,
    ) -> Result<(), DecodeError> {
        let bytes = self.bytes(state)?;
        let mut nested = Decoder::new(bytes);
        let value = destination.get_or_insert_with(M::default);
        nested.merge_message(value, state, depth + 1)
    }

    /// Skips one unknown field while validating its complete wire form.
    ///
    /// # Errors
    ///
    /// Returns a bounded decoding error for malformed input or exceeded limits.
    pub fn skip_field(
        &mut self,
        field_number: u32,
        wire_type: WireType,
        state: &mut DecodeState,
        depth: usize,
    ) -> Result<(), DecodeError> {
        match wire_type {
            WireType::Varint => self.varint().map(|_| ()),
            WireType::Fixed64 => self.take(8).map(|_| ()),
            WireType::LengthDelimited => self.bytes(state).map(|_| ()),
            WireType::StartGroup => self.skip_group(field_number, state, depth + 1),
            WireType::EndGroup => Err(DecodeError::new(DecodeErrorKind::InvalidKey, self.position)),
            WireType::Fixed32 => self.take(4).map(|_| ()),
        }
    }

    fn skip_group(
        &mut self,
        expected_field: u32,
        state: &mut DecodeState,
        depth: usize,
    ) -> Result<(), DecodeError> {
        state.depth(depth, self.position)?;
        while !self.is_empty() {
            let offset = self.position;
            let key = self.varint()?;
            let field_number = u32::try_from(key >> 3)
                .map_err(|_| DecodeError::new(DecodeErrorKind::InvalidKey, offset))?;
            let wire_type = WireType::from_key(key, offset)?;
            state.field(offset)?;
            if wire_type == WireType::EndGroup {
                return if field_number == expected_field {
                    Ok(())
                } else {
                    Err(DecodeError::new(DecodeErrorKind::InvalidKey, offset))
                };
            }
            self.skip_field(field_number, wire_type, state, depth)?;
        }
        Err(DecodeError::new(
            DecodeErrorKind::UnterminatedGroup,
            self.position,
        ))
    }

    fn take_byte(&mut self) -> Result<u8, DecodeError> {
        let byte = self
            .input
            .get(self.position)
            .copied()
            .ok_or_else(|| DecodeError::new(DecodeErrorKind::Truncated, self.position))?;
        self.position += 1;
        Ok(byte)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], DecodeError> {
        let start = self.position;
        let end = start
            .checked_add(length)
            .ok_or_else(|| DecodeError::new(DecodeErrorKind::LengthOverflow, start))?;
        let value = self
            .input
            .get(start..end)
            .ok_or_else(|| DecodeError::new(DecodeErrorKind::Truncated, start))?;
        self.position = end;
        Ok(value)
    }
}
