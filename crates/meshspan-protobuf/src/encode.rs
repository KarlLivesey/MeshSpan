// SPDX-License-Identifier: GPL-2.0-only

//! Exact-length Protocol Buffers encoding primitives.

use crate::{EncodeError, Message, WireType};

/// Checked encoded-length accumulator used by generated messages.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EncodedLength(usize);

impl EncodedLength {
    /// Creates an empty accumulator.
    #[must_use]
    pub const fn new() -> Self {
        Self(0)
    }

    /// Adds a field's encoded length.
    ///
    /// # Errors
    ///
    /// Returns an error if the total cannot fit in `usize`.
    pub fn add(&mut self, value: usize) -> Result<(), EncodeError> {
        self.0 = self
            .0
            .checked_add(value)
            .ok_or(EncodeError::LengthOverflow)?;
        Ok(())
    }

    /// Returns the accumulated length.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0
    }
}

/// Infallible writer used only after exact output reservation succeeds.
pub struct Encoder<'a> {
    output: &'a mut Vec<u8>,
}

impl<'a> Encoder<'a> {
    /// Creates an encoder over an already reserved output buffer.
    pub fn new(output: &'a mut Vec<u8>) -> Self {
        Self { output }
    }

    /// Writes a `uint32`, `uint64`, enum or Boolean field.
    pub fn varint_field(&mut self, field_number: u32, value: u64) {
        self.key(field_number, WireType::Varint);
        self.varint(value);
    }

    /// Writes an enum/int32 field with the Protocol Buffers signed expansion.
    pub fn int32_field(&mut self, field_number: u32, value: i32) {
        self.varint_field(field_number, int32_to_varint(value));
    }

    /// Writes a zig-zag encoded signed 64-bit field.
    pub fn sint64_field(&mut self, field_number: u32, value: i64) {
        self.varint_field(field_number, zig_zag_encode(value));
    }

    /// Writes a little-endian fixed-width 64-bit field.
    pub fn fixed64_field(&mut self, field_number: u32, value: u64) {
        self.key(field_number, WireType::Fixed64);
        self.output.extend_from_slice(&value.to_le_bytes());
    }

    /// Writes a byte or UTF-8 string field.
    ///
    /// # Errors
    ///
    /// Returns an error if the byte length cannot be represented on the wire.
    pub fn bytes_field(&mut self, field_number: u32, value: &[u8]) -> Result<(), EncodeError> {
        self.key(field_number, WireType::LengthDelimited);
        self.varint(u64::try_from(value.len()).map_err(|_| EncodeError::LengthOverflow)?);
        self.output.extend_from_slice(value);
        Ok(())
    }

    /// Writes one embedded message field.
    ///
    /// # Errors
    ///
    /// Returns an error if the nested encoded length overflows.
    pub fn message_field<M: Message>(
        &mut self,
        field_number: u32,
        value: &M,
    ) -> Result<(), EncodeError> {
        self.key(field_number, WireType::LengthDelimited);
        let length = value.encoded_length()?;
        self.varint(u64::try_from(length).map_err(|_| EncodeError::LengthOverflow)?);
        value.encode_fields(self)
    }

    /// Writes a packed sequence of already converted varints.
    ///
    /// # Errors
    ///
    /// Returns an error if packed length arithmetic overflows.
    pub fn packed_varints(&mut self, field_number: u32, values: &[u64]) -> Result<(), EncodeError> {
        self.key(field_number, WireType::LengthDelimited);
        let mut packed_length = EncodedLength::new();
        for value in values {
            packed_length.add(varint_len(*value))?;
        }
        self.varint(u64::try_from(packed_length.get()).map_err(|_| EncodeError::LengthOverflow)?);
        for value in values {
            self.varint(*value);
        }
        Ok(())
    }

    /// Writes a packed uint32 field without a temporary conversion allocation.
    ///
    /// # Errors
    ///
    /// Returns an error if packed length arithmetic overflows.
    pub fn packed_uint32(&mut self, field_number: u32, values: &[u32]) -> Result<(), EncodeError> {
        self.packed_converted(field_number, values.iter().copied().map(u64::from))
    }

    /// Writes a packed enum/int32 field without a temporary allocation.
    ///
    /// # Errors
    ///
    /// Returns an error if packed length arithmetic overflows.
    pub fn packed_int32(&mut self, field_number: u32, values: &[i32]) -> Result<(), EncodeError> {
        self.packed_converted(field_number, values.iter().copied().map(int32_to_varint))
    }

    fn packed_converted(
        &mut self,
        field_number: u32,
        values: impl Iterator<Item = u64> + Clone,
    ) -> Result<(), EncodeError> {
        self.key(field_number, WireType::LengthDelimited);
        let mut packed_length = EncodedLength::new();
        for value in values.clone() {
            packed_length.add(varint_len(value))?;
        }
        self.varint(u64::try_from(packed_length.get()).map_err(|_| EncodeError::LengthOverflow)?);
        for value in values {
            self.varint(value);
        }
        Ok(())
    }

    fn key(&mut self, field_number: u32, wire_type: WireType) {
        self.varint((u64::from(field_number) << 3) | wire_type as u64);
    }

    fn varint(&mut self, mut value: u64) {
        while value >= 0x80 {
            self.output.push((value.to_le_bytes()[0] & 0x7f) | 0x80);
            value >>= 7;
        }
        self.output.push(value.to_le_bytes()[0]);
    }
}

/// Returns the encoded key length for a valid field number.
#[must_use]
pub fn key_len(field_number: u32) -> usize {
    varint_len(u64::from(field_number) << 3)
}

/// Returns a varint field's encoded length.
#[must_use]
pub fn varint_field_len(field_number: u32, value: u64) -> usize {
    key_len(field_number) + varint_len(value)
}

/// Returns a fixed64 field's encoded length.
#[must_use]
pub fn fixed64_field_len(field_number: u32) -> usize {
    key_len(field_number) + 8
}

/// Returns a length-delimited field's encoded length.
///
/// # Errors
///
/// Returns an error when length arithmetic overflows.
pub fn bytes_field_len(field_number: u32, length: usize) -> Result<usize, EncodeError> {
    key_len(field_number)
        .checked_add(varint_len_usize(length))
        .and_then(|total| total.checked_add(length))
        .ok_or(EncodeError::LengthOverflow)
}

/// Returns an embedded message field's encoded length.
///
/// # Errors
///
/// Returns an error when the message or field length overflows.
pub fn message_field_len<M: Message>(field_number: u32, value: &M) -> Result<usize, EncodeError> {
    bytes_field_len(field_number, value.encoded_length()?)
}

/// Returns a packed varint field's encoded length.
///
/// # Errors
///
/// Returns an error when length arithmetic overflows.
pub fn packed_varint_field_len(field_number: u32, values: &[u64]) -> Result<usize, EncodeError> {
    let mut packed = EncodedLength::new();
    for value in values {
        packed.add(varint_len(*value))?;
    }
    bytes_field_len(field_number, packed.get())
}

/// Returns a packed uint32 field's encoded length.
///
/// # Errors
///
/// Returns an error when length arithmetic overflows.
pub fn packed_uint32_field_len(field_number: u32, values: &[u32]) -> Result<usize, EncodeError> {
    packed_converted_field_len(field_number, values.iter().copied().map(u64::from))
}

/// Returns a packed enum/int32 field's encoded length.
///
/// # Errors
///
/// Returns an error when length arithmetic overflows.
pub fn packed_int32_field_len(field_number: u32, values: &[i32]) -> Result<usize, EncodeError> {
    packed_converted_field_len(field_number, values.iter().copied().map(int32_to_varint))
}

/// Returns one unsigned varint's byte length.
#[must_use]
pub const fn varint_len(value: u64) -> usize {
    let significant_bits = 64 - value.leading_zeros();
    let bytes = significant_bits.div_ceil(7);
    if bytes == 0 { 1 } else { bytes as usize }
}

/// Zig-zag encodes a signed integer without overflowing.
#[must_use]
pub const fn zig_zag_encode(value: i64) -> u64 {
    ((value << 1) ^ (value >> 63)).cast_unsigned()
}

/// Converts an enum/int32 value to its wire varint representation.
#[must_use]
pub fn int32_to_varint(value: i32) -> u64 {
    i64::from(value).cast_unsigned()
}

fn packed_converted_field_len(
    field_number: u32,
    values: impl Iterator<Item = u64>,
) -> Result<usize, EncodeError> {
    let mut packed = EncodedLength::new();
    for value in values {
        packed.add(varint_len(value))?;
    }
    bytes_field_len(field_number, packed.get())
}

fn varint_len_usize(value: usize) -> usize {
    varint_len(value as u64)
}
