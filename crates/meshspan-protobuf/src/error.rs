// SPDX-License-Identifier: GPL-2.0-only

//! Stable codec failure kinds without input disclosure.

use core::fmt;

/// A stable hostile-input decoding failure kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeErrorKind {
    /// The complete input exceeds the configured message bound.
    MessageTooLarge,
    /// One length-delimited value exceeds its configured bound.
    FieldTooLarge,
    /// The message contains too many encoded fields.
    TooManyFields,
    /// A repeated field contains too many values.
    TooManyItems,
    /// Nested messages or groups exceed the configured depth.
    RecursionLimit,
    /// A varint is truncated or exceeds its type's wire width.
    InvalidVarint,
    /// A field key has an invalid number or wire type.
    InvalidKey,
    /// The wire type does not match the schema field.
    WrongWireType,
    /// A fixed-width or length-delimited value is truncated.
    Truncated,
    /// A string field is not valid UTF-8.
    InvalidUtf8,
    /// A deprecated group has no matching end marker.
    UnterminatedGroup,
    /// Length arithmetic cannot be represented by this process.
    LengthOverflow,
}

/// A decoding error carrying only stable kind and byte offset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeError {
    kind: DecodeErrorKind,
    offset: usize,
}

impl DecodeError {
    /// Creates an error at the byte offset where validation failed.
    #[must_use]
    pub const fn new(kind: DecodeErrorKind, offset: usize) -> Self {
        Self { kind, offset }
    }

    /// Returns the stable failure kind.
    #[must_use]
    pub const fn kind(self) -> DecodeErrorKind {
        self.kind
    }

    /// Returns the byte offset where validation failed.
    #[must_use]
    pub const fn offset(self) -> usize {
        self.offset
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Protocol Buffers decode failed at byte {}: {:?}",
            self.offset, self.kind
        )
    }
}

impl std::error::Error for DecodeError {}

/// A fallible encoding failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// Encoded length arithmetic overflowed `usize`.
    LengthOverflow,
    /// Exact output reservation failed.
    AllocationFailed,
    /// Generated length and write implementations disagree.
    LengthMismatch,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Protocol Buffers encode failed: {self:?}")
    }
}

impl std::error::Error for EncodeError {}
