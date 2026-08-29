// SPDX-License-Identifier: GPL-2.0-only

//! Allocation-safe framing that always runs semantic validation.

use prost::Message;
use thiserror::Error;

use crate::v1::{ControlEnvelope, DataControlEnvelope, DataFrame, FederationEnvelope};
use crate::validation::{
    validate_control_envelope, validate_data_control_envelope, validate_data_frame,
    validate_federation_envelope,
};

const FRAME_PREFIX_BYTES: usize = 4;
const HARD_MAXIMUM_CONTROL_BYTES: usize = 16 * 1_024 * 1_024;
const HARD_MAXIMUM_DATA_FRAME_BYTES: usize = 8 * 1_024 * 1_024;
const HARD_MAXIMUM_ITEMS: usize = 65_536;
const HARD_MAXIMUM_TEXT_BYTES: usize = 16 * 1_024;

/// Negotiated bounds constrained by non-configurable implementation ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WireLimits {
    control_bytes: usize,
    data_frame_bytes: usize,
    items: usize,
    text_bytes: usize,
}

impl WireLimits {
    /// Constructs useful limits no larger than compiled safety ceilings.
    ///
    /// # Errors
    ///
    /// Rejects zero values and values beyond compiled allocation ceilings.
    pub const fn new(
        maximum_control_bytes: usize,
        maximum_data_frame_bytes: usize,
        maximum_items: usize,
        maximum_text_bytes: usize,
    ) -> Result<Self, WireContractError> {
        let invalid = maximum_control_bytes == 0
            || maximum_control_bytes > HARD_MAXIMUM_CONTROL_BYTES
            || maximum_data_frame_bytes == 0
            || maximum_data_frame_bytes > HARD_MAXIMUM_DATA_FRAME_BYTES
            || maximum_items == 0
            || maximum_items > HARD_MAXIMUM_ITEMS
            || maximum_text_bytes == 0
            || maximum_text_bytes > HARD_MAXIMUM_TEXT_BYTES;
        if invalid {
            Err(WireContractError::InvalidLimits)
        } else {
            Ok(Self {
                control_bytes: maximum_control_bytes,
                data_frame_bytes: maximum_data_frame_bytes,
                items: maximum_items,
                text_bytes: maximum_text_bytes,
            })
        }
    }

    /// Maximum encoded control payload bytes.
    #[must_use]
    pub const fn maximum_control_bytes(self) -> usize {
        self.control_bytes
    }

    /// Maximum bytes carried by one bulk data frame.
    #[must_use]
    pub const fn maximum_data_frame_bytes(self) -> usize {
        self.data_frame_bytes
    }

    /// Maximum items accepted in any repeated field.
    #[must_use]
    pub const fn maximum_items(self) -> usize {
        self.items
    }

    /// Maximum UTF-8 bytes accepted in any text field.
    #[must_use]
    pub const fn maximum_text_bytes(self) -> usize {
        self.text_bytes
    }
}

/// A control envelope that passed framing and all current semantic bounds.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedControlEnvelope(ControlEnvelope);

impl ValidatedControlEnvelope {
    /// Borrows the generated message after validation.
    #[must_use]
    pub const fn as_inner(&self) -> &ControlEnvelope {
        &self.0
    }

    /// Consumes the proof wrapper and returns the generated message.
    #[must_use]
    pub fn into_inner(self) -> ControlEnvelope {
        self.0
    }
}

/// A bulk frame that passed its independent encoded and payload limits.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedDataFrame(DataFrame);

impl ValidatedDataFrame {
    /// Borrows the generated data frame after validation.
    #[must_use]
    pub const fn as_inner(&self) -> &DataFrame {
        &self.0
    }

    /// Consumes the proof wrapper and returns the generated data frame.
    #[must_use]
    pub fn into_inner(self) -> DataFrame {
        self.0
    }
}

/// A data-stream control envelope that passed framing and semantic validation.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedDataControlEnvelope(DataControlEnvelope);

impl ValidatedDataControlEnvelope {
    /// Borrows the generated message after validation.
    #[must_use]
    pub const fn as_inner(&self) -> &DataControlEnvelope {
        &self.0
    }

    /// Consumes the proof wrapper and returns the generated message.
    #[must_use]
    pub fn into_inner(self) -> DataControlEnvelope {
        self.0
    }
}

/// A cross-swarm envelope that passed framing and federation-specific validation.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedFederationEnvelope(FederationEnvelope);

impl ValidatedFederationEnvelope {
    /// Borrows the generated message after validation.
    #[must_use]
    pub const fn as_inner(&self) -> &FederationEnvelope {
        &self.0
    }

    /// Consumes the proof wrapper and returns the generated message.
    #[must_use]
    pub fn into_inner(self) -> FederationEnvelope {
        self.0
    }
}

/// Stable rejection categories for hostile private-wire bytes.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WireContractError {
    /// Configured bounds are zero or exceed compiled safety ceilings.
    #[error("wire limits are invalid")]
    InvalidLimits,
    /// The frame is shorter than its mandatory length prefix.
    #[error("wire frame is truncated")]
    Truncated,
    /// The declared or actual encoded payload exceeds the negotiated limit.
    #[error("wire frame exceeds its negotiated limit")]
    FrameTooLarge,
    /// The declared frame length does not exactly match the received bytes.
    #[error("wire frame length does not match its prefix")]
    LengthMismatch,
    /// Protobuf bytes are malformed.
    #[error("wire payload is malformed")]
    Malformed,
    /// A decoded field is absent, unknown, excessive or semantically invalid.
    #[error("wire message is invalid")]
    InvalidMessage,
}

/// Validates and length-prefixes one outgoing control envelope.
///
/// # Errors
///
/// Rejects every semantically invalid value or encoded payload beyond negotiated limits.
pub fn encode_control_frame(
    envelope: &ControlEnvelope,
    limits: WireLimits,
) -> Result<Vec<u8>, WireContractError> {
    validate_control_envelope(envelope, limits)?;
    encode_prefixed(envelope, limits.control_bytes)
}

/// Decodes one exactly framed control message and returns only a validated wrapper.
///
/// # Errors
///
/// Rejects truncation and excess before Protobuf allocation, then validates every field.
pub fn decode_control_frame(
    frame: &[u8],
    limits: WireLimits,
) -> Result<ValidatedControlEnvelope, WireContractError> {
    let payload = payload_after_prefix(frame, limits.control_bytes)?;
    let envelope = ControlEnvelope::decode(payload).map_err(|_| WireContractError::Malformed)?;
    validate_control_envelope(&envelope, limits)?;
    Ok(ValidatedControlEnvelope(envelope))
}

/// Validates and length-prefixes one outgoing data-stream control envelope.
///
/// # Errors
///
/// Rejects every invalid value or encoded payload beyond the control-message limit.
pub fn encode_data_control_frame(
    envelope: &DataControlEnvelope,
    limits: WireLimits,
) -> Result<Vec<u8>, WireContractError> {
    validate_data_control_envelope(envelope, limits)?;
    encode_prefixed(envelope, limits.control_bytes)
}

/// Decodes one data-stream control message and returns only a validated wrapper.
///
/// # Errors
///
/// Rejects truncation and excess before allocation, then validates every field.
pub fn decode_data_control_frame(
    frame: &[u8],
    limits: WireLimits,
) -> Result<ValidatedDataControlEnvelope, WireContractError> {
    let payload = payload_after_prefix(frame, limits.control_bytes)?;
    let envelope =
        DataControlEnvelope::decode(payload).map_err(|_| WireContractError::Malformed)?;
    validate_data_control_envelope(&envelope, limits)?;
    Ok(ValidatedDataControlEnvelope(envelope))
}

/// Validates and length-prefixes one outgoing cross-swarm federation envelope.
///
/// # Errors
///
/// Rejects every invalid value or encoded payload beyond the control-message limit.
pub fn encode_federation_frame(
    envelope: &FederationEnvelope,
    limits: WireLimits,
) -> Result<Vec<u8>, WireContractError> {
    validate_federation_envelope(envelope, limits)?;
    encode_prefixed(envelope, limits.control_bytes)
}

/// Decodes one cross-swarm message and returns only a federation-validated wrapper.
///
/// # Errors
///
/// Rejects truncation and excess before allocation, then validates every authority-bound field.
pub fn decode_federation_frame(
    frame: &[u8],
    limits: WireLimits,
) -> Result<ValidatedFederationEnvelope, WireContractError> {
    let payload = payload_after_prefix(frame, limits.control_bytes)?;
    let envelope = FederationEnvelope::decode(payload).map_err(|_| WireContractError::Malformed)?;
    validate_federation_envelope(&envelope, limits)?;
    Ok(ValidatedFederationEnvelope(envelope))
}

/// Validates and length-prefixes one outgoing bulk data frame.
///
/// # Errors
///
/// Rejects empty or excessive frame bytes and excessive encoded overhead.
pub fn encode_data_frame(
    frame: &DataFrame,
    limits: WireLimits,
) -> Result<Vec<u8>, WireContractError> {
    validate_data_frame(frame, limits)?;
    let encoded_limit = limits
        .data_frame_bytes
        .checked_add(32)
        .ok_or(WireContractError::FrameTooLarge)?;
    encode_prefixed(frame, encoded_limit)
}

/// Decodes one exactly framed bulk data message behind independent bounds.
///
/// # Errors
///
/// Rejects truncation and excess before allocation, then validates the payload bound.
pub fn decode_data_frame(
    frame: &[u8],
    limits: WireLimits,
) -> Result<ValidatedDataFrame, WireContractError> {
    let encoded_limit = limits
        .data_frame_bytes
        .checked_add(32)
        .ok_or(WireContractError::FrameTooLarge)?;
    let payload = payload_after_prefix(frame, encoded_limit)?;
    let data_frame = DataFrame::decode(payload).map_err(|_| WireContractError::Malformed)?;
    validate_data_frame(&data_frame, limits)?;
    Ok(ValidatedDataFrame(data_frame))
}

fn encode_prefixed(
    message: &impl Message,
    maximum_bytes: usize,
) -> Result<Vec<u8>, WireContractError> {
    let encoded_length = message.encoded_len();
    if encoded_length == 0 || encoded_length > maximum_bytes {
        return Err(WireContractError::FrameTooLarge);
    }
    let prefix = u32::try_from(encoded_length).map_err(|_| WireContractError::FrameTooLarge)?;
    let capacity = encoded_length
        .checked_add(FRAME_PREFIX_BYTES)
        .ok_or(WireContractError::FrameTooLarge)?;
    let mut encoded = Vec::with_capacity(capacity);
    encoded.extend_from_slice(&prefix.to_be_bytes());
    message
        .encode(&mut encoded)
        .map_err(|_| WireContractError::Malformed)?;
    Ok(encoded)
}

fn payload_after_prefix(frame: &[u8], maximum_bytes: usize) -> Result<&[u8], WireContractError> {
    let prefix: [u8; FRAME_PREFIX_BYTES] = frame
        .get(..FRAME_PREFIX_BYTES)
        .ok_or(WireContractError::Truncated)?
        .try_into()
        .map_err(|_| WireContractError::Truncated)?;
    let declared = usize::try_from(u32::from_be_bytes(prefix))
        .map_err(|_| WireContractError::FrameTooLarge)?;
    if declared == 0 || declared > maximum_bytes {
        return Err(WireContractError::FrameTooLarge);
    }
    let expected = declared
        .checked_add(FRAME_PREFIX_BYTES)
        .ok_or(WireContractError::FrameTooLarge)?;
    if frame.len() != expected {
        return Err(WireContractError::LengthMismatch);
    }
    Ok(&frame[FRAME_PREFIX_BYTES..])
}
