// SPDX-License-Identifier: GPL-2.0-only

//! Narrow, canonical SPNEGO token boundary for embedded NTLM authentication.

const NTLM_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";
const SPNEGO_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
const NTLM_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];
const MAXIMUM_TOKEN_LENGTH: usize = u16::MAX as usize;
const MAXIMUM_DER_LENGTH_BYTES: usize = 3;

/// NTLM message accepted from a client SPNEGO exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtlmTokenKind {
    /// Initial NTLM capabilities message.
    Negotiate,
    /// Final NTLM identity and proof message.
    Authenticate,
}

/// One exact NTLM token extracted from a bounded client security token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpnegoClientToken<'a> {
    /// NTLM phase encoded by the message type.
    pub kind: NtlmTokenKind,
    /// Exact NTLMSSP bytes retained for transcript/MIC verification.
    pub ntlm_message: &'a [u8],
    /// Whether the client used SPNEGO rather than its permitted raw NTLM path.
    pub wrapped: bool,
}

impl<'a> SpnegoClientToken<'a> {
    /// Parses a canonical SPNEGO initial/response token or permitted raw NTLM token.
    ///
    /// # Errors
    ///
    /// Rejects indefinite/non-canonical DER, unexpected mechanisms, duplicate or
    /// out-of-order fields, missing mechanism tokens and unsupported NTLM phases.
    pub fn parse(token: &'a [u8]) -> Result<Self, SpnegoTokenError> {
        if token.len() > MAXIMUM_TOKEN_LENGTH {
            return Err(SpnegoTokenError::TokenTooLarge);
        }
        if token.starts_with(NTLM_SIGNATURE) {
            return from_ntlm(token, false);
        }
        let mut root = DerReader::new(token);
        let top = root.read_any()?;
        root.finish()?;
        let ntlm = match top.tag {
            0x60 => parse_initial_context(top.value)?,
            0xa1 => parse_neg_token_response(top.value)?,
            _ => return Err(SpnegoTokenError::UnexpectedTag),
        };
        from_ntlm(ntlm, true)
    }
}

/// Encodes `NegTokenResp(accept-incomplete, NTLM, challenge)` canonically.
///
/// # Errors
///
/// Rejects a malformed NTLM challenge or output beyond the SMB token bound.
pub fn encode_spnego_challenge(ntlm_challenge: &[u8]) -> Result<Vec<u8>, SpnegoTokenError> {
    if ntlm_kind(ntlm_challenge)? != NtlmWireKind::Challenge {
        return Err(SpnegoTokenError::UnexpectedNtlmMessage);
    }
    let state = encode_explicit(0xa0, &encode_tlv(0x0a, &[1])?)?;
    let mechanism = encode_explicit(0xa1, &encode_tlv(0x06, NTLM_OID)?)?;
    let response = encode_explicit(0xa2, &encode_tlv(0x04, ntlm_challenge)?)?;
    let sequence = encode_tlv(0x30, &[state, mechanism, response].concat())?;
    ensure_output(encode_explicit(0xa1, &sequence)?)
}

/// Encodes `NegTokenResp(accept-complete)` canonically.
///
/// # Errors
///
/// Returns an error only if the fixed canonical token cannot be encoded.
pub fn encode_spnego_complete() -> Result<Vec<u8>, SpnegoTokenError> {
    let state = encode_explicit(0xa0, &encode_tlv(0x0a, &[0])?)?;
    let sequence = encode_tlv(0x30, &state)?;
    ensure_output(encode_explicit(0xa1, &sequence)?)
}

fn parse_initial_context(value: &[u8]) -> Result<&[u8], SpnegoTokenError> {
    let mut context = DerReader::new(value);
    let mechanism = context.read(0x06)?;
    if mechanism != SPNEGO_OID {
        return Err(SpnegoTokenError::WrongMechanism);
    }
    let negotiation = context.read(0xa0)?;
    context.finish()?;
    let mut explicit = DerReader::new(negotiation);
    let sequence = explicit.read(0x30)?;
    explicit.finish()?;
    parse_initial_sequence(sequence)
}

fn parse_initial_sequence(sequence: &[u8]) -> Result<&[u8], SpnegoTokenError> {
    let mut fields = DerReader::new(sequence);
    let mut last_tag = None;
    let mut supports_ntlm = false;
    let mut mechanism_token = None;
    while !fields.is_empty() {
        let field = fields.read_any()?;
        validate_context_field(field.tag, 0xa0, 0xa4, &mut last_tag)?;
        match field.tag {
            0xa0 => supports_ntlm = parse_mechanism_list(field.value)?,
            0xa2 => mechanism_token = Some(parse_explicit_octet(field.value)?),
            _ => validate_ignored_explicit(field.value)?,
        }
    }
    if !supports_ntlm {
        return Err(SpnegoTokenError::NtlmNotOffered);
    }
    mechanism_token.ok_or(SpnegoTokenError::MissingMechanismToken)
}

fn parse_neg_token_response(value: &[u8]) -> Result<&[u8], SpnegoTokenError> {
    let mut explicit = DerReader::new(value);
    let sequence = explicit.read(0x30)?;
    explicit.finish()?;
    let mut fields = DerReader::new(sequence);
    let mut last_tag = None;
    let mut response_token = None;
    while !fields.is_empty() {
        let field = fields.read_any()?;
        validate_context_field(field.tag, 0xa0, 0xa3, &mut last_tag)?;
        match field.tag {
            0xa0 => validate_negotiation_state(field.value)?,
            0xa1 => validate_supported_mechanism(field.value)?,
            0xa2 => response_token = Some(parse_explicit_octet(field.value)?),
            0xa3 => validate_ignored_explicit(field.value)?,
            _ => return Err(SpnegoTokenError::UnexpectedTag),
        }
    }
    response_token.ok_or(SpnegoTokenError::MissingMechanismToken)
}

fn parse_mechanism_list(value: &[u8]) -> Result<bool, SpnegoTokenError> {
    let mut explicit = DerReader::new(value);
    let list = explicit.read(0x30)?;
    explicit.finish()?;
    let mut mechanisms = DerReader::new(list);
    let mut found_ntlm = false;
    let mut count = 0_u8;
    while !mechanisms.is_empty() {
        let oid = mechanisms.read(0x06)?;
        count = count
            .checked_add(1)
            .filter(|count| *count <= 16)
            .ok_or(SpnegoTokenError::TooManyMechanisms)?;
        found_ntlm |= oid == NTLM_OID;
    }
    if count == 0 {
        return Err(SpnegoTokenError::NtlmNotOffered);
    }
    Ok(found_ntlm)
}

fn validate_negotiation_state(value: &[u8]) -> Result<(), SpnegoTokenError> {
    let mut explicit = DerReader::new(value);
    let state = explicit.read(0x0a)?;
    explicit.finish()?;
    if state.len() == 1 && state[0] <= 3 {
        Ok(())
    } else {
        Err(SpnegoTokenError::InvalidNegotiationState)
    }
}

fn validate_supported_mechanism(value: &[u8]) -> Result<(), SpnegoTokenError> {
    let mut explicit = DerReader::new(value);
    let mechanism = explicit.read(0x06)?;
    explicit.finish()?;
    if mechanism == NTLM_OID {
        Ok(())
    } else {
        Err(SpnegoTokenError::WrongMechanism)
    }
}

fn parse_explicit_octet(value: &[u8]) -> Result<&[u8], SpnegoTokenError> {
    let mut explicit = DerReader::new(value);
    let octets = explicit.read(0x04)?;
    explicit.finish()?;
    if octets.is_empty() {
        Err(SpnegoTokenError::MissingMechanismToken)
    } else {
        Ok(octets)
    }
}

fn validate_ignored_explicit(value: &[u8]) -> Result<(), SpnegoTokenError> {
    let mut explicit = DerReader::new(value);
    explicit.read_any()?;
    explicit.finish()
}

fn validate_context_field(
    tag: u8,
    minimum: u8,
    maximum: u8,
    last_tag: &mut Option<u8>,
) -> Result<(), SpnegoTokenError> {
    if !(minimum..=maximum).contains(&tag) {
        return Err(SpnegoTokenError::UnexpectedTag);
    }
    if last_tag.is_some_and(|last| tag <= last) {
        return Err(SpnegoTokenError::DuplicateOrOutOfOrderField);
    }
    *last_tag = Some(tag);
    Ok(())
}

fn from_ntlm(token: &[u8], wrapped: bool) -> Result<SpnegoClientToken<'_>, SpnegoTokenError> {
    let kind = match ntlm_kind(token)? {
        NtlmWireKind::Negotiate => NtlmTokenKind::Negotiate,
        NtlmWireKind::Authenticate => NtlmTokenKind::Authenticate,
        NtlmWireKind::Challenge => return Err(SpnegoTokenError::UnexpectedNtlmMessage),
    };
    Ok(SpnegoClientToken {
        kind,
        ntlm_message: token,
        wrapped,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NtlmWireKind {
    Negotiate,
    Challenge,
    Authenticate,
}

fn ntlm_kind(token: &[u8]) -> Result<NtlmWireKind, SpnegoTokenError> {
    if token.len() < 12 || token.get(..8) != Some(NTLM_SIGNATURE) {
        return Err(SpnegoTokenError::InvalidNtlmToken);
    }
    match u32::from_le_bytes(
        token[8..12]
            .try_into()
            .map_err(|_| SpnegoTokenError::InvalidNtlmToken)?,
    ) {
        1 => Ok(NtlmWireKind::Negotiate),
        2 => Ok(NtlmWireKind::Challenge),
        3 => Ok(NtlmWireKind::Authenticate),
        _ => Err(SpnegoTokenError::UnexpectedNtlmMessage),
    }
}

fn encode_explicit(tag: u8, value: &[u8]) -> Result<Vec<u8>, SpnegoTokenError> {
    encode_tlv(tag, value)
}

fn encode_tlv(tag: u8, value: &[u8]) -> Result<Vec<u8>, SpnegoTokenError> {
    let mut output = Vec::with_capacity(
        value
            .len()
            .checked_add(5)
            .ok_or(SpnegoTokenError::TokenTooLarge)?,
    );
    output.push(tag);
    encode_length(value.len(), &mut output)?;
    output.extend_from_slice(value);
    Ok(output)
}

fn encode_length(length: usize, output: &mut Vec<u8>) -> Result<(), SpnegoTokenError> {
    if length < 128 {
        output.push(u8::try_from(length).map_err(|_| SpnegoTokenError::TokenTooLarge)?);
        return Ok(());
    }
    let encoded = length.to_be_bytes();
    let first = encoded
        .iter()
        .position(|byte| *byte != 0)
        .ok_or(SpnegoTokenError::InvalidLength)?;
    let bytes = &encoded[first..];
    if bytes.len() > MAXIMUM_DER_LENGTH_BYTES {
        return Err(SpnegoTokenError::TokenTooLarge);
    }
    output.push(0x80 | u8::try_from(bytes.len()).map_err(|_| SpnegoTokenError::TokenTooLarge)?);
    output.extend_from_slice(bytes);
    Ok(())
}

fn ensure_output(output: Vec<u8>) -> Result<Vec<u8>, SpnegoTokenError> {
    if output.len() <= MAXIMUM_TOKEN_LENGTH {
        Ok(output)
    } else {
        Err(SpnegoTokenError::TokenTooLarge)
    }
}

#[derive(Clone, Copy)]
struct DerValue<'a> {
    tag: u8,
    value: &'a [u8],
}

struct DerReader<'a> {
    remaining: &'a [u8],
}

impl<'a> DerReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }

    fn read(&mut self, expected_tag: u8) -> Result<&'a [u8], SpnegoTokenError> {
        let value = self.read_any()?;
        if value.tag == expected_tag {
            Ok(value.value)
        } else {
            Err(SpnegoTokenError::UnexpectedTag)
        }
    }

    fn read_any(&mut self) -> Result<DerValue<'a>, SpnegoTokenError> {
        let (&tag, after_tag) = self
            .remaining
            .split_first()
            .ok_or(SpnegoTokenError::Truncated)?;
        let (length, length_bytes) = decode_length(after_tag)?;
        let value_start = 1_usize
            .checked_add(length_bytes)
            .ok_or(SpnegoTokenError::InvalidLength)?;
        let value_end = value_start
            .checked_add(length)
            .ok_or(SpnegoTokenError::InvalidLength)?;
        let value = self
            .remaining
            .get(value_start..value_end)
            .ok_or(SpnegoTokenError::Truncated)?;
        self.remaining = self
            .remaining
            .get(value_end..)
            .ok_or(SpnegoTokenError::Truncated)?;
        Ok(DerValue { tag, value })
    }

    fn finish(self) -> Result<(), SpnegoTokenError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(SpnegoTokenError::TrailingData)
        }
    }
}

fn decode_length(bytes: &[u8]) -> Result<(usize, usize), SpnegoTokenError> {
    let first = *bytes.first().ok_or(SpnegoTokenError::Truncated)?;
    if first & 0x80 == 0 {
        return Ok((usize::from(first), 1));
    }
    let count = usize::from(first & 0x7f);
    if count == 0 || count > MAXIMUM_DER_LENGTH_BYTES {
        return Err(SpnegoTokenError::InvalidLength);
    }
    let encoded = bytes.get(1..=count).ok_or(SpnegoTokenError::Truncated)?;
    if encoded[0] == 0 {
        return Err(SpnegoTokenError::NonCanonicalLength);
    }
    let length = encoded
        .iter()
        .try_fold(0_usize, |value, byte| {
            value
                .checked_mul(256)
                .and_then(|value| value.checked_add(usize::from(*byte)))
        })
        .ok_or(SpnegoTokenError::InvalidLength)?;
    if length < 128 {
        return Err(SpnegoTokenError::NonCanonicalLength);
    }
    Ok((length, count + 1))
}

/// Invalid or unsupported SPNEGO/NTLM token framing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SpnegoTokenError {
    /// The complete DER tag, length or value is absent.
    #[error("SPNEGO token is truncated")]
    Truncated,
    /// A DER length is indefinite, excessive or overflows local bounds.
    #[error("SPNEGO DER length is invalid")]
    InvalidLength,
    /// A long-form DER length was not minimally encoded.
    #[error("SPNEGO DER length is not canonical")]
    NonCanonicalLength,
    /// A required or permitted tag was not present at this position.
    #[error("SPNEGO token contains an unexpected tag")]
    UnexpectedTag,
    /// Bytes remained after one complete explicit value.
    #[error("SPNEGO token contains trailing data")]
    TrailingData,
    /// Context fields were duplicated or encoded in descending order.
    #[error("SPNEGO token fields are duplicated or out of order")]
    DuplicateOrOutOfOrderField,
    /// The SPNEGO or selected mechanism OID does not match the required value.
    #[error("SPNEGO token selected an unsupported mechanism")]
    WrongMechanism,
    /// The offered mechanism list is empty or omits NTLM.
    #[error("SPNEGO client did not offer NTLM")]
    NtlmNotOffered,
    /// The bounded mechanism count was exceeded.
    #[error("SPNEGO client offered too many mechanisms")]
    TooManyMechanisms,
    /// No optimistic or response mechanism token was supplied.
    #[error("SPNEGO mechanism token is missing")]
    MissingMechanismToken,
    /// The negotiation state is not one of RFC 4178's four values.
    #[error("SPNEGO negotiation state is invalid")]
    InvalidNegotiationState,
    /// The embedded token does not carry the NTLMSSP signature and type.
    #[error("SPNEGO embedded NTLM token is invalid")]
    InvalidNtlmToken,
    /// The NTLM message phase is not valid in this direction.
    #[error("SPNEGO embedded NTLM message type is unexpected")]
    UnexpectedNtlmMessage,
    /// The token exceeds the SMB security-buffer wire bound.
    #[error("SPNEGO token exceeds its wire limit")]
    TokenTooLarge,
}

#[cfg(test)]
mod tests {
    use super::{
        NtlmTokenKind, SpnegoClientToken, SpnegoTokenError, encode_spnego_challenge,
        encode_spnego_complete, encode_tlv,
    };

    #[test]
    fn initial_context_selects_ntlm_and_preserves_exact_message() -> Result<(), SpnegoTokenError> {
        let ntlm = ntlm_message(1);
        let mechanisms = encode_tlv(
            0x30,
            &[
                encode_tlv(0x06, &[0x2a, 0x03, 0x04])?,
                encode_tlv(
                    0x06,
                    &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a],
                )?,
            ]
            .concat(),
        )?;
        let mech_types = encode_tlv(0xa0, &mechanisms)?;
        let mech_token = encode_tlv(0xa2, &encode_tlv(0x04, &ntlm)?)?;
        let negotiation = encode_tlv(0xa0, &encode_tlv(0x30, &[mech_types, mech_token].concat())?)?;
        let mut contents = encode_tlv(0x06, &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02])?;
        contents.extend_from_slice(&negotiation);
        let token = encode_tlv(0x60, &contents)?;
        let parsed = SpnegoClientToken::parse(&token)?;
        assert_eq!(parsed.kind, NtlmTokenKind::Negotiate);
        assert_eq!(parsed.ntlm_message, ntlm);
        assert!(parsed.wrapped);
        Ok(())
    }

    #[test]
    fn response_and_raw_paths_reject_wrong_phases_and_noncanonical_lengths()
    -> Result<(), SpnegoTokenError> {
        let authenticate = ntlm_message(3);
        let response = encode_tlv(0xa2, &encode_tlv(0x04, &authenticate)?)?;
        let token = encode_tlv(0xa1, &encode_tlv(0x30, &response)?)?;
        let parsed = SpnegoClientToken::parse(&token)?;
        assert_eq!(parsed.kind, NtlmTokenKind::Authenticate);
        assert!(parsed.wrapped);
        let raw = SpnegoClientToken::parse(&authenticate)?;
        assert!(!raw.wrapped);
        assert_eq!(
            SpnegoClientToken::parse(&ntlm_message(2)),
            Err(SpnegoTokenError::UnexpectedNtlmMessage)
        );
        assert_eq!(
            SpnegoClientToken::parse(&[0x60, 0x81, 0x01, 0]),
            Err(SpnegoTokenError::NonCanonicalLength)
        );
        Ok(())
    }

    #[test]
    fn server_challenge_and_completion_are_exact_canonical_der() -> Result<(), SpnegoTokenError> {
        let challenge = encode_spnego_challenge(&ntlm_message(2))?;
        assert_eq!(challenge[0], 0xa1);
        assert!(challenge.windows(10).any(|window| {
            window == [0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a]
        }));
        assert_eq!(
            encode_spnego_complete()?,
            [0xa1, 7, 0x30, 5, 0xa0, 3, 0x0a, 1, 0]
        );
        Ok(())
    }

    fn ntlm_message(message_type: u32) -> Vec<u8> {
        let mut message = b"NTLMSSP\0".to_vec();
        message.extend_from_slice(&message_type.to_le_bytes());
        message
    }
}
