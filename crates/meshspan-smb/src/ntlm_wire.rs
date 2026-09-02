// SPDX-License-Identifier: GPL-2.0-only

//! Strict `NTLMv2` negotiate, challenge and authenticate message semantics.

use crate::{NtlmPasswordVerifier, NtlmSessionBaseKey, NtlmVerificationError};

const NTLM_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";
const NEGOTIATE_MESSAGE: u32 = 1;
const CHALLENGE_MESSAGE: u32 = 2;
const AUTHENTICATE_MESSAGE: u32 = 3;
const NEGOTIATE_FIXED_LENGTH: usize = 32;
const CHALLENGE_FIXED_LENGTH: usize = 48;
const AUTHENTICATE_FIXED_LENGTH: usize = 64;
const MAXIMUM_MESSAGE_LENGTH: usize = u16::MAX as usize;
const MAXIMUM_IDENTITY_UNITS: usize = 256;
const MAXIMUM_AV_PAIRS: usize = 32;

const NEGOTIATE_UNICODE: u32 = 0x0000_0001;
const REQUEST_TARGET: u32 = 0x0000_0004;
const NEGOTIATE_DATAGRAM: u32 = 0x0000_0040;
const NEGOTIATE_LM_KEY: u32 = 0x0000_0080;
const NEGOTIATE_NTLM: u32 = 0x0000_0200;
const NEGOTIATE_ANONYMOUS: u32 = 0x0000_0800;
const NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;
const TARGET_TYPE_SERVER: u32 = 0x0002_0000;
const NEGOTIATE_EXTENDED_SESSION_SECURITY: u32 = 0x0008_0000;
const REQUEST_NON_NT_SESSION_KEY: u32 = 0x0040_0000;
const NEGOTIATE_TARGET_INFO: u32 = 0x0080_0000;
const NEGOTIATE_VERSION: u32 = 0x0200_0000;
const NEGOTIATE_128: u32 = 0x2000_0000;
const NEGOTIATE_KEY_EXCHANGE: u32 = 0x4000_0000;
const NEGOTIATE_56: u32 = 0x8000_0000;

const REQUIRED_CLIENT_FLAGS: u32 =
    NEGOTIATE_UNICODE | REQUEST_TARGET | NEGOTIATE_NTLM | NEGOTIATE_EXTENDED_SESSION_SECURITY;
const FORBIDDEN_CLIENT_FLAGS: u32 =
    NEGOTIATE_DATAGRAM | NEGOTIATE_LM_KEY | NEGOTIATE_ANONYMOUS | REQUEST_NON_NT_SESSION_KEY;
const SERVER_FLAGS: u32 = NEGOTIATE_UNICODE
    | REQUEST_TARGET
    | NEGOTIATE_NTLM
    | NEGOTIATE_ALWAYS_SIGN
    | TARGET_TYPE_SERVER
    | NEGOTIATE_EXTENDED_SESSION_SECURITY
    | NEGOTIATE_TARGET_INFO;

const MSV_AV_EOL: u16 = 0;
const MSV_AV_NB_COMPUTER_NAME: u16 = 1;
const MSV_AV_NB_DOMAIN_NAME: u16 = 2;
const MSV_AV_DNS_COMPUTER_NAME: u16 = 3;
const MSV_AV_DNS_DOMAIN_NAME: u16 = 4;
const HIGHEST_KNOWN_AV_ID: u16 = 10;

/// Validated client NTLM capabilities used to construct one challenge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NtlmNegotiate {
    flags: u32,
}

impl NtlmNegotiate {
    /// Parses a complete NTLM negotiate message and rejects legacy downgrade modes.
    ///
    /// # Errors
    ///
    /// Rejects invalid signatures/types, unsupported flags and hostile security buffers.
    pub fn parse(message: &[u8]) -> Result<Self, NtlmWireError> {
        validate_message(message, NEGOTIATE_MESSAGE, NEGOTIATE_FIXED_LENGTH)?;
        let flags = read_u32(message, 12)?;
        if flags & REQUIRED_CLIENT_FLAGS != REQUIRED_CLIENT_FLAGS
            || flags & FORBIDDEN_CLIENT_FLAGS != 0
        {
            return Err(NtlmWireError::UnsupportedFlags);
        }
        validate_optional_buffer(message, 16, flags & 0x0000_1000 != 0)?;
        validate_optional_buffer(message, 24, flags & 0x0000_2000 != 0)?;
        if flags & NEGOTIATE_VERSION != 0 && message.len() < 40 {
            return Err(NtlmWireError::Truncated);
        }
        Ok(Self { flags })
    }
}

/// Server-owned values encoded into an `NTLMv2` challenge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NtlmChallengeConfig<'a> {
    /// Fresh connection/session-specific challenge that must not be all zeroes.
    pub server_challenge: [u8; 8],
    /// SMB server's NetBIOS-compatible name.
    pub computer_name: &'a str,
    /// Authentication realm shown to ordinary clients.
    pub domain_name: &'a str,
    /// Optional DNS server name.
    pub dns_computer_name: Option<&'a str>,
    /// Optional DNS realm name.
    pub dns_domain_name: Option<&'a str>,
}

/// Exact server challenge plus the target constraints required in the client proof.
pub struct NtlmChallenge {
    message: Vec<u8>,
    server_challenge: [u8; 8],
    flags: u32,
    required_target_info: Vec<AvPair>,
}

impl NtlmChallenge {
    /// Constructs a canonical NTLMv2-only challenge from one validated offer.
    ///
    /// # Errors
    ///
    /// Rejects blank/oversized names, a zero challenge or a message beyond wire bounds.
    pub fn encode(
        negotiate: NtlmNegotiate,
        config: NtlmChallengeConfig<'_>,
    ) -> Result<Self, NtlmWireError> {
        if config.server_challenge == [0; 8] {
            return Err(NtlmWireError::InvalidChallenge);
        }
        let target_name = utf16(config.domain_name, false)?;
        let mut required_target_info = vec![
            AvPair::text(MSV_AV_NB_COMPUTER_NAME, config.computer_name)?,
            AvPair::text(MSV_AV_NB_DOMAIN_NAME, config.domain_name)?,
        ];
        if let Some(name) = config.dns_computer_name {
            required_target_info.push(AvPair::text(MSV_AV_DNS_COMPUTER_NAME, name)?);
        }
        if let Some(name) = config.dns_domain_name {
            required_target_info.push(AvPair::text(MSV_AV_DNS_DOMAIN_NAME, name)?);
        }
        let target_info = encode_av_pairs(&required_target_info)?;
        let flags = SERVER_FLAGS
            | negotiate.flags
                & (NEGOTIATE_128 | NEGOTIATE_56)
                & !NEGOTIATE_KEY_EXCHANGE
                & !NEGOTIATE_VERSION;
        let target_name_offset = CHALLENGE_FIXED_LENGTH;
        let target_info_offset = target_name_offset
            .checked_add(target_name.len())
            .ok_or(NtlmWireError::MessageTooLarge)?;
        let mut message = vec![0; CHALLENGE_FIXED_LENGTH];
        message[..8].copy_from_slice(NTLM_SIGNATURE);
        message[8..12].copy_from_slice(&CHALLENGE_MESSAGE.to_le_bytes());
        write_security_buffer(&mut message, 12, target_name.len(), target_name_offset)?;
        message[20..24].copy_from_slice(&flags.to_le_bytes());
        message[24..32].copy_from_slice(&config.server_challenge);
        write_security_buffer(&mut message, 40, target_info.len(), target_info_offset)?;
        message.extend_from_slice(&target_name);
        message.extend_from_slice(&target_info);
        if message.len() > MAXIMUM_MESSAGE_LENGTH {
            return Err(NtlmWireError::MessageTooLarge);
        }
        Ok(Self {
            message,
            server_challenge: config.server_challenge,
            flags,
            required_target_info,
        })
    }

    /// Returns the exact immutable challenge bytes for SPNEGO and transcript binding.
    #[must_use]
    pub fn message(&self) -> &[u8] {
        &self.message
    }
}

/// Validated identity and `NTLMv2` proof extracted from an authenticate message.
pub struct NtlmAuthenticate<'a> {
    /// Exact user name supplied by the SMB client.
    pub username: String,
    /// Exact authentication realm supplied by the SMB client.
    pub domain: String,
    nt_challenge_response: &'a [u8],
}

impl<'a> NtlmAuthenticate<'a> {
    /// Parses a final authenticate message against the exact issued challenge.
    ///
    /// # Errors
    ///
    /// Rejects legacy responses, malformed/overlapping buffers, invalid UTF-16,
    /// flag downgrades, key-exchange material and changed target information.
    pub fn parse(message: &'a [u8], challenge: &NtlmChallenge) -> Result<Self, NtlmWireError> {
        validate_message(message, AUTHENTICATE_MESSAGE, AUTHENTICATE_FIXED_LENGTH)?;
        let flags = read_u32(message, 60)?;
        if flags & challenge.flags != challenge.flags
            || flags & FORBIDDEN_CLIENT_FLAGS != 0
            || flags & NEGOTIATE_KEY_EXCHANGE != 0
        {
            return Err(NtlmWireError::UnsupportedFlags);
        }
        let lm_response = security_buffer(message, 12, false)?;
        if !(lm_response.is_empty()
            || lm_response.len() == 24 && lm_response.iter().all(|byte| *byte == 0))
        {
            return Err(NtlmWireError::LegacyResponseForbidden);
        }
        let nt_challenge_response = security_buffer(message, 20, true)?;
        if nt_challenge_response.len() < 48 {
            return Err(NtlmWireError::InvalidNtlmV2Response);
        }
        let domain = decode_utf16(security_buffer(message, 28, false)?, true)?;
        let username = decode_utf16(security_buffer(message, 36, true)?, false)?;
        let _workstation = decode_utf16(security_buffer(message, 44, false)?, true)?;
        if !security_buffer(message, 52, false)?.is_empty() {
            return Err(NtlmWireError::UnexpectedSessionKey);
        }
        validate_client_target_info(nt_challenge_response, &challenge.required_target_info)?;
        Ok(Self {
            username,
            domain,
            nt_challenge_response,
        })
    }

    /// Verifies possession of one ordinary API-key-backed verifier.
    ///
    /// # Errors
    ///
    /// Returns the exact NTLM proof failure without exposing verifier material.
    pub fn verify(
        &self,
        verifier: &NtlmPasswordVerifier,
        challenge: &NtlmChallenge,
    ) -> Result<NtlmSessionBaseKey, NtlmVerificationError> {
        verifier.verify_ntlm_v2(
            &self.username,
            &self.domain,
            challenge.server_challenge,
            self.nt_challenge_response,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AvPair {
    id: u16,
    value: Vec<u8>,
}

impl AvPair {
    fn text(id: u16, value: &str) -> Result<Self, NtlmWireError> {
        Ok(Self {
            id,
            value: utf16(value, false)?,
        })
    }
}

#[derive(Clone, Copy)]
struct SecurityBuffer {
    length: usize,
    maximum_length: usize,
    offset: usize,
}

fn validate_message(
    message: &[u8],
    expected_type: u32,
    minimum_length: usize,
) -> Result<(), NtlmWireError> {
    if message.len() < minimum_length {
        return Err(NtlmWireError::Truncated);
    }
    if message.len() > MAXIMUM_MESSAGE_LENGTH {
        return Err(NtlmWireError::MessageTooLarge);
    }
    if message.get(..8) != Some(NTLM_SIGNATURE) {
        return Err(NtlmWireError::InvalidSignature);
    }
    if read_u32(message, 8)? != expected_type {
        return Err(NtlmWireError::WrongMessageType);
    }
    Ok(())
}

fn validate_optional_buffer(
    message: &[u8],
    field_offset: usize,
    supplied: bool,
) -> Result<(), NtlmWireError> {
    let field = read_security_buffer(message, field_offset)?;
    if !supplied && field.length != 0 {
        return Err(NtlmWireError::InvalidSecurityBuffer);
    }
    validate_buffer_range(message, field, false).map(|_| ())
}

fn security_buffer(
    message: &[u8],
    field_offset: usize,
    required: bool,
) -> Result<&[u8], NtlmWireError> {
    validate_buffer_range(
        message,
        read_security_buffer(message, field_offset)?,
        required,
    )
}

fn read_security_buffer(
    message: &[u8],
    field_offset: usize,
) -> Result<SecurityBuffer, NtlmWireError> {
    Ok(SecurityBuffer {
        length: usize::from(read_u16(message, field_offset)?),
        maximum_length: usize::from(read_u16(message, field_offset + 2)?),
        offset: usize::try_from(read_u32(message, field_offset + 4)?)
            .map_err(|_| NtlmWireError::InvalidSecurityBuffer)?,
    })
}

fn validate_buffer_range(
    message: &[u8],
    field: SecurityBuffer,
    required: bool,
) -> Result<&[u8], NtlmWireError> {
    if field.length > field.maximum_length || (required && field.length == 0) {
        return Err(NtlmWireError::InvalidSecurityBuffer);
    }
    if field.length == 0 {
        return Ok(&[]);
    }
    let end = field
        .offset
        .checked_add(field.length)
        .ok_or(NtlmWireError::InvalidSecurityBuffer)?;
    message
        .get(field.offset..end)
        .ok_or(NtlmWireError::InvalidSecurityBuffer)
}

fn write_security_buffer(
    message: &mut [u8],
    field_offset: usize,
    length: usize,
    payload_offset: usize,
) -> Result<(), NtlmWireError> {
    let length = u16::try_from(length).map_err(|_| NtlmWireError::MessageTooLarge)?;
    let payload_offset =
        u32::try_from(payload_offset).map_err(|_| NtlmWireError::MessageTooLarge)?;
    message[field_offset..field_offset + 2].copy_from_slice(&length.to_le_bytes());
    message[field_offset + 2..field_offset + 4].copy_from_slice(&length.to_le_bytes());
    message[field_offset + 4..field_offset + 8].copy_from_slice(&payload_offset.to_le_bytes());
    Ok(())
}

fn utf16(value: &str, allow_empty: bool) -> Result<Vec<u8>, NtlmWireError> {
    let units = value.encode_utf16().collect::<Vec<_>>();
    if (!allow_empty && units.is_empty()) || units.len() > MAXIMUM_IDENTITY_UNITS {
        return Err(NtlmWireError::InvalidIdentity);
    }
    Ok(units
        .into_iter()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>())
}

fn decode_utf16(bytes: &[u8], allow_empty: bool) -> Result<String, NtlmWireError> {
    if !bytes.len().is_multiple_of(2) {
        return Err(NtlmWireError::InvalidIdentity);
    }
    let units = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|bytes| u16::from_le_bytes(*bytes))
        .collect::<Vec<_>>();
    if (!allow_empty && units.is_empty()) || units.len() > MAXIMUM_IDENTITY_UNITS {
        return Err(NtlmWireError::InvalidIdentity);
    }
    String::from_utf16(&units).map_err(|_| NtlmWireError::InvalidIdentity)
}

fn encode_av_pairs(pairs: &[AvPair]) -> Result<Vec<u8>, NtlmWireError> {
    let mut output = Vec::new();
    for pair in pairs {
        output.extend_from_slice(&pair.id.to_le_bytes());
        output.extend_from_slice(
            &u16::try_from(pair.value.len())
                .map_err(|_| NtlmWireError::MessageTooLarge)?
                .to_le_bytes(),
        );
        output.extend_from_slice(&pair.value);
    }
    output.extend_from_slice(&[0; 4]);
    Ok(output)
}

fn validate_client_target_info(response: &[u8], required: &[AvPair]) -> Result<(), NtlmWireError> {
    let client_challenge = response
        .get(16..)
        .ok_or(NtlmWireError::InvalidNtlmV2Response)?;
    let av_end = client_challenge
        .len()
        .checked_sub(4)
        .filter(|end| *end >= 28)
        .ok_or(NtlmWireError::InvalidNtlmV2Response)?;
    let pairs = parse_av_pairs(&client_challenge[28..av_end])?;
    for expected in required {
        if !pairs
            .iter()
            .any(|actual| actual.id == expected.id && actual.value == expected.value)
        {
            return Err(NtlmWireError::TargetInfoMismatch);
        }
    }
    Ok(())
}

fn parse_av_pairs(mut bytes: &[u8]) -> Result<Vec<AvPair>, NtlmWireError> {
    let mut pairs = Vec::new();
    let mut terminated = false;
    while !bytes.is_empty() {
        if pairs.len() >= MAXIMUM_AV_PAIRS || bytes.len() < 4 {
            return Err(NtlmWireError::InvalidTargetInfo);
        }
        let id = u16::from_le_bytes(
            bytes[..2]
                .try_into()
                .map_err(|_| NtlmWireError::InvalidTargetInfo)?,
        );
        let length = usize::from(u16::from_le_bytes(
            bytes[2..4]
                .try_into()
                .map_err(|_| NtlmWireError::InvalidTargetInfo)?,
        ));
        bytes = &bytes[4..];
        if id == MSV_AV_EOL {
            if length != 0 || !bytes.is_empty() {
                return Err(NtlmWireError::InvalidTargetInfo);
            }
            terminated = true;
            break;
        }
        if id > HIGHEST_KNOWN_AV_ID || pairs.iter().any(|pair: &AvPair| pair.id == id) {
            return Err(NtlmWireError::InvalidTargetInfo);
        }
        let (value, remaining) = bytes
            .split_at_checked(length)
            .ok_or(NtlmWireError::InvalidTargetInfo)?;
        pairs.push(AvPair {
            id,
            value: value.to_vec(),
        });
        bytes = remaining;
    }
    if terminated {
        Ok(pairs)
    } else {
        Err(NtlmWireError::InvalidTargetInfo)
    }
}

fn read_u16(message: &[u8], offset: usize) -> Result<u16, NtlmWireError> {
    message
        .get(offset..offset + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(NtlmWireError::Truncated)
}

fn read_u32(message: &[u8], offset: usize) -> Result<u32, NtlmWireError> {
    message
        .get(offset..offset + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(NtlmWireError::Truncated)
}

/// Invalid or unsupported NTLM wire message.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NtlmWireError {
    /// Required fixed fields are absent.
    #[error("NTLM message is truncated")]
    Truncated,
    /// The NTLMSSP marker is absent.
    #[error("NTLM message signature is invalid")]
    InvalidSignature,
    /// The message phase is not the expected one.
    #[error("NTLM message type is invalid for this exchange")]
    WrongMessageType,
    /// Client flags request a legacy, anonymous or unsupported downgrade.
    #[error("NTLM negotiation flags are unsupported")]
    UnsupportedFlags,
    /// A payload security buffer is inconsistent or out of bounds.
    #[error("NTLM security buffer is invalid")]
    InvalidSecurityBuffer,
    /// The server challenge is the reserved all-zero value.
    #[error("NTLM server challenge is invalid")]
    InvalidChallenge,
    /// An identity string is blank, oversized or invalid UTF-16.
    #[error("NTLM identity is invalid")]
    InvalidIdentity,
    /// A legacy LM response was supplied instead of the NTLMv2-only profile.
    #[error("legacy NTLM response is forbidden")]
    LegacyResponseForbidden,
    /// The NT challenge response is too short to carry `NTLMv2` proof and target data.
    #[error("NTLMv2 response is invalid")]
    InvalidNtlmV2Response,
    /// Session-key exchange material appeared although key exchange was not negotiated.
    #[error("NTLM authenticate message contains an unexpected session key")]
    UnexpectedSessionKey,
    /// Client target information is malformed, duplicated or unterminated.
    #[error("NTLMv2 target information is invalid")]
    InvalidTargetInfo,
    /// Client target information did not preserve the issued server constraints.
    #[error("NTLMv2 target information does not match the challenge")]
    TargetInfoMismatch,
    /// The bounded NTLM token cannot fit its SMB security buffer.
    #[error("NTLM message exceeds its wire limit")]
    MessageTooLarge,
}

#[cfg(test)]
mod tests {
    use crate::NtlmPasswordVerifier;

    use super::{
        NtlmAuthenticate, NtlmChallenge, NtlmChallengeConfig, NtlmNegotiate, NtlmWireError,
        SERVER_FLAGS,
    };

    #[test]
    fn microsoft_ntlmv2_authenticate_vector_verifies_through_wire_messages()
    -> Result<(), Box<dyn std::error::Error>> {
        let negotiate = NtlmNegotiate::parse(&negotiate_message())?;
        let challenge = NtlmChallenge::encode(
            negotiate,
            NtlmChallengeConfig {
                server_challenge: hex8("0123456789abcdef"),
                computer_name: "Server",
                domain_name: "Domain",
                dns_computer_name: None,
                dns_domain_name: None,
            },
        )?;
        assert_eq!(&challenge.message()[..8], b"NTLMSSP\0");
        assert_eq!(&challenge.message()[8..12], &2_u32.to_le_bytes());
        let message = authenticate_message();
        let authenticate = NtlmAuthenticate::parse(&message, &challenge)?;
        assert_eq!(authenticate.username, "User");
        assert_eq!(authenticate.domain, "Domain");
        let verifier = NtlmPasswordVerifier::derive("Password")?;
        let session = authenticate.verify(&verifier, &challenge)?;
        assert_eq!(
            session.expose_for_derivation(),
            &hex16("8de40ccadbc14a82f15cb0ad0de95ca3")
        );
        Ok(())
    }

    #[test]
    fn legacy_flags_ranges_and_changed_target_info_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut legacy = negotiate_message();
        let flags = u32::from_le_bytes(legacy[12..16].try_into()?) | 0x40;
        legacy[12..16].copy_from_slice(&flags.to_le_bytes());
        assert_eq!(
            NtlmNegotiate::parse(&legacy),
            Err(NtlmWireError::UnsupportedFlags)
        );
        let negotiate = NtlmNegotiate::parse(&negotiate_message())?;
        let challenge = NtlmChallenge::encode(
            negotiate,
            NtlmChallengeConfig {
                server_challenge: hex8("0123456789abcdef"),
                computer_name: "Server",
                domain_name: "Domain",
                dns_computer_name: None,
                dns_domain_name: None,
            },
        )?;
        let mut changed = authenticate_message();
        let response_offset = usize::try_from(u32::from_le_bytes(changed[24..28].try_into()?))?;
        changed[response_offset + 16 + 28 + 4] ^= 1;
        assert!(matches!(
            NtlmAuthenticate::parse(&changed, &challenge),
            Err(NtlmWireError::TargetInfoMismatch)
        ));
        changed[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            NtlmAuthenticate::parse(&changed, &challenge),
            Err(NtlmWireError::InvalidSecurityBuffer)
        ));
        Ok(())
    }

    fn negotiate_message() -> Vec<u8> {
        let mut message = vec![0; 32];
        message[..8].copy_from_slice(b"NTLMSSP\0");
        message[8..12].copy_from_slice(&1_u32.to_le_bytes());
        message[12..16].copy_from_slice(&SERVER_FLAGS.to_le_bytes());
        message
    }

    fn authenticate_message() -> Vec<u8> {
        let mut response = Vec::from(hex16("68cd0ab851e51c96aabc927bebef6a1c"));
        let mut client = vec![1, 1, 0, 0, 0, 0, 0, 0];
        client.extend_from_slice(&[0; 8]);
        client.extend_from_slice(&[0xaa; 8]);
        client.extend_from_slice(&[0; 4]);
        append_av_pair(&mut client, 2, "Domain");
        append_av_pair(&mut client, 1, "Server");
        client.extend_from_slice(&[0; 8]);
        response.extend_from_slice(&client);

        let domain = utf16("Domain");
        let user = utf16("User");
        let mut message = vec![0; 64];
        message[..8].copy_from_slice(b"NTLMSSP\0");
        message[8..12].copy_from_slice(&3_u32.to_le_bytes());
        let domain_offset = 64;
        let user_offset = domain_offset + domain.len();
        let response_offset = user_offset + user.len();
        set_buffer(&mut message, 28, domain.len(), domain_offset);
        set_buffer(&mut message, 36, user.len(), user_offset);
        set_buffer(&mut message, 20, response.len(), response_offset);
        message[60..64].copy_from_slice(&SERVER_FLAGS.to_le_bytes());
        message.extend_from_slice(&domain);
        message.extend_from_slice(&user);
        message.extend_from_slice(&response);
        message
    }

    fn set_buffer(message: &mut [u8], offset: usize, length: usize, payload_offset: usize) {
        let length = u16::try_from(length).unwrap_or_default();
        message[offset..offset + 2].copy_from_slice(&length.to_le_bytes());
        message[offset + 2..offset + 4].copy_from_slice(&length.to_le_bytes());
        message[offset + 4..offset + 8].copy_from_slice(
            &u32::try_from(payload_offset)
                .unwrap_or_default()
                .to_le_bytes(),
        );
    }

    fn append_av_pair(output: &mut Vec<u8>, identifier: u16, value: &str) {
        let encoded = utf16(value);
        output.extend_from_slice(&identifier.to_le_bytes());
        output.extend_from_slice(&(u16::try_from(encoded.len()).unwrap_or_default()).to_le_bytes());
        output.extend_from_slice(&encoded);
    }

    fn utf16(value: &str) -> Vec<u8> {
        value.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    fn hex16(value: &str) -> [u8; 16] {
        decode_hex(value).try_into().unwrap_or_default()
    }

    fn hex8(value: &str) -> [u8; 8] {
        decode_hex(value).try_into().unwrap_or_default()
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let text = std::str::from_utf8(pair).unwrap_or_default();
                u8::from_str_radix(text, 16).unwrap_or_default()
            })
            .collect()
    }
}
