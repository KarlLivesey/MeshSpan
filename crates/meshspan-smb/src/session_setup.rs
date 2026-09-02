// SPDX-License-Identifier: GPL-2.0-only

//! SMB 3.1.1 session-setup framing around an opaque bounded GSS token.

use crate::{Smb2Command, Smb2Header, Smb2HeaderError};

const SMB2_HEADER_LENGTH: usize = 64;
const REQUEST_FIXED_END: usize = 88;
const RESPONSE_BUFFER_OFFSET: u16 = 72;
const REQUEST_STRUCTURE_SIZE: u16 = 25;
const RESPONSE_STRUCTURE_SIZE: u16 = 9;
const SESSION_BINDING: u8 = 0x01;
const SIGNING_ENABLED: u8 = 0x01;
const SIGNING_REQUIRED: u8 = 0x02;
const ALLOWED_SECURITY_MODE: u8 = SIGNING_ENABLED | SIGNING_REQUIRED;
const ALLOWED_CAPABILITIES: u32 = 0x0000_000f;
const SESSION_FLAG_ENCRYPT_DATA: u16 = 0x0004;
const MAXIMUM_SECURITY_TOKEN_LENGTH: usize = u16::MAX as usize;

/// Validated fields of one SMB 3.1.1 `SESSION_SETUP` request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionSetupRequest<'a> {
    /// Parsed synchronous SMB2 request header.
    pub header: Smb2Header,
    /// Whether this request binds an existing session to another channel.
    pub binding: bool,
    /// Whether the client requires message signing.
    pub signing_required: bool,
    /// Client-advertised capabilities retained for policy decisions.
    pub capabilities: u32,
    /// Previous disconnected session to retire after successful authentication.
    pub previous_session_id: u64,
    /// Exact bounded SPNEGO/GSS token bytes.
    pub security_token: &'a [u8],
}

impl<'a> SessionSetupRequest<'a> {
    /// Parses a complete request and bounds its security token before GSS dispatch.
    ///
    /// # Errors
    ///
    /// Rejects malformed headers, reserved flags/capabilities, invalid binding
    /// transitions, empty or out-of-range security buffers and wrong commands.
    pub fn parse(packet: &'a [u8]) -> Result<Self, SmbSessionSetupError> {
        let header = Smb2Header::parse_request(packet)?;
        if header.command != Smb2Command::SessionSetup {
            return Err(SmbSessionSetupError::WrongCommand);
        }
        let command_end = command_end(packet, header.next_command)?;
        if command_end < REQUEST_FIXED_END {
            return Err(SmbSessionSetupError::Truncated);
        }
        if read_u16(packet, SMB2_HEADER_LENGTH)? != REQUEST_STRUCTURE_SIZE {
            return Err(SmbSessionSetupError::InvalidStructureSize);
        }
        let flags = packet[66];
        if flags & !SESSION_BINDING != 0 {
            return Err(SmbSessionSetupError::InvalidFlags);
        }
        let security_mode = packet[67];
        if security_mode == 0 || security_mode & !ALLOWED_SECURITY_MODE != 0 {
            return Err(SmbSessionSetupError::InvalidSecurityMode);
        }
        let capabilities = read_u32(packet, 68)?;
        if capabilities & !ALLOWED_CAPABILITIES != 0 {
            return Err(SmbSessionSetupError::InvalidCapabilities);
        }
        let binding = flags & SESSION_BINDING != 0;
        let previous_session_id = read_u64(packet, 80)?;
        validate_session_transition(binding, header.session_id, previous_session_id)?;
        let token_offset = usize::from(read_u16(packet, 76)?);
        let token_length = usize::from(read_u16(packet, 78)?);
        let security_token = bounded_token(packet, token_offset, token_length, command_end)?;
        Ok(Self {
            header,
            binding,
            signing_required: security_mode & SIGNING_REQUIRED != 0,
            capabilities,
            previous_session_id,
            security_token,
        })
    }
}

/// Values used to encode one bounded `SESSION_SETUP` response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionSetupResponseConfig<'a> {
    /// NTSTATUS for this authentication round.
    pub status: u32,
    /// Non-zero session identity allocated before the first challenge response.
    pub session_id: u64,
    /// Exact SPNEGO/GSS output token, if this round produces one.
    pub security_token: &'a [u8],
    /// Require SMB encryption after authentication succeeds.
    pub encrypt_data: bool,
}

/// Encoded response packet, excluding Direct TCP framing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionSetupResponse {
    /// Exact SMB2 response bytes.
    pub packet: Vec<u8>,
}

impl SessionSetupResponse {
    /// Encodes one session-setup response correlated to its validated request.
    ///
    /// # Errors
    ///
    /// Rejects zero session identities or tokens beyond the 16-bit wire bound.
    pub fn encode(
        request: &SessionSetupRequest<'_>,
        config: SessionSetupResponseConfig<'_>,
    ) -> Result<Self, SmbSessionSetupError> {
        if config.session_id == 0 {
            return Err(SmbSessionSetupError::InvalidSessionTransition);
        }
        let token_length = u16::try_from(config.security_token.len())
            .map_err(|_| SmbSessionSetupError::SecurityTokenTooLarge)?;
        let mut packet = Vec::with_capacity(
            usize::from(RESPONSE_BUFFER_OFFSET)
                .checked_add(config.security_token.len())
                .ok_or(SmbSessionSetupError::SecurityTokenTooLarge)?,
        );
        packet.extend_from_slice(&request.header.encode_response(
            config.status,
            1,
            0,
            config.session_id,
        ));
        packet.extend_from_slice(&RESPONSE_STRUCTURE_SIZE.to_le_bytes());
        let session_flags = if config.encrypt_data {
            SESSION_FLAG_ENCRYPT_DATA
        } else {
            0
        };
        packet.extend_from_slice(&session_flags.to_le_bytes());
        packet.extend_from_slice(&RESPONSE_BUFFER_OFFSET.to_le_bytes());
        packet.extend_from_slice(&token_length.to_le_bytes());
        packet.extend_from_slice(config.security_token);
        Ok(Self { packet })
    }
}

fn command_end(packet: &[u8], next_command: u32) -> Result<usize, SmbSessionSetupError> {
    if next_command == 0 {
        Ok(packet.len())
    } else {
        usize::try_from(next_command).map_err(|_| SmbSessionSetupError::InvalidSecurityBuffer)
    }
}

fn bounded_token(
    packet: &[u8],
    offset: usize,
    length: usize,
    command_end: usize,
) -> Result<&[u8], SmbSessionSetupError> {
    if length == 0 || length > MAXIMUM_SECURITY_TOKEN_LENGTH || offset < REQUEST_FIXED_END {
        return Err(SmbSessionSetupError::InvalidSecurityBuffer);
    }
    let end = offset
        .checked_add(length)
        .filter(|end| *end <= command_end)
        .ok_or(SmbSessionSetupError::InvalidSecurityBuffer)?;
    packet
        .get(offset..end)
        .ok_or(SmbSessionSetupError::InvalidSecurityBuffer)
}

fn validate_session_transition(
    binding: bool,
    session_id: u64,
    previous_session_id: u64,
) -> Result<(), SmbSessionSetupError> {
    if binding && (session_id == 0 || previous_session_id != 0) {
        return Err(SmbSessionSetupError::InvalidSessionTransition);
    }
    if !binding && session_id != 0 && previous_session_id != 0 {
        return Err(SmbSessionSetupError::InvalidSessionTransition);
    }
    Ok(())
}

fn read_u16(packet: &[u8], offset: usize) -> Result<u16, SmbSessionSetupError> {
    packet
        .get(offset..offset + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(SmbSessionSetupError::Truncated)
}

fn read_u32(packet: &[u8], offset: usize) -> Result<u32, SmbSessionSetupError> {
    packet
        .get(offset..offset + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(SmbSessionSetupError::Truncated)
}

fn read_u64(packet: &[u8], offset: usize) -> Result<u64, SmbSessionSetupError> {
    packet
        .get(offset..offset + 8)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(SmbSessionSetupError::Truncated)
}

/// Invalid SMB session-setup framing or transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SmbSessionSetupError {
    /// The complete request fixed fields are absent.
    #[error("SMB session-setup request is truncated")]
    Truncated,
    /// The parsed SMB command was not `SESSION_SETUP`.
    #[error("SMB session-setup parser received another command")]
    WrongCommand,
    /// The fixed request structure marker is not 25.
    #[error("SMB session-setup structure size is invalid")]
    InvalidStructureSize,
    /// Reserved request flag bits were supplied.
    #[error("SMB session-setup flags are invalid")]
    InvalidFlags,
    /// Signing was neither enabled nor required, or reserved bits were set.
    #[error("SMB session-setup security mode is invalid")]
    InvalidSecurityMode,
    /// Reserved capability bits were supplied.
    #[error("SMB session-setup capabilities are invalid")]
    InvalidCapabilities,
    /// Session, binding and previous-session fields form an invalid transition.
    #[error("SMB session-setup transition is invalid")]
    InvalidSessionTransition,
    /// The GSS token range is empty, overlapping fixed fields or out of bounds.
    #[error("SMB session-setup security buffer is invalid")]
    InvalidSecurityBuffer,
    /// A generated GSS token cannot fit its 16-bit wire length.
    #[error("SMB session-setup security token exceeds its wire limit")]
    SecurityTokenTooLarge,
    /// The common SMB2 header is invalid.
    #[error(transparent)]
    Header(#[from] Smb2HeaderError),
}

#[cfg(test)]
mod tests {
    use super::{
        SessionSetupRequest, SessionSetupResponse, SessionSetupResponseConfig, SmbSessionSetupError,
    };

    #[test]
    fn request_preserves_exact_bounded_token_and_response_offsets()
    -> Result<(), SmbSessionSetupError> {
        let packet = request_packet(0, 0, 0, b"bounded SPNEGO token");
        let request = SessionSetupRequest::parse(&packet)?;
        assert!(!request.binding);
        assert!(request.signing_required);
        assert_eq!(request.security_token, b"bounded SPNEGO token");
        let response = SessionSetupResponse::encode(
            &request,
            SessionSetupResponseConfig {
                status: 0xc000_0016,
                session_id: 9,
                security_token: b"server challenge",
                encrypt_data: true,
            },
        )?;
        assert_eq!(&response.packet[64..66], &9_u16.to_le_bytes());
        assert_eq!(&response.packet[66..68], &4_u16.to_le_bytes());
        assert_eq!(&response.packet[68..70], &72_u16.to_le_bytes());
        assert_eq!(&response.packet[70..72], &16_u16.to_le_bytes());
        assert_eq!(&response.packet[72..], b"server challenge");
        assert_eq!(&response.packet[40..48], &9_u64.to_le_bytes());
        Ok(())
    }

    #[test]
    fn hostile_offsets_modes_and_binding_transitions_fail_closed() {
        let mut packet = request_packet(0, 0, 0, b"token");
        packet[76..78].copy_from_slice(&64_u16.to_le_bytes());
        assert_eq!(
            SessionSetupRequest::parse(&packet),
            Err(SmbSessionSetupError::InvalidSecurityBuffer)
        );
        let mut packet = request_packet(0, 0, 0, b"token");
        packet[67] = 0;
        assert_eq!(
            SessionSetupRequest::parse(&packet),
            Err(SmbSessionSetupError::InvalidSecurityMode)
        );
        let packet = request_packet(1, 0, 0, b"token");
        assert_eq!(
            SessionSetupRequest::parse(&packet),
            Err(SmbSessionSetupError::InvalidSessionTransition)
        );
    }

    fn request_packet(
        flags: u8,
        session_id: u64,
        previous_session_id: u64,
        token: &[u8],
    ) -> Vec<u8> {
        let mut packet = vec![0; 88];
        packet[..4].copy_from_slice(&[0xfe, b'S', b'M', b'B']);
        packet[4..6].copy_from_slice(&64_u16.to_le_bytes());
        packet[12..14].copy_from_slice(&1_u16.to_le_bytes());
        packet[14..16].copy_from_slice(&1_u16.to_le_bytes());
        packet[24..32].copy_from_slice(&1_u64.to_le_bytes());
        packet[40..48].copy_from_slice(&session_id.to_le_bytes());
        packet[64..66].copy_from_slice(&25_u16.to_le_bytes());
        packet[66] = flags;
        packet[67] = 3;
        packet[76..78].copy_from_slice(&88_u16.to_le_bytes());
        packet[78..80]
            .copy_from_slice(&(u16::try_from(token.len()).unwrap_or_default()).to_le_bytes());
        packet[80..88].copy_from_slice(&previous_session_id.to_le_bytes());
        packet.extend_from_slice(token);
        packet
    }
}
