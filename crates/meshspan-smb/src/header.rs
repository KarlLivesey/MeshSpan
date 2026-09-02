// SPDX-License-Identifier: GPL-2.0-only

//! SMB2 synchronous packet headers.

const HEADER_LENGTH: usize = 64;
const PROTOCOL_ID: [u8; 4] = [0xfe, b'S', b'M', b'B'];
const SERVER_TO_CLIENT: u32 = 0x0000_0001;
const ASYNC_COMMAND: u32 = 0x0000_0002;
const RELATED_OPERATIONS: u32 = 0x0000_0004;
const SIGNED: u32 = 0x0000_0008;
const RESPONSE_FLAGS_FROM_REQUEST: u32 = RELATED_OPERATIONS | SIGNED;
const ALLOWED_REQUEST_FLAGS: u32 = 0x3000_007e;

/// One command in the SMB 2/3 command space.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Smb2Command {
    /// Negotiate protocol capabilities.
    Negotiate = 0x0000,
    /// Establish or continue a user session.
    SessionSetup = 0x0001,
    /// End a user session.
    Logoff = 0x0002,
    /// Connect a session to a share.
    TreeConnect = 0x0003,
    /// Disconnect a share tree.
    TreeDisconnect = 0x0004,
    /// Create or open a file or directory.
    Create = 0x0005,
    /// Close an open file.
    Close = 0x0006,
    /// Flush acknowledged file data.
    Flush = 0x0007,
    /// Read file data.
    Read = 0x0008,
    /// Write file data.
    Write = 0x0009,
    /// Apply or release byte-range locks.
    Lock = 0x000a,
    /// Execute a filesystem control operation.
    Ioctl = 0x000b,
    /// Cancel an asynchronous request.
    Cancel = 0x000c,
    /// Verify that a connection remains live.
    Echo = 0x000d,
    /// Enumerate a directory.
    QueryDirectory = 0x000e,
    /// Register for namespace change notifications.
    ChangeNotify = 0x000f,
    /// Read file, filesystem or security information.
    QueryInfo = 0x0010,
    /// Change file, filesystem or security information.
    SetInfo = 0x0011,
    /// Acknowledge an oplock or lease break.
    OplockBreak = 0x0012,
}

impl Smb2Command {
    fn parse(value: u16) -> Result<Self, Smb2HeaderError> {
        match value {
            0x0000 => Ok(Self::Negotiate),
            0x0001 => Ok(Self::SessionSetup),
            0x0002 => Ok(Self::Logoff),
            0x0003 => Ok(Self::TreeConnect),
            0x0004 => Ok(Self::TreeDisconnect),
            0x0005 => Ok(Self::Create),
            0x0006 => Ok(Self::Close),
            0x0007 => Ok(Self::Flush),
            0x0008 => Ok(Self::Read),
            0x0009 => Ok(Self::Write),
            0x000a => Ok(Self::Lock),
            0x000b => Ok(Self::Ioctl),
            0x000c => Ok(Self::Cancel),
            0x000d => Ok(Self::Echo),
            0x000e => Ok(Self::QueryDirectory),
            0x000f => Ok(Self::ChangeNotify),
            0x0010 => Ok(Self::QueryInfo),
            0x0011 => Ok(Self::SetInfo),
            0x0012 => Ok(Self::OplockBreak),
            _ => Err(Smb2HeaderError::UnknownCommand),
        }
    }

    /// Returns the exact SMB2 command number.
    #[must_use]
    pub const fn wire_value(self) -> u16 {
        self as u16
    }
}

/// Validated fields shared by one synchronous SMB2 request and its response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Smb2Header {
    /// Credits consumed by this request.
    pub credit_charge: u16,
    /// Requested operation.
    pub command: Smb2Command,
    /// Credits requested by the client.
    pub credits_requested: u16,
    /// Validated request flags.
    pub flags: u32,
    /// Offset of the next compounded command, or zero.
    pub next_command: u32,
    /// Connection-unique message identity.
    pub message_id: u64,
    /// Client process identity.
    pub process_id: u32,
    /// Connected share identity.
    pub tree_id: u32,
    /// Authenticated session identity.
    pub session_id: u64,
    /// Message signature bytes.
    pub signature: [u8; 16],
}

impl Smb2Header {
    /// Parses and validates a synchronous client request header.
    ///
    /// # Errors
    ///
    /// Rejects truncated, malformed, server-originated, asynchronous or
    /// structurally invalid request headers.
    pub fn parse_request(packet: &[u8]) -> Result<Self, Smb2HeaderError> {
        if packet.len() < HEADER_LENGTH {
            return Err(Smb2HeaderError::Truncated);
        }
        if packet[..4] != PROTOCOL_ID {
            return Err(Smb2HeaderError::InvalidProtocol);
        }
        if read_u16(packet, 4)? != 64 {
            return Err(Smb2HeaderError::InvalidStructureSize);
        }
        let flags = read_u32(packet, 16)?;
        validate_request_flags(flags, &packet[48..64])?;
        let next_command = read_u32(packet, 20)?;
        validate_next_command(next_command, packet.len())?;
        Ok(Self {
            credit_charge: read_u16(packet, 6)?,
            command: Smb2Command::parse(read_u16(packet, 12)?)?,
            credits_requested: read_u16(packet, 14)?,
            flags,
            next_command,
            message_id: read_u64(packet, 24)?,
            process_id: read_u32(packet, 32)?,
            tree_id: read_u32(packet, 36)?,
            session_id: read_u64(packet, 40)?,
            signature: packet[48..64]
                .try_into()
                .map_err(|_| Smb2HeaderError::Truncated)?,
        })
    }

    /// Encodes the synchronous response header corresponding to this request.
    #[must_use]
    pub fn encode_response(
        self,
        status: u32,
        credits_granted: u16,
        tree_id: u32,
        session_id: u64,
    ) -> [u8; HEADER_LENGTH] {
        let mut output = [0_u8; HEADER_LENGTH];
        output[..4].copy_from_slice(&PROTOCOL_ID);
        output[4..6].copy_from_slice(&64_u16.to_le_bytes());
        output[6..8].copy_from_slice(&self.credit_charge.to_le_bytes());
        output[8..12].copy_from_slice(&status.to_le_bytes());
        output[12..14].copy_from_slice(&self.command.wire_value().to_le_bytes());
        output[14..16].copy_from_slice(&credits_granted.to_le_bytes());
        let response_flags = self.flags & RESPONSE_FLAGS_FROM_REQUEST | SERVER_TO_CLIENT;
        output[16..20].copy_from_slice(&response_flags.to_le_bytes());
        output[24..32].copy_from_slice(&self.message_id.to_le_bytes());
        output[36..40].copy_from_slice(&tree_id.to_le_bytes());
        output[40..48].copy_from_slice(&session_id.to_le_bytes());
        output
    }
}

fn validate_request_flags(flags: u32, signature: &[u8]) -> Result<(), Smb2HeaderError> {
    if flags & SERVER_TO_CLIENT != 0 {
        return Err(Smb2HeaderError::ServerResponseReceived);
    }
    if flags & ASYNC_COMMAND != 0 {
        return Err(Smb2HeaderError::AsyncRequestUnsupported);
    }
    if flags & !ALLOWED_REQUEST_FLAGS != 0 {
        return Err(Smb2HeaderError::UnknownFlags);
    }
    if flags & SIGNED == 0 && signature.iter().any(|byte| *byte != 0) {
        return Err(Smb2HeaderError::UnexpectedSignature);
    }
    Ok(())
}

fn validate_next_command(next_command: u32, packet_length: usize) -> Result<(), Smb2HeaderError> {
    if next_command == 0 {
        return Ok(());
    }
    let offset = usize::try_from(next_command).map_err(|_| Smb2HeaderError::InvalidCompound)?;
    if offset < HEADER_LENGTH || !offset.is_multiple_of(8) || offset >= packet_length {
        return Err(Smb2HeaderError::InvalidCompound);
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, Smb2HeaderError> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or(Smb2HeaderError::Truncated)?;
    Ok(u16::from_le_bytes(
        value.try_into().map_err(|_| Smb2HeaderError::Truncated)?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, Smb2HeaderError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or(Smb2HeaderError::Truncated)?;
    Ok(u32::from_le_bytes(
        value.try_into().map_err(|_| Smb2HeaderError::Truncated)?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, Smb2HeaderError> {
    let value = bytes
        .get(offset..offset + 8)
        .ok_or(Smb2HeaderError::Truncated)?;
    Ok(u64::from_le_bytes(
        value.try_into().map_err(|_| Smb2HeaderError::Truncated)?,
    ))
}

/// Invalid SMB2 packet header.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Smb2HeaderError {
    /// The complete fixed header is not present.
    #[error("SMB2 header is truncated")]
    Truncated,
    /// The packet is not an SMB2 packet.
    #[error("SMB2 protocol identifier is invalid")]
    InvalidProtocol,
    /// The fixed structure-size marker is not 64.
    #[error("SMB2 header structure size is invalid")]
    InvalidStructureSize,
    /// The command number is outside the defined SMB2 command space.
    #[error("SMB2 command is unknown")]
    UnknownCommand,
    /// A client sent a header marked as a server response.
    #[error("SMB2 server response was received on the request boundary")]
    ServerResponseReceived,
    /// The first synchronous profile does not accept asynchronous request headers.
    #[error("SMB2 asynchronous request header is unsupported")]
    AsyncRequestUnsupported,
    /// Reserved or unsupported request flags were present.
    #[error("SMB2 request flags are invalid")]
    UnknownFlags,
    /// An unsigned request carried non-zero signature bytes.
    #[error("unsigned SMB2 request carries signature bytes")]
    UnexpectedSignature,
    /// A compound offset is misaligned or outside the packet.
    #[error("SMB2 compound command offset is invalid")]
    InvalidCompound,
}

#[cfg(test)]
mod tests {
    use super::{SERVER_TO_CLIENT, SIGNED, Smb2Command, Smb2Header, Smb2HeaderError};

    fn request() -> [u8; 64] {
        let mut bytes = [0_u8; 64];
        bytes[..4].copy_from_slice(&[0xfe, b'S', b'M', b'B']);
        bytes[4..6].copy_from_slice(&64_u16.to_le_bytes());
        bytes[6..8].copy_from_slice(&1_u16.to_le_bytes());
        bytes[12..14].copy_from_slice(&Smb2Command::Create.wire_value().to_le_bytes());
        bytes[14..16].copy_from_slice(&4_u16.to_le_bytes());
        bytes[24..32].copy_from_slice(&77_u64.to_le_bytes());
        bytes[32..36].copy_from_slice(&12_u32.to_le_bytes());
        bytes[36..40].copy_from_slice(&13_u32.to_le_bytes());
        bytes[40..48].copy_from_slice(&14_u64.to_le_bytes());
        bytes
    }

    #[test]
    fn synchronous_request_round_trips_response_correlation() -> Result<(), Smb2HeaderError> {
        let parsed = Smb2Header::parse_request(&request())?;
        assert_eq!(parsed.command, Smb2Command::Create);
        assert_eq!(parsed.message_id, 77);
        let response = parsed.encode_response(0xc000_0022, 2, 91, 92);
        assert_eq!(
            u32::from_le_bytes(response[8..12].try_into().unwrap_or_default()),
            0xc000_0022
        );
        assert_eq!(
            u32::from_le_bytes(response[16..20].try_into().unwrap_or_default()),
            SERVER_TO_CLIENT
        );
        assert_eq!(
            u64::from_le_bytes(response[24..32].try_into().unwrap_or_default()),
            77
        );
        assert_eq!(
            u32::from_le_bytes(response[36..40].try_into().unwrap_or_default()),
            91
        );
        assert_eq!(
            u64::from_le_bytes(response[40..48].try_into().unwrap_or_default()),
            92
        );
        Ok(())
    }

    #[test]
    fn hostile_header_shapes_fail_before_dispatch() {
        let mut bytes = request();
        bytes[0] = 0xff;
        assert_eq!(
            Smb2Header::parse_request(&bytes),
            Err(Smb2HeaderError::InvalidProtocol)
        );

        let mut bytes = request();
        bytes[16..20].copy_from_slice(&SERVER_TO_CLIENT.to_le_bytes());
        assert_eq!(
            Smb2Header::parse_request(&bytes),
            Err(Smb2HeaderError::ServerResponseReceived)
        );

        let mut bytes = request();
        bytes[48] = 1;
        assert_eq!(
            Smb2Header::parse_request(&bytes),
            Err(Smb2HeaderError::UnexpectedSignature)
        );

        let mut bytes = request();
        bytes[16..20].copy_from_slice(&SIGNED.to_le_bytes());
        bytes[20..24].copy_from_slice(&65_u32.to_le_bytes());
        assert_eq!(
            Smb2Header::parse_request(&bytes),
            Err(Smb2HeaderError::InvalidCompound)
        );
    }
}
