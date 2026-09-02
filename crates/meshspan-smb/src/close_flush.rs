// SPDX-License-Identifier: GPL-2.0-only

//! SMB 3.1.1 flush and close lifecycle framing.

use crate::{Smb2Command, Smb2Header, Smb2HeaderError, SmbFileId};

const REQUEST_STRUCTURE_SIZE: u16 = 24;
const REQUEST_BYTES: usize = 88;
const FLUSH_RESPONSE_STRUCTURE_SIZE: u16 = 4;
const CLOSE_RESPONSE_STRUCTURE_SIZE: u16 = 60;
const CLOSE_RESPONSE_BYTES: usize = 124;
const POSTQUERY_ATTRIBUTES: u16 = 0x0001;

/// Validated `SMB2 FLUSH` request for one exact open.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlushRequest {
    /// Validated synchronous request header.
    pub header: Smb2Header,
    /// Exact connection-visible open identity.
    pub file_id: SmbFileId,
}

impl FlushRequest {
    /// Parses one fixed flush request.
    ///
    /// # Errors
    ///
    /// Rejects invalid identity, reserved fields, structure length or command family.
    pub fn parse(packet: &[u8]) -> Result<Self, SmbCloseFlushError> {
        let header = parse_fixed(packet, Smb2Command::Flush)?;
        if read_u16(packet, 66)? != 0 {
            return Err(SmbCloseFlushError::InvalidStructure);
        }
        Ok(Self {
            header,
            file_id: read_file_id(packet)?,
        })
    }

    /// Encodes success only after the common filesystem publication barrier succeeds.
    #[must_use]
    pub fn success_response(self) -> [u8; 68] {
        let mut packet = [0_u8; 68];
        packet[..64].copy_from_slice(&self.header.encode_response(
            0,
            self.header.credit_charge.max(1),
            self.header.tree_id,
            self.header.session_id,
        ));
        packet[64..66].copy_from_slice(&FLUSH_RESPONSE_STRUCTURE_SIZE.to_le_bytes());
        packet
    }
}

/// Validated `SMB2 CLOSE` request for one exact open.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CloseRequest {
    /// Validated synchronous request header.
    pub header: Smb2Header,
    /// Exact connection-visible open identity.
    pub file_id: SmbFileId,
    /// Whether the client requested post-close attributes.
    pub postquery_attributes: bool,
}

impl CloseRequest {
    /// Parses one fixed close request.
    ///
    /// # Errors
    ///
    /// Rejects invalid flags, identity, reserved fields, structure length or command family.
    pub fn parse(packet: &[u8]) -> Result<Self, SmbCloseFlushError> {
        let header = parse_fixed(packet, Smb2Command::Close)?;
        let flags = read_u16(packet, 66)?;
        if flags & !POSTQUERY_ATTRIBUTES != 0 {
            return Err(SmbCloseFlushError::InvalidFlags);
        }
        Ok(Self {
            header,
            file_id: read_file_id(packet)?,
            postquery_attributes: flags & POSTQUERY_ATTRIBUTES != 0,
        })
    }
}

/// Portable attributes returned after an exact successful close.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CloseResponseAttributes {
    /// Creation time as a Windows `FILETIME`.
    pub creation_time: u64,
    /// Last access time as a Windows `FILETIME`.
    pub last_access_time: u64,
    /// Last content-write time as a Windows `FILETIME`.
    pub last_write_time: u64,
    /// Last namespace/attribute change time as a Windows `FILETIME`.
    pub change_time: u64,
    /// Allocated bytes reported to the client.
    pub allocation_size: u64,
    /// Exact logical byte length.
    pub end_of_file: u64,
    /// Portable DOS/basic attributes.
    pub file_attributes: u32,
}

/// Exact successful `SMB2 CLOSE` response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CloseResponse {
    /// Fixed response before signing, encryption and direct-TCP framing.
    pub packet: [u8; CLOSE_RESPONSE_BYTES],
}

impl CloseResponse {
    /// Encodes success, returning attributes exactly when requested by the client.
    #[must_use]
    pub fn encode(request: CloseRequest, attributes: Option<CloseResponseAttributes>) -> Self {
        let selected = if request.postquery_attributes {
            attributes.unwrap_or(CloseResponseAttributes::ZERO)
        } else {
            CloseResponseAttributes::ZERO
        };
        let mut packet = [0_u8; CLOSE_RESPONSE_BYTES];
        packet[..64].copy_from_slice(&request.header.encode_response(
            0,
            request.header.credit_charge.max(1),
            request.header.tree_id,
            request.header.session_id,
        ));
        packet[64..66].copy_from_slice(&CLOSE_RESPONSE_STRUCTURE_SIZE.to_le_bytes());
        if request.postquery_attributes {
            packet[66..68].copy_from_slice(&POSTQUERY_ATTRIBUTES.to_le_bytes());
        }
        for (offset, value) in [
            (72, selected.creation_time),
            (80, selected.last_access_time),
            (88, selected.last_write_time),
            (96, selected.change_time),
            (104, selected.allocation_size),
            (112, selected.end_of_file),
        ] {
            packet[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        packet[120..124].copy_from_slice(&selected.file_attributes.to_le_bytes());
        Self { packet }
    }
}

impl CloseResponseAttributes {
    const ZERO: Self = Self {
        creation_time: 0,
        last_access_time: 0,
        last_write_time: 0,
        change_time: 0,
        allocation_size: 0,
        end_of_file: 0,
        file_attributes: 0,
    };
}

fn parse_fixed(
    packet: &[u8],
    expected_command: Smb2Command,
) -> Result<Smb2Header, SmbCloseFlushError> {
    let header = Smb2Header::parse_request(packet)?;
    if header.command != expected_command {
        return Err(SmbCloseFlushError::WrongCommand);
    }
    if header.session_id == 0 || header.tree_id == 0 {
        return Err(SmbCloseFlushError::InvalidIdentity);
    }
    let end = if header.next_command == 0 {
        packet.len()
    } else {
        usize::try_from(header.next_command).map_err(|_| SmbCloseFlushError::InvalidStructure)?
    };
    if end != REQUEST_BYTES
        || read_u16(packet, 64)? != REQUEST_STRUCTURE_SIZE
        || read_u32(packet, 68)? != 0
    {
        return Err(SmbCloseFlushError::InvalidStructure);
    }
    Ok(header)
}

fn read_file_id(packet: &[u8]) -> Result<SmbFileId, SmbCloseFlushError> {
    let bytes = packet
        .get(72..88)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(SmbCloseFlushError::Truncated)?;
    SmbFileId::from_wire(bytes).map_err(|_| SmbCloseFlushError::InvalidIdentity)
}

fn read_u16(packet: &[u8], offset: usize) -> Result<u16, SmbCloseFlushError> {
    packet
        .get(offset..offset + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(SmbCloseFlushError::Truncated)
}

fn read_u32(packet: &[u8], offset: usize) -> Result<u32, SmbCloseFlushError> {
    packet
        .get(offset..offset + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(SmbCloseFlushError::Truncated)
}

/// Invalid fixed file-lifecycle framing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SmbCloseFlushError {
    /// Required fixed fields are absent.
    #[error("SMB close/flush request is truncated")]
    Truncated,
    /// Another command family reached this parser.
    #[error("SMB close/flush parser received another command")]
    WrongCommand,
    /// Session, tree or file identity is invalid.
    #[error("SMB close/flush identity is invalid")]
    InvalidIdentity,
    /// Fixed size or reserved fields are invalid.
    #[error("SMB close/flush structure is invalid")]
    InvalidStructure,
    /// Reserved close flags were supplied.
    #[error("SMB close flags are invalid")]
    InvalidFlags,
    /// The common SMB2 header is invalid.
    #[error(transparent)]
    Header(#[from] Smb2HeaderError),
}

#[cfg(test)]
mod tests {
    use super::{
        CloseRequest, CloseResponse, CloseResponseAttributes, FlushRequest, SmbCloseFlushError,
    };

    #[test]
    fn flush_and_close_round_trip_exact_open_and_attribute_contract()
    -> Result<(), SmbCloseFlushError> {
        let flush = FlushRequest::parse(&request_packet(7, 0))?;
        assert_eq!(&flush.success_response()[64..68], &[4, 0, 0, 0]);

        let close = CloseRequest::parse(&request_packet(6, 1))?;
        assert!(close.postquery_attributes);
        let response = CloseResponse::encode(
            close,
            Some(CloseResponseAttributes {
                creation_time: 1,
                last_access_time: 2,
                last_write_time: 3,
                change_time: 4,
                allocation_size: 8,
                end_of_file: 7,
                file_attributes: 0x20,
            }),
        );
        assert_eq!(&response.packet[66..68], &1_u16.to_le_bytes());
        assert_eq!(&response.packet[112..120], &7_u64.to_le_bytes());
        Ok(())
    }

    #[test]
    fn reserved_fields_flags_and_file_ids_fail_closed() {
        let mut packet = request_packet(7, 0);
        packet[70] = 1;
        assert_eq!(
            FlushRequest::parse(&packet),
            Err(SmbCloseFlushError::InvalidStructure)
        );

        let mut packet = request_packet(6, 2);
        assert_eq!(
            CloseRequest::parse(&packet),
            Err(SmbCloseFlushError::InvalidFlags)
        );
        packet[66..68].fill(0);
        packet[72..88].fill(0);
        assert_eq!(
            CloseRequest::parse(&packet),
            Err(SmbCloseFlushError::InvalidIdentity)
        );
    }

    fn request_packet(command: u16, flags: u16) -> Vec<u8> {
        let mut packet = vec![0; 88];
        packet[..4].copy_from_slice(&[0xfe, b'S', b'M', b'B']);
        packet[4..6].copy_from_slice(&64_u16.to_le_bytes());
        packet[6..8].copy_from_slice(&1_u16.to_le_bytes());
        packet[12..14].copy_from_slice(&command.to_le_bytes());
        packet[14..16].copy_from_slice(&1_u16.to_le_bytes());
        packet[24..32].copy_from_slice(&59_u64.to_le_bytes());
        packet[32..36].copy_from_slice(&61_u32.to_le_bytes());
        packet[36..40].copy_from_slice(&67_u32.to_le_bytes());
        packet[40..48].copy_from_slice(&71_u64.to_le_bytes());
        packet[64..66].copy_from_slice(&24_u16.to_le_bytes());
        packet[66..68].copy_from_slice(&flags.to_le_bytes());
        packet[72..80].copy_from_slice(&73_u64.to_le_bytes());
        packet[80..88].copy_from_slice(&79_u64.to_le_bytes());
        packet
    }
}
