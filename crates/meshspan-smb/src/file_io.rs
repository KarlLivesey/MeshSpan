// SPDX-License-Identifier: GPL-2.0-only

//! Bounded SMB 3.1.1 read and write wire operations.

use crate::{Smb2Command, Smb2Header, Smb2HeaderError, SmbFileId};

const IO_REQUEST_FIXED_END: usize = 112;
const IO_REQUEST_STRUCTURE_SIZE: u16 = 49;
const IO_RESPONSE_STRUCTURE_SIZE: u16 = 17;
const RESPONSE_DATA_OFFSET: u8 = 80;
/// Initial per-command IO ceiling; negotiated connection limits may narrow it further.
pub const MAXIMUM_FILE_IO_BYTES: usize = 16 * 1_024 * 1_024;
const WRITE_THROUGH: u32 = 0x0000_0001;
const WRITE_UNBUFFERED: u32 = 0x0000_0002;
const SUPPORTED_WRITE_FLAGS: u32 = WRITE_THROUGH | WRITE_UNBUFFERED;

/// Validated bounded `SMB2 READ` request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadRequest {
    /// Validated synchronous request header.
    pub header: Smb2Header,
    /// Exact connection-visible open identity.
    pub file_id: SmbFileId,
    /// First requested logical byte.
    pub offset: u64,
    /// Positive requested byte count.
    pub length: u32,
    /// Minimum byte count accepted by the client.
    pub minimum_count: u32,
}

impl ReadRequest {
    /// Parses the initial direct-TCP read profile without RDMA channel data.
    ///
    /// # Errors
    ///
    /// Rejects malformed identities, unsupported flags/channels, invalid bounds and compounds.
    pub fn parse(packet: &[u8]) -> Result<Self, SmbFileIoError> {
        let header = validated_header(packet, Smb2Command::Read)?;
        require_exact_command(packet, header.next_command, IO_REQUEST_FIXED_END + 1)?;
        if read_u16(packet, 64)? != IO_REQUEST_STRUCTURE_SIZE
            || read_u8(packet, 67)? != 0
            || read_u32(packet, 100)? != 0
            || read_u32(packet, 104)? != 0
            || read_u16(packet, 108)? != 0
            || read_u16(packet, 110)? != 0
        {
            return Err(SmbFileIoError::UnsupportedProfile);
        }
        let length = read_u32(packet, 68)?;
        let minimum_count = read_u32(packet, 96)?;
        validate_read_length(length, minimum_count)?;
        Ok(Self {
            header,
            file_id: read_file_id(packet, 80)?,
            offset: read_u64(packet, 72)?,
            length,
            minimum_count,
        })
    }
}

/// Encoded successful `SMB2 READ` response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadResponse {
    /// Exact SMB2 response packet before signing, encryption and direct-TCP framing.
    pub packet: Vec<u8>,
}

impl ReadResponse {
    /// Encodes one non-empty successful read.
    ///
    /// # Errors
    ///
    /// Rejects empty or over-limit output; end-of-file is represented by an error response.
    pub fn encode(request: ReadRequest, bytes: &[u8]) -> Result<Self, SmbFileIoError> {
        if bytes.is_empty()
            || bytes.len() > MAXIMUM_FILE_IO_BYTES
            || bytes.len() > usize::try_from(request.length).unwrap_or(usize::MAX)
        {
            return Err(SmbFileIoError::InvalidLength);
        }
        let length = u32::try_from(bytes.len()).map_err(|_| SmbFileIoError::InvalidLength)?;
        let mut packet = Vec::with_capacity(80 + bytes.len());
        packet.extend_from_slice(&request.header.encode_response(
            0,
            request.header.credit_charge.max(1),
            request.header.tree_id,
            request.header.session_id,
        ));
        packet.extend_from_slice(&IO_RESPONSE_STRUCTURE_SIZE.to_le_bytes());
        packet.push(RESPONSE_DATA_OFFSET);
        packet.push(0);
        packet.extend_from_slice(&length.to_le_bytes());
        packet.extend_from_slice(&0_u32.to_le_bytes());
        packet.extend_from_slice(&0_u32.to_le_bytes());
        packet.extend_from_slice(bytes);
        Ok(Self { packet })
    }
}

/// Validated bounded `SMB2 WRITE` request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WriteRequest {
    /// Validated synchronous request header.
    pub header: Smb2Header,
    /// Exact connection-visible open identity.
    pub file_id: SmbFileId,
    /// First logical byte replaced by this write.
    pub offset: u64,
    /// Validated request bytes, copied out of the hostile packet boundary.
    pub bytes: Vec<u8>,
    /// Whether success must include the filesystem publication barrier.
    pub write_through: bool,
    /// Whether the client requested unbuffered handling.
    pub unbuffered: bool,
}

impl WriteRequest {
    /// Parses the initial direct-TCP write profile without RDMA channel data.
    ///
    /// # Errors
    ///
    /// Rejects malformed identities, unsupported channels/flags, overlaps and allocations.
    pub fn parse(packet: &[u8]) -> Result<Self, SmbFileIoError> {
        let header = validated_header(packet, Smb2Command::Write)?;
        let command_end = command_end(packet, header.next_command)?;
        if command_end < IO_REQUEST_FIXED_END
            || read_u16(packet, 64)? != IO_REQUEST_STRUCTURE_SIZE
            || read_u32(packet, 96)? != 0
            || read_u32(packet, 100)? != 0
            || read_u16(packet, 104)? != 0
            || read_u16(packet, 106)? != 0
        {
            return Err(SmbFileIoError::UnsupportedProfile);
        }
        let flags = read_u32(packet, 108)?;
        if flags & !SUPPORTED_WRITE_FLAGS != 0 {
            return Err(SmbFileIoError::UnsupportedProfile);
        }
        let length = read_u32(packet, 68)?;
        validate_write_length(length)?;
        let data_offset = usize::from(read_u16(packet, 66)?);
        let data_end = data_offset
            .checked_add(usize::try_from(length).map_err(|_| SmbFileIoError::InvalidLength)?)
            .filter(|end| data_offset >= IO_REQUEST_FIXED_END && *end <= command_end)
            .ok_or(SmbFileIoError::InvalidOffset)?;
        let bytes = packet
            .get(data_offset..data_end)
            .ok_or(SmbFileIoError::InvalidOffset)?
            .to_vec();
        Ok(Self {
            header,
            file_id: read_file_id(packet, 80)?,
            offset: read_u64(packet, 72)?,
            bytes,
            write_through: flags & WRITE_THROUGH != 0,
            unbuffered: flags & WRITE_UNBUFFERED != 0,
        })
    }
}

/// Exact successful `SMB2 WRITE` response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriteResponse {
    /// Fixed SMB2 response packet before signing, encryption and direct-TCP framing.
    pub packet: [u8; 80],
}

impl WriteResponse {
    /// Encodes the exact number of durably staged bytes accepted by the filesystem service.
    ///
    /// # Errors
    ///
    /// Rejects partial or impossible success counts.
    pub fn encode(request: &WriteRequest, count: u32) -> Result<Self, SmbFileIoError> {
        let requested =
            u32::try_from(request.bytes.len()).map_err(|_| SmbFileIoError::InvalidLength)?;
        if count != requested {
            return Err(SmbFileIoError::PartialWrite);
        }
        let mut packet = [0_u8; 80];
        packet[..64].copy_from_slice(&request.header.encode_response(
            0,
            request.header.credit_charge.max(1),
            request.header.tree_id,
            request.header.session_id,
        ));
        packet[64..66].copy_from_slice(&IO_RESPONSE_STRUCTURE_SIZE.to_le_bytes());
        packet[68..72].copy_from_slice(&count.to_le_bytes());
        Ok(Self { packet })
    }
}

fn validated_header(packet: &[u8], command: Smb2Command) -> Result<Smb2Header, SmbFileIoError> {
    let header = Smb2Header::parse_request(packet)?;
    if header.command != command {
        return Err(SmbFileIoError::WrongCommand);
    }
    if header.session_id == 0 || header.tree_id == 0 {
        return Err(SmbFileIoError::InvalidIdentity);
    }
    Ok(header)
}

fn require_exact_command(
    packet: &[u8],
    next_command: u32,
    minimum_length: usize,
) -> Result<(), SmbFileIoError> {
    let end = command_end(packet, next_command)?;
    if end < minimum_length {
        Err(SmbFileIoError::Truncated)
    } else {
        Ok(())
    }
}

fn command_end(packet: &[u8], next_command: u32) -> Result<usize, SmbFileIoError> {
    if next_command == 0 {
        Ok(packet.len())
    } else {
        usize::try_from(next_command).map_err(|_| SmbFileIoError::InvalidOffset)
    }
}

fn validate_read_length(length: u32, minimum_count: u32) -> Result<(), SmbFileIoError> {
    let requested = usize::try_from(length).map_err(|_| SmbFileIoError::InvalidLength)?;
    if requested == 0 || requested > MAXIMUM_FILE_IO_BYTES || minimum_count > length {
        Err(SmbFileIoError::InvalidLength)
    } else {
        Ok(())
    }
}

fn validate_write_length(length: u32) -> Result<(), SmbFileIoError> {
    if usize::try_from(length).map_err(|_| SmbFileIoError::InvalidLength)? > MAXIMUM_FILE_IO_BYTES {
        Err(SmbFileIoError::InvalidLength)
    } else {
        Ok(())
    }
}

fn read_file_id(packet: &[u8], offset: usize) -> Result<SmbFileId, SmbFileIoError> {
    let bytes = packet
        .get(offset..offset + 16)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(SmbFileIoError::Truncated)?;
    SmbFileId::from_wire(bytes).map_err(|_| SmbFileIoError::InvalidIdentity)
}

fn read_u8(packet: &[u8], offset: usize) -> Result<u8, SmbFileIoError> {
    packet.get(offset).copied().ok_or(SmbFileIoError::Truncated)
}

macro_rules! read_integer {
    ($name:ident, $type:ty, $size:literal) => {
        fn $name(packet: &[u8], offset: usize) -> Result<$type, SmbFileIoError> {
            packet
                .get(offset..offset + $size)
                .and_then(|bytes| bytes.try_into().ok())
                .map(<$type>::from_le_bytes)
                .ok_or(SmbFileIoError::Truncated)
        }
    };
}

read_integer!(read_u16, u16, 2);
read_integer!(read_u32, u32, 4);
read_integer!(read_u64, u64, 8);

/// Invalid or unsupported bounded file IO request/response.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SmbFileIoError {
    /// Required fixed fields or data bytes are absent.
    #[error("SMB file IO request is truncated")]
    Truncated,
    /// Another command family reached this parser.
    #[error("SMB file IO parser received another command")]
    WrongCommand,
    /// Session, tree or file identity is invalid.
    #[error("SMB file IO identity is invalid")]
    InvalidIdentity,
    /// A byte count is zero, inconsistent or above the service ceiling.
    #[error("SMB file IO length is invalid")]
    InvalidLength,
    /// A variable region falls outside its exact compound command.
    #[error("SMB file IO offset is invalid")]
    InvalidOffset,
    /// RDMA, compression or unsupported flags were requested.
    #[error("SMB file IO profile is unsupported")]
    UnsupportedProfile,
    /// The shared filesystem did not accept every byte in one successful request.
    #[error("SMB successful writes must be complete")]
    PartialWrite,
    /// The common SMB2 header is invalid.
    #[error(transparent)]
    Header(#[from] Smb2HeaderError),
}

#[cfg(test)]
mod tests {
    use super::{ReadRequest, ReadResponse, SmbFileIoError, WriteRequest, WriteResponse};

    #[test]
    fn read_and_write_round_trip_exact_ranges_and_identities() -> Result<(), SmbFileIoError> {
        let read = ReadRequest::parse(&read_packet(4096, 2048, 16))?;
        assert_eq!(read.offset, 4096);
        assert_eq!(read.length, 2048);
        assert_eq!(read.minimum_count, 16);
        let response = ReadResponse::encode(read, b"verified")?;
        assert_eq!(&response.packet[68..72], &8_u32.to_le_bytes());
        assert_eq!(&response.packet[80..], b"verified");

        let write = WriteRequest::parse(&write_packet(7, b"complete", 1))?;
        assert_eq!(write.offset, 7);
        assert_eq!(write.bytes, b"complete");
        assert!(write.write_through);
        let response = WriteResponse::encode(&write, 8)?;
        assert_eq!(&response.packet[68..72], &8_u32.to_le_bytes());
        Ok(())
    }

    #[test]
    fn hostile_lengths_channels_flags_and_ids_fail_closed() {
        let mut read = read_packet(0, 32, 0);
        read[100..104].copy_from_slice(&1_u32.to_le_bytes());
        assert_eq!(
            ReadRequest::parse(&read),
            Err(SmbFileIoError::UnsupportedProfile)
        );

        let mut write = write_packet(0, b"bytes", 0);
        write[66..68].copy_from_slice(&u16::MAX.to_le_bytes());
        assert_eq!(
            WriteRequest::parse(&write),
            Err(SmbFileIoError::InvalidOffset)
        );

        let mut write = write_packet(0, b"bytes", 0);
        write[108..112].copy_from_slice(&4_u32.to_le_bytes());
        assert_eq!(
            WriteRequest::parse(&write),
            Err(SmbFileIoError::UnsupportedProfile)
        );

        let mut read = read_packet(0, 32, 0);
        read[80..96].fill(0);
        assert_eq!(
            ReadRequest::parse(&read),
            Err(SmbFileIoError::InvalidIdentity)
        );
    }

    fn read_packet(offset: u64, length: u32, minimum_count: u32) -> Vec<u8> {
        let mut packet = request_header(8);
        packet.extend_from_slice(&49_u16.to_le_bytes());
        packet.extend_from_slice(&[0, 0]);
        packet.extend_from_slice(&length.to_le_bytes());
        packet.extend_from_slice(&offset.to_le_bytes());
        packet.extend_from_slice(&file_id());
        packet.extend_from_slice(&minimum_count.to_le_bytes());
        packet.extend_from_slice(&[0; 12]);
        packet.push(0);
        packet
    }

    fn write_packet(offset: u64, bytes: &[u8], flags: u32) -> Vec<u8> {
        let mut packet = request_header(9);
        packet.extend_from_slice(&49_u16.to_le_bytes());
        packet.extend_from_slice(&112_u16.to_le_bytes());
        packet.extend_from_slice(&u32::try_from(bytes.len()).unwrap_or_default().to_le_bytes());
        packet.extend_from_slice(&offset.to_le_bytes());
        packet.extend_from_slice(&file_id());
        packet.extend_from_slice(&[0; 12]);
        packet.extend_from_slice(&flags.to_le_bytes());
        packet.extend_from_slice(bytes);
        packet
    }

    fn file_id() -> [u8; 16] {
        let mut bytes = [0_u8; 16];
        bytes[..8].copy_from_slice(&7_u64.to_le_bytes());
        bytes[8..].copy_from_slice(&11_u64.to_le_bytes());
        bytes
    }

    fn request_header(command: u16) -> Vec<u8> {
        let mut packet = vec![0; 64];
        packet[..4].copy_from_slice(&[0xfe, b'S', b'M', b'B']);
        packet[4..6].copy_from_slice(&64_u16.to_le_bytes());
        packet[6..8].copy_from_slice(&1_u16.to_le_bytes());
        packet[12..14].copy_from_slice(&command.to_le_bytes());
        packet[14..16].copy_from_slice(&1_u16.to_le_bytes());
        packet[24..32].copy_from_slice(&17_u64.to_le_bytes());
        packet[32..36].copy_from_slice(&19_u32.to_le_bytes());
        packet[36..40].copy_from_slice(&23_u32.to_le_bytes());
        packet[40..48].copy_from_slice(&29_u64.to_le_bytes());
        packet
    }
}
