// SPDX-License-Identifier: GPL-2.0-only

//! Bounded SMB 3.1.1 directory-enumeration framing.

use crate::{Smb2Command, Smb2Header, Smb2HeaderError, SmbFileId};

const REQUEST_STRUCTURE_SIZE: u16 = 33;
const REQUEST_FIXED_BYTES: usize = 96;
const RESPONSE_STRUCTURE_SIZE: u16 = 9;
const RESPONSE_BUFFER_OFFSET: u16 = 72;
const MAXIMUM_OUTPUT_BYTES: usize = 16 * 1_024 * 1_024;
const RESTART_SCANS: u8 = 0x01;
const RETURN_SINGLE_ENTRY: u8 = 0x02;
const INDEX_SPECIFIED: u8 = 0x04;
const REOPEN: u8 = 0x10;
const SUPPORTED_FLAGS: u8 = RESTART_SCANS | RETURN_SINGLE_ENTRY | REOPEN;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;

/// Directory information layouts used by ordinary SMB clients.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryInformationClass {
    /// `FILE_DIRECTORY_INFORMATION`.
    Directory,
    /// `FILE_FULL_DIR_INFORMATION`.
    Full,
    /// `FILE_BOTH_DIR_INFORMATION` with no generated 8.3 alias.
    Both,
    /// `FILE_NAMES_INFORMATION`.
    Names,
    /// `FILE_ID_FULL_DIR_INFORMATION`.
    IdFull,
    /// `FILE_ID_BOTH_DIR_INFORMATION` with no generated 8.3 alias.
    IdBoth,
}

impl DirectoryInformationClass {
    fn parse(value: u8) -> Result<Self, SmbQueryDirectoryError> {
        match value {
            0x01 => Ok(Self::Directory),
            0x02 => Ok(Self::Full),
            0x03 => Ok(Self::Both),
            0x0c => Ok(Self::Names),
            0x26 => Ok(Self::IdFull),
            0x25 => Ok(Self::IdBoth),
            _ => Err(SmbQueryDirectoryError::UnsupportedInformationClass),
        }
    }

    const fn fixed_entry_bytes(self) -> usize {
        match self {
            Self::Directory => 64,
            Self::Full => 68,
            Self::Both => 94,
            Self::Names => 12,
            Self::IdFull => 80,
            Self::IdBoth => 104,
        }
    }
}

/// Validated `SMB2 QUERY_DIRECTORY` request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryDirectoryRequest {
    /// Validated synchronous request header.
    pub header: Smb2Header,
    /// Requested entry layout.
    pub information_class: DirectoryInformationClass,
    /// Restart enumeration from the beginning.
    pub restart_scan: bool,
    /// Return no more than one entry.
    pub return_single_entry: bool,
    /// Restart and replace the search pattern.
    pub reopen: bool,
    /// Exact directory open identity.
    pub file_id: SmbFileId,
    /// Optional UTF-16 search pattern.
    pub search_pattern: Option<String>,
    /// Maximum response bytes accepted by the client.
    pub output_buffer_length: u32,
}

impl QueryDirectoryRequest {
    /// Parses one bounded enumeration request without byte-index continuation.
    ///
    /// # Errors
    ///
    /// Rejects malformed identities, unsupported information classes or flags, invalid UTF-16,
    /// excessive output claims, out-of-packet offsets and compounds.
    pub fn parse(packet: &[u8]) -> Result<Self, SmbQueryDirectoryError> {
        let header = Smb2Header::parse_request(packet)?;
        if header.command != Smb2Command::QueryDirectory {
            return Err(SmbQueryDirectoryError::WrongCommand);
        }
        if header.session_id == 0 || header.tree_id == 0 {
            return Err(SmbQueryDirectoryError::InvalidIdentity);
        }
        let flags = read_u8(packet, 67)?;
        let output_buffer_length = read_u32(packet, 92)?;
        if header.next_command != 0
            || packet.len() < REQUEST_FIXED_BYTES
            || read_u16(packet, 64)? != REQUEST_STRUCTURE_SIZE
            || flags & !(SUPPORTED_FLAGS | INDEX_SPECIFIED) != 0
            || flags & INDEX_SPECIFIED != 0
            || read_u32(packet, 68)? != 0
            || output_buffer_length == 0
            || usize::try_from(output_buffer_length).unwrap_or(usize::MAX) > MAXIMUM_OUTPUT_BYTES
        {
            return Err(SmbQueryDirectoryError::InvalidStructure);
        }
        let file_id = SmbFileId::from_wire(read_array(packet, 72)?)
            .map_err(|_| SmbQueryDirectoryError::InvalidIdentity)?;
        Ok(Self {
            header,
            information_class: DirectoryInformationClass::parse(read_u8(packet, 66)?)?,
            restart_scan: flags & RESTART_SCANS != 0,
            return_single_entry: flags & RETURN_SINGLE_ENTRY != 0,
            reopen: flags & REOPEN != 0,
            file_id,
            search_pattern: parse_pattern(packet)?,
            output_buffer_length,
        })
    }
}

/// One protocol-neutral directory result ready for a selected SMB layout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryResponseEntry {
    /// Case-preserved leaf name.
    pub name: String,
    /// Stable truncated 64-bit object identity.
    pub file_id: u64,
    /// Whether this is a directory.
    pub is_directory: bool,
    /// Exact logical bytes, zero for directories.
    pub logical_length: u64,
    /// Creation time as Windows `FILETIME`.
    pub creation_time: u64,
    /// Last access time as Windows `FILETIME`.
    pub last_access_time: u64,
    /// Last content-write time as Windows `FILETIME`.
    pub last_write_time: u64,
    /// Last metadata change time as Windows `FILETIME`.
    pub change_time: u64,
}

/// Encoded successful directory-enumeration response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryDirectoryResponse {
    /// SMB response packet before signing, encryption and direct-TCP framing.
    pub packet: Vec<u8>,
}

impl QueryDirectoryResponse {
    /// Encodes a non-empty result page in the exact requested information layout.
    ///
    /// # Errors
    ///
    /// Rejects empty pages, invalid names or a page exceeding the client's byte bound.
    pub fn encode(
        request: &QueryDirectoryRequest,
        entries: &[DirectoryResponseEntry],
    ) -> Result<Self, SmbQueryDirectoryError> {
        if entries.is_empty() {
            return Err(SmbQueryDirectoryError::EmptyResult);
        }
        let mut encoded = Vec::new();
        for (index, entry) in entries.iter().enumerate() {
            encode_entry(
                &mut encoded,
                request.information_class,
                entry,
                index + 1 < entries.len(),
            )?;
        }
        if encoded.len()
            > usize::try_from(request.output_buffer_length)
                .map_err(|_| SmbQueryDirectoryError::OutputTooLarge)?
        {
            return Err(SmbQueryDirectoryError::OutputTooLarge);
        }
        let length =
            u32::try_from(encoded.len()).map_err(|_| SmbQueryDirectoryError::OutputTooLarge)?;
        let mut packet = Vec::with_capacity(usize::from(RESPONSE_BUFFER_OFFSET) + encoded.len());
        packet.extend_from_slice(&request.header.encode_response(
            0,
            request.header.credit_charge.max(1),
            request.header.tree_id,
            request.header.session_id,
        ));
        packet.extend_from_slice(&RESPONSE_STRUCTURE_SIZE.to_le_bytes());
        packet.extend_from_slice(&RESPONSE_BUFFER_OFFSET.to_le_bytes());
        packet.extend_from_slice(&length.to_le_bytes());
        packet.extend_from_slice(&encoded);
        Ok(Self { packet })
    }
}

fn encode_entry(
    output: &mut Vec<u8>,
    class: DirectoryInformationClass,
    entry: &DirectoryResponseEntry,
    followed: bool,
) -> Result<(), SmbQueryDirectoryError> {
    if entry.name.is_empty()
        || entry
            .name
            .chars()
            .any(|character| matches!(character, '\0' | '\\' | '/'))
    {
        return Err(SmbQueryDirectoryError::InvalidName);
    }
    let name = entry
        .name
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    let fixed = class.fixed_entry_bytes();
    let raw_length = fixed
        .checked_add(name.len())
        .ok_or(SmbQueryDirectoryError::OutputTooLarge)?;
    let encoded_length = if followed {
        raw_length
            .checked_add(7)
            .map(|length| length & !7)
            .ok_or(SmbQueryDirectoryError::OutputTooLarge)?
    } else {
        raw_length
    };
    let start = output.len();
    output.resize(
        start
            .checked_add(encoded_length)
            .ok_or(SmbQueryDirectoryError::OutputTooLarge)?,
        0,
    );
    if followed {
        write_u32(
            output,
            start,
            u32::try_from(encoded_length).map_err(|_| SmbQueryDirectoryError::OutputTooLarge)?,
        )?;
    }
    write_u32(
        output,
        start + name_length_offset(class),
        u32::try_from(name.len()).map_err(|_| SmbQueryDirectoryError::OutputTooLarge)?,
    )?;
    if class != DirectoryInformationClass::Names {
        write_common_attributes(output, start, entry)?;
        match class {
            DirectoryInformationClass::IdFull => write_u64(output, start + 72, entry.file_id)?,
            DirectoryInformationClass::IdBoth => write_u64(output, start + 96, entry.file_id)?,
            _ => {}
        }
    }
    output[start + fixed..start + fixed + name.len()].copy_from_slice(&name);
    Ok(())
}

fn write_common_attributes(
    output: &mut [u8],
    start: usize,
    entry: &DirectoryResponseEntry,
) -> Result<(), SmbQueryDirectoryError> {
    for (offset, value) in [
        (8, entry.creation_time),
        (16, entry.last_access_time),
        (24, entry.last_write_time),
        (32, entry.change_time),
        (40, entry.logical_length),
        (48, entry.logical_length),
    ] {
        write_u64(output, start + offset, value)?;
    }
    write_u32(
        output,
        start + 56,
        if entry.is_directory {
            FILE_ATTRIBUTE_DIRECTORY
        } else {
            FILE_ATTRIBUTE_NORMAL
        },
    )
}

const fn name_length_offset(class: DirectoryInformationClass) -> usize {
    if matches!(class, DirectoryInformationClass::Names) {
        8
    } else {
        60
    }
}

fn parse_pattern(packet: &[u8]) -> Result<Option<String>, SmbQueryDirectoryError> {
    let offset = usize::from(read_u16(packet, 88)?);
    let length = usize::from(read_u16(packet, 90)?);
    if length == 0 {
        return if offset == 0 || offset >= REQUEST_FIXED_BYTES {
            Ok(None)
        } else {
            Err(SmbQueryDirectoryError::InvalidPattern)
        };
    }
    if offset < REQUEST_FIXED_BYTES || !length.is_multiple_of(2) {
        return Err(SmbQueryDirectoryError::InvalidPattern);
    }
    let bytes = packet
        .get(
            offset
                ..offset
                    .checked_add(length)
                    .ok_or(SmbQueryDirectoryError::InvalidPattern)?,
        )
        .ok_or(SmbQueryDirectoryError::InvalidPattern)?;
    let units = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .copied()
        .map(u16::from_le_bytes)
        .collect::<Vec<_>>();
    let pattern = String::from_utf16(&units).map_err(|_| SmbQueryDirectoryError::InvalidPattern)?;
    if pattern.is_empty() || pattern.chars().any(char::is_control) {
        Err(SmbQueryDirectoryError::InvalidPattern)
    } else {
        Ok(Some(pattern))
    }
}

fn read_array(packet: &[u8], offset: usize) -> Result<[u8; 16], SmbQueryDirectoryError> {
    packet
        .get(offset..offset + 16)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(SmbQueryDirectoryError::Truncated)
}

fn write_u32(output: &mut [u8], offset: usize, value: u32) -> Result<(), SmbQueryDirectoryError> {
    output
        .get_mut(offset..offset + 4)
        .ok_or(SmbQueryDirectoryError::OutputTooLarge)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u64(output: &mut [u8], offset: usize, value: u64) -> Result<(), SmbQueryDirectoryError> {
    output
        .get_mut(offset..offset + 8)
        .ok_or(SmbQueryDirectoryError::OutputTooLarge)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn read_u8(packet: &[u8], offset: usize) -> Result<u8, SmbQueryDirectoryError> {
    packet
        .get(offset)
        .copied()
        .ok_or(SmbQueryDirectoryError::Truncated)
}

macro_rules! read_integer {
    ($name:ident, $type:ty, $size:literal) => {
        fn $name(packet: &[u8], offset: usize) -> Result<$type, SmbQueryDirectoryError> {
            packet
                .get(offset..offset + $size)
                .and_then(|bytes| bytes.try_into().ok())
                .map(<$type>::from_le_bytes)
                .ok_or(SmbQueryDirectoryError::Truncated)
        }
    };
}

read_integer!(read_u16, u16, 2);
read_integer!(read_u32, u32, 4);

/// Invalid or unsupported SMB directory-enumeration framing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SmbQueryDirectoryError {
    /// Required fixed or referenced bytes are absent.
    #[error("SMB query-directory request is truncated")]
    Truncated,
    /// Another command family reached this parser.
    #[error("SMB query-directory parser received another command")]
    WrongCommand,
    /// Session, tree or directory-open identity is invalid.
    #[error("SMB query-directory identity is invalid")]
    InvalidIdentity,
    /// Fixed fields, flags, output bounds or compound shape are invalid.
    #[error("SMB query-directory structure is invalid")]
    InvalidStructure,
    /// The requested directory layout is outside the initial profile.
    #[error("SMB directory information class is unsupported")]
    UnsupportedInformationClass,
    /// Search pattern offset, encoding or content is invalid.
    #[error("SMB directory search pattern is invalid")]
    InvalidPattern,
    /// A common namespace name cannot be represented in the selected layout.
    #[error("SMB directory response name is invalid")]
    InvalidName,
    /// An empty page requires a protocol status rather than a success response.
    #[error("SMB directory success response cannot be empty")]
    EmptyResult,
    /// The encoded page exceeds the client or implementation byte bound.
    #[error("SMB directory response exceeds its byte bound")]
    OutputTooLarge,
    /// The common SMB2 header is invalid.
    #[error(transparent)]
    Header(#[from] Smb2HeaderError),
}

#[cfg(test)]
mod tests {
    use super::{
        DirectoryInformationClass, DirectoryResponseEntry, QueryDirectoryRequest,
        QueryDirectoryResponse, SmbQueryDirectoryError,
    };

    #[test]
    fn id_both_page_encodes_aligned_entries() -> Result<(), SmbQueryDirectoryError> {
        let request = QueryDirectoryRequest::parse(&request_packet(0x25, 1, "*", 4_096))?;
        assert_eq!(request.information_class, DirectoryInformationClass::IdBoth);
        let response = QueryDirectoryResponse::encode(
            &request,
            &[entry("one", 7, false, 11), entry("folder", 8, true, 0)],
        )?;
        assert_eq!(&response.packet[64..66], &9_u16.to_le_bytes());
        assert_eq!(&response.packet[66..68], &72_u16.to_le_bytes());
        let first_length = u32::from_le_bytes(
            response.packet[72..76]
                .try_into()
                .map_err(|_| SmbQueryDirectoryError::OutputTooLarge)?,
        );
        assert_eq!(first_length % 8, 0);
        assert_eq!(&response.packet[72 + 96..72 + 104], &7_u64.to_le_bytes());
        Ok(())
    }

    #[test]
    fn hostile_offsets_flags_classes_and_bounds_fail_closed() {
        let mut packet = request_packet(0x25, 0, "*", 4_096);
        packet[88..90].copy_from_slice(&u16::MAX.to_le_bytes());
        assert_eq!(
            QueryDirectoryRequest::parse(&packet),
            Err(SmbQueryDirectoryError::InvalidPattern)
        );

        let packet = request_packet(0xff, 0, "*", 4_096);
        assert_eq!(
            QueryDirectoryRequest::parse(&packet),
            Err(SmbQueryDirectoryError::UnsupportedInformationClass)
        );

        let packet = request_packet(0x25, 4, "*", 4_096);
        assert_eq!(
            QueryDirectoryRequest::parse(&packet),
            Err(SmbQueryDirectoryError::InvalidStructure)
        );

        let packet = request_packet(0x25, 0, "*", 0);
        assert_eq!(
            QueryDirectoryRequest::parse(&packet),
            Err(SmbQueryDirectoryError::InvalidStructure)
        );
    }

    fn entry(
        name: &str,
        file_id: u64,
        is_directory: bool,
        logical_length: u64,
    ) -> DirectoryResponseEntry {
        DirectoryResponseEntry {
            name: name.to_owned(),
            file_id,
            is_directory,
            logical_length,
            creation_time: 1,
            last_access_time: 2,
            last_write_time: 3,
            change_time: 4,
        }
    }

    fn request_packet(class: u8, flags: u8, pattern: &str, output_length: u32) -> Vec<u8> {
        let encoded = pattern
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let mut packet = vec![0; 96];
        packet[..4].copy_from_slice(&[0xfe, b'S', b'M', b'B']);
        packet[4..6].copy_from_slice(&64_u16.to_le_bytes());
        packet[6..8].copy_from_slice(&1_u16.to_le_bytes());
        packet[12..14].copy_from_slice(&14_u16.to_le_bytes());
        packet[14..16].copy_from_slice(&1_u16.to_le_bytes());
        packet[24..32].copy_from_slice(&17_u64.to_le_bytes());
        packet[36..40].copy_from_slice(&23_u32.to_le_bytes());
        packet[40..48].copy_from_slice(&29_u64.to_le_bytes());
        packet[64..66].copy_from_slice(&33_u16.to_le_bytes());
        packet[66] = class;
        packet[67] = flags;
        packet[72..80].copy_from_slice(&7_u64.to_le_bytes());
        packet[80..88].copy_from_slice(&11_u64.to_le_bytes());
        packet[88..90].copy_from_slice(&96_u16.to_le_bytes());
        packet[90..92].copy_from_slice(
            &u16::try_from(encoded.len())
                .unwrap_or_default()
                .to_le_bytes(),
        );
        packet[92..96].copy_from_slice(&output_length.to_le_bytes());
        packet.extend_from_slice(&encoded);
        packet
    }
}
