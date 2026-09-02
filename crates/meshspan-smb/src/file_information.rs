// SPDX-License-Identifier: GPL-2.0-only

//! Bounded SMB 3.1.1 file-information query and mutation framing.

use crate::{Smb2Command, Smb2Header, Smb2HeaderError, SmbFileId};

const QUERY_REQUEST_SIZE: u16 = 41;
const QUERY_REQUEST_BYTES: usize = 104;
const SET_REQUEST_SIZE: u16 = 33;
const SET_REQUEST_BYTES: usize = 96;
const QUERY_RESPONSE_SIZE: u16 = 9;
const QUERY_RESPONSE_OFFSET: u16 = 72;
const SET_RESPONSE_SIZE: u16 = 2;
const MAXIMUM_INFORMATION_BYTES: usize = 16 * 1_024 * 1_024;
const FILE_INFORMATION_TYPE: u8 = 0x01;

/// File information layouts used by ordinary SMB clients.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileInformationClass {
    /// Creation/change times and DOS attributes.
    Basic,
    /// Length, link count and deletion state.
    Standard,
    /// Stable file identity reduced to 64 bits.
    Internal,
    /// Extended-attribute byte count; `MeshSpan` exposes none.
    Ea,
    /// Granted SMB access mask.
    Access,
    /// Connection-local current byte position.
    Position,
    /// Open mode flags.
    Mode,
    /// Required byte alignment.
    Alignment,
    /// Composite ordinary file information.
    All,
    /// Network-open timestamps, lengths and attributes.
    NetworkOpen,
    /// DOS attributes and reparse tag.
    AttributeTag,
    /// Canonical full path.
    NormalizedName,
    /// Volume and 128-bit file identity.
    Id,
}

impl FileInformationClass {
    fn parse_query(value: u8) -> Result<Self, SmbFileInformationError> {
        match value {
            4 => Ok(Self::Basic),
            5 => Ok(Self::Standard),
            6 => Ok(Self::Internal),
            7 => Ok(Self::Ea),
            8 => Ok(Self::Access),
            14 => Ok(Self::Position),
            16 => Ok(Self::Mode),
            17 => Ok(Self::Alignment),
            18 => Ok(Self::All),
            34 => Ok(Self::NetworkOpen),
            35 => Ok(Self::AttributeTag),
            48 => Ok(Self::NormalizedName),
            59 => Ok(Self::Id),
            _ => Err(SmbFileInformationError::UnsupportedInformationClass),
        }
    }
}

/// Validated `SMB2 QUERY_INFO` request for file information.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryInfoRequest {
    /// Validated synchronous request header.
    pub header: Smb2Header,
    /// Requested file-information layout.
    pub information_class: FileInformationClass,
    /// Maximum response bytes accepted by the client.
    pub output_buffer_length: u32,
    /// Exact open identity.
    pub file_id: SmbFileId,
}

impl QueryInfoRequest {
    /// Parses the initial bounded file-information profile.
    ///
    /// # Errors
    ///
    /// Rejects malformed identities, compounds, unsupported information types/classes, input
    /// buffers and excessive or zero output bounds.
    pub fn parse(packet: &[u8]) -> Result<Self, SmbFileInformationError> {
        let header = validated_header(packet, Smb2Command::QueryInfo)?;
        if header.next_command != 0
            || packet.len() < QUERY_REQUEST_BYTES
            || read_u16(packet, 64)? != QUERY_REQUEST_SIZE
            || read_u8(packet, 66)? != FILE_INFORMATION_TYPE
            || read_u16(packet, 74)? != 0
            || read_u16(packet, 72)? != 0
            || read_u32(packet, 76)? != 0
            || read_u32(packet, 80)? != 0
            || read_u32(packet, 84)? != 0
        {
            return Err(SmbFileInformationError::UnsupportedProfile);
        }
        let output_buffer_length = read_u32(packet, 68)?;
        validate_bound(output_buffer_length)?;
        Ok(Self {
            header,
            information_class: FileInformationClass::parse_query(read_u8(packet, 67)?)?,
            output_buffer_length,
            file_id: read_file_id(packet, 88)?,
        })
    }
}

/// Protocol-neutral values used to encode supported file-information layouts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileInformationValues {
    /// Creation time in Windows `FILETIME` units.
    pub creation_time: u64,
    /// Last access time in Windows `FILETIME` units.
    pub last_access_time: u64,
    /// Last content-write time in Windows `FILETIME` units.
    pub last_write_time: u64,
    /// Last metadata-change time in Windows `FILETIME` units.
    pub change_time: u64,
    /// Allocation rounded to the logical volume's advertised allocation unit.
    pub allocation_size: u64,
    /// Exact logical length.
    pub end_of_file: u64,
    /// Supported DOS attribute bits.
    pub file_attributes: u32,
    /// Whether final deletion is pending.
    pub delete_pending: bool,
    /// Whether the open identifies a directory.
    pub directory: bool,
    /// Exact granted SMB access mask.
    pub granted_access: u32,
    /// Connection-local sequential byte position.
    pub current_byte_offset: u64,
    /// Stable open/object identity.
    pub file_id: [u8; 16],
    /// Root-relative canonical path with a leading separator.
    pub normalized_name: String,
}

/// Encoded successful `SMB2 QUERY_INFO` response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryInfoResponse {
    /// Response packet before signing, encryption and direct-TCP framing.
    pub packet: Vec<u8>,
}

impl QueryInfoResponse {
    /// Encodes the selected exact information layout.
    ///
    /// # Errors
    ///
    /// Rejects invalid names, inconsistent directory values or output exceeding the client bound.
    pub fn encode(
        request: QueryInfoRequest,
        values: &FileInformationValues,
    ) -> Result<Self, SmbFileInformationError> {
        validate_values(values)?;
        let payload = encode_query_payload(request.information_class, values)?;
        if payload.len()
            > usize::try_from(request.output_buffer_length)
                .map_err(|_| SmbFileInformationError::OutputTooLarge)?
        {
            return Err(SmbFileInformationError::OutputTooLarge);
        }
        let payload_length =
            u32::try_from(payload.len()).map_err(|_| SmbFileInformationError::OutputTooLarge)?;
        let mut packet = Vec::with_capacity(usize::from(QUERY_RESPONSE_OFFSET) + payload.len());
        packet.extend_from_slice(&success_header(request.header));
        packet.extend_from_slice(&QUERY_RESPONSE_SIZE.to_le_bytes());
        packet.extend_from_slice(&QUERY_RESPONSE_OFFSET.to_le_bytes());
        packet.extend_from_slice(&payload_length.to_le_bytes());
        packet.extend_from_slice(&payload);
        Ok(Self { packet })
    }
}

/// Supported file mutation decoded from one `SMB2 SET_INFO` request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SetFileInformation {
    /// Rename or move an open object to one root-relative path.
    Rename {
        /// Whether an existing target may be replaced.
        replace_if_exists: bool,
        /// Validated root-relative destination components.
        target_components: Vec<String>,
    },
    /// Set or clear delete-on-close state.
    Disposition {
        /// Whether deletion is pending.
        delete_pending: bool,
    },
    /// Set the exact logical end of file.
    EndOfFile {
        /// New logical length.
        length: u64,
    },
}

/// Validated `SMB2 SET_INFO` request for file information.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetInfoRequest {
    /// Validated synchronous request header.
    pub header: Smb2Header,
    /// Exact open identity.
    pub file_id: SmbFileId,
    /// Validated semantic mutation.
    pub information: SetFileInformation,
}

impl SetInfoRequest {
    /// Parses supported bounded file mutations.
    ///
    /// # Errors
    ///
    /// Rejects malformed identities, compounds, offsets, lengths, unsupported types/classes,
    /// invalid UTF-16 paths, non-zero root handles and non-file information.
    pub fn parse(packet: &[u8]) -> Result<Self, SmbFileInformationError> {
        let header = validated_header(packet, Smb2Command::SetInfo)?;
        if header.next_command != 0
            || packet.len() < SET_REQUEST_BYTES
            || read_u16(packet, 64)? != SET_REQUEST_SIZE
            || read_u8(packet, 66)? != FILE_INFORMATION_TYPE
            || read_u16(packet, 74)? != 0
            || read_u32(packet, 76)? != 0
        {
            return Err(SmbFileInformationError::UnsupportedProfile);
        }
        let payload = set_payload(packet)?;
        let information = match read_u8(packet, 67)? {
            10 => parse_rename(payload)?,
            13 => parse_disposition(payload)?,
            20 => parse_end_of_file(payload)?,
            _ => return Err(SmbFileInformationError::UnsupportedInformationClass),
        };
        Ok(Self {
            header,
            file_id: read_file_id(packet, 80)?,
            information,
        })
    }

    /// Encodes the fixed successful `SMB2 SET_INFO` response.
    #[must_use]
    pub fn success_response(&self) -> [u8; 66] {
        let mut packet = [0_u8; 66];
        packet[..64].copy_from_slice(&success_header(self.header));
        packet[64..].copy_from_slice(&SET_RESPONSE_SIZE.to_le_bytes());
        packet
    }
}

fn encode_query_payload(
    class: FileInformationClass,
    values: &FileInformationValues,
) -> Result<Vec<u8>, SmbFileInformationError> {
    match class {
        FileInformationClass::Basic => Ok(encode_basic(values).to_vec()),
        FileInformationClass::Standard => Ok(encode_standard(values).to_vec()),
        FileInformationClass::Internal => Ok(values.file_id[..8].to_vec()),
        FileInformationClass::Ea | FileInformationClass::Mode | FileInformationClass::Alignment => {
            Ok(vec![0; 4])
        }
        FileInformationClass::Access => Ok(values.granted_access.to_le_bytes().to_vec()),
        FileInformationClass::Position => Ok(values.current_byte_offset.to_le_bytes().to_vec()),
        FileInformationClass::All => encode_all(values),
        FileInformationClass::NetworkOpen => Ok(encode_network_open(values).to_vec()),
        FileInformationClass::AttributeTag => {
            let mut payload = Vec::with_capacity(8);
            payload.extend_from_slice(&values.file_attributes.to_le_bytes());
            payload.extend_from_slice(&0_u32.to_le_bytes());
            Ok(payload)
        }
        FileInformationClass::NormalizedName => encode_name(&values.normalized_name),
        FileInformationClass::Id => {
            let mut payload = Vec::with_capacity(24);
            payload.extend_from_slice(&volume_serial(values.file_id).to_le_bytes());
            payload.extend_from_slice(&values.file_id);
            Ok(payload)
        }
    }
}

fn encode_all(values: &FileInformationValues) -> Result<Vec<u8>, SmbFileInformationError> {
    let name = encode_name(&values.normalized_name)?;
    let mut payload = Vec::with_capacity(96 + name.len());
    payload.extend_from_slice(&encode_basic(values));
    payload.extend_from_slice(&encode_standard(values));
    payload.extend_from_slice(&values.file_id[..8]);
    payload.extend_from_slice(&0_u32.to_le_bytes());
    payload.extend_from_slice(&values.granted_access.to_le_bytes());
    payload.extend_from_slice(&values.current_byte_offset.to_le_bytes());
    payload.extend_from_slice(&0_u32.to_le_bytes());
    payload.extend_from_slice(&0_u32.to_le_bytes());
    payload.extend_from_slice(&name);
    Ok(payload)
}

fn encode_basic(values: &FileInformationValues) -> [u8; 40] {
    let mut payload = [0_u8; 40];
    for (offset, value) in [
        (0, values.creation_time),
        (8, values.last_access_time),
        (16, values.last_write_time),
        (24, values.change_time),
    ] {
        payload[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    payload[32..36].copy_from_slice(&values.file_attributes.to_le_bytes());
    payload
}

fn encode_standard(values: &FileInformationValues) -> [u8; 24] {
    let mut payload = [0_u8; 24];
    payload[..8].copy_from_slice(&values.allocation_size.to_le_bytes());
    payload[8..16].copy_from_slice(&values.end_of_file.to_le_bytes());
    payload[16..20].copy_from_slice(&1_u32.to_le_bytes());
    payload[20] = u8::from(values.delete_pending);
    payload[21] = u8::from(values.directory);
    payload
}

fn encode_network_open(values: &FileInformationValues) -> [u8; 56] {
    let mut payload = [0_u8; 56];
    for (offset, value) in [
        (0, values.creation_time),
        (8, values.last_access_time),
        (16, values.last_write_time),
        (24, values.change_time),
        (32, values.allocation_size),
        (40, values.end_of_file),
    ] {
        payload[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    payload[48..52].copy_from_slice(&values.file_attributes.to_le_bytes());
    payload
}

fn encode_name(name: &str) -> Result<Vec<u8>, SmbFileInformationError> {
    validate_name(name)?;
    let encoded = name
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    let length =
        u32::try_from(encoded.len()).map_err(|_| SmbFileInformationError::OutputTooLarge)?;
    let mut payload = Vec::with_capacity(4 + encoded.len());
    payload.extend_from_slice(&length.to_le_bytes());
    payload.extend_from_slice(&encoded);
    Ok(payload)
}

fn parse_rename(payload: &[u8]) -> Result<SetFileInformation, SmbFileInformationError> {
    if payload.len() < 24 || !matches!(payload[0], 0 | 1) || read_u64(payload, 8)? != 0 {
        return Err(SmbFileInformationError::InvalidMutation);
    }
    let name_length = usize::try_from(read_u32(payload, 16)?)
        .map_err(|_| SmbFileInformationError::InvalidMutation)?;
    let name_end = 20_usize
        .checked_add(name_length)
        .filter(|end| *end <= payload.len())
        .ok_or(SmbFileInformationError::InvalidMutation)?;
    let name = decode_utf16(
        payload
            .get(20..name_end)
            .ok_or(SmbFileInformationError::InvalidMutation)?,
    )?;
    Ok(SetFileInformation::Rename {
        replace_if_exists: payload[0] == 1,
        target_components: parse_path(&name)?,
    })
}

fn parse_disposition(payload: &[u8]) -> Result<SetFileInformation, SmbFileInformationError> {
    if payload.len() != 1 || !matches!(payload[0], 0 | 1) {
        return Err(SmbFileInformationError::InvalidMutation);
    }
    Ok(SetFileInformation::Disposition {
        delete_pending: payload[0] == 1,
    })
}

fn parse_end_of_file(payload: &[u8]) -> Result<SetFileInformation, SmbFileInformationError> {
    if payload.len() != 8 {
        return Err(SmbFileInformationError::InvalidMutation);
    }
    let length = read_u64(payload, 0)?;
    if length > i64::MAX as u64 {
        return Err(SmbFileInformationError::InvalidMutation);
    }
    Ok(SetFileInformation::EndOfFile { length })
}

fn set_payload(packet: &[u8]) -> Result<&[u8], SmbFileInformationError> {
    let length = usize::try_from(read_u32(packet, 68)?)
        .map_err(|_| SmbFileInformationError::InvalidMutation)?;
    let offset = usize::from(read_u16(packet, 72)?);
    if length == 0 || length > MAXIMUM_INFORMATION_BYTES || offset < SET_REQUEST_BYTES {
        return Err(SmbFileInformationError::InvalidMutation);
    }
    packet
        .get(
            offset
                ..offset
                    .checked_add(length)
                    .ok_or(SmbFileInformationError::InvalidMutation)?,
        )
        .ok_or(SmbFileInformationError::InvalidMutation)
}

fn parse_path(name: &str) -> Result<Vec<String>, SmbFileInformationError> {
    let trimmed = name.trim_start_matches('\\');
    if trimmed.is_empty()
        || trimmed.contains('/')
        || trimmed.split('\\').any(|component| {
            component.is_empty()
                || matches!(component, "." | "..")
                || component.chars().any(char::is_control)
        })
    {
        return Err(SmbFileInformationError::InvalidPath);
    }
    Ok(trimmed.split('\\').map(str::to_owned).collect())
}

fn decode_utf16(bytes: &[u8]) -> Result<String, SmbFileInformationError> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(2) {
        return Err(SmbFileInformationError::InvalidPath);
    }
    let units = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .copied()
        .map(u16::from_le_bytes)
        .collect::<Vec<_>>();
    String::from_utf16(&units).map_err(|_| SmbFileInformationError::InvalidPath)
}

fn validate_values(values: &FileInformationValues) -> Result<(), SmbFileInformationError> {
    if values.file_id == [0; 16]
        || values.file_id == [0xff; 16]
        || values.allocation_size < values.end_of_file
        || values.directory && (values.allocation_size != 0 || values.end_of_file != 0)
    {
        Err(SmbFileInformationError::InvalidValues)
    } else {
        validate_name(&values.normalized_name)
    }
}

fn validate_name(name: &str) -> Result<(), SmbFileInformationError> {
    if name == "\\" {
        return Ok(());
    }
    if !name.starts_with('\\')
        || name.chars().any(char::is_control)
        || name.contains('/')
        || name.split('\\').skip(1).any(str::is_empty)
    {
        Err(SmbFileInformationError::InvalidPath)
    } else {
        Ok(())
    }
}

fn validate_bound(length: u32) -> Result<(), SmbFileInformationError> {
    if length == 0 || usize::try_from(length).unwrap_or(usize::MAX) > MAXIMUM_INFORMATION_BYTES {
        Err(SmbFileInformationError::InvalidBound)
    } else {
        Ok(())
    }
}

fn validated_header(
    packet: &[u8],
    command: Smb2Command,
) -> Result<Smb2Header, SmbFileInformationError> {
    let header = Smb2Header::parse_request(packet)?;
    if header.command != command {
        return Err(SmbFileInformationError::WrongCommand);
    }
    if header.session_id == 0 || header.tree_id == 0 {
        return Err(SmbFileInformationError::InvalidIdentity);
    }
    Ok(header)
}

fn success_header(header: Smb2Header) -> [u8; 64] {
    header.encode_response(
        0,
        header.credit_charge.max(1),
        header.tree_id,
        header.session_id,
    )
}

fn read_file_id(packet: &[u8], offset: usize) -> Result<SmbFileId, SmbFileInformationError> {
    let bytes = packet
        .get(offset..offset + 16)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(SmbFileInformationError::Truncated)?;
    SmbFileId::from_wire(bytes).map_err(|_| SmbFileInformationError::InvalidIdentity)
}

fn volume_serial(file_id: [u8; 16]) -> u64 {
    u64::from_le_bytes([
        file_id[8],
        file_id[9],
        file_id[10],
        file_id[11],
        file_id[12],
        file_id[13],
        file_id[14],
        file_id[15],
    ])
}

fn read_u8(packet: &[u8], offset: usize) -> Result<u8, SmbFileInformationError> {
    packet
        .get(offset)
        .copied()
        .ok_or(SmbFileInformationError::Truncated)
}

macro_rules! read_integer {
    ($name:ident, $type:ty, $size:literal) => {
        fn $name(packet: &[u8], offset: usize) -> Result<$type, SmbFileInformationError> {
            packet
                .get(offset..offset + $size)
                .and_then(|bytes| bytes.try_into().ok())
                .map(<$type>::from_le_bytes)
                .ok_or(SmbFileInformationError::Truncated)
        }
    };
}

read_integer!(read_u16, u16, 2);
read_integer!(read_u32, u32, 4);
read_integer!(read_u64, u64, 8);

/// Invalid or unsupported bounded SMB file-information framing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SmbFileInformationError {
    /// Required fixed or referenced bytes are absent.
    #[error("SMB file-information request is truncated")]
    Truncated,
    /// Another command family reached this parser.
    #[error("SMB file-information parser received another command")]
    WrongCommand,
    /// Session, tree or file identity is invalid.
    #[error("SMB file-information identity is invalid")]
    InvalidIdentity,
    /// Input buffers or non-file information are outside the initial profile.
    #[error("SMB file-information profile is unsupported")]
    UnsupportedProfile,
    /// The requested information layout is not supported.
    #[error("SMB file-information class is unsupported")]
    UnsupportedInformationClass,
    /// A query output claim is zero or exceeds the implementation ceiling.
    #[error("SMB file-information output bound is invalid")]
    InvalidBound,
    /// A mutation payload has an invalid length, value, offset or relationship.
    #[error("SMB file-information mutation is invalid")]
    InvalidMutation,
    /// A logical path is malformed or cannot be represented safely.
    #[error("SMB file-information path is invalid")]
    InvalidPath,
    /// Protocol-neutral response values are inconsistent.
    #[error("SMB file-information response values are invalid")]
    InvalidValues,
    /// The encoded response exceeds the client's bound.
    #[error("SMB file-information response exceeds its byte bound")]
    OutputTooLarge,
    /// The common SMB2 header is invalid.
    #[error(transparent)]
    Header(#[from] Smb2HeaderError),
}

#[cfg(test)]
mod tests {
    use super::{
        FileInformationClass, FileInformationValues, QueryInfoRequest, QueryInfoResponse,
        SetFileInformation, SetInfoRequest, SmbFileInformationError,
    };

    #[test]
    fn query_all_information_encodes_exact_composite_layout() -> Result<(), SmbFileInformationError>
    {
        let request = QueryInfoRequest::parse(&query_packet(18, 4_096))?;
        assert_eq!(request.information_class, FileInformationClass::All);
        let response = QueryInfoResponse::encode(request, &values())?;
        assert_eq!(&response.packet[64..66], &9_u16.to_le_bytes());
        assert_eq!(&response.packet[66..68], &72_u16.to_le_bytes());
        assert_eq!(&response.packet[72 + 48..72 + 56], &19_u64.to_le_bytes());
        assert_eq!(response.packet[72 + 61], 0);
        assert_eq!(
            &response.packet[72 + 76..72 + 80],
            &0x0012_0089_u32.to_le_bytes()
        );
        assert_eq!(&response.packet[72 + 96..72 + 100], &24_u32.to_le_bytes());
        Ok(())
    }

    #[test]
    fn root_normalized_name_is_representable() -> Result<(), SmbFileInformationError> {
        let request = QueryInfoRequest::parse(&query_packet(48, 4_096))?;
        let mut root = values();
        root.normalized_name = "\\".to_owned();
        root.directory = true;
        root.allocation_size = 0;
        root.end_of_file = 0;
        let response = QueryInfoResponse::encode(request, &root)?;
        assert_eq!(&response.packet[76..], &[b'\\', 0]);
        Ok(())
    }

    #[test]
    fn set_rename_disposition_and_length_decode_exact_semantics()
    -> Result<(), SmbFileInformationError> {
        let rename = SetInfoRequest::parse(&set_packet(10, &rename_payload("\\new\\name")))?;
        assert_eq!(
            rename.information,
            SetFileInformation::Rename {
                replace_if_exists: false,
                target_components: vec!["new".to_owned(), "name".to_owned()],
            }
        );
        let disposition = SetInfoRequest::parse(&set_packet(13, &[1]))?;
        assert_eq!(
            disposition.information,
            SetFileInformation::Disposition {
                delete_pending: true
            }
        );
        let length = SetInfoRequest::parse(&set_packet(20, &99_i64.to_le_bytes()))?;
        assert_eq!(
            length.information,
            SetFileInformation::EndOfFile { length: 99 }
        );
        assert_eq!(&length.success_response()[64..], &2_u16.to_le_bytes());
        Ok(())
    }

    #[test]
    fn hostile_bounds_offsets_types_paths_and_signed_lengths_fail_closed() {
        let mut query = query_packet(18, 4_096);
        query[76..80].copy_from_slice(&1_u32.to_le_bytes());
        assert_eq!(
            QueryInfoRequest::parse(&query),
            Err(SmbFileInformationError::UnsupportedProfile)
        );

        let mut rename = set_packet(10, &rename_payload("\\safe"));
        rename[72..74].copy_from_slice(&u16::MAX.to_le_bytes());
        assert_eq!(
            SetInfoRequest::parse(&rename),
            Err(SmbFileInformationError::InvalidMutation)
        );

        let invalid = set_packet(10, &rename_payload("\\..\\escape"));
        assert_eq!(
            SetInfoRequest::parse(&invalid),
            Err(SmbFileInformationError::InvalidPath)
        );

        let invalid = set_packet(20, &(-1_i64).to_le_bytes());
        assert_eq!(
            SetInfoRequest::parse(&invalid),
            Err(SmbFileInformationError::InvalidMutation)
        );
    }

    fn values() -> FileInformationValues {
        FileInformationValues {
            creation_time: 1,
            last_access_time: 2,
            last_write_time: 3,
            change_time: 4,
            allocation_size: 4_096,
            end_of_file: 19,
            file_attributes: 0x80,
            delete_pending: false,
            directory: false,
            granted_access: 0x0012_0089,
            current_byte_offset: 7,
            file_id: [7; 16],
            normalized_name: "\\folder\\file".to_owned(),
        }
    }

    fn query_packet(class: u8, output_length: u32) -> Vec<u8> {
        let mut packet = request_header(0x10, 104);
        packet[64..66].copy_from_slice(&41_u16.to_le_bytes());
        packet[66] = 1;
        packet[67] = class;
        packet[68..72].copy_from_slice(&output_length.to_le_bytes());
        packet[88..96].copy_from_slice(&7_u64.to_le_bytes());
        packet[96..104].copy_from_slice(&11_u64.to_le_bytes());
        packet
    }

    fn set_packet(class: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = request_header(0x11, 96);
        packet[64..66].copy_from_slice(&33_u16.to_le_bytes());
        packet[66] = 1;
        packet[67] = class;
        packet[68..72].copy_from_slice(
            &u32::try_from(payload.len())
                .unwrap_or_default()
                .to_le_bytes(),
        );
        packet[72..74].copy_from_slice(&96_u16.to_le_bytes());
        packet[80..88].copy_from_slice(&7_u64.to_le_bytes());
        packet[88..96].copy_from_slice(&11_u64.to_le_bytes());
        packet.extend_from_slice(payload);
        packet
    }

    fn rename_payload(name: &str) -> Vec<u8> {
        let encoded = name
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let mut payload = vec![0; 20];
        payload[16..20].copy_from_slice(
            &u32::try_from(encoded.len())
                .unwrap_or_default()
                .to_le_bytes(),
        );
        payload.extend_from_slice(&encoded);
        payload.resize(payload.len().max(24), 0);
        payload
    }

    fn request_header(command: u16, length: usize) -> Vec<u8> {
        let mut packet = vec![0; length];
        packet[..4].copy_from_slice(&[0xfe, b'S', b'M', b'B']);
        packet[4..6].copy_from_slice(&64_u16.to_le_bytes());
        packet[6..8].copy_from_slice(&1_u16.to_le_bytes());
        packet[12..14].copy_from_slice(&command.to_le_bytes());
        packet[14..16].copy_from_slice(&1_u16.to_le_bytes());
        packet[24..32].copy_from_slice(&17_u64.to_le_bytes());
        packet[36..40].copy_from_slice(&23_u32.to_le_bytes());
        packet[40..48].copy_from_slice(&29_u64.to_le_bytes());
        packet
    }
}
