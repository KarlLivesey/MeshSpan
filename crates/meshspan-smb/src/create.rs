// SPDX-License-Identifier: GPL-2.0-only

//! SMB 3.1.1 create/open framing and protocol-semantic validation.

use crate::{Smb2Command, Smb2Header, Smb2HeaderError, SmbFileId};

const CREATE_REQUEST_STRUCTURE_SIZE: u16 = 57;
const CREATE_REQUEST_FIXED_END: usize = 120;
const CREATE_RESPONSE_STRUCTURE_SIZE: u16 = 89;
const CREATE_RESPONSE_BYTES: usize = 152;
const MAXIMUM_PATH_BYTES: usize = 4_096;
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
const FILE_WRITE_THROUGH: u32 = 0x0000_0002;
const FILE_SEQUENTIAL_ONLY: u32 = 0x0000_0004;
const FILE_NO_INTERMEDIATE_BUFFERING: u32 = 0x0000_0008;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
const FILE_RANDOM_ACCESS: u32 = 0x0000_0800;
const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;
const FILE_NO_COMPRESSION: u32 = 0x0000_8000;
const SUPPORTED_CREATE_OPTIONS: u32 = FILE_DIRECTORY_FILE
    | FILE_WRITE_THROUGH
    | FILE_SEQUENTIAL_ONLY
    | FILE_NO_INTERMEDIATE_BUFFERING
    | FILE_NON_DIRECTORY_FILE
    | FILE_RANDOM_ACCESS
    | FILE_DELETE_ON_CLOSE
    | FILE_NO_COMPRESSION;
const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
const FILE_ATTRIBUTE_SYSTEM: u32 = 0x0000_0004;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
const FILE_ATTRIBUTE_TEMPORARY: u32 = 0x0000_0100;
const FILE_ATTRIBUTE_NOT_CONTENT_INDEXED: u32 = 0x0000_2000;
const SUPPORTED_ATTRIBUTES: u32 = FILE_ATTRIBUTE_READONLY
    | FILE_ATTRIBUTE_HIDDEN
    | FILE_ATTRIBUTE_SYSTEM
    | FILE_ATTRIBUTE_DIRECTORY
    | FILE_ATTRIBUTE_ARCHIVE
    | FILE_ATTRIBUTE_NORMAL
    | FILE_ATTRIBUTE_TEMPORARY
    | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;

/// SMB create/open choice after exact wire decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateDisposition {
    /// Fail unless the path already exists.
    OpenExisting,
    /// Fail if the path already exists.
    CreateNew,
    /// Open or create atomically.
    OpenOrCreate,
    /// Truncate an existing file.
    OverwriteExisting,
    /// Truncate an existing file or create it atomically.
    OverwriteOrCreate,
}

/// SMB access bits reduced to the common handle operations and retained raw mask.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SmbRequestedAccess {
    /// Exact validated wire mask for attributes and later profile extensions.
    pub wire_mask: u32,
    /// Whether content read access is requested.
    pub read_data: bool,
    /// Whether content write or append access is requested.
    pub write_data: bool,
    /// Whether deletion access is requested.
    pub delete: bool,
}

/// Operations this open permits on concurrent handles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SmbShareAccess {
    /// Permit concurrent reads.
    pub read: bool,
    /// Permit concurrent writes.
    pub write: bool,
    /// Permit concurrent deletion.
    pub delete: bool,
}

/// Object-kind constraint carried by one create/open request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateTargetKind {
    /// Either a file or directory may satisfy the open.
    Any,
    /// The target must be a directory.
    Directory,
    /// The target must be a regular file.
    File,
}

/// Namespace and durability behaviours carried by SMB create options.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreateOptions {
    /// Required target kind.
    pub target_kind: CreateTargetKind,
    /// Whether final close must remove the namespace entry.
    pub delete_on_close: bool,
    /// Whether each successful write must cross the publication barrier.
    pub write_through: bool,
}

/// Validated `SMB2 CREATE` request without provider paths or authority claims.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateRequest {
    /// Validated synchronous request header.
    pub header: Smb2Header,
    /// Root-relative path components in client display spelling; empty opens the share root.
    pub path_components: Vec<String>,
    /// Existing/creation behaviour.
    pub disposition: CreateDisposition,
    /// Requested common handle access.
    pub desired_access: SmbRequestedAccess,
    /// Concurrent sharing contract.
    pub share_access: SmbShareAccess,
    /// Portable DOS/basic attributes requested on creation.
    pub file_attributes: u32,
    /// Target-kind, close and publication behaviours.
    pub options: CreateOptions,
}

impl CreateRequest {
    /// Parses the first create/open profile without DFS or create contexts.
    ///
    /// # Errors
    ///
    /// Rejects malformed paths, unsupported contexts/options, contradictory flags and bounds.
    pub fn parse(packet: &[u8]) -> Result<Self, SmbCreateError> {
        let header = Smb2Header::parse_request(packet)?;
        validate_header(header)?;
        let command_end = command_end(packet, header.next_command)?;
        if command_end < CREATE_REQUEST_FIXED_END
            || read_u16(packet, 64)? != CREATE_REQUEST_STRUCTURE_SIZE
            || read_u8(packet, 66)? != 0
            || read_u64(packet, 72)? != 0
        {
            return Err(SmbCreateError::InvalidStructure);
        }
        let attributes = read_u32(packet, 92)?;
        let options = read_u32(packet, 104)?;
        validate_options(attributes, options)?;
        let contexts_offset = read_u32(packet, 112)?;
        let contexts_length = read_u32(packet, 116)?;
        if contexts_offset != 0 || contexts_length != 0 {
            return Err(SmbCreateError::UnsupportedContext);
        }
        Ok(Self {
            header,
            path_components: parse_path(packet, command_end)?,
            disposition: parse_disposition(read_u32(packet, 100)?)?,
            desired_access: parse_access(read_u32(packet, 88)?)?,
            share_access: parse_share_access(read_u32(packet, 96)?)?,
            file_attributes: attributes,
            options: parse_options(options),
        })
    }
}

/// Action taken by a successful create/open operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum CreateAction {
    /// Existing object was opened without replacement.
    Opened = 1,
    /// New object was created.
    Created = 2,
    /// Existing file content was replaced.
    Overwritten = 3,
}

/// Filesystem values returned after a successful common-service open.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreateResponseValues {
    /// Result classification.
    pub action: CreateAction,
    /// Creation time as an exact Windows `FILETIME` value.
    pub creation_time: u64,
    /// Last access time as an exact Windows `FILETIME` value.
    pub last_access_time: u64,
    /// Last content-write time as an exact Windows `FILETIME` value.
    pub last_write_time: u64,
    /// Last namespace/attribute change time as an exact Windows `FILETIME` value.
    pub change_time: u64,
    /// Allocated physical/logical bytes reported to the client.
    pub allocation_size: u64,
    /// Exact logical file length.
    pub end_of_file: u64,
    /// Portable DOS/basic attributes.
    pub file_attributes: u32,
    /// Connection-visible open identity.
    pub file_id: SmbFileId,
}

/// Exact successful `SMB2 CREATE` response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreateResponse {
    /// Fixed response before signing, encryption and direct-TCP framing.
    pub packet: [u8; CREATE_RESPONSE_BYTES],
}

impl CreateResponse {
    /// Encodes a successful open without unsupported oplock/create contexts.
    ///
    /// # Errors
    ///
    /// Rejects unsupported attributes or contradictory directory state.
    pub fn encode(
        request: &CreateRequest,
        values: CreateResponseValues,
    ) -> Result<Self, SmbCreateError> {
        if values.file_attributes & !SUPPORTED_ATTRIBUTES != 0
            || request.options.target_kind == CreateTargetKind::Directory
                && values.file_attributes & FILE_ATTRIBUTE_DIRECTORY == 0
            || request.options.target_kind == CreateTargetKind::File
                && values.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0
        {
            return Err(SmbCreateError::InvalidResponse);
        }
        let mut packet = [0_u8; CREATE_RESPONSE_BYTES];
        packet[..64].copy_from_slice(&request.header.encode_response(
            0,
            request.header.credit_charge.max(1),
            request.header.tree_id,
            request.header.session_id,
        ));
        packet[64..66].copy_from_slice(&CREATE_RESPONSE_STRUCTURE_SIZE.to_le_bytes());
        packet[68..72].copy_from_slice(&(values.action as u32).to_le_bytes());
        for (offset, value) in [
            (72, values.creation_time),
            (80, values.last_access_time),
            (88, values.last_write_time),
            (96, values.change_time),
            (104, values.allocation_size),
            (112, values.end_of_file),
        ] {
            packet[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        packet[120..124].copy_from_slice(&values.file_attributes.to_le_bytes());
        packet[128..144].copy_from_slice(&values.file_id.to_wire());
        Ok(Self { packet })
    }
}

fn validate_header(header: Smb2Header) -> Result<(), SmbCreateError> {
    if header.command != Smb2Command::Create {
        Err(SmbCreateError::WrongCommand)
    } else if header.session_id == 0 || header.tree_id == 0 {
        Err(SmbCreateError::InvalidIdentity)
    } else if header.flags & 0x1000_0000 != 0 {
        Err(SmbCreateError::UnsupportedDfs)
    } else {
        Ok(())
    }
}

fn validate_options(attributes: u32, options: u32) -> Result<(), SmbCreateError> {
    if attributes & !SUPPORTED_ATTRIBUTES != 0
        || options & !SUPPORTED_CREATE_OPTIONS != 0
        || options & FILE_DIRECTORY_FILE != 0 && options & FILE_NON_DIRECTORY_FILE != 0
        || options & FILE_SEQUENTIAL_ONLY != 0 && options & FILE_RANDOM_ACCESS != 0
    {
        Err(SmbCreateError::UnsupportedOption)
    } else {
        Ok(())
    }
}

const fn parse_options(options: u32) -> CreateOptions {
    let target_kind = if options & FILE_DIRECTORY_FILE != 0 {
        CreateTargetKind::Directory
    } else if options & FILE_NON_DIRECTORY_FILE != 0 {
        CreateTargetKind::File
    } else {
        CreateTargetKind::Any
    };
    CreateOptions {
        target_kind,
        delete_on_close: options & FILE_DELETE_ON_CLOSE != 0,
        write_through: options & FILE_WRITE_THROUGH != 0,
    }
}

fn parse_path(packet: &[u8], command_end: usize) -> Result<Vec<String>, SmbCreateError> {
    let offset = usize::from(read_u16(packet, 108)?);
    let length = usize::from(read_u16(packet, 110)?);
    if length == 0 {
        return if offset == 0 || offset >= CREATE_REQUEST_FIXED_END {
            Ok(Vec::new())
        } else {
            Err(SmbCreateError::InvalidPath)
        };
    }
    if offset < CREATE_REQUEST_FIXED_END || !length.is_multiple_of(2) || length > MAXIMUM_PATH_BYTES
    {
        return Err(SmbCreateError::InvalidPath);
    }
    let end = offset
        .checked_add(length)
        .filter(|end| *end <= command_end)
        .ok_or(SmbCreateError::InvalidPath)?;
    let bytes = packet.get(offset..end).ok_or(SmbCreateError::InvalidPath)?;
    let units = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect::<Vec<_>>();
    let path = String::from_utf16(&units).map_err(|_| SmbCreateError::InvalidPath)?;
    let components = path.split('\\').map(str::to_owned).collect::<Vec<_>>();
    if components.is_empty()
        || components.len() > 256
        || components.iter().any(|component| {
            component.is_empty()
                || matches!(component.as_str(), "." | "..")
                || component.encode_utf16().count() > 255
                || component.chars().any(char::is_control)
        })
    {
        Err(SmbCreateError::InvalidPath)
    } else {
        Ok(components)
    }
}

fn parse_disposition(value: u32) -> Result<CreateDisposition, SmbCreateError> {
    match value {
        1 => Ok(CreateDisposition::OpenExisting),
        2 => Ok(CreateDisposition::CreateNew),
        3 => Ok(CreateDisposition::OpenOrCreate),
        4 => Ok(CreateDisposition::OverwriteExisting),
        5 => Ok(CreateDisposition::OverwriteOrCreate),
        _ => Err(SmbCreateError::UnsupportedDisposition),
    }
}

fn parse_access(mask: u32) -> Result<SmbRequestedAccess, SmbCreateError> {
    const DELETE: u32 = 0x0001_0000;
    const GENERIC_ALL: u32 = 0x1000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const GENERIC_READ: u32 = 0x8000_0000;
    let read_data = mask & (0x0000_0001 | GENERIC_READ | GENERIC_ALL) != 0;
    let write_data = mask & (0x0000_0002 | 0x0000_0004 | GENERIC_WRITE | GENERIC_ALL) != 0;
    let delete = mask & (DELETE | 0x0000_0040 | GENERIC_ALL) != 0;
    if mask == 0 {
        Err(SmbCreateError::InvalidAccess)
    } else {
        Ok(SmbRequestedAccess {
            wire_mask: mask,
            read_data,
            write_data,
            delete,
        })
    }
}

fn parse_share_access(mask: u32) -> Result<SmbShareAccess, SmbCreateError> {
    if mask & !0x0000_0007 != 0 {
        return Err(SmbCreateError::InvalidShareAccess);
    }
    Ok(SmbShareAccess {
        read: mask & 1 != 0,
        write: mask & 2 != 0,
        delete: mask & 4 != 0,
    })
}

fn command_end(packet: &[u8], next_command: u32) -> Result<usize, SmbCreateError> {
    if next_command == 0 {
        Ok(packet.len())
    } else {
        usize::try_from(next_command).map_err(|_| SmbCreateError::InvalidPath)
    }
}

fn read_u8(packet: &[u8], offset: usize) -> Result<u8, SmbCreateError> {
    packet.get(offset).copied().ok_or(SmbCreateError::Truncated)
}

macro_rules! read_integer {
    ($name:ident, $type:ty, $size:literal) => {
        fn $name(packet: &[u8], offset: usize) -> Result<$type, SmbCreateError> {
            packet
                .get(offset..offset + $size)
                .and_then(|bytes| bytes.try_into().ok())
                .map(<$type>::from_le_bytes)
                .ok_or(SmbCreateError::Truncated)
        }
    };
}

read_integer!(read_u16, u16, 2);
read_integer!(read_u32, u32, 4);
read_integer!(read_u64, u64, 8);

/// Invalid or unsupported SMB create/open framing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SmbCreateError {
    /// Fixed or referenced input is absent.
    #[error("SMB create request is truncated")]
    Truncated,
    /// Another command family reached this parser.
    #[error("SMB create parser received another command")]
    WrongCommand,
    /// The session/tree identity is absent.
    #[error("SMB create identity is invalid")]
    InvalidIdentity,
    /// Fixed structure or reserved fields are invalid.
    #[error("SMB create structure is invalid")]
    InvalidStructure,
    /// DFS path semantics are outside the initial profile.
    #[error("SMB DFS create paths are unsupported")]
    UnsupportedDfs,
    /// A create context is outside the current bounded profile.
    #[error("SMB create context is unsupported")]
    UnsupportedContext,
    /// File attributes or create options are unsupported or contradictory.
    #[error("SMB create option is unsupported")]
    UnsupportedOption,
    /// The create disposition cannot be represented safely.
    #[error("SMB create disposition is unsupported")]
    UnsupportedDisposition,
    /// Requested access is empty or invalid.
    #[error("SMB requested access is invalid")]
    InvalidAccess,
    /// Concurrent sharing bits are outside the closed mask.
    #[error("SMB share access is invalid")]
    InvalidShareAccess,
    /// Root-relative UTF-16 path is malformed or excessive.
    #[error("SMB create path is invalid")]
    InvalidPath,
    /// Common-service response values contradict this open.
    #[error("SMB create response is invalid")]
    InvalidResponse,
    /// The common SMB2 header is invalid.
    #[error(transparent)]
    Header(#[from] Smb2HeaderError),
}

#[cfg(test)]
mod tests {
    use super::{
        CreateAction, CreateRequest, CreateResponse, CreateResponseValues, SmbCreateError,
    };
    use crate::SmbFileId;

    #[test]
    fn file_create_round_trips_path_access_and_exact_response() -> Result<(), SmbCreateError> {
        let request = CreateRequest::parse(&create_packet("Folder\\Report.txt"))?;
        assert_eq!(request.path_components, ["Folder", "Report.txt"]);
        assert!(request.desired_access.read_data);
        assert!(request.desired_access.write_data);
        assert!(request.share_access.read);
        let response = CreateResponse::encode(
            &request,
            CreateResponseValues {
                action: CreateAction::Created,
                creation_time: 1,
                last_access_time: 2,
                last_write_time: 3,
                change_time: 4,
                allocation_size: 4_096,
                end_of_file: 7,
                file_attributes: 0x20,
                file_id: SmbFileId::new(31, 37).map_err(|_| SmbCreateError::InvalidResponse)?,
            },
        )?;
        assert_eq!(&response.packet[68..72], &2_u32.to_le_bytes());
        assert_eq!(&response.packet[112..120], &7_u64.to_le_bytes());
        assert_eq!(&response.packet[128..136], &31_u64.to_le_bytes());
        Ok(())
    }

    #[test]
    fn hostile_paths_options_contexts_and_dispositions_fail_closed() {
        let mut packet = create_packet("Folder\\..\\secret");
        assert_eq!(
            CreateRequest::parse(&packet),
            Err(SmbCreateError::InvalidPath)
        );

        packet = create_packet("file");
        packet[104..108].copy_from_slice(&0x21_u32.to_le_bytes());
        assert_eq!(
            CreateRequest::parse(&packet),
            Err(SmbCreateError::UnsupportedOption)
        );

        packet = create_packet("file");
        packet[112..116].copy_from_slice(&120_u32.to_le_bytes());
        packet[116..120].copy_from_slice(&8_u32.to_le_bytes());
        assert_eq!(
            CreateRequest::parse(&packet),
            Err(SmbCreateError::UnsupportedContext)
        );

        packet = create_packet("file");
        packet[100..104].fill(0);
        assert_eq!(
            CreateRequest::parse(&packet),
            Err(SmbCreateError::UnsupportedDisposition)
        );
    }

    fn create_packet(path: &str) -> Vec<u8> {
        let encoded = path
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let mut packet = request_header();
        packet.extend_from_slice(&57_u16.to_le_bytes());
        packet.extend_from_slice(&[0, 0]);
        packet.extend_from_slice(&2_u32.to_le_bytes());
        packet.extend_from_slice(&[0; 16]);
        packet.extend_from_slice(&0xc000_0003_u32.to_le_bytes());
        packet.extend_from_slice(&0x20_u32.to_le_bytes());
        packet.extend_from_slice(&7_u32.to_le_bytes());
        packet.extend_from_slice(&3_u32.to_le_bytes());
        packet.extend_from_slice(&0x40_u32.to_le_bytes());
        packet.extend_from_slice(&120_u16.to_le_bytes());
        packet.extend_from_slice(
            &u16::try_from(encoded.len())
                .unwrap_or_default()
                .to_le_bytes(),
        );
        packet.extend_from_slice(&[0; 8]);
        packet.extend_from_slice(&encoded);
        packet
    }

    fn request_header() -> Vec<u8> {
        let mut packet = vec![0; 64];
        packet[..4].copy_from_slice(&[0xfe, b'S', b'M', b'B']);
        packet[4..6].copy_from_slice(&64_u16.to_le_bytes());
        packet[6..8].copy_from_slice(&1_u16.to_le_bytes());
        packet[12..14].copy_from_slice(&5_u16.to_le_bytes());
        packet[14..16].copy_from_slice(&1_u16.to_le_bytes());
        packet[24..32].copy_from_slice(&41_u64.to_le_bytes());
        packet[32..36].copy_from_slice(&43_u32.to_le_bytes());
        packet[36..40].copy_from_slice(&47_u32.to_le_bytes());
        packet[40..48].copy_from_slice(&53_u64.to_le_bytes());
        packet
    }
}
