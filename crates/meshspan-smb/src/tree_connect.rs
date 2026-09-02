// SPDX-License-Identifier: GPL-2.0-only

//! SMB 3.1.1 share-tree connection and disconnection framing.

use crate::{Smb2Command, Smb2Header, Smb2HeaderError};

const HEADER_BYTES: usize = 64;
const TREE_CONNECT_REQUEST_BYTES: usize = 72;
const TREE_CONNECT_REQUEST_STRUCTURE_SIZE: u16 = 9;
const TREE_CONNECT_RESPONSE_STRUCTURE_SIZE: u16 = 16;
const TREE_DISCONNECT_STRUCTURE_SIZE: u16 = 4;
const SHARE_TYPE_DISK: u8 = 1;
const SHARE_FLAG_ENCRYPT_DATA: u32 = 0x0000_8000;
const MAXIMUM_UNC_UNITS: usize = 512;
const MAXIMUM_COMPONENT_UNITS: usize = 255;

/// Validated root-only UNC target from one `TREE_CONNECT` request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeConnectRequest {
    /// Parsed synchronous request header.
    pub header: Smb2Header,
    /// Server name supplied by the client for routing diagnostics.
    pub server_name: String,
    /// User-visible published share name.
    pub share_name: String,
}

impl TreeConnectRequest {
    /// Parses one complete root-only disk-share request.
    ///
    /// # Errors
    ///
    /// Rejects invalid headers, flags, offsets, UTF-16, UNC shapes or path components.
    pub fn parse(packet: &[u8]) -> Result<Self, SmbTreeConnectError> {
        let header = Smb2Header::parse_request(packet)?;
        if header.command != Smb2Command::TreeConnect {
            return Err(SmbTreeConnectError::WrongCommand);
        }
        if header.session_id == 0 || header.tree_id != 0 {
            return Err(SmbTreeConnectError::InvalidSession);
        }
        let command_end = command_end(packet, header.next_command)?;
        if command_end < TREE_CONNECT_REQUEST_BYTES {
            return Err(SmbTreeConnectError::Truncated);
        }
        if read_u16(packet, HEADER_BYTES)? != TREE_CONNECT_REQUEST_STRUCTURE_SIZE {
            return Err(SmbTreeConnectError::InvalidStructureSize);
        }
        if read_u16(packet, 66)? != 0 {
            return Err(SmbTreeConnectError::UnsupportedFlags);
        }
        let path_offset = usize::from(read_u16(packet, 68)?);
        let path_length = usize::from(read_u16(packet, 70)?);
        if path_offset < TREE_CONNECT_REQUEST_BYTES
            || path_length == 0
            || !path_length.is_multiple_of(2)
            || path_length / 2 > MAXIMUM_UNC_UNITS
        {
            return Err(SmbTreeConnectError::InvalidPath);
        }
        let end = path_offset
            .checked_add(path_length)
            .filter(|end| *end <= command_end)
            .ok_or(SmbTreeConnectError::InvalidPath)?;
        let path = decode_utf16(
            packet
                .get(path_offset..end)
                .ok_or(SmbTreeConnectError::InvalidPath)?,
        )?;
        let (server_name, share_name) = parse_unc(&path)?;
        Ok(Self {
            header,
            server_name,
            share_name,
        })
    }
}

/// Values used to expose one authorised logical share as an SMB disk tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TreeConnectResponseConfig {
    /// Non-zero connection-local tree identity.
    pub tree_id: u32,
    /// Windows-compatible maximal access mask derived from effective `MeshSpan` rights.
    pub maximal_access: u32,
    /// Whether packets on this tree must use the encrypted transform.
    pub encryption_required: bool,
}

/// Encoded successful `TREE_CONNECT` response, excluding Direct TCP framing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeConnectResponse {
    /// Exact SMB2 response packet.
    pub packet: Vec<u8>,
}

impl TreeConnectResponse {
    /// Encodes a successful disk-tree response for one authorised share.
    ///
    /// # Errors
    ///
    /// Rejects reserved tree identities or an empty effective access mask.
    pub fn encode(
        request: &TreeConnectRequest,
        config: TreeConnectResponseConfig,
    ) -> Result<Self, SmbTreeConnectError> {
        if config.tree_id == 0 || config.maximal_access == 0 {
            return Err(SmbTreeConnectError::InvalidResponse);
        }
        let mut packet = Vec::with_capacity(80);
        packet.extend_from_slice(&request.header.encode_response(
            0,
            1,
            config.tree_id,
            request.header.session_id,
        ));
        packet.extend_from_slice(&TREE_CONNECT_RESPONSE_STRUCTURE_SIZE.to_le_bytes());
        packet.push(SHARE_TYPE_DISK);
        packet.push(0);
        packet.extend_from_slice(
            &(if config.encryption_required {
                SHARE_FLAG_ENCRYPT_DATA
            } else {
                0
            })
            .to_le_bytes(),
        );
        packet.extend_from_slice(&0_u32.to_le_bytes());
        packet.extend_from_slice(&config.maximal_access.to_le_bytes());
        Ok(Self { packet })
    }
}

/// Validated `TREE_DISCONNECT` request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TreeDisconnectRequest {
    /// Parsed synchronous request header.
    pub header: Smb2Header,
}

impl TreeDisconnectRequest {
    /// Parses one exact fixed-size disconnect request.
    ///
    /// # Errors
    ///
    /// Rejects invalid headers, identities, structure fields or trailing command bytes.
    pub fn parse(packet: &[u8]) -> Result<Self, SmbTreeConnectError> {
        let header = Smb2Header::parse_request(packet)?;
        if header.command != Smb2Command::TreeDisconnect {
            return Err(SmbTreeConnectError::WrongCommand);
        }
        if header.session_id == 0 || header.tree_id == 0 {
            return Err(SmbTreeConnectError::InvalidSession);
        }
        if command_end(packet, header.next_command)? != 68
            || read_u16(packet, 64)? != TREE_DISCONNECT_STRUCTURE_SIZE
            || read_u16(packet, 66)? != 0
        {
            return Err(SmbTreeConnectError::InvalidStructureSize);
        }
        Ok(Self { header })
    }

    /// Encodes the exact successful fixed response.
    #[must_use]
    pub fn success_response(self) -> [u8; 68] {
        let mut packet = [0_u8; 68];
        packet[..64].copy_from_slice(&self.header.encode_response(
            0,
            1,
            self.header.tree_id,
            self.header.session_id,
        ));
        packet[64..66].copy_from_slice(&TREE_DISCONNECT_STRUCTURE_SIZE.to_le_bytes());
        packet
    }
}

fn parse_unc(path: &str) -> Result<(String, String), SmbTreeConnectError> {
    let remainder = path
        .strip_prefix("\\\\")
        .ok_or(SmbTreeConnectError::InvalidPath)?;
    let mut components = remainder.split('\\');
    let server = components.next().ok_or(SmbTreeConnectError::InvalidPath)?;
    let share = components.next().ok_or(SmbTreeConnectError::InvalidPath)?;
    if components.next().is_some() || !valid_component(server) || !valid_component(share) {
        return Err(SmbTreeConnectError::InvalidPath);
    }
    Ok((server.to_owned(), share.to_owned()))
}

fn valid_component(value: &str) -> bool {
    let units = value.encode_utf16().count();
    value == value.trim()
        && (1..=MAXIMUM_COMPONENT_UNITS).contains(&units)
        && !value
            .chars()
            .any(|character| character.is_control() || matches!(character, '\\' | '/'))
}

fn decode_utf16(bytes: &[u8]) -> Result<String, SmbTreeConnectError> {
    let units = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|bytes| u16::from_le_bytes(*bytes))
        .collect::<Vec<_>>();
    String::from_utf16(&units).map_err(|_| SmbTreeConnectError::InvalidPath)
}

fn command_end(packet: &[u8], next_command: u32) -> Result<usize, SmbTreeConnectError> {
    if next_command == 0 {
        Ok(packet.len())
    } else {
        usize::try_from(next_command).map_err(|_| SmbTreeConnectError::InvalidPath)
    }
}

fn read_u16(packet: &[u8], offset: usize) -> Result<u16, SmbTreeConnectError> {
    packet
        .get(offset..offset + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(SmbTreeConnectError::Truncated)
}

/// Invalid share-tree wire framing or unsupported semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SmbTreeConnectError {
    /// Required fixed fields are absent.
    #[error("SMB tree request is truncated")]
    Truncated,
    /// The parser received another command family.
    #[error("SMB tree parser received another command")]
    WrongCommand,
    /// The command structure marker or fixed extent is invalid.
    #[error("SMB tree request structure is invalid")]
    InvalidStructureSize,
    /// Unsupported extension flags were supplied.
    #[error("SMB tree request flags are unsupported")]
    UnsupportedFlags,
    /// Session or tree identity is invalid for this transition.
    #[error("SMB tree session identity is invalid")]
    InvalidSession,
    /// UNC bytes, UTF-16 or root-only component shape is invalid.
    #[error("SMB tree path is invalid")]
    InvalidPath,
    /// Daemon-owned response values are invalid.
    #[error("SMB tree response is invalid")]
    InvalidResponse,
    /// The common SMB2 header is invalid.
    #[error(transparent)]
    Header(#[from] Smb2HeaderError),
}

#[cfg(test)]
mod tests {
    use super::{
        SmbTreeConnectError, TreeConnectRequest, TreeConnectResponse, TreeConnectResponseConfig,
        TreeDisconnectRequest,
    };

    #[test]
    fn root_unc_connect_and_disconnect_round_trip_exact_tree_identity()
    -> Result<(), SmbTreeConnectError> {
        let request = TreeConnectRequest::parse(&tree_connect_packet("\\\\meshspan\\Accounts"))?;
        assert_eq!(request.server_name, "meshspan");
        assert_eq!(request.share_name, "Accounts");
        let response = TreeConnectResponse::encode(
            &request,
            TreeConnectResponseConfig {
                tree_id: 17,
                maximal_access: 0x001f_01ff,
                encryption_required: true,
            },
        )?;
        assert_eq!(&response.packet[36..40], &17_u32.to_le_bytes());
        assert_eq!(&response.packet[40..48], &9_u64.to_le_bytes());
        assert_eq!(&response.packet[68..72], &0x8000_u32.to_le_bytes());

        let disconnect = TreeDisconnectRequest::parse(&tree_disconnect_packet(17))?;
        let response = disconnect.success_response();
        assert_eq!(&response[36..40], &17_u32.to_le_bytes());
        assert_eq!(&response[64..68], &[4, 0, 0, 0]);
        Ok(())
    }

    #[test]
    fn nested_malformed_and_extension_paths_fail_closed() {
        for path in [
            "meshspan\\share",
            "\\\\meshspan\\share\\folder",
            "\\\\meshspan\\",
            "\\\\\\share",
        ] {
            assert!(matches!(
                TreeConnectRequest::parse(&tree_connect_packet(path)),
                Err(SmbTreeConnectError::InvalidPath)
            ));
        }
        let mut packet = tree_connect_packet("\\\\meshspan\\share");
        packet[66..68].copy_from_slice(&1_u16.to_le_bytes());
        assert_eq!(
            TreeConnectRequest::parse(&packet),
            Err(SmbTreeConnectError::UnsupportedFlags)
        );
        packet[66..68].fill(0);
        packet[70..72].copy_from_slice(&3_u16.to_le_bytes());
        assert_eq!(
            TreeConnectRequest::parse(&packet),
            Err(SmbTreeConnectError::InvalidPath)
        );
    }

    fn tree_connect_packet(path: &str) -> Vec<u8> {
        let encoded = path
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let mut packet = request_header(3, 0);
        packet.extend_from_slice(&9_u16.to_le_bytes());
        packet.extend_from_slice(&0_u16.to_le_bytes());
        packet.extend_from_slice(&72_u16.to_le_bytes());
        packet.extend_from_slice(
            &u16::try_from(encoded.len())
                .unwrap_or_default()
                .to_le_bytes(),
        );
        packet.extend_from_slice(&encoded);
        packet
    }

    fn tree_disconnect_packet(tree_id: u32) -> Vec<u8> {
        let mut packet = request_header(4, tree_id);
        packet.extend_from_slice(&[4, 0, 0, 0]);
        packet
    }

    fn request_header(command: u16, tree_id: u32) -> Vec<u8> {
        let mut packet = vec![0; 64];
        packet[..4].copy_from_slice(&[0xfe, b'S', b'M', b'B']);
        packet[4..6].copy_from_slice(&64_u16.to_le_bytes());
        packet[12..14].copy_from_slice(&command.to_le_bytes());
        packet[14..16].copy_from_slice(&1_u16.to_le_bytes());
        packet[24..32].copy_from_slice(&1_u64.to_le_bytes());
        packet[32..36].copy_from_slice(&2_u32.to_le_bytes());
        packet[36..40].copy_from_slice(&tree_id.to_le_bytes());
        packet[40..48].copy_from_slice(&9_u64.to_le_bytes());
        packet
    }
}
