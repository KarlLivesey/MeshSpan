// SPDX-License-Identifier: GPL-2.0-only

//! Fixed SMB connection-liveness, session-release and error messages.

use crate::{NtStatus, Smb2Command, Smb2Header, Smb2HeaderError};

const FIXED_REQUEST_BYTES: usize = 68;
const FIXED_STRUCTURE_SIZE: u16 = 4;
const ERROR_STRUCTURE_SIZE: u16 = 9;
const ERROR_FIXED_BYTES: usize = 72;
const MAXIMUM_ERROR_DATA_BYTES: usize = 64 * 1_024;

/// Validated authenticated SMB echo request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EchoRequest {
    /// Exact request header retained for response correlation.
    pub header: Smb2Header,
}

impl EchoRequest {
    /// Parses one exact fixed echo request.
    ///
    /// # Errors
    ///
    /// Rejects malformed headers, absent sessions, compounds and non-zero reserved bytes.
    pub fn parse(packet: &[u8]) -> Result<Self, SmbConnectionControlError> {
        let header = parse_fixed(packet, Smb2Command::Echo)?;
        if header.session_id == 0 {
            return Err(SmbConnectionControlError::InvalidSession);
        }
        Ok(Self { header })
    }

    /// Encodes one exactly correlated successful echo response.
    #[must_use]
    pub fn success_response(self) -> [u8; FIXED_REQUEST_BYTES] {
        fixed_success(self.header, self.header.tree_id, self.header.session_id)
    }
}

/// Validated SMB session-release request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogoffRequest {
    /// Exact request header retained for response correlation.
    pub header: Smb2Header,
}

impl LogoffRequest {
    /// Parses one exact fixed logoff request.
    ///
    /// # Errors
    ///
    /// Rejects malformed headers, absent sessions, tree-scoped logoff, compounds and reserved data.
    pub fn parse(packet: &[u8]) -> Result<Self, SmbConnectionControlError> {
        let header = parse_fixed(packet, Smb2Command::Logoff)?;
        if header.session_id == 0 || header.tree_id != 0 {
            return Err(SmbConnectionControlError::InvalidSession);
        }
        Ok(Self { header })
    }

    /// Encodes one exactly correlated successful logoff response.
    #[must_use]
    pub fn success_response(self) -> [u8; FIXED_REQUEST_BYTES] {
        fixed_success(self.header, 0, self.header.session_id)
    }
}

/// Canonical SMB2 error response with bounded optional protocol data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmbErrorResponse {
    /// Complete SMB2 error packet excluding Direct TCP framing.
    pub packet: Vec<u8>,
}

impl SmbErrorResponse {
    /// Encodes one error correlated to a successfully parsed request header.
    ///
    /// # Errors
    ///
    /// Rejects success status and response data beyond the fixed defensive bound.
    pub fn encode(
        header: Smb2Header,
        status: NtStatus,
        data: &[u8],
    ) -> Result<Self, SmbConnectionControlError> {
        if status == NtStatus::Success || data.len() > MAXIMUM_ERROR_DATA_BYTES {
            return Err(SmbConnectionControlError::InvalidErrorResponse);
        }
        let byte_count = u32::try_from(data.len())
            .map_err(|_| SmbConnectionControlError::InvalidErrorResponse)?;
        let mut packet = Vec::with_capacity(
            ERROR_FIXED_BYTES
                .checked_add(data.len())
                .ok_or(SmbConnectionControlError::InvalidErrorResponse)?,
        );
        packet.extend_from_slice(&header.encode_response(
            status.wire_value(),
            1,
            header.tree_id,
            header.session_id,
        ));
        packet.extend_from_slice(&ERROR_STRUCTURE_SIZE.to_le_bytes());
        packet.push(0);
        packet.push(0);
        packet.extend_from_slice(&byte_count.to_le_bytes());
        packet.extend_from_slice(data);
        Ok(Self { packet })
    }
}

fn parse_fixed(
    packet: &[u8],
    expected: Smb2Command,
) -> Result<Smb2Header, SmbConnectionControlError> {
    let header = Smb2Header::parse_request(packet)?;
    if header.command != expected {
        return Err(SmbConnectionControlError::WrongCommand);
    }
    if header.next_command != 0
        || packet.len() != FIXED_REQUEST_BYTES
        || read_u16(packet, 64)? != FIXED_STRUCTURE_SIZE
        || read_u16(packet, 66)? != 0
    {
        return Err(SmbConnectionControlError::InvalidStructure);
    }
    Ok(header)
}

fn fixed_success(header: Smb2Header, tree_id: u32, session_id: u64) -> [u8; FIXED_REQUEST_BYTES] {
    let mut packet = [0; FIXED_REQUEST_BYTES];
    packet[..64].copy_from_slice(&header.encode_response(0, 1, tree_id, session_id));
    packet[64..66].copy_from_slice(&FIXED_STRUCTURE_SIZE.to_le_bytes());
    packet
}

fn read_u16(packet: &[u8], offset: usize) -> Result<u16, SmbConnectionControlError> {
    packet
        .get(offset..offset + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(SmbConnectionControlError::InvalidStructure)
}

/// Invalid SMB connection-control message.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SmbConnectionControlError {
    /// The successfully parsed request belongs to another command.
    #[error("SMB connection-control parser received another command")]
    WrongCommand,
    /// The request length, compound state, structure marker or reserved bytes are invalid.
    #[error("SMB connection-control request structure is invalid")]
    InvalidStructure,
    /// The request does not name a valid session for this transition.
    #[error("SMB connection-control session is invalid")]
    InvalidSession,
    /// The selected status or bounded error data cannot form a canonical response.
    #[error("SMB error response input is invalid")]
    InvalidErrorResponse,
    /// The common SMB2 header is invalid.
    #[error(transparent)]
    Header(#[from] Smb2HeaderError),
}

#[cfg(test)]
mod tests {
    use super::{EchoRequest, LogoffRequest, SmbConnectionControlError, SmbErrorResponse};
    use crate::{NtStatus, Smb2Command};

    #[test]
    fn echo_logoff_and_error_responses_preserve_exact_correlation()
    -> Result<(), SmbConnectionControlError> {
        let echo = EchoRequest::parse(&request(Smb2Command::Echo, 17, 23))?;
        let response = echo.success_response();
        assert_eq!(&response[8..12], &[0; 4]);
        assert_eq!(&response[36..40], &23_u32.to_le_bytes());
        assert_eq!(&response[40..48], &17_u64.to_le_bytes());

        let logoff = LogoffRequest::parse(&request(Smb2Command::Logoff, 17, 0))?;
        assert_eq!(&logoff.success_response()[36..40], &[0; 4]);
        let error = SmbErrorResponse::encode(echo.header, NtStatus::InvalidParameter, b"bounded")?;
        assert_eq!(
            &error.packet[8..12],
            &NtStatus::InvalidParameter.wire_value().to_le_bytes()
        );
        assert_eq!(&error.packet[68..72], &7_u32.to_le_bytes());
        assert_eq!(&error.packet[72..], b"bounded");
        Ok(())
    }

    #[test]
    fn hostile_fixed_shapes_and_invalid_status_fail_closed() -> Result<(), SmbConnectionControlError>
    {
        let mut echo = request(Smb2Command::Echo, 17, 23);
        echo[66] = 1;
        assert_eq!(
            EchoRequest::parse(&echo),
            Err(SmbConnectionControlError::InvalidStructure)
        );
        assert_eq!(
            LogoffRequest::parse(&request(Smb2Command::Logoff, 0, 0)),
            Err(SmbConnectionControlError::InvalidSession)
        );
        let header = EchoRequest::parse(&request(Smb2Command::Echo, 17, 23))?.header;
        assert_eq!(
            SmbErrorResponse::encode(header, NtStatus::Success, &[]),
            Err(SmbConnectionControlError::InvalidErrorResponse)
        );
        Ok(())
    }

    fn request(command: Smb2Command, session_id: u64, tree_id: u32) -> [u8; 68] {
        let mut packet = [0; 68];
        packet[..4].copy_from_slice(&[0xfe, b'S', b'M', b'B']);
        packet[4..6].copy_from_slice(&64_u16.to_le_bytes());
        packet[6..8].copy_from_slice(&1_u16.to_le_bytes());
        packet[12..14].copy_from_slice(&command.wire_value().to_le_bytes());
        packet[14..16].copy_from_slice(&1_u16.to_le_bytes());
        packet[24..32].copy_from_slice(&31_u64.to_le_bytes());
        packet[32..36].copy_from_slice(&37_u32.to_le_bytes());
        packet[36..40].copy_from_slice(&tree_id.to_le_bytes());
        packet[40..48].copy_from_slice(&session_id.to_le_bytes());
        packet[64..66].copy_from_slice(&4_u16.to_le_bytes());
        packet
    }
}
