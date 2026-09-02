// SPDX-License-Identifier: GPL-2.0-only

//! Bounded SMB 3.1.1 byte-range lock and unlock framing.

use crate::{Smb2Command, Smb2Header, Smb2HeaderError, SmbFileId};

const REQUEST_STRUCTURE_SIZE: u16 = 48;
const REQUEST_FIXED_BYTES: usize = 88;
const LOCK_ELEMENT_BYTES: usize = 24;
const RESPONSE_STRUCTURE_SIZE: u16 = 4;
const MAXIMUM_LOCK_ELEMENTS: usize = 1_024;
const SHARED_LOCK: u32 = 0x0000_0001;
const EXCLUSIVE_LOCK: u32 = 0x0000_0002;
const UNLOCK: u32 = 0x0000_0004;
const FAIL_IMMEDIATELY: u32 = 0x0000_0010;
const SHARED_IMMEDIATE: u32 = SHARED_LOCK | FAIL_IMMEDIATELY;
const EXCLUSIVE_IMMEDIATE: u32 = EXCLUSIVE_LOCK | FAIL_IMMEDIATELY;

/// One validated SMB range transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LockElement {
    /// First affected byte.
    pub offset: u64,
    /// Positive affected byte count.
    pub length: u64,
    /// Lock or unlock operation.
    pub kind: LockKind,
}

/// Valid combinations from one `SMB2_LOCK_ELEMENT`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockKind {
    /// Shared lock, optionally requiring immediate conflict failure.
    Shared {
        /// Whether a conflict must return immediately rather than wait.
        fail_immediately: bool,
    },
    /// Exclusive lock, optionally requiring immediate conflict failure.
    Exclusive {
        /// Whether a conflict must return immediately rather than wait.
        fail_immediately: bool,
    },
    /// Release the exact previously acquired range.
    Unlock,
}

/// Validated bounded `SMB2 LOCK` request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockRequest {
    /// Validated synchronous request header.
    pub header: Smb2Header,
    /// Exact connection-visible open identity.
    pub file_id: SmbFileId,
    /// Non-empty bounded lock array in wire order.
    pub elements: Vec<LockElement>,
}

impl LockRequest {
    /// Parses the initial profile without persistent-handle lock sequencing.
    ///
    /// # Errors
    ///
    /// Rejects malformed identities, unsupported sequence state, excessive arrays, invalid
    /// ranges, mixed flag combinations, compounds and non-zero reserved fields.
    pub fn parse(packet: &[u8]) -> Result<Self, SmbLockError> {
        let header = Smb2Header::parse_request(packet)?;
        if header.command != Smb2Command::Lock {
            return Err(SmbLockError::WrongCommand);
        }
        if header.session_id == 0 || header.tree_id == 0 {
            return Err(SmbLockError::InvalidIdentity);
        }
        let count = usize::from(read_u16(packet, 66)?);
        let expected_bytes = count
            .checked_mul(LOCK_ELEMENT_BYTES)
            .and_then(|bytes| REQUEST_FIXED_BYTES.checked_add(bytes))
            .ok_or(SmbLockError::InvalidCount)?;
        if count == 0
            || count > MAXIMUM_LOCK_ELEMENTS
            || header.next_command != 0
            || packet.len() != expected_bytes
            || read_u16(packet, 64)? != REQUEST_STRUCTURE_SIZE
            || read_u32(packet, 68)? != 0
        {
            return Err(SmbLockError::InvalidCount);
        }
        let file_id = SmbFileId::from_wire(read_array(packet, 72)?)
            .map_err(|_| SmbLockError::InvalidIdentity)?;
        let mut elements = Vec::with_capacity(count);
        for index in 0..count {
            elements.push(parse_element(packet, index, count)?);
        }
        Ok(Self {
            header,
            file_id,
            elements,
        })
    }

    /// Encodes success after every preceding range transition succeeded.
    #[must_use]
    pub fn success_response(&self) -> LockResponse {
        let mut packet = [0_u8; 68];
        packet[..64].copy_from_slice(&self.header.encode_response(
            0,
            self.header.credit_charge.max(1),
            self.header.tree_id,
            self.header.session_id,
        ));
        packet[64..66].copy_from_slice(&RESPONSE_STRUCTURE_SIZE.to_le_bytes());
        LockResponse { packet }
    }
}

/// Fixed successful `SMB2 LOCK` response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LockResponse {
    /// Response packet before signing, encryption and direct-TCP framing.
    pub packet: [u8; 68],
}

fn parse_element(packet: &[u8], index: usize, count: usize) -> Result<LockElement, SmbLockError> {
    let start = REQUEST_FIXED_BYTES + index * LOCK_ELEMENT_BYTES;
    let offset = read_u64(packet, start)?;
    let length = read_u64(packet, start + 8)?;
    let flags = read_u32(packet, start + 16)?;
    if length == 0 || offset.checked_add(length).is_none() || read_u32(packet, start + 20)? != 0 {
        return Err(SmbLockError::InvalidRange);
    }
    let kind = match flags {
        SHARED_LOCK => LockKind::Shared {
            fail_immediately: false,
        },
        SHARED_IMMEDIATE => LockKind::Shared {
            fail_immediately: true,
        },
        EXCLUSIVE_LOCK => LockKind::Exclusive {
            fail_immediately: false,
        },
        EXCLUSIVE_IMMEDIATE => LockKind::Exclusive {
            fail_immediately: true,
        },
        UNLOCK => LockKind::Unlock,
        _ => return Err(SmbLockError::InvalidFlags),
    };
    if count > 1
        && matches!(
            kind,
            LockKind::Shared {
                fail_immediately: false
            } | LockKind::Exclusive {
                fail_immediately: false
            }
        )
    {
        return Err(SmbLockError::InvalidFlags);
    }
    Ok(LockElement {
        offset,
        length,
        kind,
    })
}

fn read_array(packet: &[u8], offset: usize) -> Result<[u8; 16], SmbLockError> {
    packet
        .get(offset..offset + 16)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(SmbLockError::Truncated)
}

macro_rules! read_integer {
    ($name:ident, $type:ty, $size:literal) => {
        fn $name(packet: &[u8], offset: usize) -> Result<$type, SmbLockError> {
            packet
                .get(offset..offset + $size)
                .and_then(|bytes| bytes.try_into().ok())
                .map(<$type>::from_le_bytes)
                .ok_or(SmbLockError::Truncated)
        }
    };
}

read_integer!(read_u16, u16, 2);
read_integer!(read_u32, u32, 4);
read_integer!(read_u64, u64, 8);

/// Invalid or unsupported SMB byte-range lock framing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SmbLockError {
    /// Required fixed or element bytes are absent.
    #[error("SMB lock request is truncated")]
    Truncated,
    /// Another command family reached this parser.
    #[error("SMB lock parser received another command")]
    WrongCommand,
    /// Session, tree or file identity is invalid.
    #[error("SMB lock identity is invalid")]
    InvalidIdentity,
    /// Element count, request size or unsupported sequence state is invalid.
    #[error("SMB lock element count or request size is invalid")]
    InvalidCount,
    /// A range is empty, overflowing or has non-zero reserved state.
    #[error("SMB lock range is invalid")]
    InvalidRange,
    /// Element flags are not one of the protocol's closed combinations.
    #[error("SMB lock flags are invalid")]
    InvalidFlags,
    /// The common SMB2 header is invalid.
    #[error(transparent)]
    Header(#[from] Smb2HeaderError),
}

#[cfg(test)]
mod tests {
    use super::{LockKind, LockRequest, SmbLockError};

    #[test]
    fn lock_array_round_trips_ranges_and_success() -> Result<(), SmbLockError> {
        let request = LockRequest::parse(&packet(&[(7, 11, 0x11), (30, 5, 0x12)]))?;
        assert_eq!(request.elements.len(), 2);
        assert_eq!(request.elements[0].offset, 7);
        assert_eq!(request.elements[0].length, 11);
        assert_eq!(
            request.elements[1].kind,
            LockKind::Exclusive {
                fail_immediately: true
            }
        );
        assert_eq!(&request.success_response().packet[64..68], &[4, 0, 0, 0]);
        Ok(())
    }

    #[test]
    fn hostile_counts_ranges_flags_and_sequence_fail_closed() {
        let mut request = packet(&[(0, 1, 1)]);
        request[66..68].fill(0);
        assert_eq!(
            LockRequest::parse(&request),
            Err(SmbLockError::InvalidCount)
        );

        let request = packet(&[(u64::MAX, 2, 1)]);
        assert_eq!(
            LockRequest::parse(&request),
            Err(SmbLockError::InvalidRange)
        );

        let request = packet(&[(0, 1, 3)]);
        assert_eq!(
            LockRequest::parse(&request),
            Err(SmbLockError::InvalidFlags)
        );

        let mut request = packet(&[(0, 1, 1)]);
        request[68..72].copy_from_slice(&1_u32.to_le_bytes());
        assert_eq!(
            LockRequest::parse(&request),
            Err(SmbLockError::InvalidCount)
        );

        let request = packet(&[(0, 1, 1), (2, 1, 0x11)]);
        assert_eq!(
            LockRequest::parse(&request),
            Err(SmbLockError::InvalidFlags)
        );
    }

    fn packet(elements: &[(u64, u64, u32)]) -> Vec<u8> {
        let mut packet = vec![0; 88];
        packet[..4].copy_from_slice(&[0xfe, b'S', b'M', b'B']);
        packet[4..6].copy_from_slice(&64_u16.to_le_bytes());
        packet[6..8].copy_from_slice(&1_u16.to_le_bytes());
        packet[12..14].copy_from_slice(&10_u16.to_le_bytes());
        packet[14..16].copy_from_slice(&1_u16.to_le_bytes());
        packet[24..32].copy_from_slice(&17_u64.to_le_bytes());
        packet[36..40].copy_from_slice(&23_u32.to_le_bytes());
        packet[40..48].copy_from_slice(&29_u64.to_le_bytes());
        packet[64..66].copy_from_slice(&48_u16.to_le_bytes());
        packet[66..68].copy_from_slice(
            &u16::try_from(elements.len())
                .unwrap_or_default()
                .to_le_bytes(),
        );
        packet[72..80].copy_from_slice(&7_u64.to_le_bytes());
        packet[80..88].copy_from_slice(&11_u64.to_le_bytes());
        for (offset, length, flags) in elements {
            packet.extend_from_slice(&offset.to_le_bytes());
            packet.extend_from_slice(&length.to_le_bytes());
            packet.extend_from_slice(&flags.to_le_bytes());
            packet.extend_from_slice(&0_u32.to_le_bytes());
        }
        packet
    }
}
