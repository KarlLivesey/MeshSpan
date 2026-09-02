// SPDX-License-Identifier: GPL-2.0-only

//! SMB 3.1.1 negotiation request validation.

use crate::{Smb2Command, Smb2Header, Smb2HeaderError};

const HEADER_LENGTH: usize = 64;
const FIXED_REQUEST_LENGTH: usize = 36;
const DIALECT_3_1_1: u16 = 0x0311;
const PREAUTH_SHA512: u16 = 0x0001;
const MAX_DIALECTS: usize = 64;
const MAX_CONTEXTS: usize = 32;
const MAX_CONTEXT_ALGORITHMS: usize = 32;

/// One negotiate-context kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NegotiateContextType {
    /// Pre-authentication integrity hashes and salt.
    PreauthIntegrity,
    /// Session encryption ciphers.
    Encryption,
    /// Compression algorithms, unsupported by the first profile.
    Compression,
    /// Requested server network name.
    NetName,
    /// Transport capabilities.
    Transport,
    /// RDMA transforms, unsupported by the first profile.
    RdmaTransform,
    /// Packet-signing algorithms.
    Signing,
    /// Reserved context type that must be ignored.
    Reserved,
    /// A forward-compatible context not interpreted by this server.
    Unknown(u16),
}

impl NegotiateContextType {
    fn from_wire(value: u16) -> Self {
        match value {
            0x0001 => Self::PreauthIntegrity,
            0x0002 => Self::Encryption,
            0x0003 => Self::Compression,
            0x0005 => Self::NetName,
            0x0006 => Self::Transport,
            0x0007 => Self::RdmaTransform,
            0x0008 => Self::Signing,
            0x0100 => Self::Reserved,
            unknown => Self::Unknown(unknown),
        }
    }
}

/// One bounded negotiate context borrowed from its validated request packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NegotiateContext<'a> {
    /// Context kind.
    pub context_type: NegotiateContextType,
    /// Exact context-specific bytes.
    pub data: &'a [u8],
}

/// A validated SMB 3.1.1 negotiation request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegotiateRequest<'a> {
    /// Correlation and credit header.
    pub header: Smb2Header,
    /// Whether the client requires packet signing.
    pub signing_required: bool,
    /// Client capability bitset.
    pub capabilities: u32,
    /// Stable client GUID in wire byte order.
    pub client_guid: [u8; 16],
    /// Offered dialects in client preference order.
    pub dialects: Vec<u16>,
    /// Bounded, structurally validated contexts in arbitrary client order.
    pub contexts: Vec<NegotiateContext<'a>>,
}

impl<'a> NegotiateRequest<'a> {
    /// Parses an SMB request packet and accepts only a valid SMB 3.1.1 offer.
    ///
    /// # Errors
    ///
    /// Rejects malformed headers, legacy-only offers, missing mandatory pre-auth
    /// integrity, duplicate singleton contexts and out-of-bounds context data.
    pub fn parse(packet: &'a [u8]) -> Result<Self, NegotiateRequestError> {
        let header = Smb2Header::parse_request(packet)?;
        validate_negotiate_header(header)?;
        let fixed = packet
            .get(HEADER_LENGTH..HEADER_LENGTH + FIXED_REQUEST_LENGTH)
            .ok_or(NegotiateRequestError::Truncated)?;
        if read_u16(fixed, 0)? != 36 {
            return Err(NegotiateRequestError::InvalidStructureSize);
        }
        let dialect_count = bounded_count(read_u16(fixed, 2)?, MAX_DIALECTS)?;
        let security_mode = read_u16(fixed, 4)?;
        if security_mode == 0 || security_mode & !0x0003 != 0 {
            return Err(NegotiateRequestError::InvalidSecurityMode);
        }
        let dialects = parse_dialects(packet, dialect_count)?;
        if !dialects.contains(&DIALECT_3_1_1) {
            return Err(NegotiateRequestError::Smb311NotOffered);
        }
        let context_offset = usize::try_from(read_u32(fixed, 28)?)
            .map_err(|_| NegotiateRequestError::InvalidContextOffset)?;
        let context_count = bounded_count(read_u16(fixed, 32)?, MAX_CONTEXTS)?;
        if context_count == 0 {
            return Err(NegotiateRequestError::MissingPreauthIntegrity);
        }
        let dialects_end = HEADER_LENGTH + FIXED_REQUEST_LENGTH + dialect_count * 2;
        validate_context_start(context_offset, dialects_end, packet.len())?;
        let contexts = parse_contexts(packet, context_offset, context_count)?;
        validate_context_set(&contexts)?;
        Ok(Self {
            header,
            signing_required: security_mode & 0x0002 != 0,
            capabilities: read_u32(fixed, 8)?,
            client_guid: fixed[12..28]
                .try_into()
                .map_err(|_| NegotiateRequestError::Truncated)?,
            dialects,
            contexts,
        })
    }
}

fn validate_negotiate_header(header: Smb2Header) -> Result<(), NegotiateRequestError> {
    if header.command != Smb2Command::Negotiate
        || header.flags != 0
        || header.next_command != 0
        || header.tree_id != 0
        || header.session_id != 0
    {
        return Err(NegotiateRequestError::InvalidHeaderState);
    }
    Ok(())
}

fn parse_dialects(packet: &[u8], count: usize) -> Result<Vec<u16>, NegotiateRequestError> {
    let start = HEADER_LENGTH + FIXED_REQUEST_LENGTH;
    let byte_length = count
        .checked_mul(2)
        .ok_or(NegotiateRequestError::ListTooLarge)?;
    let bytes = packet
        .get(start..start + byte_length)
        .ok_or(NegotiateRequestError::Truncated)?;
    let mut dialects = Vec::with_capacity(count);
    for encoded in bytes.as_chunks::<2>().0 {
        dialects.push(u16::from_le_bytes(*encoded));
    }
    Ok(dialects)
}

fn validate_context_start(
    context_offset: usize,
    dialects_end: usize,
    packet_length: usize,
) -> Result<(), NegotiateRequestError> {
    if context_offset < dialects_end
        || !context_offset.is_multiple_of(8)
        || context_offset >= packet_length
    {
        Err(NegotiateRequestError::InvalidContextOffset)
    } else {
        Ok(())
    }
}

fn parse_contexts(
    packet: &[u8],
    mut offset: usize,
    count: usize,
) -> Result<Vec<NegotiateContext<'_>>, NegotiateRequestError> {
    let mut contexts = Vec::with_capacity(count);
    for index in 0..count {
        let context_header = packet
            .get(offset..offset + 8)
            .ok_or(NegotiateRequestError::TruncatedContext)?;
        let context_type = NegotiateContextType::from_wire(read_u16(context_header, 0)?);
        let data_length = usize::from(read_u16(context_header, 2)?);
        let data_start = offset + 8;
        let data_end = data_start
            .checked_add(data_length)
            .ok_or(NegotiateRequestError::TruncatedContext)?;
        let data = packet
            .get(data_start..data_end)
            .ok_or(NegotiateRequestError::TruncatedContext)?;
        validate_known_context(context_type, data)?;
        contexts.push(NegotiateContext { context_type, data });
        if index + 1 < count {
            offset = align_to_eight(data_end)?;
            if offset >= packet.len() {
                return Err(NegotiateRequestError::TruncatedContext);
            }
        }
    }
    Ok(contexts)
}

fn validate_known_context(
    context_type: NegotiateContextType,
    data: &[u8],
) -> Result<(), NegotiateRequestError> {
    match context_type {
        NegotiateContextType::PreauthIntegrity => validate_preauth(data),
        NegotiateContextType::Encryption | NegotiateContextType::Signing => {
            validate_algorithm_list(data)
        }
        _ => Ok(()),
    }
}

fn validate_preauth(data: &[u8]) -> Result<(), NegotiateRequestError> {
    let count = bounded_count(read_u16(data, 0)?, MAX_CONTEXT_ALGORITHMS)?;
    let salt_length = usize::from(read_u16(data, 2)?);
    let algorithms_end = 4 + count * 2;
    if data.len() != algorithms_end + salt_length {
        return Err(NegotiateRequestError::InvalidContextData);
    }
    let has_sha512 = data[4..algorithms_end]
        .as_chunks::<2>()
        .0
        .iter()
        .any(|value| u16::from_le_bytes([value[0], value[1]]) == PREAUTH_SHA512);
    if !has_sha512 {
        return Err(NegotiateRequestError::MissingSha512);
    }
    Ok(())
}

fn validate_algorithm_list(data: &[u8]) -> Result<(), NegotiateRequestError> {
    let count = bounded_count(read_u16(data, 0)?, MAX_CONTEXT_ALGORITHMS)?;
    if data.len() != 2 + count * 2 {
        return Err(NegotiateRequestError::InvalidContextData);
    }
    Ok(())
}

fn validate_context_set(contexts: &[NegotiateContext<'_>]) -> Result<(), NegotiateRequestError> {
    let preauth = count_contexts(contexts, NegotiateContextType::PreauthIntegrity);
    if preauth == 0 {
        return Err(NegotiateRequestError::MissingPreauthIntegrity);
    }
    if preauth > 1
        || count_contexts(contexts, NegotiateContextType::Encryption) > 1
        || count_contexts(contexts, NegotiateContextType::Signing) > 1
    {
        return Err(NegotiateRequestError::DuplicateSingletonContext);
    }
    Ok(())
}

fn count_contexts(contexts: &[NegotiateContext<'_>], selected: NegotiateContextType) -> usize {
    contexts
        .iter()
        .filter(|context| context.context_type == selected)
        .count()
}

fn bounded_count(value: u16, maximum: usize) -> Result<usize, NegotiateRequestError> {
    let count = usize::from(value);
    if count == 0 {
        return Err(NegotiateRequestError::EmptyList);
    }
    if count > maximum {
        return Err(NegotiateRequestError::ListTooLarge);
    }
    Ok(count)
}

fn align_to_eight(value: usize) -> Result<usize, NegotiateRequestError> {
    value
        .checked_add(7)
        .map(|candidate| candidate & !7)
        .ok_or(NegotiateRequestError::InvalidContextOffset)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, NegotiateRequestError> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or(NegotiateRequestError::Truncated)?;
    Ok(u16::from_le_bytes(
        value
            .try_into()
            .map_err(|_| NegotiateRequestError::Truncated)?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, NegotiateRequestError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or(NegotiateRequestError::Truncated)?;
    Ok(u32::from_le_bytes(
        value
            .try_into()
            .map_err(|_| NegotiateRequestError::Truncated)?,
    ))
}

/// Invalid SMB 3.1.1 negotiation request.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NegotiateRequestError {
    /// The common SMB2 header is invalid.
    #[error("SMB2 negotiate header is invalid: {0}")]
    Header(#[from] Smb2HeaderError),
    /// The fixed negotiate request is truncated.
    #[error("SMB2 negotiate request is truncated")]
    Truncated,
    /// The fixed negotiate structure-size marker is not 36.
    #[error("SMB2 negotiate structure size is invalid")]
    InvalidStructureSize,
    /// The SMB2 header is not valid for initial negotiation.
    #[error("SMB2 negotiate header state is invalid")]
    InvalidHeaderState,
    /// The signing-mode flags are empty or contain unknown bits.
    #[error("SMB2 negotiate security mode is invalid")]
    InvalidSecurityMode,
    /// A variable-length list is empty.
    #[error("SMB2 negotiate list is empty")]
    EmptyList,
    /// A bounded list exceeds the implementation's negotiation ceiling.
    #[error("SMB2 negotiate list exceeds its limit")]
    ListTooLarge,
    /// The client did not offer SMB 3.1.1.
    #[error("SMB 3.1.1 was not offered")]
    Smb311NotOffered,
    /// The first context offset is unaligned or overlaps another request field.
    #[error("SMB2 negotiate context offset is invalid")]
    InvalidContextOffset,
    /// A context header or payload extends beyond the packet.
    #[error("SMB2 negotiate context is truncated")]
    TruncatedContext,
    /// A known context's internal count or length is inconsistent.
    #[error("SMB2 negotiate context data is invalid")]
    InvalidContextData,
    /// A singleton capability context occurred more than once.
    #[error("SMB2 negotiate singleton context is duplicated")]
    DuplicateSingletonContext,
    /// SMB 3.1.1 requires exactly one pre-auth integrity context.
    #[error("SMB2 pre-authentication integrity context is missing")]
    MissingPreauthIntegrity,
    /// The required SMB 3.1.1 SHA-512 pre-auth hash was not offered.
    #[error("SMB2 SHA-512 pre-authentication hash is missing")]
    MissingSha512,
}

#[cfg(test)]
mod tests {
    use super::{NegotiateContextType, NegotiateRequest, NegotiateRequestError};

    fn valid_request() -> Vec<u8> {
        let mut bytes = vec![0_u8; 164];
        bytes[..4].copy_from_slice(&[0xfe, b'S', b'M', b'B']);
        bytes[4..6].copy_from_slice(&64_u16.to_le_bytes());
        bytes[14..16].copy_from_slice(&1_u16.to_le_bytes());
        bytes[64..66].copy_from_slice(&36_u16.to_le_bytes());
        bytes[66..68].copy_from_slice(&1_u16.to_le_bytes());
        bytes[68..70].copy_from_slice(&3_u16.to_le_bytes());
        bytes[72..76].copy_from_slice(&0x44_u32.to_le_bytes());
        bytes[76..92].copy_from_slice(&[7_u8; 16]);
        bytes[92..96].copy_from_slice(&104_u32.to_le_bytes());
        bytes[96..98].copy_from_slice(&2_u16.to_le_bytes());
        bytes[100..102].copy_from_slice(&0x0311_u16.to_le_bytes());

        bytes[104..106].copy_from_slice(&1_u16.to_le_bytes());
        bytes[106..108].copy_from_slice(&38_u16.to_le_bytes());
        bytes[112..114].copy_from_slice(&1_u16.to_le_bytes());
        bytes[114..116].copy_from_slice(&32_u16.to_le_bytes());
        bytes[116..118].copy_from_slice(&1_u16.to_le_bytes());
        bytes[118..150].copy_from_slice(&[9_u8; 32]);

        bytes[152..154].copy_from_slice(&2_u16.to_le_bytes());
        bytes[154..156].copy_from_slice(&4_u16.to_le_bytes());
        bytes[160..162].copy_from_slice(&1_u16.to_le_bytes());
        bytes[162..164].copy_from_slice(&2_u16.to_le_bytes());
        bytes
    }

    #[test]
    fn smb311_offer_preserves_context_order_and_capabilities() -> Result<(), NegotiateRequestError>
    {
        let bytes = valid_request();
        let request = NegotiateRequest::parse(&bytes)?;
        assert!(request.signing_required);
        assert_eq!(request.capabilities, 0x44);
        assert_eq!(request.client_guid, [7_u8; 16]);
        assert_eq!(request.dialects, vec![0x0311]);
        assert_eq!(request.contexts.len(), 2);
        assert_eq!(
            request.contexts[0].context_type,
            NegotiateContextType::PreauthIntegrity
        );
        assert_eq!(
            request.contexts[1].context_type,
            NegotiateContextType::Encryption
        );
        Ok(())
    }

    #[test]
    fn legacy_missing_and_duplicated_capabilities_fail_closed() {
        let mut legacy = valid_request();
        legacy[100..102].copy_from_slice(&0x0302_u16.to_le_bytes());
        assert_eq!(
            NegotiateRequest::parse(&legacy),
            Err(NegotiateRequestError::Smb311NotOffered)
        );

        let mut missing = valid_request();
        missing[104..106].copy_from_slice(&0x9999_u16.to_le_bytes());
        assert_eq!(
            NegotiateRequest::parse(&missing),
            Err(NegotiateRequestError::MissingPreauthIntegrity)
        );

        let mut duplicate = valid_request();
        duplicate.resize(166, 0);
        duplicate[152..154].copy_from_slice(&1_u16.to_le_bytes());
        duplicate[154..156].copy_from_slice(&6_u16.to_le_bytes());
        duplicate[160..162].copy_from_slice(&1_u16.to_le_bytes());
        duplicate[162..164].copy_from_slice(&0_u16.to_le_bytes());
        duplicate[164..166].copy_from_slice(&1_u16.to_le_bytes());
        assert_eq!(
            NegotiateRequest::parse(&duplicate),
            Err(NegotiateRequestError::DuplicateSingletonContext)
        );
    }
}
