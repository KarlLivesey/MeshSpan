// SPDX-License-Identifier: GPL-2.0-only

//! SMB 3.1.1 negotiation selection and response encoding.

use crate::{NegotiateContext, NegotiateContextType, NegotiateRequest};

const DIALECT_3_1_1: u16 = 0x0311;
const SIGNING_ENABLED_AND_REQUIRED: u16 = 0x0003;
const GLOBAL_CAP_ENCRYPTION: u32 = 0x0000_0040;
const MINIMUM_IO_SIZE: u32 = 65_536;
const RESPONSE_FIXED_END: usize = 128;
const PREAUTH_CONTEXT: u16 = 0x0001;
const ENCRYPTION_CONTEXT: u16 = 0x0002;
const SIGNING_CONTEXT: u16 = 0x0008;
const SHA512: u16 = 0x0001;

/// Encryption cipher selected for the SMB 3.1.1 connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum EncryptionCipher {
    /// AES-128-GCM authenticated encryption.
    Aes128Gcm = 0x0002,
    /// AES-256-GCM authenticated encryption.
    Aes256Gcm = 0x0004,
}

/// Packet-signing algorithm selected for the SMB 3.1.1 connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum SigningAlgorithm {
    /// AES-CMAC signing, the SMB 3.x compatibility default.
    AesCmac = 0x0001,
    /// AES-GMAC signing negotiated by current clients.
    AesGmac = 0x0002,
}

/// Algorithms selected from one validated client offer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NegotiateSelection {
    /// Selected encryption cipher.
    pub encryption: EncryptionCipher,
    /// Selected signing algorithm.
    pub signing: SigningAlgorithm,
}

impl NegotiateSelection {
    fn select(request: &NegotiateRequest<'_>) -> Result<Self, NegotiateResponseError> {
        let encryption = find_context(request, NegotiateContextType::Encryption)
            .ok_or(NegotiateResponseError::EncryptionRequired)
            .and_then(select_encryption)?;
        let signing = find_context(request, NegotiateContextType::Signing)
            .map_or(Ok(SigningAlgorithm::AesCmac), select_signing)?;
        Ok(Self {
            encryption,
            signing,
        })
    }
}

/// Daemon-owned, bounded values included in one negotiation response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NegotiateResponseConfig {
    /// Stable server GUID in SMB wire byte order.
    pub server_guid: [u8; 16],
    /// Maximum accepted metadata transaction buffer.
    pub maximum_transaction_size: u32,
    /// Maximum accepted read length.
    pub maximum_read_size: u32,
    /// Maximum accepted write length.
    pub maximum_write_size: u32,
    /// Current UTC instant encoded as Windows FILETIME.
    pub system_time: u64,
    /// Fresh connection-specific pre-authentication salt.
    pub preauth_salt: [u8; 32],
}

impl NegotiateResponseConfig {
    /// Validates response limits and stable server identity.
    ///
    /// # Errors
    ///
    /// Rejects an all-zero server GUID or IO limits below the interoperability
    /// floor recommended by the SMB specification.
    pub fn validate(self) -> Result<Self, NegotiateResponseError> {
        if self.server_guid.iter().all(|byte| *byte == 0) {
            return Err(NegotiateResponseError::InvalidServerGuid);
        }
        if self.maximum_transaction_size < MINIMUM_IO_SIZE
            || self.maximum_read_size < MINIMUM_IO_SIZE
            || self.maximum_write_size < MINIMUM_IO_SIZE
        {
            return Err(NegotiateResponseError::IoLimitTooSmall);
        }
        Ok(self)
    }
}

/// One encoded negotiation response plus the algorithms bound to its connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegotiateResponse {
    /// Exact SMB2 packet bytes, excluding Direct TCP framing.
    pub packet: Vec<u8>,
    /// Algorithms that all later session processing must use.
    pub selection: NegotiateSelection,
}

impl NegotiateResponse {
    /// Selects mandatory security algorithms and encodes an SMB 3.1.1 response.
    ///
    /// The response intentionally emits an empty GSS negotiation buffer so the
    /// client initiates session authentication in `SESSION_SETUP`.
    ///
    /// # Errors
    ///
    /// Rejects invalid server configuration or a client without a mutually
    /// supported authenticated-encryption and signing combination.
    pub fn encode(
        request: &NegotiateRequest<'_>,
        config: NegotiateResponseConfig,
    ) -> Result<Self, NegotiateResponseError> {
        let config = config.validate()?;
        let selection = NegotiateSelection::select(request)?;
        let mut packet = vec![0_u8; RESPONSE_FIXED_END];
        packet[..64].copy_from_slice(&request.header.encode_response(0, 1, 0, 0));
        encode_fixed_response(&mut packet, config);
        append_context(
            &mut packet,
            PREAUTH_CONTEXT,
            &preauth_data(config.preauth_salt),
        )?;
        append_context(
            &mut packet,
            ENCRYPTION_CONTEXT,
            &algorithm_data(selection.encryption as u16),
        )?;
        append_context(
            &mut packet,
            SIGNING_CONTEXT,
            &algorithm_data(selection.signing as u16),
        )?;
        Ok(Self { packet, selection })
    }
}

fn encode_fixed_response(packet: &mut [u8], config: NegotiateResponseConfig) {
    packet[64..66].copy_from_slice(&65_u16.to_le_bytes());
    packet[66..68].copy_from_slice(&SIGNING_ENABLED_AND_REQUIRED.to_le_bytes());
    packet[68..70].copy_from_slice(&DIALECT_3_1_1.to_le_bytes());
    packet[70..72].copy_from_slice(&3_u16.to_le_bytes());
    packet[72..88].copy_from_slice(&config.server_guid);
    packet[88..92].copy_from_slice(&GLOBAL_CAP_ENCRYPTION.to_le_bytes());
    packet[92..96].copy_from_slice(&config.maximum_transaction_size.to_le_bytes());
    packet[96..100].copy_from_slice(&config.maximum_read_size.to_le_bytes());
    packet[100..104].copy_from_slice(&config.maximum_write_size.to_le_bytes());
    packet[104..112].copy_from_slice(&config.system_time.to_le_bytes());
    packet[120..122].copy_from_slice(&128_u16.to_le_bytes());
    packet[124..128].copy_from_slice(&128_u32.to_le_bytes());
}

fn preauth_data(salt: [u8; 32]) -> Vec<u8> {
    let mut data = Vec::with_capacity(38);
    data.extend_from_slice(&1_u16.to_le_bytes());
    data.extend_from_slice(&32_u16.to_le_bytes());
    data.extend_from_slice(&SHA512.to_le_bytes());
    data.extend_from_slice(&salt);
    data
}

fn algorithm_data(algorithm: u16) -> [u8; 4] {
    let mut data = [0_u8; 4];
    data[..2].copy_from_slice(&1_u16.to_le_bytes());
    data[2..].copy_from_slice(&algorithm.to_le_bytes());
    data
}

fn append_context(
    packet: &mut Vec<u8>,
    context_type: u16,
    data: &[u8],
) -> Result<(), NegotiateResponseError> {
    while !packet.len().is_multiple_of(8) {
        packet.push(0);
    }
    packet.extend_from_slice(&context_type.to_le_bytes());
    let data_length =
        u16::try_from(data.len()).map_err(|_| NegotiateResponseError::ContextDataTooLarge)?;
    packet.extend_from_slice(&data_length.to_le_bytes());
    packet.extend_from_slice(&0_u32.to_le_bytes());
    packet.extend_from_slice(data);
    Ok(())
}

fn find_context<'a>(
    request: &'a NegotiateRequest<'a>,
    selected: NegotiateContextType,
) -> Option<NegotiateContext<'a>> {
    request
        .contexts
        .iter()
        .copied()
        .find(|context| context.context_type == selected)
}

fn select_encryption(
    context: NegotiateContext<'_>,
) -> Result<EncryptionCipher, NegotiateResponseError> {
    for algorithm in algorithm_ids(context.data) {
        match algorithm {
            0x0002 => return Ok(EncryptionCipher::Aes128Gcm),
            0x0004 => return Ok(EncryptionCipher::Aes256Gcm),
            _ => {}
        }
    }
    Err(NegotiateResponseError::NoSharedEncryptionCipher)
}

fn select_signing(
    context: NegotiateContext<'_>,
) -> Result<SigningAlgorithm, NegotiateResponseError> {
    for algorithm in algorithm_ids(context.data) {
        match algorithm {
            0x0002 => return Ok(SigningAlgorithm::AesGmac),
            0x0001 => return Ok(SigningAlgorithm::AesCmac),
            _ => {}
        }
    }
    Err(NegotiateResponseError::NoSharedSigningAlgorithm)
}

fn algorithm_ids(data: &[u8]) -> impl Iterator<Item = u16> + '_ {
    data[2..]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|encoded| u16::from_le_bytes(*encoded))
}

/// Failure to select or encode a secure SMB 3.1.1 negotiation response.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NegotiateResponseError {
    /// Stable server identity cannot be all zeroes.
    #[error("SMB server GUID is invalid")]
    InvalidServerGuid,
    /// Advertised IO sizes are below the SMB interoperability floor.
    #[error("SMB IO limit is below 65536 bytes")]
    IoLimitTooSmall,
    /// The client did not offer encryption capabilities.
    #[error("SMB 3.1.1 encryption capability is required")]
    EncryptionRequired,
    /// The client offered no GCM cipher implemented by this profile.
    #[error("SMB client and server share no encryption cipher")]
    NoSharedEncryptionCipher,
    /// The client offered no signing algorithm implemented by this profile.
    #[error("SMB client and server share no signing algorithm")]
    NoSharedSigningAlgorithm,
    /// A server-generated context cannot fit its 16-bit wire length.
    #[error("SMB negotiate response context exceeds its wire limit")]
    ContextDataTooLarge,
}

#[cfg(test)]
mod tests {
    use crate::NegotiateRequest;

    use super::{
        EncryptionCipher, NegotiateResponse, NegotiateResponseConfig, NegotiateResponseError,
        SigningAlgorithm,
    };

    fn request_packet(encryption: u16, signing: Option<u16>) -> Vec<u8> {
        let context_count = if signing.is_some() { 3_u16 } else { 2_u16 };
        let packet_length = if signing.is_some() { 180 } else { 164 };
        let mut bytes = vec![0_u8; packet_length];
        bytes[..4].copy_from_slice(&[0xfe, b'S', b'M', b'B']);
        bytes[4..6].copy_from_slice(&64_u16.to_le_bytes());
        bytes[14..16].copy_from_slice(&1_u16.to_le_bytes());
        bytes[64..66].copy_from_slice(&36_u16.to_le_bytes());
        bytes[66..68].copy_from_slice(&1_u16.to_le_bytes());
        bytes[68..70].copy_from_slice(&1_u16.to_le_bytes());
        bytes[76..92].copy_from_slice(&[7_u8; 16]);
        bytes[92..96].copy_from_slice(&104_u32.to_le_bytes());
        bytes[96..98].copy_from_slice(&context_count.to_le_bytes());
        bytes[100..102].copy_from_slice(&0x0311_u16.to_le_bytes());
        encode_context(&mut bytes, 104, 1, &preauth());
        encode_context(&mut bytes, 152, 2, &algorithm(encryption));
        if let Some(signing) = signing {
            encode_context(&mut bytes, 168, 8, &algorithm(signing));
        }
        bytes
    }

    fn encode_context(packet: &mut [u8], offset: usize, kind: u16, data: &[u8]) {
        packet[offset..offset + 2].copy_from_slice(&kind.to_le_bytes());
        packet[offset + 2..offset + 4]
            .copy_from_slice(&(u16::try_from(data.len()).unwrap_or_default()).to_le_bytes());
        packet[offset + 8..offset + 8 + data.len()].copy_from_slice(data);
    }

    fn preauth() -> [u8; 38] {
        let mut data = [0_u8; 38];
        data[..2].copy_from_slice(&1_u16.to_le_bytes());
        data[2..4].copy_from_slice(&32_u16.to_le_bytes());
        data[4..6].copy_from_slice(&1_u16.to_le_bytes());
        data[6..].copy_from_slice(&[9_u8; 32]);
        data
    }

    fn algorithm(value: u16) -> [u8; 4] {
        let mut data = [0_u8; 4];
        data[..2].copy_from_slice(&1_u16.to_le_bytes());
        data[2..].copy_from_slice(&value.to_le_bytes());
        data
    }

    fn config() -> NegotiateResponseConfig {
        NegotiateResponseConfig {
            server_guid: [3_u8; 16],
            maximum_transaction_size: 1_048_576,
            maximum_read_size: 1_048_576,
            maximum_write_size: 1_048_576,
            system_time: 77,
            preauth_salt: [5_u8; 32],
        }
    }

    #[test]
    fn response_selects_client_compatible_security_and_exact_offsets()
    -> Result<(), Box<dyn std::error::Error>> {
        let packet = request_packet(2, Some(2));
        let request = NegotiateRequest::parse(&packet)?;
        let response = NegotiateResponse::encode(&request, config())?;
        assert_eq!(response.selection.encryption, EncryptionCipher::Aes128Gcm);
        assert_eq!(response.selection.signing, SigningAlgorithm::AesGmac);
        assert_eq!(&response.packet[68..70], &0x0311_u16.to_le_bytes());
        assert_eq!(&response.packet[70..72], &3_u16.to_le_bytes());
        assert_eq!(&response.packet[88..92], &0x40_u32.to_le_bytes());
        assert_eq!(&response.packet[124..128], &128_u32.to_le_bytes());
        assert_eq!(&response.packet[128..130], &1_u16.to_le_bytes());
        Ok(())
    }

    #[test]
    fn absent_signing_context_uses_cmac_but_encryption_never_downgrades()
    -> Result<(), Box<dyn std::error::Error>> {
        let packet = request_packet(2, None);
        let request = NegotiateRequest::parse(&packet)?;
        let response = NegotiateResponse::encode(&request, config())?;
        assert_eq!(response.selection.signing, SigningAlgorithm::AesCmac);

        let unsupported_packet = request_packet(1, None);
        let unsupported = NegotiateRequest::parse(&unsupported_packet)?;
        assert_eq!(
            NegotiateResponse::encode(&unsupported, config()),
            Err(NegotiateResponseError::NoSharedEncryptionCipher)
        );
        Ok(())
    }
}
