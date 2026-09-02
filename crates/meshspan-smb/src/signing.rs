// SPDX-License-Identifier: GPL-2.0-only

//! SMB 3.1.1 packet signing and verification.

use aes::Aes128;
use aes_gcm::aead::{AeadInOut, KeyInit};
use cmac::{Cmac, Mac};
use subtle::ConstantTimeEq;

use crate::SigningAlgorithm;

const SMB2_HEADER_LENGTH: usize = 64;
const PROTOCOL_ID: [u8; 4] = [0xfe, b'S', b'M', b'B'];
const FLAGS_OFFSET: usize = 16;
const MESSAGE_ID_OFFSET: usize = 24;
const COMMAND_OFFSET: usize = 12;
const SIGNATURE_OFFSET: usize = 48;
const SIGNATURE_LENGTH: usize = 16;
const SERVER_TO_CLIENT_FLAG: u32 = 0x0000_0001;
const SIGNED_FLAG: u32 = 0x0000_0008;
const CANCEL_COMMAND: u16 = 0x000c;

/// Origin of one SMB packet, used to bind the AES-GMAC nonce direction bit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SmbPacketSender {
    /// Request sent by an SMB client.
    Client,
    /// Response or notification sent by this server.
    Server,
}

/// Signs one complete SMB 3.1.1 message in place.
///
/// The packet must begin at the SMB2 header and include compound padding, but
/// not Direct TCP framing. The signed flag and signature field are canonicalised
/// before the MAC is calculated.
///
/// # Errors
///
/// Rejects malformed headers, a direction mismatch or cryptographic setup failure.
pub fn sign_smb311(
    packet: &mut [u8],
    signing_key: &[u8; SIGNATURE_LENGTH],
    algorithm: SigningAlgorithm,
    sender: SmbPacketSender,
) -> Result<(), SmbSigningError> {
    validate_packet(packet, sender, false)?;
    let flags = read_u32(packet, FLAGS_OFFSET)? | SIGNED_FLAG;
    packet[FLAGS_OFFSET..FLAGS_OFFSET + 4].copy_from_slice(&flags.to_le_bytes());
    packet[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_LENGTH].fill(0);
    let signature = calculate_signature(packet, signing_key, algorithm, sender)?;
    packet[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_LENGTH].copy_from_slice(&signature);
    Ok(())
}

/// Verifies one complete signed SMB 3.1.1 message in constant time.
///
/// The original signature is restored before this function returns, including
/// when verification fails.
///
/// # Errors
///
/// Rejects malformed, unsigned, direction-confused or unauthentic packets.
pub fn verify_smb311(
    packet: &mut [u8],
    signing_key: &[u8; SIGNATURE_LENGTH],
    algorithm: SigningAlgorithm,
    sender: SmbPacketSender,
) -> Result<(), SmbSigningError> {
    validate_packet(packet, sender, true)?;
    let signature: [u8; SIGNATURE_LENGTH] = packet
        .get(SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_LENGTH)
        .ok_or(SmbSigningError::Truncated)?
        .try_into()
        .map_err(|_| SmbSigningError::Truncated)?;
    packet[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_LENGTH].fill(0);
    let expected = calculate_signature(packet, signing_key, algorithm, sender);
    packet[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_LENGTH].copy_from_slice(&signature);
    let expected = expected?;
    if expected.ct_eq(&signature).unwrap_u8() == 1 {
        Ok(())
    } else {
        Err(SmbSigningError::SignatureMismatch)
    }
}

fn calculate_signature(
    packet: &[u8],
    signing_key: &[u8; SIGNATURE_LENGTH],
    algorithm: SigningAlgorithm,
    sender: SmbPacketSender,
) -> Result<[u8; SIGNATURE_LENGTH], SmbSigningError> {
    match algorithm {
        SigningAlgorithm::AesCmac => calculate_cmac(packet, signing_key),
        SigningAlgorithm::AesGmac => calculate_gmac(packet, signing_key, sender),
    }
}

fn calculate_cmac(
    packet: &[u8],
    signing_key: &[u8; SIGNATURE_LENGTH],
) -> Result<[u8; SIGNATURE_LENGTH], SmbSigningError> {
    let mut mac = <Cmac<Aes128> as KeyInit>::new_from_slice(signing_key)
        .map_err(|_| SmbSigningError::InvalidSigningKey)?;
    mac.update(packet);
    Ok(mac.finalize().into_bytes().into())
}

fn calculate_gmac(
    packet: &[u8],
    signing_key: &[u8; SIGNATURE_LENGTH],
    sender: SmbPacketSender,
) -> Result<[u8; SIGNATURE_LENGTH], SmbSigningError> {
    let cipher = aes_gcm::Aes128Gcm::new_from_slice(signing_key)
        .map_err(|_| SmbSigningError::InvalidSigningKey)?;
    let nonce = gmac_nonce(packet, sender)?;
    let mut empty = [];
    cipher
        .encrypt_inout_detached(&nonce.into(), packet, (&mut empty[..]).into())
        .map(Into::into)
        .map_err(|_| SmbSigningError::SigningFailed)
}

fn gmac_nonce(packet: &[u8], sender: SmbPacketSender) -> Result<[u8; 12], SmbSigningError> {
    let mut nonce = [0; 12];
    nonce[..8].copy_from_slice(
        packet
            .get(MESSAGE_ID_OFFSET..MESSAGE_ID_OFFSET + 8)
            .ok_or(SmbSigningError::Truncated)?,
    );
    let command = read_u16(packet, COMMAND_OFFSET)?;
    let mut flags = u32::from(matches!(sender, SmbPacketSender::Server));
    if command == CANCEL_COMMAND {
        flags |= 0x0000_0002;
    }
    nonce[8..].copy_from_slice(&flags.to_le_bytes());
    Ok(nonce)
}

fn validate_packet(
    packet: &[u8],
    sender: SmbPacketSender,
    require_signature: bool,
) -> Result<(), SmbSigningError> {
    if packet.len() < SMB2_HEADER_LENGTH {
        return Err(SmbSigningError::Truncated);
    }
    if packet[..4] != PROTOCOL_ID {
        return Err(SmbSigningError::InvalidProtocol);
    }
    if read_u16(packet, 4)? != 64 {
        return Err(SmbSigningError::InvalidStructureSize);
    }
    let flags = read_u32(packet, FLAGS_OFFSET)?;
    let server_flag = flags & SERVER_TO_CLIENT_FLAG != 0;
    if server_flag != matches!(sender, SmbPacketSender::Server) {
        return Err(SmbSigningError::DirectionMismatch);
    }
    if require_signature && flags & SIGNED_FLAG == 0 {
        return Err(SmbSigningError::UnsignedPacket);
    }
    Ok(())
}

fn read_u16(packet: &[u8], offset: usize) -> Result<u16, SmbSigningError> {
    packet
        .get(offset..offset + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(SmbSigningError::Truncated)
}

fn read_u32(packet: &[u8], offset: usize) -> Result<u32, SmbSigningError> {
    packet
        .get(offset..offset + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(SmbSigningError::Truncated)
}

/// SMB 3.1.1 message-signing failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SmbSigningError {
    /// The complete fixed SMB2 header is absent.
    #[error("SMB packet is truncated before signing")]
    Truncated,
    /// The protocol marker does not identify an SMB2/3 packet.
    #[error("SMB packet protocol identifier is invalid")]
    InvalidProtocol,
    /// The fixed SMB2 header length marker is not 64.
    #[error("SMB packet header structure size is invalid")]
    InvalidStructureSize,
    /// The header's server bit disagrees with the signing direction.
    #[error("SMB packet signing direction does not match its header")]
    DirectionMismatch,
    /// Verification was requested for a packet without the signed flag.
    #[error("SMB packet is not marked as signed")]
    UnsignedPacket,
    /// The fixed-width AES signing key could not initialise the selected primitive.
    #[error("SMB signing key is invalid")]
    InvalidSigningKey,
    /// The selected signing primitive rejected the packet.
    #[error("SMB packet signing failed")]
    SigningFailed,
    /// The transmitted signature did not authenticate the complete packet.
    #[error("SMB packet signature does not match")]
    SignatureMismatch,
}

#[cfg(test)]
mod tests {
    use crate::SigningAlgorithm;

    use super::{SmbPacketSender, SmbSigningError, sign_smb311, verify_smb311};

    #[test]
    fn cmac_signs_exact_packet_and_rejects_tampering() -> Result<(), SmbSigningError> {
        let mut packet = test_packet(SmbPacketSender::Client, 0x0009, 42);
        sign_smb311(
            &mut packet,
            &[0x11; 16],
            SigningAlgorithm::AesCmac,
            SmbPacketSender::Client,
        )?;
        assert_eq!(&packet[48..64], &hex16("be108031be6b39dc1027a3bebee783e9"));
        verify_smb311(
            &mut packet,
            &[0x11; 16],
            SigningAlgorithm::AesCmac,
            SmbPacketSender::Client,
        )?;
        packet[70] ^= 1;
        assert_eq!(
            verify_smb311(
                &mut packet,
                &[0x11; 16],
                SigningAlgorithm::AesCmac,
                SmbPacketSender::Client,
            ),
            Err(SmbSigningError::SignatureMismatch)
        );
        Ok(())
    }

    #[test]
    fn gmac_binds_message_id_direction_and_cancel_bit() -> Result<(), SmbSigningError> {
        let mut response = test_packet(SmbPacketSender::Server, 0x000d, 42);
        sign_smb311(
            &mut response,
            &[0x22; 16],
            SigningAlgorithm::AesGmac,
            SmbPacketSender::Server,
        )?;
        let signature = response[48..64].to_vec();
        assert_eq!(
            signature.as_slice(),
            &hex16("ce57d90a78e055f885156c38aa4a16fe")
        );
        verify_smb311(
            &mut response,
            &[0x22; 16],
            SigningAlgorithm::AesGmac,
            SmbPacketSender::Server,
        )?;
        response[24] ^= 1;
        assert_eq!(
            verify_smb311(
                &mut response,
                &[0x22; 16],
                SigningAlgorithm::AesGmac,
                SmbPacketSender::Server,
            ),
            Err(SmbSigningError::SignatureMismatch)
        );
        assert_eq!(&response[48..64], signature.as_slice());
        let mut cancel = test_packet(SmbPacketSender::Client, 0x000c, 42);
        sign_smb311(
            &mut cancel,
            &[0x22; 16],
            SigningAlgorithm::AesGmac,
            SmbPacketSender::Client,
        )?;
        assert_eq!(&cancel[48..64], &hex16("9cbd391f9271e4e364c4792bde5fb245"));
        Ok(())
    }

    #[test]
    fn unsigned_and_direction_confused_packets_fail_closed() {
        let mut request = test_packet(SmbPacketSender::Client, 0x000d, 7);
        assert_eq!(
            verify_smb311(
                &mut request,
                &[3; 16],
                SigningAlgorithm::AesCmac,
                SmbPacketSender::Client,
            ),
            Err(SmbSigningError::UnsignedPacket)
        );
        assert_eq!(
            sign_smb311(
                &mut request,
                &[3; 16],
                SigningAlgorithm::AesCmac,
                SmbPacketSender::Server,
            ),
            Err(SmbSigningError::DirectionMismatch)
        );
    }

    fn test_packet(sender: SmbPacketSender, command: u16, message_id: u64) -> Vec<u8> {
        let mut packet = vec![0; 80];
        packet[..4].copy_from_slice(&[0xfe, b'S', b'M', b'B']);
        packet[4..6].copy_from_slice(&64_u16.to_le_bytes());
        packet[12..14].copy_from_slice(&command.to_le_bytes());
        let flags = u32::from(matches!(sender, SmbPacketSender::Server));
        packet[16..20].copy_from_slice(&flags.to_le_bytes());
        packet[24..32].copy_from_slice(&message_id.to_le_bytes());
        packet[40..48].copy_from_slice(&9_u64.to_le_bytes());
        packet[64..].copy_from_slice(b"signed test body");
        packet
    }

    fn hex16(value: &str) -> [u8; 16] {
        value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let text = std::str::from_utf8(pair).unwrap_or_default();
                u8::from_str_radix(text, 16).unwrap_or_default()
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap_or_default()
    }
}
