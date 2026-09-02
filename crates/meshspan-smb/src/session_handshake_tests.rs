// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::UnixMicros;

use super::{SmbSessionAuthenticator, SmbSessionHandshake, SmbSessionHandshakeError};
use crate::{
    EncryptionCipher, NegotiateResponseConfig, NtlmAuthenticate, NtlmChallenge,
    NtlmChallengeConfig, NtlmPasswordVerifier, NtlmSessionBaseKey, Smb311PreauthHash,
    Smb311SessionKeys,
};

#[test]
fn exact_negotiate_challenge_and_proof_establish_one_encrypted_session()
-> Result<(), Box<dyn std::error::Error>> {
    let mut handshake = SmbSessionHandshake::new(9)?;
    let negotiate = negotiate_packet();
    let response = handshake.negotiate(&negotiate, negotiate_config())?;
    assert_eq!(&response[68..70], &0x0311_u16.to_le_bytes());

    let first_setup = session_setup_packet(2, 0, &ntlm_negotiate());
    let challenge = handshake.challenge(
        &first_setup,
        NtlmChallengeConfig {
            server_challenge: hex8("0123456789abcdef"),
            computer_name: "Server",
            domain_name: "Domain",
            dns_computer_name: None,
            dns_domain_name: None,
        },
    )?;
    assert_eq!(&challenge[8..12], &0xc000_0016_u32.to_le_bytes());
    assert_eq!(&challenge[40..48], &9_u64.to_le_bytes());

    let final_setup = session_setup_packet(3, 9, &ntlm_authenticate());
    let mut authenticator = TestAuthenticator;
    let session =
        handshake.authenticate(&final_setup, &mut authenticator, UnixMicros::new(10), true)?;
    assert_eq!(session.session_id(), 9);
    assert_eq!(*session.identity(), 17);
    assert!(session.encryption_required());
    assert_eq!(&session.response()[8..12], &[0; 4]);
    assert_eq!(session.keys().signing_key().len(), 16);
    assert!(matches!(
        handshake.negotiate(&negotiate, negotiate_config()),
        Err(SmbSessionHandshakeError::OutOfOrder)
    ));
    Ok(())
}

#[test]
fn zero_session_and_out_of_order_messages_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    assert!(matches!(
        SmbSessionHandshake::new(0),
        Err(SmbSessionHandshakeError::InvalidSession)
    ));
    let mut handshake = SmbSessionHandshake::new(9)?;
    assert!(matches!(
        handshake.challenge(
            &session_setup_packet(1, 0, &ntlm_negotiate()),
            NtlmChallengeConfig {
                server_challenge: [1; 8],
                computer_name: "Server",
                domain_name: "Domain",
                dns_computer_name: None,
                dns_domain_name: None,
            }
        ),
        Err(SmbSessionHandshakeError::OutOfOrder)
    ));
    Ok(())
}

struct TestAuthenticator;

impl SmbSessionAuthenticator for TestAuthenticator {
    type Identity = u8;
    type Verified = NtlmSessionBaseKey;
    type Error = TestAuthenticationError;

    fn verify(
        &mut self,
        authenticate: &NtlmAuthenticate<'_>,
        challenge: &NtlmChallenge,
        _observed_at: UnixMicros,
    ) -> Result<Self::Verified, Self::Error> {
        let verifier =
            NtlmPasswordVerifier::derive("Password").map_err(|_| TestAuthenticationError)?;
        authenticate
            .verify(&verifier, challenge)
            .map_err(|_| TestAuthenticationError)
    }

    fn establish(
        &mut self,
        verified: Self::Verified,
        preauth: &Smb311PreauthHash,
        cipher: EncryptionCipher,
    ) -> Result<(Self::Identity, Smb311SessionKeys), Self::Error> {
        let keys = Smb311SessionKeys::derive(&verified, preauth, cipher)
            .map_err(|_| TestAuthenticationError)?;
        Ok((17, keys))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("test authentication failed")]
struct TestAuthenticationError;

fn negotiate_config() -> NegotiateResponseConfig {
    NegotiateResponseConfig {
        server_guid: [3; 16],
        maximum_transaction_size: 1_048_576,
        maximum_read_size: 1_048_576,
        maximum_write_size: 1_048_576,
        system_time: 77,
        preauth_salt: [5; 32],
    }
}

fn negotiate_packet() -> Vec<u8> {
    let mut bytes = vec![0; 164];
    header(&mut bytes, 0, 1, 0);
    bytes[64..66].copy_from_slice(&36_u16.to_le_bytes());
    bytes[66..68].copy_from_slice(&1_u16.to_le_bytes());
    bytes[68..70].copy_from_slice(&1_u16.to_le_bytes());
    bytes[76..92].copy_from_slice(&[7; 16]);
    bytes[92..96].copy_from_slice(&104_u32.to_le_bytes());
    bytes[96..98].copy_from_slice(&2_u16.to_le_bytes());
    bytes[100..102].copy_from_slice(&0x0311_u16.to_le_bytes());
    encode_context(&mut bytes, 104, 1, &preauth_context());
    encode_context(&mut bytes, 152, 2, &algorithm_context(2));
    bytes
}

fn session_setup_packet(message_id: u64, session_id: u64, token: &[u8]) -> Vec<u8> {
    let mut packet = vec![0; 88];
    header(&mut packet, 1, message_id, session_id);
    packet[64..66].copy_from_slice(&25_u16.to_le_bytes());
    packet[67] = 3;
    packet[76..78].copy_from_slice(&88_u16.to_le_bytes());
    packet[78..80].copy_from_slice(&u16::try_from(token.len()).unwrap_or_default().to_le_bytes());
    packet.extend_from_slice(token);
    packet
}

fn header(packet: &mut [u8], command: u16, message_id: u64, session_id: u64) {
    packet[..4].copy_from_slice(&[0xfe, b'S', b'M', b'B']);
    packet[4..6].copy_from_slice(&64_u16.to_le_bytes());
    packet[6..8].copy_from_slice(&1_u16.to_le_bytes());
    packet[12..14].copy_from_slice(&command.to_le_bytes());
    packet[14..16].copy_from_slice(&1_u16.to_le_bytes());
    packet[24..32].copy_from_slice(&message_id.to_le_bytes());
    packet[32..36].copy_from_slice(&37_u32.to_le_bytes());
    packet[40..48].copy_from_slice(&session_id.to_le_bytes());
}

fn encode_context(packet: &mut [u8], offset: usize, kind: u16, data: &[u8]) {
    packet[offset..offset + 2].copy_from_slice(&kind.to_le_bytes());
    packet[offset + 2..offset + 4]
        .copy_from_slice(&u16::try_from(data.len()).unwrap_or_default().to_le_bytes());
    packet[offset + 8..offset + 8 + data.len()].copy_from_slice(data);
}

fn preauth_context() -> [u8; 38] {
    let mut data = [0; 38];
    data[..2].copy_from_slice(&1_u16.to_le_bytes());
    data[2..4].copy_from_slice(&32_u16.to_le_bytes());
    data[4..6].copy_from_slice(&1_u16.to_le_bytes());
    data[6..].copy_from_slice(&[9; 32]);
    data
}

fn algorithm_context(value: u16) -> [u8; 4] {
    let mut data = [0; 4];
    data[..2].copy_from_slice(&1_u16.to_le_bytes());
    data[2..].copy_from_slice(&value.to_le_bytes());
    data
}

fn ntlm_negotiate() -> Vec<u8> {
    let mut message = vec![0; 32];
    message[..8].copy_from_slice(b"NTLMSSP\0");
    message[8..12].copy_from_slice(&1_u32.to_le_bytes());
    message[12..16].copy_from_slice(&0x008a_8205_u32.to_le_bytes());
    message
}

fn ntlm_authenticate() -> Vec<u8> {
    let mut response = Vec::from(hex16("68cd0ab851e51c96aabc927bebef6a1c"));
    let mut client = vec![1, 1, 0, 0, 0, 0, 0, 0];
    client.extend_from_slice(&[0; 8]);
    client.extend_from_slice(&[0xaa; 8]);
    client.extend_from_slice(&[0; 4]);
    append_av_pair(&mut client, 2, "Domain");
    append_av_pair(&mut client, 1, "Server");
    client.extend_from_slice(&[0; 8]);
    response.extend_from_slice(&client);

    let domain = utf16("Domain");
    let user = utf16("User");
    let mut message = vec![0; 64];
    message[..8].copy_from_slice(b"NTLMSSP\0");
    message[8..12].copy_from_slice(&3_u32.to_le_bytes());
    let domain_offset = 64;
    let user_offset = domain_offset + domain.len();
    let response_offset = user_offset + user.len();
    set_buffer(&mut message, 28, domain.len(), domain_offset);
    set_buffer(&mut message, 36, user.len(), user_offset);
    set_buffer(&mut message, 20, response.len(), response_offset);
    message[60..64].copy_from_slice(&0x008a_8205_u32.to_le_bytes());
    message.extend_from_slice(&domain);
    message.extend_from_slice(&user);
    message.extend_from_slice(&response);
    message
}

fn set_buffer(message: &mut [u8], offset: usize, length: usize, payload_offset: usize) {
    let encoded_length = u16::try_from(length).unwrap_or_default();
    message[offset..offset + 2].copy_from_slice(&encoded_length.to_le_bytes());
    message[offset + 2..offset + 4].copy_from_slice(&encoded_length.to_le_bytes());
    message[offset + 4..offset + 8].copy_from_slice(
        &u32::try_from(payload_offset)
            .unwrap_or_default()
            .to_le_bytes(),
    );
}

fn append_av_pair(output: &mut Vec<u8>, identifier: u16, value: &str) {
    let encoded = utf16(value);
    output.extend_from_slice(&identifier.to_le_bytes());
    output.extend_from_slice(
        &u16::try_from(encoded.len())
            .unwrap_or_default()
            .to_le_bytes(),
    );
    output.extend_from_slice(&encoded);
}

fn utf16(value: &str) -> Vec<u8> {
    value.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn hex16(value: &str) -> [u8; 16] {
    decode_hex(value).try_into().unwrap_or_default()
}

fn hex8(value: &str) -> [u8; 8] {
    decode_hex(value).try_into().unwrap_or_default()
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap_or_default();
            u8::from_str_radix(text, 16).unwrap_or_default()
        })
        .collect()
}
