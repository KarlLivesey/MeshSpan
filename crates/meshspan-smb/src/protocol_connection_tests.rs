// SPDX-License-Identifier: GPL-2.0-only

use super::{SmbProtocolConnectionError, authentication_error_response};
use crate::ConnectorFailure;

#[test]
fn authentication_rejection_is_exactly_correlated_without_an_oracle()
-> Result<(), Box<dyn std::error::Error>> {
    let packet = session_setup_header(71, 19);
    let response =
        authentication_error_response(&packet, ConnectorFailure::AuthenticationRejected)?;
    assert_eq!(&response[..4], &[0xfe, b'S', b'M', b'B']);
    assert_eq!(&response[8..12], &0xc000_006d_u32.to_le_bytes());
    assert_eq!(&response[12..14], &1_u16.to_le_bytes());
    assert_eq!(&response[24..32], &71_u64.to_le_bytes());
    assert_eq!(&response[40..48], &19_u64.to_le_bytes());
    assert_eq!(&response[64..66], &9_u16.to_le_bytes());
    Ok(())
}

#[test]
fn impossible_success_authentication_classification_fails_closed() {
    assert!(matches!(
        authentication_error_response(&session_setup_header(1, 7), ConnectorFailure::Success),
        Err(SmbProtocolConnectionError::InvalidAuthenticationClassification)
    ));
}

fn session_setup_header(message_id: u64, session_id: u64) -> Vec<u8> {
    let mut packet = vec![0; 64];
    packet[..4].copy_from_slice(&[0xfe, b'S', b'M', b'B']);
    packet[4..6].copy_from_slice(&64_u16.to_le_bytes());
    packet[6..8].copy_from_slice(&1_u16.to_le_bytes());
    packet[12..14].copy_from_slice(&1_u16.to_le_bytes());
    packet[14..16].copy_from_slice(&1_u16.to_le_bytes());
    packet[24..32].copy_from_slice(&message_id.to_le_bytes());
    packet[32..36].copy_from_slice(&44_u32.to_le_bytes());
    packet[40..48].copy_from_slice(&session_id.to_le_bytes());
    packet
}
