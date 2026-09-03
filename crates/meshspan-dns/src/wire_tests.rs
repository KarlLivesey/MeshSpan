// SPDX-License-Identifier: GPL-2.0-only

use crate::{DnsName, DnsQuery, DnsWireError, TxtValue};

#[test]
fn authoritative_compressed_txt_response_matches_exact_value()
-> Result<(), Box<dyn std::error::Error>> {
    let query = DnsQuery::txt(0x1234, DnsName::new("_acme-challenge.example.test")?)?;
    let expected = TxtValue::new(b"exact-value")?;
    let request = query.encode()?;
    let response = response(&request, b"exact-value", 0x8400);

    assert!(query.response_contains(&response, &expected)?);
    assert!(!query.response_contains(&response, &TxtValue::new(b"other")?)?);
    Ok(())
}

#[test]
fn substituted_non_authoritative_and_cyclic_responses_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let query = DnsQuery::txt(0x1234, DnsName::new("_acme-challenge.example.test")?)?;
    let expected = TxtValue::new(b"exact-value")?;
    let request = query.encode()?;
    let non_authoritative = response(&request, b"exact-value", 0x8000);
    assert_eq!(
        query.response_contains(&non_authoritative, &expected),
        Err(DnsWireError::InvalidMessage)
    );

    let mut cyclic = vec![0_u8; 12];
    cyclic[0..2].copy_from_slice(&0x1234_u16.to_be_bytes());
    cyclic[2..4].copy_from_slice(&0x8400_u16.to_be_bytes());
    cyclic[4..6].copy_from_slice(&1_u16.to_be_bytes());
    cyclic.extend_from_slice(&[0xc0, 0x0c, 0, 16, 0, 1]);
    assert_eq!(
        query.response_contains(&cyclic, &expected),
        Err(DnsWireError::InvalidMessage)
    );
    Ok(())
}

fn response(request: &[u8], value: &[u8], flags: u16) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&request[..2]);
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&[0; 4]);
    response.extend_from_slice(&request[12..]);
    response.extend_from_slice(&[0xc0, 0x0c]);
    response.extend_from_slice(&16_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&60_u32.to_be_bytes());
    let rdata_length = u16::try_from(value.len() + 1).unwrap_or(u16::MAX);
    response.extend_from_slice(&rdata_length.to_be_bytes());
    response.push(u8::try_from(value.len()).unwrap_or(u8::MAX));
    response.extend_from_slice(value);
    response
}
