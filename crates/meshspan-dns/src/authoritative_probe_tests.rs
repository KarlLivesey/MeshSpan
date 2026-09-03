// SPDX-License-Identifier: GPL-2.0-only

use std::{error::Error, net::Ipv4Addr, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};

use crate::{AuthoritativeTxtProbe, DnsName, DnsQuery, TxtValue};

#[tokio::test]
async fn retries_truncated_udp_response_over_tcp() -> Result<(), Box<dyn Error + Send + Sync>> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let server_address = listener.local_addr()?;
    let udp = UdpSocket::bind(server_address).await?;
    let expected = TxtValue::new(b"proof-token")?;
    let server_expected = expected.clone();

    let server = tokio::spawn(async move {
        let mut udp_request = vec![0_u8; 512];
        let (udp_length, peer) = udp.recv_from(&mut udp_request).await?;
        udp_request.truncate(udp_length);
        udp.send_to(&truncated_response(&udp_request)?, peer)
            .await?;

        let (mut stream, _) = listener.accept().await?;
        let tcp_length = usize::from(stream.read_u16().await?);
        let mut tcp_request = vec![0_u8; tcp_length];
        stream.read_exact(&mut tcp_request).await?;
        if tcp_request != udp_request {
            return Err("TCP retry did not preserve the exact DNS query".into());
        }
        let response = txt_response(&tcp_request, &server_expected)?;
        let response_length = u16::try_from(response.len())?;
        stream.write_all(&response_length.to_be_bytes()).await?;
        stream.write_all(&response).await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    });

    let name = DnsName::new("_acme-challenge.example.test")?;
    let query = DnsQuery::txt(0x1234, name)?;
    let probe = AuthoritativeTxtProbe::new(server_address, Duration::from_secs(2))?;
    assert!(probe.contains_txt(&query, &expected).await?);
    server.await??;
    Ok(())
}

fn truncated_response(request: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let question = request
        .get(12..)
        .ok_or("DNS request omitted its question")?;
    let identity = request.get(..2).ok_or("DNS request omitted its identity")?;
    let mut response = Vec::with_capacity(request.len());
    response.extend_from_slice(identity);
    response.extend_from_slice(&0x8600_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&[0_u8; 6]);
    response.extend_from_slice(question);
    Ok(response)
}

fn txt_response(
    request: &[u8],
    expected: &TxtValue,
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let question = request
        .get(12..)
        .ok_or("DNS request omitted its question")?;
    let identity = request.get(..2).ok_or("DNS request omitted its identity")?;
    let txt_length = u8::try_from(expected.as_bytes().len())?;
    let record_length = u16::from(txt_length) + 1;
    let mut response = Vec::with_capacity(request.len() + expected.as_bytes().len() + 13);
    response.extend_from_slice(identity);
    response.extend_from_slice(&0x8400_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&[0_u8; 4]);
    response.extend_from_slice(question);
    response.extend_from_slice(&0xc00c_u16.to_be_bytes());
    response.extend_from_slice(&16_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&30_u32.to_be_bytes());
    response.extend_from_slice(&record_length.to_be_bytes());
    response.push(txt_length);
    response.extend_from_slice(expected.as_bytes());
    Ok(response)
}
