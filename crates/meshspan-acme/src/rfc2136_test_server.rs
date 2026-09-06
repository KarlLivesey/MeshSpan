// SPDX-License-Identifier: GPL-2.0-only

use std::{
    error::Error,
    net::SocketAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    task::JoinHandle,
};

type TestError = Box<dyn Error + Send + Sync>;

const KEY_NAME: &str = "meshspan-key.example.test";
const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";

pub(crate) struct Rfc2136TestServer {
    address: SocketAddr,
    task: JoinHandle<Result<(), TestError>>,
}

impl Rfc2136TestServer {
    pub(crate) async fn start(
        zone: &'static str,
        ttl: u32,
        present_queries: usize,
        signed_at: Option<u64>,
    ) -> Result<Self, TestError> {
        let tcp = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let address = tcp.local_addr()?;
        let udp = UdpSocket::bind(address).await?;
        let task = tokio::spawn(serve(tcp, udp, zone, ttl, present_queries, signed_at));
        Ok(Self { address, task })
    }

    pub(crate) const fn address(&self) -> SocketAddr {
        self.address
    }

    pub(crate) async fn finish(mut self) -> Result<(), TestError> {
        tokio::time::timeout(Duration::from_secs(5), &mut self.task).await???;
        Ok(())
    }
}

impl Drop for Rfc2136TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(
    tcp: TcpListener,
    udp: UdpSocket,
    zone: &str,
    ttl: u32,
    present_queries: usize,
    signed_at: Option<u64>,
) -> Result<(), TestError> {
    let published = receive_update(&tcp, zone, ttl, signed_at).await?;
    if published.class != 1 {
        return Err("first DNS update was not a publish".into());
    }
    // Provider propagation and CA validation are distinct observable DNS requests.
    for _ in 0..present_queries {
        answer_query(&udp, &published, true).await?;
    }
    let removed = receive_update(&tcp, zone, ttl, signed_at).await?;
    if removed.class != 254 || removed.name != published.name || removed.value != published.value {
        return Err("cleanup was not an exact-value DNS removal".into());
    }
    answer_query(&udp, &published, false).await?;
    Ok(())
}

struct Update {
    name: String,
    value: Vec<u8>,
    class: u16,
}

async fn receive_update(
    listener: &TcpListener,
    zone: &str,
    ttl: u32,
    signed_at: Option<u64>,
) -> Result<Update, TestError> {
    let (mut stream, _) = listener.accept().await?;
    let length = usize::from(stream.read_u16().await?);
    let mut request = vec![0_u8; length];
    stream.read_exact(&mut request).await?;
    let (update, request_mac, request_id) = parse_and_verify_update(&request, zone, ttl)?;
    let signed_at = match signed_at {
        Some(value) => value,
        None => SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    };
    let response = signed_response(request_id, &request_mac, signed_at)?;
    stream
        .write_all(&u16::try_from(response.len())?.to_be_bytes())
        .await?;
    stream.write_all(&response).await?;
    Ok(update)
}

fn parse_and_verify_update(
    request: &[u8],
    expected_zone: &str,
    expected_ttl: u32,
) -> Result<(Update, Vec<u8>, u16), TestError> {
    if request.len() < 12 || request[2..12] != [0x28, 0, 0, 1, 0, 0, 0, 1, 0, 1] {
        return Err("unexpected RFC 2136 header".into());
    }
    let request_id = u16::from_be_bytes(request[..2].try_into()?);
    let mut cursor = 12;
    let zone = read_name(request, &mut cursor)?;
    if zone != expected_zone || read_u16(request, &mut cursor)? != 6 {
        return Err("unexpected RFC 2136 zone".into());
    }
    if read_u16(request, &mut cursor)? != 1 {
        return Err("unexpected RFC 2136 zone class".into());
    }
    let name = read_name(request, &mut cursor)?;
    if read_u16(request, &mut cursor)? != 16 {
        return Err("RFC 2136 update was not TXT".into());
    }
    let class = read_u16(request, &mut cursor)?;
    let ttl = read_u32(request, &mut cursor)?;
    if (class == 1 && ttl != expected_ttl) || (class == 254 && ttl != 0) {
        return Err("RFC 2136 update TTL did not match its operation".into());
    }
    let rdata_length = usize::from(read_u16(request, &mut cursor)?);
    let rdata = take(request, &mut cursor, rdata_length)?;
    let value_length = usize::from(*rdata.first().ok_or("TXT RDATA was empty")?);
    if value_length + 1 != rdata.len() {
        return Err("TXT RDATA was not one exact character-string".into());
    }
    let value = rdata[1..].to_vec();
    let tsig_start = cursor;
    let (request_mac, variables) = read_request_tsig(request, &mut cursor, request_id)?;
    if cursor != request.len() {
        return Err("RFC 2136 request had trailing bytes".into());
    }
    let mut authenticated = request[..tsig_start].to_vec();
    authenticated[10..12].copy_from_slice(&0_u16.to_be_bytes());
    authenticated.extend_from_slice(&variables);
    let mut verifier = Hmac::<Sha256>::new_from_slice(SECRET)?;
    verifier.update(&authenticated);
    verifier.verify_slice(&request_mac)?;
    Ok((Update { name, value, class }, request_mac, request_id))
}

fn read_request_tsig(
    request: &[u8],
    cursor: &mut usize,
    request_id: u16,
) -> Result<(Vec<u8>, Vec<u8>), TestError> {
    let key_name = read_name(request, cursor)?;
    if key_name != KEY_NAME
        || read_u16(request, cursor)? != 250
        || read_u16(request, cursor)? != 255
        || read_u32(request, cursor)? != 0
    {
        return Err("RFC 2136 request TSIG identity was invalid".into());
    }
    let rdata_length = usize::from(read_u16(request, cursor)?);
    let rdata_end = cursor.checked_add(rdata_length).ok_or("TSIG overflow")?;
    let algorithm = read_name(request, cursor)?;
    let time = take(request, cursor, 6)?;
    let fudge = read_u16(request, cursor)?;
    let mac_length = usize::from(read_u16(request, cursor)?);
    let mac = take(request, cursor, mac_length)?.to_vec();
    if algorithm != "hmac-sha256"
        || read_u16(request, cursor)? != request_id
        || read_u16(request, cursor)? != 0
        || read_u16(request, cursor)? != 0
        || *cursor != rdata_end
    {
        return Err("RFC 2136 request TSIG fields were invalid".into());
    }
    let mut variables = Vec::new();
    encode_name(&mut variables, KEY_NAME)?;
    variables.extend_from_slice(&255_u16.to_be_bytes());
    variables.extend_from_slice(&0_u32.to_be_bytes());
    encode_name(&mut variables, &algorithm)?;
    variables.extend_from_slice(time);
    variables.extend_from_slice(&fudge.to_be_bytes());
    variables.extend_from_slice(&[0_u8; 4]);
    Ok((mac, variables))
}

fn signed_response(
    request_id: u16,
    request_mac: &[u8],
    signed_at: u64,
) -> Result<Vec<u8>, TestError> {
    let mut unsigned = Vec::from(request_id.to_be_bytes());
    unsigned.extend_from_slice(&0xa800_u16.to_be_bytes());
    unsigned.extend_from_slice(&[0_u8; 8]);
    let variables = response_variables(signed_at)?;
    let mut authenticated = Vec::new();
    authenticated.extend_from_slice(&u16::try_from(request_mac.len())?.to_be_bytes());
    authenticated.extend_from_slice(request_mac);
    authenticated.extend_from_slice(&unsigned);
    authenticated.extend_from_slice(&variables);
    let mut signer = Hmac::<Sha256>::new_from_slice(SECRET)?;
    signer.update(&authenticated);
    let mac = signer.finalize().into_bytes();
    unsigned[10..12].copy_from_slice(&1_u16.to_be_bytes());
    append_response_tsig(&mut unsigned, request_id, &mac, signed_at)?;
    Ok(unsigned)
}

fn response_variables(signed_at: u64) -> Result<Vec<u8>, TestError> {
    let mut variables = Vec::new();
    encode_name(&mut variables, KEY_NAME)?;
    variables.extend_from_slice(&255_u16.to_be_bytes());
    variables.extend_from_slice(&0_u32.to_be_bytes());
    encode_name(&mut variables, "hmac-sha256")?;
    variables.extend_from_slice(&signed_at.to_be_bytes()[2..]);
    variables.extend_from_slice(&300_u16.to_be_bytes());
    variables.extend_from_slice(&[0_u8; 4]);
    Ok(variables)
}

fn append_response_tsig(
    response: &mut Vec<u8>,
    request_id: u16,
    mac: &[u8],
    signed_at: u64,
) -> Result<(), TestError> {
    encode_name(response, KEY_NAME)?;
    response.extend_from_slice(&250_u16.to_be_bytes());
    response.extend_from_slice(&255_u16.to_be_bytes());
    response.extend_from_slice(&0_u32.to_be_bytes());
    let mut rdata = Vec::new();
    encode_name(&mut rdata, "hmac-sha256")?;
    rdata.extend_from_slice(&signed_at.to_be_bytes()[2..]);
    rdata.extend_from_slice(&300_u16.to_be_bytes());
    rdata.extend_from_slice(&u16::try_from(mac.len())?.to_be_bytes());
    rdata.extend_from_slice(mac);
    rdata.extend_from_slice(&request_id.to_be_bytes());
    rdata.extend_from_slice(&[0_u8; 4]);
    response.extend_from_slice(&u16::try_from(rdata.len())?.to_be_bytes());
    response.extend_from_slice(&rdata);
    Ok(())
}

async fn answer_query(udp: &UdpSocket, update: &Update, present: bool) -> Result<(), TestError> {
    let mut query = vec![0_u8; 512];
    let (length, peer) = udp.recv_from(&mut query).await?;
    query.truncate(length);
    let response = query_response(&query, update, present)?;
    udp.send_to(&response, peer).await?;
    Ok(())
}

fn query_response(query: &[u8], update: &Update, present: bool) -> Result<Vec<u8>, TestError> {
    let mut cursor = 12;
    if query.len() < 12
        || read_name(query, &mut cursor)? != update.name
        || read_u16(query, &mut cursor)? != 16
        || read_u16(query, &mut cursor)? != 1
        || cursor != query.len()
    {
        return Err("authoritative probe query was invalid".into());
    }
    let question = &query[12..];
    let mut response = Vec::new();
    response.extend_from_slice(&query[..2]);
    response.extend_from_slice(&0x8400_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&u16::from(present).to_be_bytes());
    response.extend_from_slice(&[0_u8; 4]);
    response.extend_from_slice(question);
    if present {
        response.extend_from_slice(&0xc00c_u16.to_be_bytes());
        response.extend_from_slice(&16_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&30_u32.to_be_bytes());
        response.extend_from_slice(&u16::try_from(update.value.len() + 1)?.to_be_bytes());
        response.push(u8::try_from(update.value.len())?);
        response.extend_from_slice(&update.value);
    }
    Ok(response)
}

fn read_name(bytes: &[u8], cursor: &mut usize) -> Result<String, TestError> {
    let mut labels = Vec::new();
    loop {
        let length = usize::from(*bytes.get(*cursor).ok_or("DNS name was truncated")?);
        *cursor = cursor.checked_add(1).ok_or("DNS cursor overflow")?;
        if length == 0 {
            return Ok(labels.join("."));
        }
        if length > 63 {
            return Err("compressed or oversized DNS name was unexpected".into());
        }
        let label = take(bytes, cursor, length)?;
        labels.push(std::str::from_utf8(label)?);
    }
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, TestError> {
    Ok(u16::from_be_bytes(take(bytes, cursor, 2)?.try_into()?))
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, TestError> {
    Ok(u32::from_be_bytes(take(bytes, cursor, 4)?.try_into()?))
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, length: usize) -> Result<&'a [u8], TestError> {
    let end = cursor.checked_add(length).ok_or("DNS cursor overflow")?;
    let value = bytes.get(*cursor..end).ok_or("DNS field was truncated")?;
    *cursor = end;
    Ok(value)
}

fn encode_name(output: &mut Vec<u8>, name: &str) -> Result<(), TestError> {
    for label in name.split('.') {
        output.push(u8::try_from(label.len())?);
        output.extend_from_slice(label.as_bytes());
    }
    output.push(0);
    Ok(())
}
