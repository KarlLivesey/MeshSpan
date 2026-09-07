// SPDX-License-Identifier: GPL-2.0-only

//! SMTP submission: strict finite replies, TLS before AUTH, and a fixed redacted message.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use meshspan_api_contract::{NotificationDestination, NotificationSmtpTls};
use meshspan_metadata::NotificationDeliveryRecord;
use rustls::pki_types::ServerName;
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

use crate::notification_transport::{DeliveryError, NotificationTransport, event_json, event_name};

pub(crate) async fn send(
    transport: &NotificationTransport,
    destination: &NotificationDestination,
    delivery: &NotificationDeliveryRecord,
) -> Result<(), DeliveryError> {
    let NotificationDestination::Email {
        host, port, tls, ..
    } = destination
    else {
        return Err(DeliveryError::Rejected);
    };
    let server_name = ServerName::try_from(host.to_owned()).map_err(|_| DeliveryError::Rejected)?;
    let stream = TcpStream::connect((host.as_str(), *port))
        .await
        .map_err(|_| DeliveryError::Retry)?;
    let stream = match tls {
        NotificationSmtpTls::Implicit => stream,
        NotificationSmtpTls::Starttls => {
            let mut stream = BufReader::new(stream);
            expect(read_reply(&mut stream).await?, 220)?;
            let hello = command(&mut stream, b"EHLO meshspan.invalid\r\n", 250).await?;
            if !hello
                .iter()
                .any(|line| line.eq_ignore_ascii_case("STARTTLS"))
            {
                return Err(DeliveryError::Rejected);
            }
            command(&mut stream, b"STARTTLS\r\n", 220).await?;
            if !stream.buffer().is_empty() {
                return Err(DeliveryError::Rejected);
            }
            stream.into_inner()
        }
    };
    let mut config = (*transport.tls).clone();
    config.alpn_protocols.clear();
    let encrypted = TlsConnector::from(std::sync::Arc::new(config))
        .connect(server_name, stream)
        .await
        .map_err(|_| DeliveryError::Retry)?;
    let mut stream = BufReader::new(encrypted);
    if *tls == NotificationSmtpTls::Implicit {
        expect(read_reply(&mut stream).await?, 220)?;
    }
    submit(&mut stream, destination, delivery).await
}

async fn submit<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut BufReader<S>,
    destination: &NotificationDestination,
    delivery: &NotificationDeliveryRecord,
) -> Result<(), DeliveryError> {
    let NotificationDestination::Email {
        username,
        password,
        sender,
        recipients,
        ..
    } = destination
    else {
        return Err(DeliveryError::Rejected);
    };
    // RFC 3207: discard plaintext capabilities and discover AUTH again inside TLS.
    let capabilities = command(stream, b"EHLO meshspan.invalid\r\n", 250).await?;
    if !capabilities.iter().any(|line| {
        let mut words = line.split_ascii_whitespace();
        words
            .next()
            .is_some_and(|word| word.eq_ignore_ascii_case("AUTH"))
            && words.any(|word| word.eq_ignore_ascii_case("PLAIN"))
    }) {
        return Err(DeliveryError::Rejected);
    }
    let credentials = Zeroizing::new(format!("\0{username}\0{password}"));
    let encoded = Zeroizing::new(STANDARD.encode(credentials.as_bytes()));
    let auth = Zeroizing::new(format!("AUTH PLAIN {}\r\n", encoded.as_str()));
    command(stream, auth.as_bytes(), 235).await?;
    command(stream, format!("MAIL FROM:<{sender}>\r\n").as_bytes(), 250).await?;
    for recipient in recipients {
        command(
            stream,
            format!("RCPT TO:<{}>\r\n", recipient.0).as_bytes(),
            250,
        )
        .await?;
    }
    command(stream, b"DATA\r\n", 354).await?;
    let event = String::from_utf8(event_json(delivery)?).map_err(|_| DeliveryError::Rejected)?;
    let subject = event_name(delivery.event_kind);
    let instant = std::time::UNIX_EPOCH
        .checked_add(std::time::Duration::from_micros(
            u64::try_from(delivery.occurred_at.get()).map_err(|_| DeliveryError::Rejected)?,
        ))
        .ok_or(DeliveryError::Rejected)?;
    let date = httpdate::fmt_http_date(instant);
    let message = format!(
        "Date: {date}\r\nFrom: <{sender}>\r\nSubject: MeshSpan {subject}\r\nMessage-ID: <{}@meshspan.invalid>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 7bit\r\n\r\nMeshSpan operational notification. Open your authenticated administration panel for details.\r\n{event}\r\n.\r\n",
        crate::create_mesh_setup::format_uuid(delivery.delivery_id.as_bytes())
    );
    // Only fixed ASCII text and a closed event JSON object enter DATA. Neither begins with a
    // dot, and no user-controlled name, path, address, or credential is interpolated into it.
    command(stream, message.as_bytes(), 250).await?;
    Ok(())
}

async fn command<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut BufReader<S>,
    bytes: &[u8],
    expected: u16,
) -> Result<Vec<String>, DeliveryError> {
    stream
        .write_all(bytes)
        .await
        .map_err(|_| DeliveryError::Retry)?;
    stream.flush().await.map_err(|_| DeliveryError::Retry)?;
    expect(read_reply(stream).await?, expected)
}

fn expect(reply: SmtpReply, expected: u16) -> Result<Vec<String>, DeliveryError> {
    if reply.code == expected {
        return Ok(reply.lines);
    }
    if (400..=499).contains(&reply.code) {
        return Err(DeliveryError::Retry);
    }
    Err(DeliveryError::Rejected)
}

struct SmtpReply {
    code: u16,
    lines: Vec<String>,
}

async fn read_reply<S: AsyncRead + Unpin>(
    stream: &mut BufReader<S>,
) -> Result<SmtpReply, DeliveryError> {
    let mut code = None;
    let mut lines = Vec::new();
    for _ in 0..32 {
        let mut line = Vec::new();
        (&mut *stream)
            .take(513)
            .read_until(b'\n', &mut line)
            .await
            .map_err(|_| DeliveryError::Retry)?;
        if line.is_empty() {
            return Err(DeliveryError::Retry);
        }
        if line.len() > 512
            || !line.ends_with(b"\r\n")
            || line.len() < 5
            || !line[..3].iter().all(u8::is_ascii_digit)
        {
            return Err(DeliveryError::Rejected);
        }
        let received = u16::from(line[0] - b'0') * 100
            + u16::from(line[1] - b'0') * 10
            + u16::from(line[2] - b'0');
        if code.is_some_and(|code| code != received) {
            return Err(DeliveryError::Rejected);
        }
        code = Some(received);
        let final_line = match line[3] {
            b' ' => true,
            b'\r' if line.len() == 5 => true,
            b'-' => false,
            _ => return Err(DeliveryError::Rejected),
        };
        let content = if line.len() == 5 {
            ""
        } else {
            std::str::from_utf8(&line[4..line.len() - 2]).map_err(|_| DeliveryError::Rejected)?
        };
        if content
            .bytes()
            .any(|byte| byte.is_ascii_control() && byte != b'\t')
        {
            return Err(DeliveryError::Rejected);
        }
        lines.push(content.to_owned());
        if final_line {
            return Ok(SmtpReply {
                code: received,
                lines,
            });
        }
    }
    Err(DeliveryError::Rejected)
}
