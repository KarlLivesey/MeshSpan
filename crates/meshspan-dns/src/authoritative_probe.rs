// SPDX-License-Identifier: GPL-2.0-only

use std::{io, net::SocketAddr, time::Duration};

use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::timeout,
};

use crate::{DnsQuery, DnsWireError, TxtValue};

const MAXIMUM_DNS_MESSAGE_BYTES: usize = 65_535;
const MAXIMUM_TIMEOUT: Duration = Duration::from_secs(60);

/// Direct probe of one authoritative DNS server over UDP with exact TCP fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthoritativeTxtProbe {
    server: SocketAddr,
    timeout: Duration,
}

impl AuthoritativeTxtProbe {
    /// Creates a probe with one finite per-transport deadline.
    ///
    /// # Errors
    ///
    /// Rejects zero or greater-than-one-minute deadlines.
    pub fn new(server: SocketAddr, timeout: Duration) -> Result<Self, AuthoritativeDnsError> {
        if timeout.is_zero() || timeout > MAXIMUM_TIMEOUT {
            return Err(AuthoritativeDnsError::InvalidConfiguration);
        }
        Ok(Self { server, timeout })
    }

    /// Queries the configured authoritative server for one exact TXT value.
    ///
    /// A valid truncated UDP response causes one retry of the same query over TCP. No recursive
    /// resolver is consulted.
    ///
    /// # Errors
    ///
    /// Fails closed on timeouts, transport errors, hostile DNS messages and rejected responses.
    pub async fn contains_txt(
        &self,
        query: &DnsQuery,
        expected: &TxtValue,
    ) -> Result<bool, AuthoritativeDnsError> {
        let request = query.encode()?;
        let udp_response = self.exchange_udp(&request).await?;
        match query.response_contains(&udp_response, expected) {
            Ok(found) => Ok(found),
            Err(DnsWireError::Truncated) => {
                let tcp_response = self.exchange_tcp(&request).await?;
                query
                    .response_contains(&tcp_response, expected)
                    .map_err(Into::into)
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn exchange_udp(&self, request: &[u8]) -> Result<Vec<u8>, AuthoritativeDnsError> {
        let operation = async {
            let bind_address = if self.server.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let socket = UdpSocket::bind(bind_address).await?;
            socket.connect(self.server).await?;
            socket.send(request).await?;
            let mut response = vec![0_u8; MAXIMUM_DNS_MESSAGE_BYTES];
            let length = socket.recv(&mut response).await?;
            response.truncate(length);
            Ok::<_, io::Error>(response)
        };
        timeout(self.timeout, operation)
            .await
            .map_err(|_| AuthoritativeDnsError::Timeout)?
            .map_err(Into::into)
    }

    async fn exchange_tcp(&self, request: &[u8]) -> Result<Vec<u8>, AuthoritativeDnsError> {
        let request_length = u16::try_from(request.len())
            .map_err(|_| AuthoritativeDnsError::InvalidConfiguration)?;
        let operation = async {
            let mut stream = TcpStream::connect(self.server).await?;
            stream.set_nodelay(true)?;
            stream.write_all(&request_length.to_be_bytes()).await?;
            stream.write_all(request).await?;
            let response_length = stream.read_u16().await?;
            let mut response = vec![0_u8; usize::from(response_length)];
            stream.read_exact(&mut response).await?;
            Ok::<_, io::Error>(response)
        };
        timeout(self.timeout, operation)
            .await
            .map_err(|_| AuthoritativeDnsError::Timeout)?
            .map_err(Into::into)
    }
}

/// Closed authoritative probe failure without retaining hostile response bytes.
#[derive(Debug, Error)]
pub enum AuthoritativeDnsError {
    /// Probe deadline or DNS request cannot be represented safely.
    #[error("authoritative DNS probe configuration is invalid")]
    InvalidConfiguration,
    /// The configured authoritative server did not finish within the deadline.
    #[error("authoritative DNS probe timed out")]
    Timeout,
    /// Socket creation, connection or bounded message exchange failed.
    #[error("authoritative DNS transport failed")]
    Io(#[from] io::Error),
    /// The DNS request or response failed exact wire validation.
    #[error("authoritative DNS message failed validation")]
    Wire(#[from] DnsWireError),
}
