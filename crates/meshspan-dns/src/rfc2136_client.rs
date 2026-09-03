// SPDX-License-Identifier: GPL-2.0-only

use std::{io, net::SocketAddr, time::Duration};

use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

use crate::{Rfc2136ResponseError, Rfc2136TsigKey, SignedRfc2136Request};

const MAXIMUM_TIMEOUT: Duration = Duration::from_secs(60);

/// Bounded in-process RFC 2136 client using authenticated DNS-over-TCP transactions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rfc2136Client {
    server: SocketAddr,
    timeout: Duration,
}

impl Rfc2136Client {
    /// Creates a client for one configured DNS update server.
    ///
    /// # Errors
    ///
    /// Rejects zero or greater-than-one-minute transaction deadlines.
    pub fn new(server: SocketAddr, timeout: Duration) -> Result<Self, Rfc2136ClientError> {
        if timeout.is_zero() || timeout > MAXIMUM_TIMEOUT {
            return Err(Rfc2136ClientError::InvalidConfiguration);
        }
        Ok(Self { server, timeout })
    }

    /// Sends one already signed update and authenticates its exact response.
    ///
    /// The complete connect, write and read sequence shares one finite deadline. A timed-out
    /// result is inconclusive: the caller must preserve its operation and reconcile visibility.
    ///
    /// # Errors
    ///
    /// Fails closed on framing overflow, timeout, socket failure or response authentication.
    pub async fn execute(
        &self,
        request: &SignedRfc2136Request,
        key: &Rfc2136TsigKey,
        now_seconds: u64,
    ) -> Result<(), Rfc2136ClientError> {
        let request_length =
            u16::try_from(request.as_bytes().len()).map_err(|_| Rfc2136ClientError::Capacity)?;
        let operation = async {
            let mut stream = TcpStream::connect(self.server).await?;
            stream.set_nodelay(true)?;
            stream.write_all(&request_length.to_be_bytes()).await?;
            stream.write_all(request.as_bytes()).await?;
            let response_length = stream.read_u16().await?;
            let mut response = vec![0_u8; usize::from(response_length)];
            stream.read_exact(&mut response).await?;
            Ok::<_, io::Error>(response)
        };
        let response = timeout(self.timeout, operation)
            .await
            .map_err(|_| Rfc2136ClientError::Timeout)??;
        request.verify_response(&response, key, now_seconds)?;
        Ok(())
    }
}

/// Closed RFC 2136 client failure without request, response or key bytes.
#[derive(Debug, Error)]
pub enum Rfc2136ClientError {
    /// Endpoint or deadline configuration is invalid.
    #[error("RFC 2136 client configuration is invalid")]
    InvalidConfiguration,
    /// Request length does not fit DNS-over-TCP framing.
    #[error("RFC 2136 request exceeds TCP framing capacity")]
    Capacity,
    /// The transaction did not finish before its deadline.
    #[error("RFC 2136 transaction timed out")]
    Timeout,
    /// TCP connection, write or bounded response read failed.
    #[error("RFC 2136 transport failed")]
    Io(#[from] io::Error),
    /// The response was not an authenticated success for the exact request.
    #[error("RFC 2136 response failed validation")]
    Response(#[from] Rfc2136ResponseError),
}
