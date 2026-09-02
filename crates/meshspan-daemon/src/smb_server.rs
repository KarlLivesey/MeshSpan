// SPDX-License-Identifier: GPL-2.0-only

//! Resource-bounded in-process SMB Direct TCP listener.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

use meshspan_smb::{DirectTcpFrameHeader, encode_direct_tcp_header};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio::time::timeout;

const DIRECT_TCP_HEADER_BYTES: usize = 4;
const MINIMUM_SMB_PACKET_BYTES: usize = 64;
const MAXIMUM_SMB_PACKET_BYTES: usize = 16 * 1_024 * 1_024;
const CONNECTION_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Per-connection bounded message and inactivity policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SmbServerLimits {
    maximum_packet_bytes: usize,
    inactivity_timeout: Duration,
}

/// Boxed connection-local dispatch future with a borrow tied to its handler.
pub type SmbHandlerFuture<'a, E> =
    Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, E>> + Send + 'a>>;

impl SmbServerLimits {
    /// Validates one listener policy without imposing an arbitrary connection-count ceiling.
    ///
    /// # Errors
    ///
    /// Rejects packet bounds outside the Direct TCP profile or a zero inactivity timeout.
    pub const fn new(
        maximum_packet_bytes: usize,
        inactivity_timeout: Duration,
    ) -> Result<Self, SmbServerConfigurationError> {
        if maximum_packet_bytes < MINIMUM_SMB_PACKET_BYTES
            || maximum_packet_bytes > MAXIMUM_SMB_PACKET_BYTES
            || inactivity_timeout.is_zero()
        {
            Err(SmbServerConfigurationError)
        } else {
            Ok(Self {
                maximum_packet_bytes,
                inactivity_timeout,
            })
        }
    }
}

/// Mutable protocol/application state created independently for each TCP connection.
pub trait SmbConnectionHandler: Send + 'static {
    /// Connection-local dispatch failure; it never terminates the listener.
    type Error: Send;

    /// Handles one complete bounded SMB message and optionally returns one response.
    fn handle(&mut self, request: Vec<u8>) -> SmbHandlerFuture<'_, Self::Error>;
}

/// One bound embedded SMB listener.
pub struct SmbServer {
    listener: TcpListener,
    limits: SmbServerLimits,
}

impl SmbServer {
    /// Binds SMB Direct TCP without starting its accept loop.
    ///
    /// Port zero remains available for isolated real-socket tests.
    ///
    /// # Errors
    ///
    /// Returns an error when the operating system cannot bind the requested address.
    pub async fn bind(
        address: SocketAddr,
        limits: SmbServerLimits,
    ) -> Result<Self, SmbServerError> {
        let listener = TcpListener::bind(address)
            .await
            .map_err(SmbServerError::Bind)?;
        Ok(Self { listener, limits })
    }

    /// Returns the operating-system-selected listener address.
    ///
    /// # Errors
    ///
    /// Returns an error when the socket no longer exposes its local address.
    pub fn local_addr(&self) -> Result<SocketAddr, SmbServerError> {
        self.listener
            .local_addr()
            .map_err(SmbServerError::LocalAddress)
    }

    /// Accepts connections until shutdown, isolating every malformed or failed client.
    ///
    /// The operating system and Tokio scheduler provide connection admission; each connection
    /// allocates at most one configured packet plus one bounded response at a time.
    ///
    /// # Errors
    ///
    /// Returns only when the shared listener can no longer accept connections.
    pub async fn run_until<F, Make, H>(
        self,
        make_handler: Make,
        shutdown: F,
    ) -> Result<(), SmbServerError>
    where
        F: Future<Output = ()> + Send,
        Make: Fn() -> H + Clone + Send + Sync + 'static,
        H: SmbConnectionHandler,
    {
        let mut connections = JoinSet::new();
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => break,
                accepted = self.listener.accept() => {
                    let (stream, _) = accepted.map_err(SmbServerError::Accept)?;
                    let mut handler = make_handler();
                    let limits = self.limits;
                    connections.spawn(async move {
                        drop(serve_connection(stream, limits, &mut handler).await);
                    });
                }
                completed = connections.join_next(), if !connections.is_empty() => {
                    drop(completed);
                }
            }
        }
        let drain = async { while connections.join_next().await.is_some() {} };
        if timeout(CONNECTION_DRAIN_TIMEOUT, drain).await.is_err() {
            connections.shutdown().await;
        }
        Ok(())
    }
}

async fn serve_connection<H: SmbConnectionHandler>(
    mut stream: TcpStream,
    limits: SmbServerLimits,
    handler: &mut H,
) -> Result<(), SmbConnectionIoError> {
    loop {
        let Some(payload) = read_frame(&mut stream, limits).await? else {
            return Ok(());
        };
        let Some(response) = handler
            .handle(payload)
            .await
            .map_err(|_| SmbConnectionIoError::Handler)?
        else {
            continue;
        };
        write_frame(&mut stream, limits, &response).await?;
    }
}

async fn read_frame(
    stream: &mut TcpStream,
    limits: SmbServerLimits,
) -> Result<Option<Vec<u8>>, SmbConnectionIoError> {
    let mut header = [0; DIRECT_TCP_HEADER_BYTES];
    match timeout(limits.inactivity_timeout, stream.read_exact(&mut header)).await {
        Err(_) => return Err(SmbConnectionIoError::TimedOut),
        Ok(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Ok(Err(error)) => return Err(SmbConnectionIoError::Io(error)),
        Ok(Ok(_)) => {}
    }
    let header = DirectTcpFrameHeader::parse(header, limits.maximum_packet_bytes)
        .map_err(|_| SmbConnectionIoError::InvalidFrame)?;
    let mut payload = vec![0; header.payload_length()];
    timeout(limits.inactivity_timeout, stream.read_exact(&mut payload))
        .await
        .map_err(|_| SmbConnectionIoError::TimedOut)?
        .map_err(SmbConnectionIoError::Io)?;
    Ok(Some(payload))
}

async fn write_frame(
    stream: &mut TcpStream,
    limits: SmbServerLimits,
    response: &[u8],
) -> Result<(), SmbConnectionIoError> {
    if response.len() > limits.maximum_packet_bytes {
        return Err(SmbConnectionIoError::InvalidFrame);
    }
    let header =
        encode_direct_tcp_header(response.len()).map_err(|_| SmbConnectionIoError::InvalidFrame)?;
    timeout(limits.inactivity_timeout, async {
        stream.write_all(&header).await?;
        stream.write_all(response).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| SmbConnectionIoError::TimedOut)?
    .map_err(SmbConnectionIoError::Io)
}

/// Invalid listener configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("SMB server limits are invalid")]
pub struct SmbServerConfigurationError;

/// Shared listener lifecycle failure.
#[derive(Debug, Error)]
pub enum SmbServerError {
    /// The requested local address could not be bound.
    #[error("could not bind the SMB listener: {0}")]
    Bind(#[source] io::Error),
    /// The bound listener address could not be read.
    #[error("could not read the SMB listener address: {0}")]
    LocalAddress(#[source] io::Error),
    /// The listener failed while accepting a connection.
    #[error("the SMB listener failed while accepting a connection: {0}")]
    Accept(#[source] io::Error),
}

#[derive(Debug, Error)]
enum SmbConnectionIoError {
    #[error("SMB connection IO failed")]
    Io(#[source] io::Error),
    #[error("SMB connection timed out")]
    TimedOut,
    #[error("SMB Direct TCP frame is invalid")]
    InvalidFrame,
    #[error("SMB connection handler failed")]
    Handler,
}

#[cfg(test)]
#[path = "smb_server_tests.rs"]
mod tests;
