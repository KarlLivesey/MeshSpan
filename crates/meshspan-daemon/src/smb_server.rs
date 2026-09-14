// SPDX-License-Identifier: GPL-2.0-only

//! Resource-bounded in-process SMB Direct TCP listener.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use crate::gateway_transfer_io::ObservedGatewayIo;
use meshspan_contracts::{GatewayProtocol, GatewayTransferObserver};
use meshspan_smb::{DIRECT_TCP_MAX_PAYLOAD_LENGTH, DirectTcpFrameHeader, encode_direct_tcp_header};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::{JoinError, JoinSet};
use tokio::time::timeout;

const DIRECT_TCP_HEADER_BYTES: usize = 4;
const MINIMUM_SMB_PACKET_BYTES: usize = 64;
const MAXIMUM_SMB_PACKET_BYTES: usize = DIRECT_TCP_MAX_PAYLOAD_LENGTH;
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(1);

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
    /// Display must contain stable, redacted details suitable for a cleanup report.
    type Error: Send + std::fmt::Display;

    /// Handles one complete bounded SMB message and optionally returns one response.
    fn handle(&mut self, request: Vec<u8>) -> SmbHandlerFuture<'_, Self::Error>;

    /// Advances one bounded idle-maintenance step and returns its next wake delay.
    fn maintain(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Duration, Self::Error>> + Send + '_>> {
        Box::pin(async { Ok(Duration::from_secs(1)) })
    }

    /// Observes connection-local cleanup after all in-flight dispatch has completed.
    fn shutdown(&mut self) -> Pin<Box<dyn Future<Output = Result<(), Self::Error>> + Send + '_>> {
        Box::pin(async { Ok(()) })
    }
}

#[cfg(test)]
#[path = "smb_server_lifecycle_tests.rs"]
mod lifecycle_tests;

/// One bound embedded SMB listener.
pub struct SmbServer {
    listener: TcpListener,
    limits: SmbServerLimits,
    transfer_observer: Option<Arc<dyn GatewayTransferObserver>>,
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
        Ok(Self {
            listener,
            limits,
            transfer_observer: None,
        })
    }

    pub(crate) fn with_transfer_observer(
        mut self,
        observer: Arc<dyn GatewayTransferObserver>,
    ) -> Self {
        self.transfer_observer = Some(observer);
        self
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
    /// Reports listener or owned cleanup failures after every started connection has drained.
    /// Shutdown is cooperative: it never abandons a running blocking filesystem operation.
    pub async fn run_until<F, Make, H, E>(
        self,
        make_handler: Make,
        shutdown: F,
    ) -> Result<(), SmbServerError>
    where
        F: Future<Output = ()> + Send,
        Make: Fn() -> Result<H, E> + Clone + Send + Sync + 'static,
        H: SmbConnectionHandler,
        E: Send,
    {
        let mut connections = JoinSet::new();
        let (stop, stopped) = watch::channel(false);
        let mut failures = ConnectionFailures::default();
        tokio::pin!(shutdown);
        let primary = loop {
            tokio::select! {
                () = &mut shutdown => break None,
                accepted = self.listener.accept() => {
                    let (stream, _) = match accepted {
                        Ok(connection) => connection,
                        Err(error) => break Some(Box::new(SmbServerError::Accept(error))),
                    };
                    let Ok(mut handler) = make_handler() else {
                        continue;
                    };
                    let limits = self.limits;
                    let stream = ObservedGatewayIo::new(stream, GatewayProtocol::Smb, self.transfer_observer.clone());
                    let stopped = stopped.clone();
                    connections.spawn(async move {
                        // Peer/protocol failures close only this client. If cleanup also fails,
                        // retain both outcomes in the bounded listener shutdown report.
                        let primary = serve_connection(stream, limits, &mut handler, stopped).await.err();
                        handler.shutdown().await.map_err(|cleanup| {
                            format!("dispatch: {}; cleanup: {}",
                                bounded_failure(format_args!("{primary:?}"), 224),
                                bounded_failure(format_args!("{cleanup}"), 224))
                        })
                    });
                }
                Some(completed) = connections.join_next(), if !connections.is_empty() => {
                    failures.observe(completed);
                }
            }
        };
        // Stopping an idle read is safe; started handler work retains ownership until completion.
        stop.send_replace(true);
        while let Some(completed) = connections.join_next().await {
            failures.observe(completed);
        }
        failures.finish(primary)
    }
}

#[derive(Default)]
struct ConnectionFailures {
    first: Option<String>,
    additional: u64,
}

impl ConnectionFailures {
    fn observe(&mut self, completed: Result<Result<(), String>, JoinError>) {
        let failure = match completed {
            Ok(Ok(())) => return,
            Ok(Err(failure)) => failure,
            Err(_) => "SMB connection task stopped unexpectedly".to_owned(),
        };
        if self.first.is_none() {
            self.first = Some(failure);
        } else {
            self.additional = self.additional.saturating_add(1);
        }
    }

    fn finish(self, primary: Option<Box<SmbServerError>>) -> Result<(), SmbServerError> {
        match (self.first, primary) {
            (Some(first), primary) => Err(SmbServerError::Cleanup {
                primary,
                first,
                additional_failures: self.additional,
            }),
            (None, Some(primary)) => Err(*primary),
            (None, None) => Ok(()),
        }
    }
}

// Bound diagnostics during formatting, before a possibly long handler message allocates.
fn bounded_failure(arguments: std::fmt::Arguments<'_>, maximum_bytes: usize) -> String {
    use std::fmt::Write;
    struct Report {
        text: String,
        maximum_bytes: usize,
    }
    impl std::fmt::Write for Report {
        fn write_str(&mut self, value: &str) -> std::fmt::Result {
            let remaining = self.maximum_bytes.saturating_sub(self.text.len());
            let mut end = remaining.min(value.len());
            while !value.is_char_boundary(end) {
                end -= 1;
            }
            self.text.push_str(&value[..end]);
            Ok(())
        }
    }
    let mut report = Report {
        text: String::new(),
        maximum_bytes,
    };
    // Report's writer always succeeds, including after its fixed bound is reached.
    if report.write_fmt(arguments).is_err() {
        return "SMB connection failure could not be formatted".to_owned();
    }
    report.text
}

async fn serve_connection<H: SmbConnectionHandler>(
    mut stream: ObservedGatewayIo<TcpStream>,
    limits: SmbServerLimits,
    handler: &mut H,
    mut stopped: watch::Receiver<bool>,
) -> Result<(), SmbConnectionIoError> {
    let mut maintenance = tokio::time::Instant::now() + MAINTENANCE_INTERVAL;
    loop {
        let payload = {
            // Keep the same read future across maintenance: partial headers and its inactivity
            // deadline belong to that frame, and must never restart on an idle tick.
            let reading = read_frame(&mut stream, limits);
            tokio::pin!(reading);
            loop {
                if *stopped.borrow() {
                    return Ok(());
                }
                tokio::select! {
                    biased;
                    _ = stopped.changed() => return Ok(()),
                    () = tokio::time::sleep_until(maintenance) => {
                        let delay = handler.maintain().await.map_err(|error| SmbConnectionIoError::Handler(bounded_failure(format_args!("{error}"), 224)))?;
                        maintenance = tokio::time::Instant::now() + delay;
                    }
                    result = &mut reading => break result?,
                }
            }
        };
        let Some(payload) = payload else {
            return Ok(());
        };
        let response = handler.handle(payload).await.map_err(|error| {
            SmbConnectionIoError::Handler(bounded_failure(format_args!("{error}"), 224))
        })?;
        if let Some(response) = response {
            write_frame(&mut stream, limits, &response).await?;
        }
    }
}

async fn read_frame(
    stream: &mut ObservedGatewayIo<TcpStream>,
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
    stream: &mut ObservedGatewayIo<TcpStream>,
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
    /// Owned connection cleanup failed after all started work was observed.
    #[error(
        "SMB cleanup failed: {first}; {additional_failures} additional failures; listener: {primary:?}"
    )]
    Cleanup {
        /// Original listener failure, when shutdown followed an accept failure.
        primary: Option<Box<Self>>,
        /// First bounded connection failure, retaining dispatch and cleanup outcomes.
        first: String,
        /// Further failures counted without retaining an unbounded history.
        additional_failures: u64,
    },
}

#[derive(Debug, Error)]
enum SmbConnectionIoError {
    #[error("SMB connection IO failed")]
    Io(#[source] io::Error),
    #[error("SMB connection timed out")]
    TimedOut,
    #[error("SMB Direct TCP frame is invalid")]
    InvalidFrame,
    #[error("SMB connection handler failed: {0}")]
    Handler(String),
}

#[cfg(test)]
#[path = "smb_server_tests.rs"]
mod tests;
