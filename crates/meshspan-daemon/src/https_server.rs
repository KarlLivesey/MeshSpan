// SPDX-License-Identifier: GPL-2.0-only

//! In-process HTTPS listener for the public appliance router.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use rustls::ServerConfig;
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECTION_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// One bound, fully in-process HTTPS appliance listener.
pub struct HttpsServer {
    listener: TcpListener,
    router: Router,
    tls: TlsAcceptor,
}

impl HttpsServer {
    /// Binds an HTTPS listener without starting its accept loop.
    ///
    /// Binding to port zero is supported for isolated process tests.
    ///
    /// # Errors
    ///
    /// Returns an error when the operating system cannot bind the requested address.
    pub async fn bind(
        address: SocketAddr,
        tls: Arc<ServerConfig>,
        router: Router,
    ) -> Result<Self, HttpsServerError> {
        let listener = TcpListener::bind(address)
            .await
            .map_err(HttpsServerError::Bind)?;
        Ok(Self {
            listener,
            router,
            tls: TlsAcceptor::from(tls),
        })
    }

    /// Returns the operating-system-selected listener address.
    ///
    /// # Errors
    ///
    /// Returns an error when the socket no longer exposes its local address.
    pub fn local_addr(&self) -> Result<SocketAddr, HttpsServerError> {
        self.listener
            .local_addr()
            .map_err(HttpsServerError::LocalAddress)
    }

    /// Accepts HTTPS connections until the supplied shutdown signal resolves.
    ///
    /// Each accepted connection is independently serviced by Tokio. Invalid TLS and HTTP input is
    /// isolated to that connection and never terminates the appliance listener.
    ///
    /// # Errors
    ///
    /// Returns an error when the bound listener can no longer accept connections.
    pub async fn run_until<F>(self, shutdown: F) -> Result<(), HttpsServerError>
    where
        F: Future<Output = ()> + Send,
    {
        let mut connections = JoinSet::new();
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => break,
                accepted = self.listener.accept() => {
                    let (stream, _) = accepted.map_err(HttpsServerError::Accept)?;
                    spawn_connection(
                        &mut connections,
                        self.tls.clone(),
                        self.router.clone(),
                        stream,
                    );
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

fn spawn_connection(
    connections: &mut JoinSet<()>,
    tls: TlsAcceptor,
    router: Router,
    stream: TcpStream,
) {
    connections.spawn(async move {
        serve_connection(tls, router, stream).await;
    });
}

async fn serve_connection(tls: TlsAcceptor, router: Router, stream: TcpStream) {
    let Ok(Ok(stream)) = timeout(TLS_HANDSHAKE_TIMEOUT, tls.accept(stream)).await else {
        return;
    };
    let service = TowerToHyperService::new(router);
    let connection = http1::Builder::new().serve_connection(TokioIo::new(stream), service);
    drop(connection.await);
}

/// HTTPS listener lifecycle failure.
#[derive(Debug, Error)]
pub enum HttpsServerError {
    /// The requested local address could not be bound.
    #[error("could not bind the HTTPS listener: {0}")]
    Bind(#[source] io::Error),
    /// The bound listener address could not be read.
    #[error("could not read the HTTPS listener address: {0}")]
    LocalAddress(#[source] io::Error),
    /// The listener failed while accepting a connection.
    #[error("the HTTPS listener failed while accepting a connection: {0}")]
    Accept(#[source] io::Error),
}
