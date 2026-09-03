// SPDX-License-Identifier: GPL-2.0-only

//! Minimal plain-HTTP listener exposing only current ACME HTTP-01 challenge material.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderValue, Response, StatusCode};
use axum::routing::get;
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use meshspan_acme::Http01Challenge;
use meshspan_domain::UnixMicros;
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;

/// One bound HTTP-01 listener with no API, redirect or filesystem routes.
pub struct Http01Server {
    listener: TcpListener,
    router: Router,
}

impl Http01Server {
    /// Binds the dedicated challenge listener without starting its accept loop.
    ///
    /// Port zero is supported for isolated acceptance tests.
    ///
    /// # Errors
    ///
    /// Returns an error when the operating system cannot bind the requested address.
    pub async fn bind(
        address: SocketAddr,
        challenges: Http01Challenge,
    ) -> Result<Self, Http01ServerError> {
        let listener = TcpListener::bind(address)
            .await
            .map_err(Http01ServerError::Bind)?;
        let router = Router::new()
            .route("/.well-known/acme-challenge/{token}", get(challenge))
            .with_state(challenges);
        Ok(Self { listener, router })
    }

    /// Returns the operating-system-selected listener address.
    ///
    /// # Errors
    ///
    /// Returns an error when the socket no longer exposes its local address.
    pub fn local_addr(&self) -> Result<SocketAddr, Http01ServerError> {
        self.listener
            .local_addr()
            .map_err(Http01ServerError::LocalAddress)
    }

    /// Accepts isolated HTTP connections until shutdown resolves.
    ///
    /// # Errors
    ///
    /// Returns an error only when the bound listener can no longer accept connections.
    pub async fn run_until<F>(self, shutdown: F) -> Result<(), Http01ServerError>
    where
        F: Future<Output = ()> + Send,
    {
        let mut connections = JoinSet::new();
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => break,
                accepted = self.listener.accept() => {
                    let (stream, _) = accepted.map_err(Http01ServerError::Accept)?;
                    spawn_connection(&mut connections, self.router.clone(), stream);
                }
                completed = connections.join_next(), if !connections.is_empty() => {
                    drop(completed);
                }
            }
        }
        connections.shutdown().await;
        Ok(())
    }
}

async fn challenge(
    Path(token): Path<String>,
    State(challenges): State<Http01Challenge>,
) -> Response<Body> {
    let Some(now) = current_time() else {
        return empty_response(StatusCode::SERVICE_UNAVAILABLE);
    };
    match challenges.response(&token, now) {
        Ok(Some(body)) => {
            let mut response = Response::new(Body::from(body));
            *response.status_mut() = StatusCode::OK;
            response.headers_mut().insert(
                CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            response
                .headers_mut()
                .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Ok(None) => empty_response(StatusCode::NOT_FOUND),
        Err(_) => empty_response(StatusCode::SERVICE_UNAVAILABLE),
    }
}

fn empty_response(status: StatusCode) -> Response<Body> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn spawn_connection(connections: &mut JoinSet<()>, router: Router, stream: TcpStream) {
    connections.spawn(async move {
        let service = TowerToHyperService::new(router);
        let connection = http1::Builder::new().serve_connection(TokioIo::new(stream), service);
        drop(connection.await);
    });
}

fn current_time() -> Option<UnixMicros> {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_micros();
    i64::try_from(micros).ok().map(UnixMicros::new)
}

/// Dedicated HTTP-01 listener lifecycle failure.
#[derive(Debug, Error)]
pub enum Http01ServerError {
    /// The configured address could not be bound.
    #[error("could not bind the HTTP-01 listener: {0}")]
    Bind(#[source] io::Error),
    /// The listener address could not be read.
    #[error("could not read the HTTP-01 listener address: {0}")]
    LocalAddress(#[source] io::Error),
    /// The listener failed while accepting another connection.
    #[error("the HTTP-01 listener failed while accepting a connection: {0}")]
    Accept(#[source] io::Error),
}
