// SPDX-License-Identifier: GPL-2.0-only

//! Shared bounded HTTP/1.1-over-rustls transport without protocol-specific semantics.

use std::{sync::Arc, time::Duration};

use bytes::{Bytes, BytesMut};
use http_body_util::{BodyExt as _, Full};
use hyper::{
    Method, Request,
    header::{AUTHORIZATION, CONNECTION, CONTENT_TYPE, HOST, USER_AGENT},
};
use hyper_util::rt::TokioIo;
use rustls::{ClientConfig, pki_types::ServerName};
use tokio::{net::TcpStream, time::timeout};
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

const MAXIMUM_RESPONSE_BODY_BYTES: usize = 1024 * 1024;
const MAXIMUM_TIMEOUT: Duration = Duration::from_mins(5);

pub(crate) struct RustlsHttpClient {
    tls: Arc<ClientConfig>,
    connect_timeout: Duration,
    request_timeout: Duration,
}

impl RustlsHttpClient {
    pub(crate) fn new(
        tls: Arc<ClientConfig>,
        connect_timeout: Duration,
        request_timeout: Duration,
    ) -> Result<Self, RustlsHttpError> {
        if connect_timeout.is_zero()
            || request_timeout.is_zero()
            || connect_timeout > MAXIMUM_TIMEOUT
            || request_timeout > MAXIMUM_TIMEOUT
        {
            return Err(RustlsHttpError::InvalidRequest);
        }
        Ok(Self {
            tls,
            connect_timeout,
            request_timeout,
        })
    }

    pub(crate) async fn send(
        &self,
        request: RustlsHttpRequest<'_>,
    ) -> Result<RustlsHttpResponse, RustlsHttpError> {
        let endpoint = HttpsEndpoint::parse(request.url)?;
        let tcp = timeout(
            self.connect_timeout,
            TcpStream::connect((endpoint.host.as_str(), endpoint.port)),
        )
        .await
        .map_err(|_| RustlsHttpError::Unavailable)?
        .map_err(|_| RustlsHttpError::Unavailable)?;
        tcp.set_nodelay(true)
            .map_err(|_| RustlsHttpError::Unavailable)?;
        let server_name = ServerName::try_from(endpoint.host.clone())
            .map_err(|_| RustlsHttpError::InvalidRequest)?;
        let tls = timeout(
            self.connect_timeout,
            TlsConnector::from(self.tls.clone()).connect(server_name, tcp),
        )
        .await
        .map_err(|_| RustlsHttpError::Unavailable)?
        .map_err(|_| RustlsHttpError::Rejected)?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|_| RustlsHttpError::Rejected)?;
        let connection_task = tokio::spawn(connection);
        let exchange = async {
            let outbound = build_request(&request, &endpoint)?;
            let inbound = sender
                .send_request(outbound)
                .await
                .map_err(|_| RustlsHttpError::Unavailable)?;
            read_response(inbound).await
        };
        let result = timeout(self.request_timeout, exchange)
            .await
            .map_err(|_| RustlsHttpError::Unavailable)?;
        connection_task.abort();
        let _ = connection_task.await;
        result
    }
}

pub(crate) struct RustlsHttpRequest<'a> {
    pub(crate) method: Method,
    pub(crate) url: &'a str,
    pub(crate) body: &'a [u8],
    pub(crate) content_type: Option<&'a str>,
    pub(crate) bearer_token: Option<&'a [u8]>,
    pub(crate) user_agent: &'static str,
}

pub(crate) struct RustlsHttpResponse {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RustlsHttpError {
    InvalidRequest,
    Unavailable,
    Rejected,
}

fn build_request(
    source: &RustlsHttpRequest<'_>,
    endpoint: &HttpsEndpoint,
) -> Result<Request<Full<Bytes>>, RustlsHttpError> {
    let mut builder = Request::builder()
        .method(source.method.clone())
        .uri(&endpoint.path_and_query)
        .header(HOST, &endpoint.authority)
        .header(USER_AGENT, source.user_agent)
        .header(CONNECTION, "close");
    if let Some(content_type) = source.content_type {
        builder = builder.header(CONTENT_TYPE, content_type);
    }
    if let Some(token) = source.bearer_token {
        let mut header = Zeroizing::new(Vec::with_capacity(7 + token.len()));
        header.extend_from_slice(b"Bearer ");
        header.extend_from_slice(token);
        builder = builder.header(AUTHORIZATION, header.as_slice());
    }
    builder
        .body(Full::new(Bytes::copy_from_slice(source.body)))
        .map_err(|_| RustlsHttpError::InvalidRequest)
}

async fn read_response(
    mut response: hyper::Response<hyper::body::Incoming>,
) -> Result<RustlsHttpResponse, RustlsHttpError> {
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| {
            value
                .to_str()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
                .map_err(|_| RustlsHttpError::Rejected)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut body = BytesMut::new();
    while let Some(frame) = response.body_mut().frame().await {
        let frame = frame.map_err(|_| RustlsHttpError::Rejected)?;
        let data = frame.data_ref().ok_or(RustlsHttpError::Rejected)?;
        if body.len().saturating_add(data.len()) > MAXIMUM_RESPONSE_BODY_BYTES {
            return Err(RustlsHttpError::Rejected);
        }
        body.extend_from_slice(data);
    }
    Ok(RustlsHttpResponse {
        status,
        headers,
        body: body.to_vec(),
    })
}

pub(crate) struct HttpsEndpoint {
    authority: String,
    host: String,
    port: u16,
    path_and_query: String,
}

impl HttpsEndpoint {
    pub(crate) fn parse(url: &str) -> Result<Self, RustlsHttpError> {
        crate::wire::bounded_url(url).map_err(|_| RustlsHttpError::InvalidRequest)?;
        let remainder = url
            .strip_prefix("https://")
            .ok_or(RustlsHttpError::InvalidRequest)?;
        let authority_end = remainder.find(['/', '?']).unwrap_or(remainder.len());
        let authority = &remainder[..authority_end];
        let suffix = &remainder[authority_end..];
        let (host, port) = split_authority(authority)?;
        let path_and_query = if suffix.is_empty() {
            "/".to_owned()
        } else if suffix.starts_with('?') {
            format!("/{suffix}")
        } else {
            suffix.to_owned()
        };
        Ok(Self {
            authority: authority.to_owned(),
            host,
            port,
            path_and_query,
        })
    }
}

fn split_authority(authority: &str) -> Result<(String, u16), RustlsHttpError> {
    if let Some(bracketed) = authority.strip_prefix('[') {
        let (host, suffix) = bracketed
            .split_once(']')
            .ok_or(RustlsHttpError::InvalidRequest)?;
        let port = parse_port_suffix(suffix)?;
        return Ok((host.to_owned(), port));
    }
    if let Some((host, port)) = authority.rsplit_once(':') {
        return Ok((host.to_owned(), parse_port(port)?));
    }
    Ok((authority.to_owned(), 443))
}

fn parse_port_suffix(value: &str) -> Result<u16, RustlsHttpError> {
    if value.is_empty() {
        Ok(443)
    } else {
        value
            .strip_prefix(':')
            .ok_or(RustlsHttpError::InvalidRequest)
            .and_then(parse_port)
    }
}

fn parse_port(value: &str) -> Result<u16, RustlsHttpError> {
    value
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or(RustlsHttpError::InvalidRequest)
}
