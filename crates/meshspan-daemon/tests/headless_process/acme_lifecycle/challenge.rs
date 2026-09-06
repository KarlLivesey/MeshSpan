// SPDX-License-Identifier: GPL-2.0-only

//! CA-side challenge validation through actual HTTP or authoritative DNS sockets.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use meshspan_dns::{AuthoritativeTxtProbe, DnsName, DnsQuery, TxtValue};
use sha2::{Digest as _, Sha256};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
};

use super::{CERTIFICATE_NAME, Duration, Error, SocketAddr};

type Failure = Box<dyn Error + Send + Sync>;
pub(super) const TOKEN: &str = "meshspan_lifecycle_challenge_token";
pub(super) const REPLACEMENT_TOKEN: &str = "meshspan_replacement_challenge_token";

#[derive(Clone, Copy)]
pub(super) enum ValidationTarget {
    Http01(SocketAddr),
    Http01Gateways([SocketAddr; 2]),
    Dns01(SocketAddr),
}

impl ValidationTarget {
    pub const fn kind(self) -> &'static str {
        match self {
            Self::Http01(_) | Self::Http01Gateways(_) => "http-01",
            Self::Dns01(_) => "dns-01",
        }
    }

    pub async fn validate(self, key_authorisation: &str) -> Result<(), Failure> {
        match self {
            Self::Http01Gateways(addresses) => {
                for address in addresses {
                    validate_http(address, key_authorisation).await?;
                }
            }
            Self::Http01(address) => {
                validate_http(address, key_authorisation).await?;
            }
            Self::Dns01(address) => {
                if !contains_dns_proof(address, key_authorisation).await? {
                    return Err("DNS-01 TXT value differs from the signing account".into());
                }
            }
        }
        Ok(())
    }

    pub async fn assert_removed(self, key_authorisation: &str) -> Result<(), Failure> {
        match self {
            Self::Http01Gateways(addresses) => {
                for address in addresses {
                    assert_http_removed(address, key_authorisation).await?;
                }
            }
            Self::Http01(address) => {
                assert_http_removed(address, key_authorisation).await?;
            }
            Self::Dns01(address) => {
                if contains_dns_proof(address, key_authorisation).await? {
                    return Err("completed DNS-01 TXT record remains published".into());
                }
            }
        }
        Ok(())
    }
}

async fn validate_http(address: SocketAddr, key_authorisation: &str) -> Result<(), Failure> {
    let response = read_challenge(address, token(key_authorisation)?).await?;
    super::require_status(&response, "200 OK", "CA HTTP-01 probe")
        .map_err(|error| error.to_string())?;
    if super::response_body(&response).map_err(|error| error.to_string())? != key_authorisation {
        return Err("HTTP-01 key authorisation differs from the signing account".into());
    }
    Ok(())
}

async fn assert_http_removed(address: SocketAddr, key_authorisation: &str) -> Result<(), Failure> {
    let response = read_challenge(address, token(key_authorisation)?).await?;
    super::require_status(&response, "404 Not Found", "completed challenge cleanup")
        .map_err(|error| format!("{address}: {error}"))?;
    Ok(())
}

/// An installed certificate is durable local state, not proof that restarted peer routing is
/// ready. Permit only temporary unavailability: serving the deleted token is always a failure.
pub(super) async fn wait_for_removed_after_restart(address: SocketAddr) -> Result<(), Failure> {
    let deadline = super::Instant::now() + super::WAIT_LIMIT;
    loop {
        let response = read_challenge(address, TOKEN).await?;
        if response.starts_with("HTTP/1.1 404 Not Found\r\n") {
            return Ok(());
        }
        super::require_status(
            &response,
            "503 Service Unavailable",
            "restarted challenge readiness",
        )
        .map_err(|error| error.to_string())?;
        if super::Instant::now() >= deadline {
            return Err(format!("{address}: HTTP-01 gateway did not regain private lookup readiness after peer restart").into());
        }
        super::sleep(super::RETRY_INTERVAL).await;
    }
}

async fn contains_dns_proof(address: SocketAddr, key_authorisation: &str) -> Result<bool, Failure> {
    // This is independently derived from the CA's authenticated JWK, not read from daemon state.
    let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(key_authorisation.as_bytes()));
    let query = DnsQuery::txt(
        73,
        DnsName::new(&format!("_acme-challenge.{CERTIFICATE_NAME}"))?,
    )?;
    Ok(AuthoritativeTxtProbe::new(address, Duration::from_secs(2))?
        .contains_txt(&query, &TxtValue::new(expected.as_bytes())?)
        .await?)
}

fn token(key_authorisation: &str) -> Result<&str, Failure> {
    key_authorisation
        .split_once('.')
        .map(|(token, _)| token)
        .ok_or_else(|| "missing challenge token".into())
}

async fn read_challenge(address: SocketAddr, token: &str) -> Result<String, Failure> {
    // The server's bounded distributed lookup can legitimately consume two seconds before
    // returning 503. The client must leave time for that response instead of racing its timer.
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut stream = TcpStream::connect(address).await?;
        stream.write_all(format!("GET /.well-known/acme-challenge/{token} HTTP/1.1\r\nHost: {CERTIFICATE_NAME}\r\nConnection: close\r\n\r\n").as_bytes()).await?;
        let mut bytes = Vec::new();
        stream.take(8192).read_to_end(&mut bytes).await?;
        Ok(String::from_utf8(bytes)?)
    }).await?
}
