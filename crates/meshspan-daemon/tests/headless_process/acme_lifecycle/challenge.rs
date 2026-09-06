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

#[derive(Clone, Copy)]
pub(super) enum ValidationTarget {
    Http01(SocketAddr),
    Dns01(SocketAddr),
}

impl ValidationTarget {
    pub const fn kind(self) -> &'static str {
        match self {
            Self::Http01(_) => "http-01",
            Self::Dns01(_) => "dns-01",
        }
    }

    pub async fn validate(self, key_authorisation: &str) -> Result<(), Failure> {
        match self {
            Self::Http01(address) => {
                let response = read_challenge(address).await?;
                super::require_status(&response, "200 OK", "CA HTTP-01 probe")
                    .map_err(|error| error.to_string())?;
                if super::response_body(&response).map_err(|error| error.to_string())?
                    != key_authorisation
                {
                    return Err("HTTP-01 key authorisation differs from the signing account".into());
                }
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
            Self::Http01(address) => {
                let response = read_challenge(address).await?;
                super::require_status(&response, "404 Not Found", "completed challenge cleanup")
                    .map_err(|error| error.to_string())?;
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

async fn read_challenge(address: SocketAddr) -> Result<String, Failure> {
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut stream = TcpStream::connect(address).await?;
        stream.write_all(format!("GET /.well-known/acme-challenge/{TOKEN} HTTP/1.1\r\nHost: {CERTIFICATE_NAME}\r\nConnection: close\r\n\r\n").as_bytes()).await?;
        let mut bytes = Vec::new();
        stream.take(8192).read_to_end(&mut bytes).await?;
        Ok(String::from_utf8(bytes)?)
    }).await?
}
