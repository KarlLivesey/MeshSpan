// SPDX-License-Identifier: GPL-2.0-only

//! System-resolver discovery followed by direct proof against every authoritative DNS address.

use std::{
    collections::BTreeSet,
    io,
    net::{IpAddr, SocketAddr},
    path::Path,
    time::Duration,
};

use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket, lookup_host},
    task::JoinSet,
    time::timeout,
};

use crate::{
    AuthoritativeDnsError, AuthoritativeTxtProbe, DnsName, DnsNameServerQuery, DnsQuery,
    DnsWireError, TxtValue,
};

const DNS_PORT: u16 = 53;
const MAXIMUM_DNS_MESSAGE_BYTES: usize = 65_535;
const MAXIMUM_RESOLV_CONF_BYTES: u64 = 64 * 1_024;
const MAXIMUM_SYSTEM_RESOLVERS: usize = 16;
const MAXIMUM_AUTHORITIES: usize = 64;
const MAXIMUM_TIMEOUT: Duration = Duration::from_secs(60);

/// Discovers a zone through configured system resolvers, then queries every authority directly.
#[derive(Clone, Debug)]
pub struct AuthoritativeTxtResolver {
    recursive_resolvers: Vec<SocketAddr>,
    timeout: Duration,
}

impl AuthoritativeTxtResolver {
    /// Loads bounded recursive resolver addresses from the host's resolver configuration.
    ///
    /// # Errors
    ///
    /// Rejects missing, oversized or malformed configuration and empty resolver sets.
    pub fn from_system(timeout: Duration) -> Result<Self, AuthoritativeResolverError> {
        Self::from_resolv_conf(Path::new("/etc/resolv.conf"), timeout)
    }

    /// Loads resolver addresses from an explicit resolv.conf path.
    ///
    /// This is public so appliance tests can exercise hostile and generated configurations
    /// without changing the host resolver.
    ///
    /// # Errors
    ///
    /// Rejects missing, oversized or malformed configuration and empty resolver sets.
    pub fn from_resolv_conf(
        file_path: &Path,
        timeout: Duration,
    ) -> Result<Self, AuthoritativeResolverError> {
        validate_timeout(timeout)?;
        let metadata = std::fs::metadata(file_path)?;
        if metadata.len() > MAXIMUM_RESOLV_CONF_BYTES {
            return Err(AuthoritativeResolverError::InvalidConfiguration);
        }
        let contents = std::fs::read_to_string(file_path)?;
        let recursive_resolvers = parse_resolvers(&contents)?;
        Ok(Self {
            recursive_resolvers,
            timeout,
        })
    }

    /// Creates a resolver from already validated recursive endpoints.
    ///
    /// # Errors
    ///
    /// Rejects empty, duplicate, excessive or non-DNS endpoints and invalid timeouts.
    pub fn new(
        recursive_resolvers: Vec<SocketAddr>,
        timeout: Duration,
    ) -> Result<Self, AuthoritativeResolverError> {
        validate_timeout(timeout)?;
        validate_resolvers(&recursive_resolvers)?;
        Ok(Self {
            recursive_resolvers,
            timeout,
        })
    }

    /// Proves that every currently published authoritative server address returns an exact TXT.
    ///
    /// # Errors
    ///
    /// Fails closed if authority discovery, address resolution, direct transport or DNS response
    /// validation is inconclusive. A conclusive absence from any authority returns `false`.
    pub async fn contains_txt(
        &self,
        name: &str,
        value: &[u8],
    ) -> Result<bool, AuthoritativeResolverError> {
        let name = DnsName::new(name)?;
        let expected = TxtValue::new(value)?;
        let authorities = self.discover_authorities(&name).await?;
        let addresses = self.resolve_authorities(authorities).await?;
        let mut probes = JoinSet::new();
        for address in addresses {
            let query = DnsQuery::txt(random_query_id()?, name.clone())?;
            let expected = expected.clone();
            let probe = AuthoritativeTxtProbe::new(address, self.timeout)?;
            probes.spawn(async move { probe.contains_txt(&query, &expected).await });
        }
        let mut visible = true;
        while let Some(result) = probes.join_next().await {
            visible &= result.map_err(|_| AuthoritativeResolverError::Unavailable)??;
        }
        Ok(visible)
    }

    async fn discover_authorities(
        &self,
        name: &DnsName,
    ) -> Result<Vec<DnsName>, AuthoritativeResolverError> {
        let labels = name.as_str().split('.').collect::<Vec<_>>();
        for offset in 0..labels.len() {
            let candidate = DnsName::new(&labels[offset..].join("."))?;
            let query = DnsNameServerQuery::new(random_query_id()?, candidate)?;
            for resolver in &self.recursive_resolvers {
                match self.query_name_servers(*resolver, &query).await {
                    Ok(authorities) if !authorities.is_empty() => return Ok(authorities),
                    Ok(_) | Err(AuthoritativeResolverError::Unavailable) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        Err(AuthoritativeResolverError::Unavailable)
    }

    async fn query_name_servers(
        &self,
        resolver: SocketAddr,
        query: &DnsNameServerQuery,
    ) -> Result<Vec<DnsName>, AuthoritativeResolverError> {
        let request = query.encode()?;
        let response = exchange_udp(resolver, self.timeout, &request).await?;
        match query.response_name_servers(&response) {
            Ok(names) => Ok(names),
            Err(DnsWireError::Truncated) => {
                let response = exchange_tcp(resolver, self.timeout, &request).await?;
                query.response_name_servers(&response).map_err(Into::into)
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn resolve_authorities(
        &self,
        authorities: Vec<DnsName>,
    ) -> Result<Vec<SocketAddr>, AuthoritativeResolverError> {
        if authorities.len() > MAXIMUM_AUTHORITIES {
            return Err(AuthoritativeResolverError::InvalidConfiguration);
        }
        let mut lookups = JoinSet::new();
        for authority in authorities {
            let timeout_duration = self.timeout;
            lookups.spawn(async move {
                timeout(
                    timeout_duration,
                    lookup_host((authority.as_str().to_owned(), DNS_PORT)),
                )
                .await
            });
        }
        let mut addresses = BTreeSet::new();
        while let Some(result) = lookups.join_next().await {
            let resolved = result
                .map_err(|_| AuthoritativeResolverError::Unavailable)?
                .map_err(|_| AuthoritativeResolverError::Timeout)??;
            for address in resolved.take(MAXIMUM_AUTHORITIES + 1) {
                addresses.insert(address);
                if addresses.len() > MAXIMUM_AUTHORITIES {
                    return Err(AuthoritativeResolverError::InvalidConfiguration);
                }
            }
        }
        if addresses.is_empty() {
            return Err(AuthoritativeResolverError::Unavailable);
        }
        Ok(addresses.into_iter().collect())
    }
}

fn parse_resolvers(contents: &str) -> Result<Vec<SocketAddr>, AuthoritativeResolverError> {
    let mut resolvers = Vec::new();
    for line in contents.lines() {
        let before_comment = line.split(['#', ';']).next().unwrap_or_default();
        let mut fields = before_comment.split_ascii_whitespace();
        if fields.next() != Some("nameserver") {
            continue;
        }
        let address = fields
            .next()
            .ok_or(AuthoritativeResolverError::InvalidConfiguration)?
            .parse::<IpAddr>()?;
        if fields.next().is_some() {
            return Err(AuthoritativeResolverError::InvalidConfiguration);
        }
        resolvers.push(SocketAddr::new(address, DNS_PORT));
    }
    validate_resolvers(&resolvers)?;
    Ok(resolvers)
}

fn validate_resolvers(resolvers: &[SocketAddr]) -> Result<(), AuthoritativeResolverError> {
    let unique = resolvers.iter().copied().collect::<BTreeSet<_>>();
    if resolvers.is_empty()
        || resolvers.len() > MAXIMUM_SYSTEM_RESOLVERS
        || unique.len() != resolvers.len()
        || resolvers.iter().any(|resolver| resolver.port() == 0)
    {
        Err(AuthoritativeResolverError::InvalidConfiguration)
    } else {
        Ok(())
    }
}

fn validate_timeout(timeout: Duration) -> Result<(), AuthoritativeResolverError> {
    if timeout.is_zero() || timeout > MAXIMUM_TIMEOUT {
        Err(AuthoritativeResolverError::InvalidConfiguration)
    } else {
        Ok(())
    }
}

fn random_query_id() -> Result<u16, AuthoritativeResolverError> {
    let mut bytes = [0_u8; 2];
    getrandom::fill(&mut bytes).map_err(|_| AuthoritativeResolverError::Entropy)?;
    let id = u16::from_be_bytes(bytes);
    Ok(id.max(1))
}

async fn exchange_udp(
    server: SocketAddr,
    timeout_duration: Duration,
    request: &[u8],
) -> Result<Vec<u8>, AuthoritativeResolverError> {
    let operation = async {
        let bind_address = if server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind_address).await?;
        socket.connect(server).await?;
        socket.send(request).await?;
        let mut response = vec![0_u8; MAXIMUM_DNS_MESSAGE_BYTES];
        let length = socket.recv(&mut response).await?;
        response.truncate(length);
        Ok::<_, io::Error>(response)
    };
    timeout(timeout_duration, operation)
        .await
        .map_err(|_| AuthoritativeResolverError::Timeout)?
        .map_err(Into::into)
}

async fn exchange_tcp(
    server: SocketAddr,
    timeout_duration: Duration,
    request: &[u8],
) -> Result<Vec<u8>, AuthoritativeResolverError> {
    let request_length = u16::try_from(request.len())
        .map_err(|_| AuthoritativeResolverError::InvalidConfiguration)?;
    let operation = async {
        let mut stream = TcpStream::connect(server).await?;
        stream.set_nodelay(true)?;
        stream.write_all(&request_length.to_be_bytes()).await?;
        stream.write_all(request).await?;
        let response_length = stream.read_u16().await?;
        let mut response = vec![0_u8; usize::from(response_length)];
        stream.read_exact(&mut response).await?;
        Ok::<_, io::Error>(response)
    };
    timeout(timeout_duration, operation)
        .await
        .map_err(|_| AuthoritativeResolverError::Timeout)?
        .map_err(Into::into)
}

/// Closed authority-discovery failure without retaining hostile DNS or host configuration bytes.
#[derive(Debug, Error)]
pub enum AuthoritativeResolverError {
    /// Resolver list, bounds or timeout are invalid.
    #[error("authoritative DNS resolver configuration is invalid")]
    InvalidConfiguration,
    /// Secure DNS transaction entropy is unavailable.
    #[error("authoritative DNS resolver entropy is unavailable")]
    Entropy,
    /// A bounded resolver operation timed out.
    #[error("authoritative DNS resolver timed out")]
    Timeout,
    /// Authority discovery or address resolution was inconclusive.
    #[error("authoritative DNS resolver is unavailable")]
    Unavailable,
    /// Host configuration or DNS transport failed.
    #[error("authoritative DNS resolver transport failed")]
    Io(#[from] io::Error),
    /// DNS wire encoding or validation failed.
    #[error("authoritative DNS resolver message failed validation")]
    Wire(#[from] DnsWireError),
    /// Direct authoritative DNS proof failed.
    #[error("authoritative DNS proof failed")]
    Authoritative(#[from] AuthoritativeDnsError),
    /// A configured resolver address was malformed.
    #[error("authoritative DNS resolver address is invalid")]
    Address(#[from] std::net::AddrParseError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolver_configuration_accepts_ipv4_ipv6_and_comments()
    -> Result<(), Box<dyn std::error::Error>> {
        let resolvers = parse_resolvers(
            "# generated\nnameserver 192.0.2.1\nnameserver 2001:db8::53 ; local\nsearch test\n",
        )?;
        assert_eq!(
            resolvers,
            vec![
                "192.0.2.1:53".parse::<SocketAddr>()?,
                "[2001:db8::53]:53".parse::<SocketAddr>()?,
            ]
        );
        Ok(())
    }

    #[test]
    fn resolver_configuration_rejects_duplicates_and_extra_fields() {
        assert!(matches!(
            parse_resolvers("nameserver 192.0.2.1\nnameserver 192.0.2.1\n"),
            Err(AuthoritativeResolverError::InvalidConfiguration)
        ));
        assert!(matches!(
            parse_resolvers("nameserver 192.0.2.1 unexpected\n"),
            Err(AuthoritativeResolverError::InvalidConfiguration)
        ));
    }
}
