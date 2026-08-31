// SPDX-License-Identifier: GPL-2.0-only

use std::fmt;
use std::sync::Arc;

use quinn_proto::crypto::{
    ClientConfig as QuinnClientConfig, ServerConfig as QuinnServerConfig, Session,
    UnsupportedVersion,
};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectError, ConnectionId};
use rustls::CipherSuite;
use rustls::quic::Suite;

use crate::{retry, session, version};

/// A provider/configuration does not supply QUIC's mandatory initial cipher.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NoInitialCipherSuite;

impl fmt::Display for NoInitialCipherSuite {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TLS_AES_128_GCM_SHA256 with QUIC support is required")
    }
}

impl std::error::Error for NoInitialCipherSuite {}

/// Provider-neutral QUIC client configuration backed by Rustls.
pub struct QuicClientConfig {
    inner: Arc<rustls::ClientConfig>,
    initial: Suite,
}

impl TryFrom<rustls::ClientConfig> for QuicClientConfig {
    type Error = NoInitialCipherSuite;

    fn try_from(config: rustls::ClientConfig) -> Result<Self, Self::Error> {
        Arc::new(config).try_into()
    }
}

impl TryFrom<Arc<rustls::ClientConfig>> for QuicClientConfig {
    type Error = NoInitialCipherSuite;

    fn try_from(config: Arc<rustls::ClientConfig>) -> Result<Self, Self::Error> {
        let initial = initial_suite(config.crypto_provider())?;
        Ok(Self {
            inner: config,
            initial,
        })
    }
}

impl QuinnClientConfig for QuicClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        parameters: &TransportParameters,
    ) -> Result<Box<dyn Session>, ConnectError> {
        let version = version::interpret(version)?;
        session::client(
            self.inner.clone(),
            self.initial,
            version,
            server_name,
            parameters,
        )
    }
}

/// Provider-neutral QUIC server configuration backed by Rustls.
pub struct QuicServerConfig {
    inner: Arc<rustls::ServerConfig>,
    initial: Suite,
}

impl TryFrom<rustls::ServerConfig> for QuicServerConfig {
    type Error = NoInitialCipherSuite;

    fn try_from(config: rustls::ServerConfig) -> Result<Self, Self::Error> {
        Arc::new(config).try_into()
    }
}

impl TryFrom<Arc<rustls::ServerConfig>> for QuicServerConfig {
    type Error = NoInitialCipherSuite;

    fn try_from(config: Arc<rustls::ServerConfig>) -> Result<Self, Self::Error> {
        let initial = initial_suite(config.crypto_provider())?;
        Ok(Self {
            inner: config,
            initial,
        })
    }
}

impl QuinnServerConfig for QuicServerConfig {
    fn initial_keys(
        &self,
        version: u32,
        destination: &ConnectionId,
    ) -> Result<quinn_proto::crypto::Keys, UnsupportedVersion> {
        let version = version::interpret(version)?;
        Ok(session::initial_keys(
            version,
            *destination,
            quinn_proto::Side::Server,
            &self.initial,
        ))
    }

    fn retry_tag(
        &self,
        version: u32,
        original_destination: &ConnectionId,
        packet: &[u8],
    ) -> [u8; 16] {
        version::interpret(version).map_or([0; 16], |version| {
            retry::tag(version, original_destination, packet)
        })
    }

    fn start_session(
        self: Arc<Self>,
        version: u32,
        parameters: &TransportParameters,
    ) -> Box<dyn Session> {
        let Ok(version) = version::interpret(version) else {
            return session::rejected(self.initial, rustls::quic::Version::V1);
        };
        session::server(self.inner.clone(), self.initial, version, parameters)
    }
}

fn initial_suite(
    provider: &Arc<rustls::crypto::CryptoProvider>,
) -> Result<Suite, NoInitialCipherSuite> {
    provider
        .cipher_suites
        .iter()
        .find_map(|suite| match (suite.suite(), suite.tls13()) {
            (CipherSuite::TLS13_AES_128_GCM_SHA256, Some(tls13)) => tls13.quic_suite(),
            _ => None,
        })
        .ok_or(NoInitialCipherSuite)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rustls::crypto::CryptoProvider;

    use super::initial_suite;

    #[test]
    fn provider_without_initial_suite_is_rejected() {
        let provider = Arc::new(CryptoProvider {
            cipher_suites: Vec::new(),
            kx_groups: Vec::new(),
            signature_verification_algorithms: rustls::crypto::WebPkiSupportedAlgorithms {
                all: &[],
                mapping: &[],
            },
            secure_random: &RejectRandom,
            key_provider: &RejectKeys,
        });
        assert!(initial_suite(&provider).is_err());
    }

    #[derive(Debug)]
    struct RejectRandom;

    impl rustls::crypto::SecureRandom for RejectRandom {
        fn fill(&self, _output: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
            Err(rustls::crypto::GetRandomFailed)
        }
    }

    #[derive(Debug)]
    struct RejectKeys;

    impl rustls::crypto::KeyProvider for RejectKeys {
        fn load_private_key(
            &self,
            _key: rustls::pki_types::PrivateKeyDer<'static>,
        ) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
            Err(rustls::Error::General("rejected test key".into()))
        }
    }
}
