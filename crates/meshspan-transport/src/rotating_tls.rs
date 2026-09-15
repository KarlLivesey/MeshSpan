// SPDX-License-Identifier: GPL-2.0-only

//! Generation-fenced replacement of internal TLS configurations without rebinding sockets.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};

mod drivers;

use rustls::RootCertStore;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::ServerCertVerifier as _;
use rustls::pki_types::{ServerName, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::sign::CertifiedKey;
use sha2::{Digest as _, Sha256};

use crate::tls::{endpoint_with_runtime, prepare_client_config, prepare_server_config};
use crate::{NodeCredentials, TransportError, TransportLimits, certificate_fingerprint};

/// Immutable sockets, trust and node name for one rotatable private transport.
pub struct NodeTransportConfig {
    /// Listening private QUIC address; port zero requests an operating-system allocation.
    pub server_address: SocketAddr,
    /// Outbound socket address, normally using an ephemeral port.
    pub client_address: SocketAddr,
    /// Exact enrolled DNS identity which every local replacement must certify.
    pub certificate_name: String,
    /// Initial committed node-certificate generation, including after restart.
    pub certificate_generation: u64,
    /// Mesh roots accepted in both directions; changing mesh roots is a separate trust operation.
    pub peer_roots: RootCertStore,
    /// Per-connection resource bounds retained across identity replacement.
    pub limits: TransportLimits,
}

/// Public evidence of the local generation selected for fresh handshakes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstalledNodeCertificate {
    /// Exact committed certificate generation selected by the caller.
    pub generation: u64,
    /// SHA-256 of the selected leaf DER.
    pub certificate_fingerprint: [u8; 32],
    /// Length-bound, domain-separated digest of the complete selected chain.
    pub chain_digest: [u8; 32],
}

/// Shared client/server identity selection; existing connections retain their negotiated identity.
///
/// Rotation creates fresh TLS configurations and resumption caches. Replacing credentials does
/// not itself retire peer admission or acknowledge a metadata transaction; the caller owns those
/// staged authority transitions and must publish trust before selecting a new certificate.
#[derive(Clone)]
pub struct RotatingNodeTransport {
    endpoints: Arc<Mutex<Option<Endpoints>>>,
    drivers: Arc<drivers::Drivers>,
    config: Arc<NodeTransportConfig>,
    state: Arc<RwLock<SelectedIdentity>>,
}

/// Owns bound sockets and queued Quinn drivers until the containing network is fully prepared.
///
/// Dropping this preparation before activation releases all queued work and sockets synchronously.
#[must_use]
pub struct PreparedNodeTransport {
    transport: RotatingNodeTransport,
}

impl PreparedNodeTransport {
    /// Borrows the transport only for pre-start endpoint/worker assembly.
    /// Do not start connection or accept work until this preparation is activated.
    #[must_use]
    pub const fn transport(&self) -> &RotatingNodeTransport {
        &self.transport
    }

    /// Starts the prepared endpoint drivers after the containing owner's fallible setup succeeds.
    #[must_use]
    pub fn start(self) -> RotatingNodeTransport {
        self.transport.drivers.start();
        self.transport.clone()
    }
}

impl Drop for PreparedNodeTransport {
    fn drop(&mut self) {
        if self.transport.drivers.abort_preparation() {
            let endpoints = self
                .transport
                .endpoints
                .lock()
                .unwrap_or_else(|poisoned| {
                    self.transport.drivers.failed();
                    poisoned.into_inner()
                })
                .take();
            drop(endpoints);
        }
    }
}

struct Endpoints {
    server: quinn::Endpoint,
    client: quinn::Endpoint,
}

struct SelectedIdentity {
    public: InstalledNodeCertificate,
    key_fingerprint: [u8; 32],
    client: quinn::ClientConfig,
}

struct PreparedIdentity {
    selected: SelectedIdentity,
    server: quinn::ServerConfig,
}

impl RotatingNodeTransport {
    /// Validates the local chain/key and starts fixed client/server sockets.
    ///
    /// # Errors
    ///
    /// Rejects zero generations, invalid trust/name/lifetime, missing client/server uses,
    /// mismatched keys, resource limits or socket binding failures. No socket opens before the
    /// complete initial TLS material has been validated using the current TLS clock.
    pub fn new(
        config: NodeTransportConfig,
        credentials: NodeCredentials,
    ) -> Result<Self, TransportError> {
        Ok(Self::prepare(config, credentials)?.start())
    }

    /// Binds both sockets but queues their drivers until the enclosing owner activates them.
    ///
    /// # Errors
    /// Applies the same identity, configuration and socket validation as [`Self::new`].
    pub fn prepare(
        config: NodeTransportConfig,
        credentials: NodeCredentials,
    ) -> Result<PreparedNodeTransport, TransportError> {
        let prepared = prepare_identity(&config, config.certificate_generation, credentials)?;
        let drivers = drivers::Drivers::prepare();
        let endpoints = (|| {
            let server = endpoint_with_runtime(
                config.server_address,
                Some(prepared.server),
                drivers.clone(),
            )?;
            let client = endpoint_with_runtime(config.client_address, None, drivers.clone())?;
            Ok::<_, TransportError>(Endpoints { server, client })
        })();
        let endpoints = match endpoints {
            Ok(endpoints) => endpoints,
            Err(error) => {
                drivers.abort_preparation();
                return Err(error);
            }
        };
        Ok(PreparedNodeTransport {
            transport: Self {
                endpoints: Arc::new(Mutex::new(Some(endpoints))),
                drivers,
                config: Arc::new(config),
                state: Arc::new(RwLock::new(prepared.selected)),
            },
        })
    }

    /// Returns the stable listening endpoint for the owning network's accept loop.
    ///
    /// # Errors
    /// Rejects access after shutdown or endpoint-state poisoning. The caller must release the
    /// returned handle before awaiting transport shutdown.
    pub fn server_endpoint(&self) -> Result<quinn::Endpoint, TransportError> {
        let endpoints = self
            .endpoints
            .lock()
            .map_err(|_| TransportError::InvalidConfiguration)?;
        Ok(endpoints
            .as_ref()
            .ok_or(TransportError::InvalidConfiguration)?
            .server
            .clone())
    }

    /// Closes both directions for every clone during owner shutdown; the transport cannot restart.
    pub fn close(&self) {
        let endpoints = self.endpoints.lock().unwrap_or_else(|poisoned| {
            self.drivers.failed();
            poisoned.into_inner()
        });
        if let Some(endpoints) = endpoints.as_ref() {
            endpoints.server.close(0_u32.into(), b"node stopped");
            endpoints.client.close(0_u32.into(), b"node stopped");
        }
    }

    /// Releases the endpoints, cancels residual QUIC IO and joins every driver for all clones.
    ///
    /// Call after externally owned accept/connection/stream workers have finished and released
    /// their handles. Canceling one waiter preserves the shared drain for another waiter.
    ///
    /// # Errors
    /// Reports any driver failure after observing all remaining driver results.
    pub async fn shutdown(&self) -> Result<(), TransportError> {
        self.close();
        let endpoints = self
            .endpoints
            .lock()
            .unwrap_or_else(|poisoned| {
                self.drivers.failed();
                poisoned.into_inner()
            })
            .take();
        // Quinn's driver cannot finish while an Endpoint reference remains. Release our shared
        // references before waiting; callers must already have released their borrowed handles.
        drop(endpoints);
        self.drivers
            .shutdown()
            .await
            .map_err(|()| TransportError::Shutdown)
    }

    /// Reports the exact selection for new handshakes without exposing private key material.
    ///
    /// # Errors
    ///
    /// Fails closed after identity-state lock poisoning.
    pub fn current(&self) -> Result<InstalledNodeCertificate, TransportError> {
        Ok(self
            .state
            .read()
            .map_err(|_| TransportError::InvalidConfiguration)?
            .public)
    }

    /// Selects a newer valid chain for the same node-owned identity key, without socket rebinding.
    ///
    /// Exact replay is idempotent. Configuration preparation happens before taking the selection
    /// lock; a rejected candidate leaves both directions unchanged. Previously started handshakes
    /// and connections may finish using the old selection until separately retired by authority.
    ///
    /// # Errors
    ///
    /// Rejects stale/conflicting generations, changed identity keys, invalid local certificates,
    /// trust/name/lifetime failures or lock poisoning. No failed selection is acknowledged.
    pub fn install(
        &self,
        generation: u64,
        credentials: NodeCredentials,
    ) -> Result<InstalledNodeCertificate, TransportError> {
        let prepared = prepare_identity(&self.config, generation, credentials)?;
        let mut selected = self
            .state
            .write()
            .map_err(|_| TransportError::InvalidConfiguration)?;
        if prepared.selected.key_fingerprint != selected.key_fingerprint {
            return Err(TransportError::InvalidConfiguration);
        }
        if prepared.selected.public == selected.public {
            return Ok(selected.public);
        }
        if generation <= selected.public.generation {
            return Err(TransportError::InvalidConfiguration);
        }
        // Lock order is selection, then endpoint. No lock is held across async IO. New outbound
        // setup cannot select the old configuration after the server selection has changed.
        let endpoints = self
            .endpoints
            .lock()
            .map_err(|_| TransportError::InvalidConfiguration)?;
        endpoints
            .as_ref()
            .ok_or(TransportError::InvalidConfiguration)?
            .server
            .set_server_config(Some(prepared.server));
        *selected = prepared.selected;
        Ok(selected.public)
    }

    /// Starts a fresh peer handshake with the currently selected local credential generation.
    ///
    /// # Errors
    ///
    /// Reports invalid peer names, configuration/state failures or authenticated handshake errors.
    pub async fn connect(
        &self,
        address: SocketAddr,
        name: &str,
    ) -> Result<quinn::Connection, TransportError> {
        if name.is_empty() || name.len() > 253 {
            return Err(TransportError::InvalidConfiguration);
        }
        let connecting = {
            let selected = self
                .state
                .read()
                .map_err(|_| TransportError::InvalidConfiguration)?;
            let endpoints = self
                .endpoints
                .lock()
                .map_err(|_| TransportError::InvalidConfiguration)?;
            endpoints
                .as_ref()
                .ok_or(TransportError::InvalidConfiguration)?
                .client
                .connect_with(selected.client.clone(), address, name)?
        };
        Ok(connecting.await?)
    }
}

fn prepare_identity(
    config: &NodeTransportConfig,
    generation: u64,
    credentials: NodeCredentials,
) -> Result<PreparedIdentity, TransportError> {
    if generation == 0 || config.certificate_name.is_empty() || config.certificate_name.len() > 253
    {
        return Err(TransportError::InvalidConfiguration);
    }
    let key_fingerprint = validate_credentials(config, &credentials)?;
    let leaf = credentials
        .certificate_chain
        .first()
        .ok_or(TransportError::InvalidConfiguration)?;
    let public = InstalledNodeCertificate {
        generation,
        certificate_fingerprint: certificate_fingerprint(leaf),
        chain_digest: chain_digest(&credentials)?,
    };
    let server_credentials = NodeCredentials::new(
        credentials.certificate_chain.clone(),
        credentials.private_key.clone_key(),
    )?;
    Ok(PreparedIdentity {
        server: prepare_server_config(
            server_credentials,
            config.peer_roots.clone(),
            config.limits,
        )?,
        selected: SelectedIdentity {
            public,
            key_fingerprint,
            client: prepare_client_config(credentials, config.peer_roots.clone(), config.limits)?,
        },
    })
}

fn validate_credentials(
    config: &NodeTransportConfig,
    credentials: &NodeCredentials,
) -> Result<[u8; 32], TransportError> {
    let provider = Arc::new(meshspan_rustls_provider::provider());
    let roots = Arc::new(config.peer_roots.clone());
    let key = CertifiedKey::from_der(
        credentials.certificate_chain.clone(),
        credentials.private_key.clone_key(),
        &provider,
    )
    .map_err(|_| TransportError::InvalidConfiguration)?;
    key.keys_match()
        .map_err(|_| TransportError::InvalidConfiguration)?;
    let key_fingerprint = Sha256::digest(
        key.key
            .public_key()
            .ok_or(TransportError::InvalidConfiguration)?,
    )
    .into();
    let (leaf, intermediates) = credentials
        .certificate_chain
        .split_first()
        .ok_or(TransportError::InvalidConfiguration)?;
    let name = ServerName::try_from(config.certificate_name.as_str())
        .map_err(|_| TransportError::InvalidConfiguration)?;
    let now = UnixTime::now();
    WebPkiServerVerifier::builder_with_provider(Arc::clone(&roots), Arc::clone(&provider))
        .build()
        .map_err(|_| TransportError::InvalidConfiguration)?
        .verify_server_cert(leaf, intermediates, &name, &[], now)
        .map_err(|_| TransportError::InvalidConfiguration)?;
    WebPkiClientVerifier::builder_with_provider(roots, provider)
        .build()
        .map_err(|_| TransportError::InvalidConfiguration)?
        .verify_client_cert(leaf, intermediates, now)
        .map_err(|_| TransportError::InvalidConfiguration)?;
    Ok(key_fingerprint)
}

fn chain_digest(credentials: &NodeCredentials) -> Result<[u8; 32], TransportError> {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.private-tls.chain.v1\0");
    for certificate in &credentials.certificate_chain {
        let length =
            u64::try_from(certificate.len()).map_err(|_| TransportError::InvalidConfiguration)?;
        digest.update(length.to_le_bytes());
        digest.update(certificate.as_ref());
    }
    Ok(digest.finalize().into())
}

#[cfg(test)]
mod tests;
