// SPDX-License-Identifier: GPL-2.0-only

//! Owned native federation sessions composed from committed pairing and node-private keys.

#[path = "federation_allocation_dispatch.rs"]
mod allocations;
#[path = "federation_application_dispatch.rs"]
mod applications;
#[path = "federation_session_authority.rs"]
mod authority;
#[path = "federation_backup_dispatch.rs"]
mod backup;
#[path = "federation_backup_consumer.rs"]
mod backup_consumer;
#[path = "federation_backup_owner.rs"]
mod backup_owner;
#[path = "federation_backup_providers.rs"]
mod backup_providers;
#[path = "federation_backup_selection.rs"]
mod backup_selection;
#[path = "federation_session_lifecycle.rs"]
mod lifecycle;

use crate::local_federation_identity::LocalFederationIdentity;
use authority::{PairedRoute, SessionAuthority};
pub(crate) use backup_consumer::FederationBackupConsumer;
pub(crate) use backup_owner::FederationBackupOwner;
pub(crate) use backup_providers::{FederationBackupProviderConfiguration, FederationBackupTargets};
use meshspan_cluster::{FederationAcceptRequest, FederationDialRequest, FederationSessionReplay};
use meshspan_domain::{DurationMicros, FederationRelationshipId, NodeId, RandomSource};
use meshspan_metadata::AuthoritativeRepository;
use meshspan_transport::{
    FederationEndpoint, FederationHelloConfig, FederationHelloContext, FederationNegotiationConfig,
    FederationPeerRegistry, FederationReplayGuard, FederationWelcomeNonces, NodeCredentials,
    TransportLimits,
};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);
const CERTIFICATE_NAME: &str = "meshspan-federation.local";
// This runtime offers exactly one version. Application admission uses the same constant;
// a peer signature cannot opt an established session into a different minor contract.
const SESSION_VERSION: meshspan_protocol::v1::ProtocolVersion =
    meshspan_protocol::v1::ProtocolVersion { major: 1, minor: 0 };

pub(crate) struct FederationSessionConfiguration {
    pub(crate) reader: AuthoritativeRepository,
    pub(crate) database_path: std::path::PathBuf,
    pub(crate) identity: LocalFederationIdentity,
    pub(crate) node: NodeId,
    pub(crate) backups: FederationBackupProviderConfiguration,
    pub(crate) private_network: Arc<crate::private_consensus_runtime::PrivateConsensusRuntime>,
}

impl FederationSessionConfiguration {
    pub(crate) fn bind(
        self,
        address: SocketAddr,
    ) -> Result<FederationSessions, FederationSessionRuntimeError> {
        let wire = meshspan_protocol::WireLimits::new(64 * 1024, 64 * 1024, 256, 4096)
            .map_err(meshspan_transport::TransportError::from)?;
        let limits = TransportLimits::new(wire, 128, 64 * 1024, 4 * 1024 * 1024)?;
        FederationSessions::new(self, address, limits)
    }
}

pub(crate) struct FederationSessions {
    endpoint: Arc<FederationEndpoint>,
    identity: Arc<LocalFederationIdentity>,
    authority: Arc<SessionAuthority>,
    replay: FederationSessionReplay,
    limits: TransportLimits,
    live: Arc<Mutex<BTreeMap<FederationRelationshipId, LiveConnection>>>,
    roots: Arc<Mutex<Vec<[u8; 32]>>>,
    application_readers: applications::AuthorityReaders,
    bulk_readers: applications::AuthorityReaders,
    backup_providers: Arc<backup_providers::FederationBackupProviders>,
    backup_admission: Arc<tokio::sync::Semaphore>,
    private_network: Arc<crate::private_consensus_runtime::PrivateConsensusRuntime>,
    node: NodeId,
    // Permits are short-lived admission, not durable receipts. Restart retires this
    // process key; a consumer obtains a fresh permit before retrying the exact operation.
    backup_permit_key: meshspan_contracts::FederatedStoragePermitMacKey,
}

struct LiveConnection {
    connection: quinn::Connection,
    route: PairedRoute,
    limits: TransportLimits,
}

/// The connection and its agreed application bounds travel together to every worker.
#[derive(Clone)]
pub(crate) struct NativeFederationSession {
    pub(crate) relationship: FederationRelationshipId,
    pub(crate) connection: quinn::Connection,
    pub(crate) limits: TransportLimits,
}

impl FederationSessions {
    pub(crate) fn new(
        configuration: FederationSessionConfiguration,
        bind: SocketAddr,
        limits: TransportLimits,
    ) -> Result<Self, FederationSessionRuntimeError> {
        let FederationSessionConfiguration {
            reader,
            identity,
            node,
            database_path,
            backups,
            private_network,
        } = configuration;
        let credentials = NodeCredentials::new(
            identity
                .certificate
                .certificate_chain()
                .iter()
                .cloned()
                .map(CertificateDer::from)
                .collect(),
            PrivatePkcs8KeyDer::from(identity.certificate.private_key_pkcs8().to_vec()).into(),
        )?;
        Ok(Self {
            endpoint: Arc::new(FederationEndpoint::bind(bind, credentials, limits)?),
            identity: Arc::new(identity),
            authority: Arc::new(SessionAuthority::new(reader, node)),
            replay: FederationSessionReplay::new(FederationReplayGuard::new(
                16_384,
                // Application backup attempts already carry deadlines up to the capability
                // ceiling. A shorter replay window would reject valid authenticated work.
                DurationMicros::new(
                    meshspan_contracts::MAXIMUM_FEDERATED_BACKUP_PERMIT_LIFETIME_MICROS
                        .unsigned_abs(),
                ),
            )?),
            limits,
            live: Arc::new(Mutex::new(BTreeMap::new())),
            roots: Arc::new(Mutex::new(Vec::new())),
            application_readers: applications::AuthorityReaders::new(database_path.clone()),
            bulk_readers: applications::AuthorityReaders::new(database_path),
            backup_providers: Arc::new(backup_providers::FederationBackupProviders::new(backups)),
            private_network,
            backup_admission: Arc::new(tokio::sync::Semaphore::new(
                std::thread::available_parallelism().map_or(4, std::num::NonZeroUsize::get),
            )),
            node,
            backup_permit_key: meshspan_contracts::FederatedStoragePermitMacKey::from_bytes(
                random()?,
            )
            .map_err(|_| FederationSessionRuntimeError::Unavailable)?,
        })
    }

    pub(crate) fn local_addr(&self) -> Result<SocketAddr, FederationSessionRuntimeError> {
        self.endpoint.local_addr().map_err(Into::into)
    }

    /// Reloads trust, closes obsolete sessions and returns relationships this mesh should dial.
    /// The lower mesh ID owns dialling; all SQL/TLS configuration work is off-executor.
    pub(crate) async fn refresh_trust(
        &self,
    ) -> Result<Vec<FederationRelationshipId>, FederationSessionRuntimeError> {
        let authority = Arc::clone(&self.authority);
        let endpoint = Arc::clone(&self.endpoint);
        let live = Arc::clone(&self.live);
        let installed = Arc::clone(&self.roots);
        let backups = Arc::clone(&self.backup_providers);
        tokio::task::spawn_blocking(move || {
            backups.retire_unavailable_targets()?;
            let now = crate::api_http::current_time()
                .ok_or(FederationSessionRuntimeError::Unavailable)?;
            let routes = authority.routes(now)?;
            let fingerprints = routes
                .values()
                .map(|route| route.authority.peer.certificate_fingerprint)
                .collect::<Vec<_>>();
            let mut installed = installed
                .lock()
                .map_err(|_| FederationSessionRuntimeError::Unavailable)?;
            if *installed != fingerprints {
                let mut roots = RootCertStore::empty();
                for route in routes.values() {
                    roots
                        .add(CertificateDer::from(route.certificate.clone()))
                        .map_err(|_| FederationSessionRuntimeError::Unavailable)?;
                }
                endpoint.replace_trust(roots)?;
                *installed = fingerprints;
            }
            let mut live = live
                .lock()
                .map_err(|_| FederationSessionRuntimeError::Unavailable)?;
            live.retain(|id, connection| {
                if routes
                    .get(id)
                    .is_some_and(|route| same_authority(route, &connection.route))
                    && connection.connection.close_reason().is_none()
                {
                    true
                } else {
                    connection
                        .connection
                        .close(0_u32.into(), b"federation authority changed");
                    false
                }
            });
            Ok(routes
                .into_iter()
                .filter_map(|(id, route)| {
                    (route.authority.local_identity.local_mesh_id.as_bytes()
                        < route.authority.local_identity.remote_mesh_id.as_bytes())
                    .then_some(id)
                })
                .collect())
        })
        .await
        .map_err(|_| FederationSessionRuntimeError::Unavailable)?
    }

    pub(crate) async fn dial(
        &self,
        relationship: FederationRelationshipId,
    ) -> Result<NativeFederationSession, FederationSessionRuntimeError> {
        let route = self.route(relationship).await?;
        let uri: axum::http::Uri = route
            .endpoint
            .parse()
            .map_err(|_| FederationSessionRuntimeError::Unavailable)?;
        let host = uri
            .host()
            .ok_or(FederationSessionRuntimeError::Unavailable)?;
        let addresses = tokio::time::timeout(
            HANDSHAKE_DEADLINE,
            tokio::net::lookup_host((host, uri.port_u16().unwrap_or(443))),
        )
        .await
        .map_err(|_| FederationSessionRuntimeError::Unavailable)?
        .map_err(|_| FederationSessionRuntimeError::Unavailable)?;
        let local = self.local_addr()?;
        let address = addresses
            .into_iter()
            .find(|value| value.is_ipv4() == local.is_ipv4())
            .ok_or(FederationSessionRuntimeError::Unavailable)?;
        let connection = tokio::time::timeout(
            HANDSHAKE_DEADLINE,
            self.endpoint.connect(address, CERTIFICATE_NAME),
        )
        .await
        .map_err(|_| FederationSessionRuntimeError::Unavailable)??;
        let outcome = self.dial_handshake(&connection, relationship).await;
        self.finish(connection, relationship, outcome).await
    }

    #[cfg(test)]
    pub(crate) async fn accept(
        &self,
    ) -> Result<NativeFederationSession, FederationSessionRuntimeError> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or(FederationSessionRuntimeError::Unavailable)?;
        self.accept_incoming(incoming).await
    }

    async fn accept_incoming(
        &self,
        incoming: quinn::Incoming,
    ) -> Result<NativeFederationSession, FederationSessionRuntimeError> {
        let connection = tokio::time::timeout(HANDSHAKE_DEADLINE, incoming)
            .await
            .map_err(|_| FederationSessionRuntimeError::Unavailable)?
            .map_err(meshspan_transport::TransportError::from)?;
        let now =
            crate::api_http::current_time().ok_or(FederationSessionRuntimeError::Unavailable)?;
        let request = FederationAcceptRequest {
            nonces: FederationWelcomeNonces::new(random()?, random()?)?,
            now,
        };
        let runtime = self.session_runtime()?;
        let outcome = tokio::time::timeout(
            HANDSHAKE_DEADLINE,
            runtime.accept_shared(&connection, self.authority.as_ref(), request, &self.replay),
        )
        .await
        .map_err(|_| FederationSessionRuntimeError::Unavailable)
        .and_then(|result| result.map_err(Into::into));
        match outcome {
            Ok(session) => {
                let relationship = session.relationship_id;
                let limits = self.negotiated_limits(
                    session.maximum_control_bytes,
                    session.maximum_data_frame_bytes,
                    session.maximum_streams,
                );
                self.finish(connection, relationship, limits).await
            }
            Err(error) => {
                connection.close(0_u32.into(), b"federation handshake rejected");
                Err(error)
            }
        }
    }

    pub(crate) fn close(&self) {
        self.endpoint.close();
    }

    async fn dial_handshake(
        &self,
        connection: &quinn::Connection,
        relationship: FederationRelationshipId,
    ) -> Result<TransportLimits, FederationSessionRuntimeError> {
        let now =
            crate::api_http::current_time().ok_or(FederationSessionRuntimeError::Unavailable)?;
        let request = FederationDialRequest {
            relationship_id: relationship,
            now,
            context: FederationHelloContext::new(
                random()?,
                random()?,
                random()?,
                now.checked_add(DurationMicros::new(10_000_000))
                    .ok_or(FederationSessionRuntimeError::Unavailable)?,
                random()?,
                random()?,
            )?,
        };
        let session = tokio::time::timeout(
            HANDSHAKE_DEADLINE,
            self.session_runtime()?.dial_shared(
                connection,
                self.authority.as_ref(),
                request,
                &self.replay,
            ),
        )
        .await
        .map_err(|_| FederationSessionRuntimeError::Unavailable)??;
        self.negotiated_limits(
            session.maximum_control_bytes,
            session.maximum_data_frame_bytes,
            session.maximum_streams,
        )
    }

    async fn finish(
        &self,
        connection: quinn::Connection,
        relationship: FederationRelationshipId,
        outcome: Result<TransportLimits, FederationSessionRuntimeError>,
    ) -> Result<NativeFederationSession, FederationSessionRuntimeError> {
        let admission = async {
            let limits = outcome?;
            let route = self.route(relationship).await?;
            FederationPeerRegistry::new([route.authority.peer])?.authenticate_connection(
                &connection,
                crate::api_http::current_time()
                    .ok_or(FederationSessionRuntimeError::Unavailable)?,
            )?;
            let mut live = self
                .live
                .lock()
                .map_err(|_| FederationSessionRuntimeError::Unavailable)?;
            if let Some(previous) = live.insert(
                relationship,
                LiveConnection {
                    connection: connection.clone(),
                    route,
                    limits,
                },
            ) {
                previous
                    .connection
                    .close(0_u32.into(), b"federation session replaced");
            }
            Ok::<_, FederationSessionRuntimeError>(limits)
        }
        .await;
        match admission {
            Ok(limits) => Ok(NativeFederationSession {
                relationship,
                connection,
                limits,
            }),
            Err(error) => {
                connection.close(0_u32.into(), b"federation authority rejected");
                Err(error)
            }
        }
    }

    fn negotiated_limits(
        &self,
        control_bytes: u64,
        data_bytes: u64,
        streams: u32,
    ) -> Result<TransportLimits, FederationSessionRuntimeError> {
        let control_bytes = usize::try_from(control_bytes)
            .map_err(|_| FederationSessionRuntimeError::Unavailable)?;
        let data_bytes =
            usize::try_from(data_bytes).map_err(|_| FederationSessionRuntimeError::Unavailable)?;
        if control_bytes > self.limits.wire.maximum_control_bytes()
            || data_bytes > self.limits.wire.maximum_data_frame_bytes()
            || streams == 0
            || streams > self.limits.maximum_bidirectional_streams
        {
            return Err(FederationSessionRuntimeError::Unavailable);
        }
        let wire = meshspan_protocol::WireLimits::new(
            control_bytes,
            data_bytes,
            self.limits.wire.maximum_items(),
            self.limits.wire.maximum_text_bytes(),
        )
        .map_err(meshspan_transport::TransportError::from)?;
        Ok(TransportLimits {
            wire,
            maximum_bidirectional_streams: streams,
            ..self.limits
        })
    }

    async fn route(
        &self,
        id: FederationRelationshipId,
    ) -> Result<PairedRoute, FederationSessionRuntimeError> {
        let authority = Arc::clone(&self.authority);
        tokio::task::spawn_blocking(move || {
            let now = crate::api_http::current_time()
                .ok_or(FederationSessionRuntimeError::Unavailable)?;
            authority
                .route(id, now)?
                .ok_or(FederationSessionRuntimeError::Unavailable)
        })
        .await
        .map_err(|_| FederationSessionRuntimeError::Unavailable)?
    }

    fn session_runtime(
        &self,
    ) -> Result<meshspan_cluster::FederationSessionRuntime<'_>, FederationSessionRuntimeError> {
        self.session_runtime_with_limits(self.limits)
    }

    fn session_runtime_with_limits(
        &self,
        limits: TransportLimits,
    ) -> Result<meshspan_cluster::FederationSessionRuntime<'_>, FederationSessionRuntimeError> {
        let version = SESSION_VERSION;
        let hello = FederationHelloConfig::new(
            vec![version],
            Vec::new(),
            limits.wire,
            limits.maximum_bidirectional_streams,
        )?;
        let negotiation = FederationNegotiationConfig::new(
            vec![version],
            limits.wire,
            limits.maximum_bidirectional_streams,
        )?;
        let certificate = self
            .identity
            .certificate
            .certificate_chain()
            .first()
            .ok_or(FederationSessionRuntimeError::Unavailable)?;
        Ok(self
            .identity
            .signing
            .session(certificate, hello, negotiation))
    }
}

fn same_authority(left: &PairedRoute, right: &PairedRoute) -> bool {
    left.authority.peer == right.authority.peer
        && left.authority.local_identity == right.authority.local_identity
        && left.endpoint == right.endpoint
}

fn random<const N: usize>() -> Result<[u8; N], FederationSessionRuntimeError> {
    let mut value = [0; N];
    crate::OperatingSystemRandom
        .fill_bytes(&mut value)
        .map_err(|_| FederationSessionRuntimeError::Unavailable)?;
    Ok(value)
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum FederationSessionRuntimeError {
    #[error("native federation session authority or IO unavailable")]
    Unavailable,
    #[error("native federation transport failed")]
    Transport(#[from] meshspan_transport::TransportError),
    #[error("native federation authority failed")]
    Authority(#[from] meshspan_cluster::FederationAuthorityError),
    #[error("native federation authentication failed")]
    Session(#[from] meshspan_cluster::FederationSessionError),
    #[error("native federation backup admission failed")]
    Backup(#[from] meshspan_cluster::FederationBackupCapabilityError),
}
