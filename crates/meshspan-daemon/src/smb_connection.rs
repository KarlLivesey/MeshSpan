// SPDX-License-Identifier: GPL-2.0-only

//! Production composition for one independently authenticated embedded SMB connection.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use meshspan_cluster::MetadataAuthorityHandle;
use meshspan_domain::{
    AssuranceLevel, AuthenticationService, DurationMicros, EntropyError, NodeId, PartitionId,
    RandomSource, UnixMicros,
};
use meshspan_filesystem::{FilesystemAccessContext, NamespaceLimits};
use meshspan_metadata::{
    AuthoritativeRepository, MetadataStoreError, PartitionDatabase, RepositoryError,
};
use meshspan_smb::{
    ConnectorFailure, NegotiateResponseConfig, SmbCommandDispatcherConfigurationError,
    SmbConnectionHandshakeConfig, SmbEstablishedSessionServices, SmbFilesystemLimits,
    SmbProtocolConnection, SmbProtocolConnectionError, SmbPublishedShare,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::native_filesystem_runtime::NativeFilesystemRuntimeError;
use crate::private_consensus_runtime::PrivateConsensusRuntime;
use crate::{
    ConsensusAuthenticationAuthority, FileApiFailure, LocalWrappingKey, LocalWrappingKeyError,
    NativeFilesystemRuntime, OperatingSystemRandom, ProtectedSmbVerifierKeySource,
    SmbAuthenticationError, SmbAuthenticationService, SmbConnectionHandler, SmbHandlerFuture,
    SmbSessionAuthority, classify_native_filesystem_error,
};

const MAXIMUM_PACKET_BYTES: u32 = meshspan_smb::DIRECT_TCP_MAX_PAYLOAD_LENGTH_U32;
const MAXIMUM_WRITABLE_FILE_BYTES: u64 = i64::MAX as u64;
const HANDLE_LEASE_MICROS: u64 = 60 * 1_000_000;
const CONTENT_TIMEOUT_MICROS: u64 = 60 * 1_000_000;
const FULL_FILE_ACCESS: u32 = 0x001f_01ff;
const WINDOWS_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;

type SmbAuthenticator = SmbAuthenticationService<
    ConsensusAuthenticationAuthority,
    ProtectedSmbVerifierKeySource<ConsensusAuthenticationAuthority, LocalWrappingKey>,
>;
type AccessContextFactory = Box<
    dyn FnMut(&SmbSessionAuthority, UnixMicros) -> Result<FilesystemAccessContext, ConnectorFailure>
        + Send,
>;
type FilesystemErrorClassifier = fn(&NativeFilesystemRuntimeError) -> ConnectorFailure;
type AuthenticationErrorClassifier =
    Box<dyn Fn(&SmbAuthenticationError) -> ConnectorFailure + Send>;
type ProductionProtocolConnection = SmbProtocolConnection<
    SmbAuthenticator,
    NativeFilesystemRuntime,
    AccessContextFactory,
    FilesystemErrorClassifier,
    AuthenticationErrorClassifier,
>;

/// Node-local paths and stable identities required by the SMB connection factory.
pub(crate) struct SmbConnectionFactoryConfiguration {
    pub(crate) observations: crate::runtime_observations::RuntimeObservations,
    pub(crate) authority_database: PathBuf,
    pub(crate) wrapping_key_path: PathBuf,
    pub(crate) partition_id: PartitionId,
    pub(crate) node_id: NodeId,
}

/// Cloneable daemon state from which each accepted TCP connection is built independently.
#[derive(Clone)]
pub(crate) struct SmbConnectionFactory {
    observations: crate::runtime_observations::RuntimeObservations,
    authority_database: PathBuf,
    wrapping_key_path: PathBuf,
    partition_id: PartitionId,
    node_id: NodeId,
    authority: MetadataAuthorityHandle,
    network: Arc<PrivateConsensusRuntime>,
    runtime: tokio::runtime::Handle,
    filesystem: NativeFilesystemRuntime,
}

impl SmbConnectionFactory {
    #[must_use]
    pub(crate) fn new(
        configuration: SmbConnectionFactoryConfiguration,
        authority: MetadataAuthorityHandle,
        network: Arc<PrivateConsensusRuntime>,
        runtime: tokio::runtime::Handle,
        filesystem: NativeFilesystemRuntime,
    ) -> Self {
        Self {
            observations: configuration.observations,
            authority_database: configuration.authority_database,
            wrapping_key_path: configuration.wrapping_key_path,
            partition_id: configuration.partition_id,
            node_id: configuration.node_id,
            authority,
            network,
            runtime,
            filesystem,
        }
    }

    /// Opens fresh read authorities and cryptographic entropy for one connection.
    pub(crate) fn open(&self) -> Result<SmbDaemonConnection, SmbConnectionOpeningError> {
        let now = current_time()?;
        let reader = self.repository(now)?;
        let shares = reader
            .smb_exports_for_gateway(self.node_id)?
            .into_iter()
            .map(|export| {
                SmbPublishedShare::new(
                    export.display_name,
                    export.volume_id,
                    export.root_components,
                    NamespaceLimits::PORTABLE,
                    FULL_FILE_ACCESS,
                    export.encryption_required,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let authentication_reader = ConsensusAuthenticationAuthority::new_routable(
            reader,
            self.authority.clone(),
            self.runtime.clone(),
            Arc::clone(&self.network),
        );
        let key_reader = ConsensusAuthenticationAuthority::new_routable(
            self.repository(now)?,
            self.authority.clone(),
            self.runtime.clone(),
            Arc::clone(&self.network),
        );
        let authenticator = SmbAuthenticationService::new(
            authentication_reader,
            ProtectedSmbVerifierKeySource::new(
                key_reader,
                LocalWrappingKey::open(&self.wrapping_key_path)?,
            ),
        );
        let filesystem_limits = SmbFilesystemLimits::new(
            MAXIMUM_WRITABLE_FILE_BYTES,
            DurationMicros::new(HANDLE_LEASE_MICROS),
            DurationMicros::new(CONTENT_TIMEOUT_MICROS),
        )
        .map_err(|_| SmbConnectionOpeningError::Configuration)?;
        let gateway_node_id = self.node_id;
        let network = self
            .network
            .network()
            .map_err(|()| SmbConnectionOpeningError::Configuration)?;
        if network.local_node_id() != gateway_node_id {
            return Err(SmbConnectionOpeningError::Configuration);
        }
        let gateway_incarnation = network.local_incarnation();
        let make_context: AccessContextFactory = Box::new(move |authority, observed_at| {
            Ok(FilesystemAccessContext {
                authentication_service: AuthenticationService::Smb,
                credential_digest: authority.credential_digest(),
                required_assurance: AssuranceLevel::SingleFactor,
                gateway_node_id,
                gateway_incarnation,
                now: observed_at,
            })
        });
        let protocol = SmbProtocolConnection::new(
            handshake_config(self.node_id, now)?,
            authenticator,
            SmbEstablishedSessionServices::new(
                self.filesystem.clone(),
                filesystem_limits,
                shares,
                make_context,
                classify_filesystem_failure as FilesystemErrorClassifier,
            ),
            authentication_classifier(self.observations.clone()),
        )?;
        Ok(SmbDaemonConnection {
            protocol: Some(protocol),
            maintenance_failure: None,
            additional_maintenance_failures: 0,
        })
    }

    fn repository(
        &self,
        now: UnixMicros,
    ) -> Result<AuthoritativeRepository, SmbConnectionOpeningError> {
        Ok(AuthoritativeRepository::new(PartitionDatabase::open(
            &self.authority_database,
            self.partition_id,
            now,
        )?))
    }
}

/// One ordered protocol connection whose blocking metadata/filesystem work uses Tokio's worker
/// pool rather than the asynchronous network executor.
pub(crate) struct SmbDaemonConnection {
    maintenance_failure: Option<Box<SmbDaemonConnectionError>>,
    additional_maintenance_failures: u64,
    protocol: Option<ProductionProtocolConnection>,
}

enum LeaseWork {
    Renew,
    Detach,
}
enum LeaseStep {
    Idle,
    Advanced,
    OpenFailed(ConnectorFailure),
}

impl SmbDaemonConnection {
    async fn lease_step(&mut self, work: LeaseWork) -> Result<LeaseStep, SmbDaemonConnectionError> {
        let mut protocol = self
            .protocol
            .take()
            .ok_or(SmbDaemonConnectionError::InvalidState)?;
        // The connection owns one blocking operation at a time. No protocol or runtime lock is
        // held across await, and the worker's result is observed before the next step begins.
        let (protocol, result) = tokio::task::spawn_blocking(move || {
            let result = current_time().map(|now| match work {
                LeaseWork::Renew => protocol.maintain(now),
                LeaseWork::Detach => protocol.detach_one(now),
            });
            (protocol, result)
        })
        .await
        .map_err(|_| SmbDaemonConnectionError::WorkerStopped)?;
        self.protocol = Some(protocol);
        Ok(match result? {
            Ok(false) => LeaseStep::Idle,
            Ok(true) => LeaseStep::Advanced,
            Err(failure) => LeaseStep::OpenFailed(failure),
        })
    }
}

impl SmbConnectionHandler for SmbDaemonConnection {
    type Error = SmbDaemonConnectionError;

    fn handle(&mut self, request: Vec<u8>) -> SmbHandlerFuture<'_, Self::Error> {
        let protocol = self.protocol.take();
        Box::pin(async move {
            let mut protocol = protocol.ok_or(SmbDaemonConnectionError::InvalidState)?;
            let (protocol, response) = tokio::task::spawn_blocking(move || {
                let result = current_time()
                    .map_err(SmbDaemonConnectionError::Opening)
                    .and_then(|now| protocol.receive(&request, now).map_err(Into::into));
                (protocol, result)
            })
            .await
            .map_err(|_| SmbDaemonConnectionError::WorkerStopped)?;
            self.protocol = Some(protocol);
            response.map(Some)
        })
    }

    fn maintain(
        &mut self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Duration, Self::Error>> + Send + '_>,
    > {
        Box::pin(async move {
            match self.lease_step(LeaseWork::Renew).await? {
                LeaseStep::Idle => Ok(Duration::from_secs(1)),
                LeaseStep::Advanced => Ok(Duration::ZERO),
                LeaseStep::OpenFailed(failure) => {
                    // Retain a bounded report without failing unrelated opens in this session.
                    if self.maintenance_failure.is_none() {
                        self.maintenance_failure = Some(Box::new(Self::Error::Lease(failure)));
                    } else {
                        self.additional_maintenance_failures =
                            self.additional_maintenance_failures.saturating_add(1);
                    }
                    Ok(Duration::ZERO)
                }
            }
        })
    }

    fn shutdown(
        &mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Self::Error>> + Send + '_>>
    {
        Box::pin(async move {
            let mut primary = self.maintenance_failure.take();
            let mut additional_failures = self.additional_maintenance_failures;
            loop {
                let (failure, terminal) = match self.lease_step(LeaseWork::Detach).await {
                    Ok(LeaseStep::Idle) => break,
                    Ok(LeaseStep::Advanced) => continue,
                    Ok(LeaseStep::OpenFailed(failure)) => (Self::Error::Lease(failure), false),
                    Err(failure) => (failure, true),
                };
                if primary.is_none() {
                    primary = Some(Box::new(failure));
                } else {
                    additional_failures = additional_failures.saturating_add(1);
                }
                if terminal {
                    break;
                }
            }
            self.protocol = None;
            match primary {
                Some(primary) => Err(Self::Error::Cleanup {
                    primary,
                    additional_failures,
                }),
                None => Ok(()),
            }
        })
    }
}

fn handshake_config(
    node_id: NodeId,
    now: UnixMicros,
) -> Result<SmbConnectionHandshakeConfig, SmbConnectionOpeningError> {
    let mut entropy = [0_u8; 48];
    OperatingSystemRandom.fill_bytes(&mut entropy)?;
    let session_id = u64::from_be_bytes(
        entropy[..8]
            .try_into()
            .map_err(|_| SmbConnectionOpeningError::Configuration)?,
    ) | 1;
    let server_challenge = entropy[8..16]
        .try_into()
        .map_err(|_| SmbConnectionOpeningError::Configuration)?;
    let preauth_salt = entropy[16..]
        .try_into()
        .map_err(|_| SmbConnectionOpeningError::Configuration)?;
    let computer_name = netbios_name(node_id);
    Ok(SmbConnectionHandshakeConfig {
        session_id,
        negotiate: NegotiateResponseConfig {
            server_guid: server_guid(node_id),
            maximum_transaction_size: MAXIMUM_PACKET_BYTES,
            maximum_read_size: MAXIMUM_PACKET_BYTES,
            maximum_write_size: MAXIMUM_PACKET_BYTES,
            system_time: windows_filetime(now)?,
            preauth_salt,
        },
        server_challenge,
        computer_name: computer_name.clone(),
        domain_name: "MESHSPAN".to_owned(),
        dns_computer_name: Some(computer_name),
        dns_domain_name: None,
        encryption_required: false,
    })
}

fn server_guid(node_id: NodeId) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.smb.server-guid.v1\0");
    digest.update(node_id.as_bytes());
    let bytes: [u8; 32] = digest.finalize().into();
    bytes[..16].try_into().unwrap_or([1; 16])
}

fn netbios_name(node_id: NodeId) -> String {
    let bytes = node_id.as_bytes();
    format!(
        "MS-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

fn current_time() -> Result<UnixMicros, SmbConnectionOpeningError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SmbConnectionOpeningError::Clock)?;
    let micros =
        i64::try_from(duration.as_micros()).map_err(|_| SmbConnectionOpeningError::Clock)?;
    Ok(UnixMicros::new(micros))
}

fn windows_filetime(now: UnixMicros) -> Result<u64, SmbConnectionOpeningError> {
    let micros = u64::try_from(now.get()).map_err(|_| SmbConnectionOpeningError::Clock)?;
    micros
        .checked_mul(10)
        .and_then(|value| value.checked_add(WINDOWS_TO_UNIX_EPOCH_100NS))
        .ok_or(SmbConnectionOpeningError::Clock)
}

fn classify_filesystem_failure(error: &NativeFilesystemRuntimeError) -> ConnectorFailure {
    match classify_native_filesystem_error(error) {
        FileApiFailure::InvalidInput => ConnectorFailure::InvalidInput,
        FileApiFailure::AccessDenied => ConnectorFailure::AccessDenied,
        FileApiFailure::NotFound => ConnectorFailure::NotFound,
        FileApiFailure::Conflict | FileApiFailure::StaleCursor => {
            ConnectorFailure::SharingViolation
        }
        FileApiFailure::Unavailable => ConnectorFailure::TemporarilyUnavailable,
        FileApiFailure::Failed => ConnectorFailure::InternalFailure,
    }
}

#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "the protocol classifier contract accepts every authentication error by reference"
)]
fn classify_authentication_failure(error: &SmbAuthenticationError) -> ConnectorFailure {
    match error {
        SmbAuthenticationError::Denied => ConnectorFailure::AuthenticationRejected,
        SmbAuthenticationError::Unavailable => ConnectorFailure::TemporarilyUnavailable,
        SmbAuthenticationError::State => ConnectorFailure::InternalFailure,
    }
}

fn authentication_classifier(
    observations: crate::runtime_observations::RuntimeObservations,
) -> AuthenticationErrorClassifier {
    Box::new(move |error| {
        if matches!(error, SmbAuthenticationError::Denied) {
            observations.record_smb_authentication_rejection();
        }
        classify_authentication_failure(error)
    })
}

/// Per-connection construction failed without affecting the shared listener.
#[derive(Debug, Error)]
pub(crate) enum SmbConnectionOpeningError {
    #[error("SMB metadata could not be opened")]
    Metadata(#[from] MetadataStoreError),
    #[error("SMB metadata query failed closed")]
    Repository(#[from] RepositoryError),
    #[error("SMB node wrapping key could not be opened")]
    WrappingKey(#[from] LocalWrappingKeyError),
    #[error("SMB entropy is unavailable")]
    Entropy(#[from] EntropyError),
    #[error("SMB connection configuration is invalid")]
    Configuration,
    #[error("SMB share configuration is invalid")]
    Share(#[from] SmbCommandDispatcherConfigurationError),
    #[error("SMB handshake configuration is invalid")]
    Handshake(#[from] meshspan_smb::SmbSessionHandshakeError),
    #[error("SMB clock is unavailable")]
    Clock,
}

/// Connection-local processing failure; the shared listener remains available.
#[derive(Debug, Error)]
pub(crate) enum SmbDaemonConnectionError {
    #[error("SMB connection state is invalid")]
    InvalidState,
    #[error("SMB connection clock failed")]
    Opening(#[from] SmbConnectionOpeningError),
    #[error("SMB protocol processing failed")]
    Protocol(#[from] SmbProtocolConnectionError),
    #[error("SMB blocking worker stopped")]
    WorkerStopped,
    #[error("SMB handle lease authority failed ({0:?})")]
    Lease(ConnectorFailure),
    #[error("SMB cleanup failed: {primary}; {additional_failures} additional failure(s)")]
    Cleanup {
        primary: Box<Self>,
        additional_failures: u64,
    },
}

#[cfg(test)]
mod tests {
    use meshspan_domain::{NodeId, UnixMicros};

    use super::{netbios_name, server_guid, windows_filetime};

    #[test]
    fn smb_authentication_metrics_preserve_protocol_outcomes_and_exclude_unavailability()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::{ConnectorFailure, SmbAuthenticationError, authentication_classifier};
        use meshspan_contracts::{RuntimeMetric, RuntimeMetricSource as _};
        let observations = crate::runtime_observations::RuntimeObservations::default();
        let classify = authentication_classifier(observations.clone());
        for (error, expected) in [
            (
                SmbAuthenticationError::Denied,
                ConnectorFailure::AuthenticationRejected,
            ),
            (
                SmbAuthenticationError::Unavailable,
                ConnectorFailure::TemporarilyUnavailable,
            ),
            (
                SmbAuthenticationError::State,
                ConnectorFailure::InternalFailure,
            ),
            (
                SmbAuthenticationError::Denied,
                ConnectorFailure::AuthenticationRejected,
            ),
        ] {
            assert_eq!(classify(&error), expected);
        }
        let snapshot = observations.collect_metrics()?;
        assert!(
            snapshot
                .samples()
                .contains(&RuntimeMetric::SmbAuthenticationRejections(2))
        );
        assert!(
            snapshot
                .samples()
                .contains(&RuntimeMetric::SmbDispatches(0))
        );
        let encoded = crate::encode_openmetrics(&snapshot)?;
        assert!(
            std::str::from_utf8(&encoded)?
                .contains("meshspan_v1_smb_authentication_rejections_total 2\n")
        );
        Ok(())
    }

    #[test]
    fn stable_server_identity_and_protocol_clock_are_well_formed()
    -> Result<(), Box<dyn std::error::Error>> {
        let node = NodeId::from_bytes([7; 16])?;
        assert_eq!(netbios_name(node), "MS-070707070707");
        assert_ne!(server_guid(node), [0; 16]);
        assert_eq!(
            windows_filetime(UnixMicros::new(0))?,
            116_444_736_000_000_000
        );
        Ok(())
    }
}
