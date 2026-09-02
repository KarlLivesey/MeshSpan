// SPDX-License-Identifier: GPL-2.0-only

//! Headless process composition for the real HTTPS appliance runtime.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use meshspan_api_contract::{
    CreateMeshSetupRequest, CreateMeshSetupResponse, HealthStatus, SetupState,
};
use meshspan_cluster::{
    ConsensusNetwork, ConsensusNetworkConfig, ConsensusNetworkError, ConsensusPeerConfig,
    MetadataAuthorityConfig, MetadataAuthorityHandle, MetadataAuthorityRequestError,
    MetadataAuthorityRuntimeError, MetadataAuthorityStartError, OutboundConsensusSnapshot,
    PartitionConsensusDriver, PeerConsensusMessage, PeerControlRequest, PeerDataStream,
    restore_member_incarnations, spawn_metadata_authority,
};
use meshspan_consensus::{
    ActiveQuorumPlan, ConsensusCore, CoreConfig, CoreError, QuorumPlanError, compile_plan,
    flat_plan,
};
use meshspan_data_plane::{RemoteShardRouter, RemoteShardService};
use meshspan_domain::{
    AuditEventId, DurationMicros, InitialBootstrapMaterial, InitialBootstrapMaterialError,
    JoinGrantBundle, NodeId, OperationId, PrincipalId, RandomSource, SnapshotId, UnixMicros,
    uuid_v8,
};
use meshspan_metadata::{
    AuthoritativeRepository, ClaimMaintenanceWork, CommandContext, ConsensusStoreError, JoinRoles,
    LocalDatabase, MetadataStoreError, PartitionDatabase, RepositoryError,
};
use meshspan_protocol::v1::control_envelope::Message;
use meshspan_protocol::v1::{
    ControlEnvelope, ErrorCode, NodeActivationResult, NodeRole, NodeRoute, NodeTopologyResult,
    NodeTopologyUpdate, OperationOutcome, OperationResult, WireError,
};
use meshspan_work::{WorkBudget, WorkSubject, WorkUsage};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use crate::headless_node_join::{activate_and_install_node, admit_headless_node, admit_node};
use crate::join_mesh_setup::{load_pending_join, remove_pending_join};
use crate::private_consensus_runtime::{
    NetworkRegisteringEnrolment, PrivateConsensusRuntime, certificate_name,
};
use crate::smb_connection::{SmbConnectionFactory, SmbConnectionFactoryConfiguration};
use crate::{
    ApiKeyIssuanceApiError, AuthenticationMethodListingApiError,
    AuthenticationMethodListingService, AuthenticationMethodRevocationApiError,
    AuthenticationMethodRevocationService, BrowserAuthenticationError, BrowserSessionAuthenticator,
    ConsensusAuthenticationAuthority, ConsensusBootstrapAuthority, CreateMeshSetupConfiguration,
    CreateMeshSetupController, CreateMeshSetupError, CreateMeshSetupService, CreateSessionService,
    CurrentNodeBootstrapPeerSource, CurrentSessionApiError, DaemonLocalState,
    DaemonLocalStateError, DirectoryListingApiError, DirectoryListingService, FileApiRoutes,
    FileReadApiError, FileReadService, GatewaySessionIdentity, HeadlessDaemonConfig,
    HeadlessDaemonConfigError, HttpsServer, HttpsServerError, IdentityAdministrationApiError,
    IdentityAdministrationService, JoinMeshSetupService, NativeApiAuthenticator,
    NativeApiKeyAuthenticator, NativeFilesystemRuntime, NativeFilesystemRuntimeConfiguration,
    NativeNamespaceMutationApiError, NativeNamespaceMutationService, NativeStorageTarget,
    NativeUploadApiError, NativeUploadService, NativeUploadServicePolicy, NodeActivationError,
    NodeActivationRequest, NodeActivationService, NodeEnrolmentApiError, NodeEnrolmentService,
    NodeJoinGrantIssuanceApiError, NodeJoinGrantIssuanceService,
    NodeWrappingKeyRegistrationService, ObjectStatApiError, ObjectStatService,
    OperatingSystemRandom, OperationStatusApiError, OperationStatusService,
    PasskeyChallengeApiError, PasskeyChallengeConfiguration, PasskeyChallengeConfigurationError,
    PasskeyChallengeService, PasskeyRegistrationApiError, PasskeyRegistrationConfiguration,
    PasskeyRegistrationConfigurationError, PasskeyRegistrationService, PasskeySessionService,
    PeriodicScrubScheduler, PermissionAdministrationApiError, PermissionAdministrationService,
    ProtectedApiKeyIssuanceController, ProtectedRecoveryCodeIssuanceController,
    ProtectedTotpFactorVerifier, ProtectedTotpRegistrationSecretProtector, PublicContractApiError,
    ReadinessSource, RecoveryBundleVerificationApiError, RecoveryBundleVerificationService,
    RecoveryCodeIssuanceApiError, ResumableStorageScrubExecution, RevokeCurrentSessionApiError,
    RevokeCurrentSessionService, SessionApiError, SetupApiError, SetupLifecycleError,
    SetupStateSnapshot, SetupStatusSource, SmbExportAdministrationApiError,
    SmbExportAdministrationService, SmbServer, SmbServerConfigurationError, SmbServerError,
    SmbServerLimits, StepUpCurrentSessionApiError, StepUpCurrentSessionService,
    StorageFolderAdministrationApiError, StorageFolderAdministrationService,
    StoragePermitLoadingService, StorageProviderOpeningError, StorageProviderOpeningService,
    StorageTargetRegistrationService, TopologyAdministrationApiError,
    TopologyAdministrationService, TotpRegistrationApiError, TotpRegistrationConfiguration,
    TotpRegistrationConfigurationError, TotpRegistrationService, VolumeAdministrationApiError,
    VolumeAdministrationService, VolumeInventoryApiError, VolumeInventoryService,
    api_key_issuance_api_router, authentication_method_listing_api_router,
    authentication_method_revocation_api_router, classify_native_filesystem_error,
    current_session_api_router, directory_listing_api_router, execute_resumable_storage_scrub,
    file_read_api_router, identity_administration_api_router, native_namespace_mutation_api_router,
    native_upload_api_router, node_enrolment_api_router, node_join_grant_api_router,
    object_stat_api_router, operation_status_api_router, passkey_challenge_api_router,
    passkey_registration_api_router, permission_administration_api_router,
    public_contract_api_router, recovery_bundle_verification_api_router,
    recovery_code_issuance_api_router, revoke_current_session_api_router, session_api_router,
    setup_api_router_with_mutations, smb_export_administration_api_router,
    step_up_current_session_api_router, storage_folder_administration_api_router,
    topology_administration_api_router, totp_registration_api_router,
    volume_administration_api_router, volume_inventory_api_router,
};

mod storage_folder_backend;

const ROOT_AUTHORITY_DATABASE: &str = "root-authority.sqlite3";
const INITIAL_MEMBERSHIP_EPOCH: u64 = 1;
const PRIVATE_CONTROL_CONCURRENCY: usize = 64;
const UPLOAD_LIFETIME_MICROS: u64 = 24 * 60 * 60 * 1_000_000;
const CONTENT_OPERATION_DEADLINE_MICROS: u64 = 60 * 1_000_000;
const TOTP_REGISTRATION_LIFETIME_MICROS: u64 = 5 * 60 * 1_000_000;
const TOTP_ISSUER: &str = "MeshSpan";
const PASSKEY_RELYING_PARTY_ID: &str = "meshspan.local";
const PASSKEY_RELYING_PARTY_NAME: &str = "MeshSpan";
const PASSKEY_CEREMONY_LIFETIME_MICROS: u64 = 5 * 60 * 1_000_000;
const SMB_PACKET_BYTES: usize = meshspan_smb::DIRECT_TCP_MAX_PAYLOAD_LENGTH;
const SMB_INACTIVITY_TIMEOUT: Duration = Duration::from_mins(5);
const SCRUB_MAXIMUM_AGE_MICROS: u64 = 7 * 24 * 60 * 60 * 1_000_000;
const SCRUB_ADMISSION_INTERVAL_MICROS: u64 = 60 * 1_000_000;
const SCRUB_PAGE_ITEMS: usize = 32;
const SCRUB_PAGE_IN_FLIGHT_BYTES: u64 =
    SCRUB_PAGE_ITEMS as u64 * crate::native_filesystem_runtime::MAXIMUM_NATIVE_SHARD_BYTES as u64;
const MAINTENANCE_LEASE_MICROS: u64 = 5 * 60 * 1_000_000;

type AuthorityTask = (
    MetadataAuthorityHandle,
    JoinHandle<Result<(), MetadataAuthorityRuntimeError>>,
    u64,
);

struct StorageRuntimeComposition {
    readiness: Arc<RuntimeReadiness>,
    targets: Arc<Mutex<StorageTargetRuntime>>,
    native_filesystem: NativeFilesystemRuntime,
}

struct ApplianceServiceComposition {
    router: Router,
    smb_connections: SmbConnectionFactory,
}

struct DaemonNodeRuntime {
    local_state: DaemonLocalState,
    setup_state: Arc<SetupStateSnapshot>,
    private_endpoint: String,
    private_network: Arc<PrivateConsensusRuntime>,
    data_streams: tokio::sync::mpsc::Sender<PeerDataStream>,
    received_data_streams: Option<tokio::sync::mpsc::Receiver<PeerDataStream>>,
    joining_peer_messages: Option<tokio::sync::mpsc::Receiver<PeerConsensusMessage>>,
    joining_control_requests: Option<tokio::sync::mpsc::Receiver<PeerControlRequest>>,
}

struct PrivateAuthorityRuntime {
    authority: MetadataAuthorityHandle,
    authority_task: JoinHandle<Result<(), MetadataAuthorityRuntimeError>>,
    removal_authority_epoch: u64,
    network_starter: PrivateNetworkStarter,
}

#[derive(Clone)]
struct PrivateNetworkStarter {
    runtime: tokio::runtime::Handle,
    network: Arc<PrivateConsensusRuntime>,
    authority: MetadataAuthorityHandle,
    state_directory: PathBuf,
    local_node_id: NodeId,
    local_private_key_pkcs8: Arc<Zeroizing<Vec<u8>>>,
    listen_address: SocketAddr,
    data_streams: tokio::sync::mpsc::Sender<PeerDataStream>,
}

impl PrivateNetworkStarter {
    fn start(&self, now: UnixMicros) -> Result<(), DaemonProcessError> {
        if self.network.network().is_ok() {
            return Ok(());
        }
        let repository = open_root_repository_at(&self.state_directory, now)?;
        let mesh_id = repository
            .local_mesh_id()?
            .ok_or(DaemonProcessError::PrivateNetworkState)?;
        let local_certificate = repository
            .active_node_certificate(self.local_node_id)?
            .ok_or(DaemonProcessError::PrivateNetworkState)?;
        let online_authority = repository
            .online_certificate_authority(mesh_id)?
            .ok_or(DaemonProcessError::PrivateNetworkState)?;
        let recovery = repository
            .mesh_recovery_authority(mesh_id)?
            .ok_or(DaemonProcessError::PrivateNetworkState)?;
        let partition_id = repository.partition_id();
        let client_address = if self.listen_address.is_ipv4() {
            SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0_u16; 8], 0))
        };
        let (peer_messages, mut received_peer_messages) = tokio::sync::mpsc::channel(256);
        let (control_requests, received_control_requests) = tokio::sync::mpsc::channel(64);
        let config = ConsensusNetworkConfig {
            local_node_id: self.local_node_id,
            local_incarnation: 1,
            mesh_id,
            partition_id,
            routing_epoch: 1,
            roles: vec![
                NodeRole::Storage,
                NodeRole::Gateway,
                NodeRole::MetadataVoter,
            ],
            listen_address: self.listen_address,
            client_address,
            certificate_chain_der: vec![
                local_certificate.certificate_der,
                online_authority.certificate_der,
            ],
            private_key_pkcs8: Zeroizing::new(self.local_private_key_pkcs8.to_vec()),
            trust_anchors: vec![recovery.root_certificate_der],
            peers: Vec::new(),
            snapshot_staging_path: None,
        };
        let network = {
            let _entered = self.runtime.enter();
            ConsensusNetwork::start_with_control_and_data(
                config,
                peer_messages,
                control_requests,
                self.data_streams.clone(),
            )?
        };
        self.network
            .install(network.clone())
            .map_err(|()| DaemonProcessError::PrivateNetworkState)?;
        let authority = self.authority.clone();
        self.runtime.spawn(async move {
            while let Some(message) = received_peer_messages.recv().await {
                if authority.receive_peer(message).await.is_err() {
                    break;
                }
            }
        });
        self.spawn_control_runtime(network, received_control_requests);
        Ok(())
    }

    fn spawn_control_runtime(
        &self,
        network: ConsensusNetwork,
        mut requests: tokio::sync::mpsc::Receiver<PeerControlRequest>,
    ) {
        let authority = self.authority.clone();
        let state_directory = self.state_directory.clone();
        let runtime = self.runtime.clone();
        let permits = Arc::new(tokio::sync::Semaphore::new(PRIVATE_CONTROL_CONCURRENCY));
        let mutations = Arc::new(tokio::sync::Semaphore::new(1));
        self.runtime.spawn(async move {
            while let Some(request) = requests.recv().await {
                let Ok(permit) = Arc::clone(&permits).acquire_owned().await else {
                    break;
                };
                let network = network.clone();
                let authority = authority.clone();
                let state_directory = state_directory.clone();
                let runtime = runtime.clone();
                let mutation_permit = (!private_control_is_fetch(&request))
                    .then(|| Arc::clone(&mutations).acquire_owned())
                    .map(|permit| async move { permit.await.ok() });
                tokio::spawn(async move {
                    let _permit = permit;
                    let _mutation_permit = match mutation_permit {
                        Some(permit) => match permit.await {
                            Some(permit) => Some(permit),
                            None => return,
                        },
                        None => None,
                    };
                    let response = handle_private_control(
                        &network,
                        &authority,
                        &state_directory,
                        &runtime,
                        &request,
                    )
                    .await;
                    if let Ok(response) = response {
                        let _closed = request.respond.send(response);
                    }
                });
            }
        });
    }
}

fn private_control_is_fetch(request: &PeerControlRequest) -> bool {
    matches!(
        request.envelope.as_inner().message.as_ref(),
        Some(
            Message::FetchNamespaceHistoryPage(_)
                | Message::FetchNamespaceHistoryObject(_)
                | Message::FetchNativeContentLayout(_)
        )
    )
}

struct NetworkStartingSetup<C> {
    inner: C,
    network: PrivateNetworkStarter,
}

impl<C> NetworkStartingSetup<C> {
    const fn new(inner: C, network: PrivateNetworkStarter) -> Self {
        Self { inner, network }
    }
}

impl<C> CreateMeshSetupController for NetworkStartingSetup<C>
where
    C: CreateMeshSetupController,
{
    fn create_mesh(
        &mut self,
        request: &CreateMeshSetupRequest,
        now: UnixMicros,
    ) -> Result<CreateMeshSetupResponse, CreateMeshSetupError> {
        let response = self.inner.create_mesh(request, now)?;
        self.network
            .start(now)
            .map_err(|_| CreateMeshSetupError::PrivateNetwork)?;
        Ok(response)
    }
}

/// Runs one fully headless appliance until the supplied shutdown signal resolves.
///
/// # Errors
///
/// Fails closed for invalid arguments, unsafe state, corrupt consensus, API construction,
/// listener failure or an authority task which stops unexpectedly.
pub async fn run_headless_daemon<F>(
    arguments: impl IntoIterator<Item = OsString>,
    shutdown: F,
) -> Result<(), DaemonProcessError>
where
    F: Future<Output = ()> + Send,
{
    let config = HeadlessDaemonConfig::parse(arguments)?;
    tokio::pin!(shutdown);
    loop {
        match run_daemon_cycle(&config, shutdown.as_mut()).await? {
            DaemonCycleExit::Shutdown => return Ok(()),
            DaemonCycleExit::RestartForJoin => {}
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DaemonCycleExit {
    Shutdown,
    RestartForJoin,
}

async fn run_daemon_cycle<F>(
    config: &HeadlessDaemonConfig,
    shutdown: Pin<&mut F>,
) -> Result<DaemonCycleExit, DaemonProcessError>
where
    F: Future<Output = ()> + Send,
{
    let started_at = current_time()?;
    let mut node = initialise_daemon_node(config, started_at).await?;
    let private_authority = start_private_authority(&mut node, config, started_at).await?;
    let (restart, restart_requests) = tokio::sync::mpsc::unbounded_channel();
    let services =
        compose_appliance_services(&mut node, &private_authority, config, restart, started_at)?;
    serve_daemon_cycle(
        config,
        &node.local_state,
        services,
        private_authority.authority,
        private_authority.authority_task,
        restart_requests,
        shutdown,
    )
    .await
}

async fn initialise_daemon_node(
    config: &HeadlessDaemonConfig,
    started_at: UnixMicros,
) -> Result<DaemonNodeRuntime, DaemonProcessError> {
    let mut local_state = DaemonLocalState::open(config, started_at)?;
    let setup_state = Arc::new(SetupStateSnapshot::new(SetupState::ClaimRequired));
    let setup_lifecycle = setup_state.reconcile(local_state.local_database())?;
    let private_endpoint = advertised_private_endpoint(config)?;
    let private_network = Arc::new(PrivateConsensusRuntime::default());
    let (data_streams, received_data_streams) = tokio::sync::mpsc::channel(128);
    let mut joining_peer_messages = None;
    let mut joining_control_requests = None;
    if setup_lifecycle == SetupState::Configured {
        remove_pending_join(&local_state.pending_interactive_join_path())
            .map_err(|_| DaemonProcessError::InteractiveNodeJoin)?;
    } else {
        let pending_join = load_pending_join(
            &local_state.pending_interactive_join_path(),
            local_state.claim_output_path(),
        )
        .map_err(|_| DaemonProcessError::InteractiveNodeJoin)?;
        let admission = if let Some(request) = pending_join.as_ref() {
            let invitation = JoinGrantBundle::parse(&request.join_code)
                .map_err(|_| DaemonProcessError::InteractiveNodeJoin)?;
            Some(
                admit_node(
                    &mut local_state,
                    &invitation,
                    request.operation_id.clone(),
                    request.host_name.clone(),
                    request.node_name.clone(),
                    &private_endpoint,
                    started_at,
                )
                .await
                .map_err(|_| DaemonProcessError::InteractiveNodeJoin)?,
            )
        } else {
            admit_headless_node(&mut local_state, config, &private_endpoint, started_at)
                .await
                .map_err(|_| DaemonProcessError::HeadlessNodeJoin)?
        };
        if let Some(admission) = admission {
            let joined = activate_and_install_node(
                &mut local_state,
                config.private_listen(),
                &admission,
                data_streams.clone(),
                current_time()?,
            )
            .await
            .map_err(|_| DaemonProcessError::HeadlessNodeJoin)?;
            private_network
                .install(joined.network)
                .map_err(|()| DaemonProcessError::PrivateNetworkState)?;
            joining_peer_messages = Some(joined.peer_messages);
            joining_control_requests = Some(joined.control_requests);
            setup_state.reconcile(local_state.local_database())?;
            if pending_join.is_some() {
                remove_pending_join(&local_state.pending_interactive_join_path())
                    .map_err(|_| DaemonProcessError::InteractiveNodeJoin)?;
            }
        }
    }
    Ok(DaemonNodeRuntime {
        local_state,
        setup_state,
        private_endpoint,
        private_network,
        data_streams,
        received_data_streams: Some(received_data_streams),
        joining_peer_messages,
        joining_control_requests,
    })
}

async fn start_private_authority(
    node: &mut DaemonNodeRuntime,
    config: &HeadlessDaemonConfig,
    started_at: UnixMicros,
) -> Result<PrivateAuthorityRuntime, DaemonProcessError> {
    let consensus_transport: Arc<dyn meshspan_cluster::ConsensusMessageTransport> =
        node.private_network.clone();
    let (authority, authority_task, removal_authority_epoch) =
        start_root_authority(&node.local_state, started_at, consensus_transport)?;
    if let Some(mut messages) = node.joining_peer_messages.take() {
        let joining_authority = authority.clone();
        tokio::spawn(async move {
            while let Some(message) = messages.recv().await {
                if joining_authority.receive_peer(message).await.is_err() {
                    break;
                }
            }
        });
    } else {
        authority.begin_election().await?;
    }
    let private_network_starter = PrivateNetworkStarter {
        runtime: tokio::runtime::Handle::current(),
        network: Arc::clone(&node.private_network),
        authority: authority.clone(),
        state_directory: node.local_state.state_directory().to_path_buf(),
        local_node_id: node.local_state.node_id(),
        local_private_key_pkcs8: Arc::new(Zeroizing::new(
            node.local_state.node_identity_private_key_pkcs8().to_vec(),
        )),
        listen_address: config.private_listen(),
        data_streams: node.data_streams.clone(),
    };
    if let Some(control_requests) = node.joining_control_requests.take() {
        private_network_starter.spawn_control_runtime(
            node.private_network
                .network()
                .map_err(|()| DaemonProcessError::PrivateNetworkState)?,
            control_requests,
        );
    }
    if node.setup_state.setup_state() == SetupState::Configured {
        private_network_starter.start(started_at)?;
    }
    Ok(PrivateAuthorityRuntime {
        authority,
        authority_task,
        removal_authority_epoch,
        network_starter: private_network_starter,
    })
}

fn compose_appliance_services(
    node: &mut DaemonNodeRuntime,
    private_authority: &PrivateAuthorityRuntime,
    config: &HeadlessDaemonConfig,
    restart: tokio::sync::mpsc::UnboundedSender<()>,
    started_at: UnixMicros,
) -> Result<ApplianceServiceComposition, DaemonProcessError> {
    let StorageRuntimeComposition {
        readiness,
        targets: storage_targets,
        native_filesystem,
    } = compose_storage_runtime(
        &node.local_state,
        &private_authority.authority,
        &node.private_network,
        private_authority.removal_authority_epoch,
        config.storage().storage_paths().to_vec(),
        started_at,
    )?;
    let received_data_streams = node
        .received_data_streams
        .take()
        .ok_or(DaemonProcessError::PrivateNetworkState)?;
    spawn_data_plane_runtime(Arc::clone(&storage_targets), received_data_streams);
    spawn_storage_target_reconciler(Arc::clone(&storage_targets));
    let gateway = GatewaySessionIdentity::new(node.local_state.node_id(), 1)?;
    let smb_connections = SmbConnectionFactory::new(
        SmbConnectionFactoryConfiguration {
            authority_database: node
                .local_state
                .state_directory()
                .join(ROOT_AUTHORITY_DATABASE),
            wrapping_key_path: node.local_state.wrapping_key_path(),
            partition_id: open_root_repository(&node.local_state, started_at)?.partition_id(),
            node_id: node.local_state.node_id(),
        },
        private_authority.authority.clone(),
        Arc::clone(&node.private_network),
        tokio::runtime::Handle::current(),
        native_filesystem.clone(),
    );
    let router = Router::new()
        .merge(public_contract_api_router(readiness)?)
        .merge(setup_and_enrolment_routes(
            node,
            private_authority,
            Arc::clone(&storage_targets),
            restart,
            started_at,
        )?)
        .merge(authentication_session_routes(
            &node.local_state,
            &private_authority.authority,
            gateway,
            started_at,
            config.https_listen(),
            &node.private_network,
            Arc::clone(&storage_targets),
        )?)
        .merge(native_file_routes(
            &node.local_state,
            &private_authority.authority,
            gateway,
            started_at,
            native_filesystem,
        )?);
    Ok(ApplianceServiceComposition {
        router,
        smb_connections,
    })
}

fn setup_and_enrolment_routes(
    node: &DaemonNodeRuntime,
    private_authority: &PrivateAuthorityRuntime,
    storage_targets: Arc<Mutex<StorageTargetRuntime>>,
    restart: tokio::sync::mpsc::UnboundedSender<()>,
    started_at: UnixMicros,
) -> Result<Router, DaemonProcessError> {
    let bootstrap = ConsensusBootstrapAuthority::new(
        private_authority.authority.clone(),
        tokio::runtime::Handle::current(),
    );
    let setup = SetupWithStorageTargets {
        setup: NetworkStartingSetup::new(
            CreateMeshSetupService::new(
                node.local_state.open_local_database(started_at)?,
                bootstrap,
                Arc::clone(&node.setup_state),
                CreateMeshSetupConfiguration::new(
                    node.local_state.claim_output_path().to_path_buf(),
                    node.local_state.pending_recovery_bundle_path(),
                    node.local_state.wrapping_public_key(),
                    node.local_state.node_identity_public_key().to_vec(),
                ),
                OperatingSystemRandom,
            ),
            private_authority.network_starter.clone(),
        ),
        storage_targets,
    };
    let enrolment = NetworkRegisteringEnrolment::new(
        NodeEnrolmentService::new(
            open_authentication_authority(
                &node.local_state,
                &private_authority.authority,
                Arc::clone(&node.private_network),
                started_at,
            )?,
            open_authentication_authority(
                &node.local_state,
                &private_authority.authority,
                Arc::clone(&node.private_network),
                started_at,
            )?,
            node.local_state.open_wrapping_key()?,
            CurrentNodeBootstrapPeerSource::new(
                open_authentication_authority(
                    &node.local_state,
                    &private_authority.authority,
                    Arc::clone(&node.private_network),
                    started_at,
                )?,
                node.local_state.node_id(),
                open_root_repository(&node.local_state, started_at)?.partition_id(),
                1,
                node.private_endpoint.clone(),
            ),
        ),
        Arc::clone(&node.private_network),
    );
    Ok(Router::new()
        .merge(setup_api_router_with_mutations(
            Arc::clone(&node.setup_state),
            setup,
            JoinMeshSetupService::new(
                node.local_state.claim_output_path().to_path_buf(),
                node.local_state.pending_interactive_join_path(),
                Arc::clone(&node.setup_state),
                restart,
            ),
        )?)
        .merge(node_enrolment_api_router(enrolment)?))
}

async fn serve_daemon_cycle<F>(
    config: &HeadlessDaemonConfig,
    local_state: &DaemonLocalState,
    services: ApplianceServiceComposition,
    authority: MetadataAuthorityHandle,
    authority_task: JoinHandle<Result<(), MetadataAuthorityRuntimeError>>,
    mut restart_requests: tokio::sync::mpsc::UnboundedReceiver<()>,
    shutdown: Pin<&mut F>,
) -> Result<DaemonCycleExit, DaemonProcessError>
where
    F: Future<Output = ()> + Send,
{
    let https_server = HttpsServer::bind(
        config.https_listen(),
        local_state.bootstrap_server_config()?,
        services.router,
    )
    .await?;
    let smb_server = SmbServer::bind(
        config.smb_listen(),
        SmbServerLimits::new(SMB_PACKET_BYTES, SMB_INACTIVITY_TIMEOUT)?,
    )
    .await?;
    let restart_requested = Arc::new(AtomicBool::new(false));
    let restart_observer = Arc::clone(&restart_requested);
    let lifecycle = async move {
        tokio::select! {
            biased;
            () = shutdown => {}
            request = restart_requests.recv() => {
                restart_observer.store(request.is_some(), Ordering::Release);
            }
        }
    };
    let (listener_shutdown, _) = tokio::sync::watch::channel(false);
    let https_shutdown = listener_shutdown.subscribe();
    let smb_shutdown = listener_shutdown.subscribe();
    let mut https_task = tokio::spawn(https_server.run_until(wait_for_shutdown(https_shutdown)));
    let connection_factory = services.smb_connections;
    let mut smb_task = tokio::spawn(smb_server.run_until(
        move || connection_factory.open(),
        wait_for_shutdown(smb_shutdown),
    ));
    let first_completion = tokio::select! {
        biased;
        () = lifecycle => ListenerCompletion::Lifecycle,
        result = &mut https_task => ListenerCompletion::Https(result),
        result = &mut smb_task => ListenerCompletion::Smb(result),
    };
    let _ = listener_shutdown.send(true);
    match first_completion {
        ListenerCompletion::Lifecycle => {
            https_task
                .await
                .map_err(|_| DaemonProcessError::ListenerTaskStopped)??;
            smb_task
                .await
                .map_err(|_| DaemonProcessError::ListenerTaskStopped)??;
        }
        ListenerCompletion::Https(result) => {
            result.map_err(|_| DaemonProcessError::ListenerTaskStopped)??;
            smb_task
                .await
                .map_err(|_| DaemonProcessError::ListenerTaskStopped)??;
        }
        ListenerCompletion::Smb(result) => {
            result.map_err(|_| DaemonProcessError::ListenerTaskStopped)??;
            https_task
                .await
                .map_err(|_| DaemonProcessError::ListenerTaskStopped)??;
        }
    }
    let shutdown_result = authority.shutdown().await;
    let authority_result = authority_task.await;
    shutdown_result?;
    authority_result.map_err(|_| DaemonProcessError::AuthorityTaskStopped)??;
    Ok(if restart_requested.load(Ordering::Acquire) {
        DaemonCycleExit::RestartForJoin
    } else {
        DaemonCycleExit::Shutdown
    })
}

enum ListenerCompletion {
    Lifecycle,
    Https(Result<Result<(), HttpsServerError>, tokio::task::JoinError>),
    Smb(Result<Result<(), SmbServerError>, tokio::task::JoinError>),
}

async fn wait_for_shutdown(mut receiver: tokio::sync::watch::Receiver<bool>) {
    if *receiver.borrow() {
        return;
    }
    while receiver.changed().await.is_ok() {
        if *receiver.borrow() {
            return;
        }
    }
}

fn compose_storage_runtime(
    local_state: &DaemonLocalState,
    authority: &MetadataAuthorityHandle,
    private_network: &Arc<PrivateConsensusRuntime>,
    removal_authority_epoch: u64,
    configured_paths: Vec<PathBuf>,
    now: UnixMicros,
) -> Result<StorageRuntimeComposition, DaemonProcessError> {
    let runtime = tokio::runtime::Handle::current();
    let root_partition_id = open_root_repository(local_state, now)?.partition_id();
    let authentication_authority = || {
        Ok::<_, DaemonProcessError>(ConsensusAuthenticationAuthority::new_routable(
            open_root_repository(local_state, now)?,
            authority.clone(),
            runtime.clone(),
            Arc::clone(private_network),
        ))
    };
    let readiness = Arc::new(RuntimeReadiness::default());
    let native_filesystem = NativeFilesystemRuntime::new(
        NativeFilesystemRuntimeConfiguration::new(
            local_state.state_directory(),
            local_state.wrapping_key_path(),
            local_state.node_id(),
            root_partition_id,
            authority.clone(),
            Arc::clone(private_network),
            runtime.clone(),
        )
        .map_err(|_| DaemonProcessError::NativeFilesystemConfiguration)?,
    );
    let services = StorageTargetRuntimeServices {
        wrapping_registration: NodeWrappingKeyRegistrationService::new(
            local_state.node_id(),
            local_state.wrapping_public_key(),
            authentication_authority()?,
            OperatingSystemRandom,
        ),
        registration: StorageTargetRegistrationService::new(
            local_state.open_local_database(now)?,
            authentication_authority()?,
            OperatingSystemRandom,
        ),
        opening: StorageProviderOpeningService::new(
            authentication_authority()?,
            local_state.open_wrapping_key()?,
            local_state.state_directory().to_path_buf(),
            removal_authority_epoch,
            OperatingSystemRandom,
        )?,
        data_permits: StoragePermitLoadingService::new(
            authentication_authority()?,
            local_state.open_wrapping_key()?,
        ),
        maintenance_authority: authentication_authority()?,
        maintenance_progress: local_state.open_local_database(now)?,
    };
    let targets = StorageTargetRuntime::new(
        services,
        local_state.node_id(),
        native_filesystem.clone(),
        configured_paths,
        Arc::clone(&readiness),
    );
    Ok(StorageRuntimeComposition {
        readiness,
        targets: Arc::new(Mutex::new(targets)),
        native_filesystem,
    })
}

fn start_root_authority(
    local_state: &DaemonLocalState,
    now: UnixMicros,
    transport: Arc<dyn meshspan_cluster::ConsensusMessageTransport>,
) -> Result<AuthorityTask, DaemonProcessError> {
    let node_id = local_state.node_id();
    let plan = compile_plan(flat_plan(
        InitialBootstrapMaterial::initial_quorum_plan_id(node_id)?,
        INITIAL_MEMBERSHIP_EPOCH,
        BTreeSet::from([node_id]),
        BTreeSet::new(),
    )?)?;
    let mut repository = open_root_repository(local_state, now)?;
    let partition_id = repository.partition_id();
    let active_plan = match repository.load_active_consensus_quorum_plan()? {
        Some(active) => active,
        None => repository.initialise_consensus_quorum_plan(&plan, now)?,
    };
    let recovery_plan = active_plan.recovery_configuration_plan().clone();
    let incarnations = restore_member_incarnations(&repository, &active_plan)
        .map_err(|_| DaemonProcessError::PrivateNetworkState)?;
    let durable = repository.load_consensus_state(active_plan.membership_epoch())?;
    let authority_epoch = active_plan.membership_epoch();
    let core = ConsensusCore::restore_active(
        CoreConfig {
            partition_id,
            local_node_id: node_id,
            local_incarnation: 1,
            plan: recovery_plan,
            member_incarnations: incarnations,
        },
        durable,
        active_plan,
    )?;
    let driver = PartitionConsensusDriver::new(core, repository);
    let (handle, task) =
        spawn_metadata_authority(driver, transport, MetadataAuthorityConfig::default())
            .map_err(DaemonProcessError::from)?;
    Ok((handle, task, authority_epoch))
}

fn authentication_session_routes(
    local_state: &DaemonLocalState,
    authority: &MetadataAuthorityHandle,
    gateway: GatewaySessionIdentity,
    now: UnixMicros,
    https_listen: SocketAddr,
    private_network: &Arc<PrivateConsensusRuntime>,
    storage_targets: Arc<Mutex<StorageTargetRuntime>>,
) -> Result<Router, DaemonProcessError> {
    let passkey_origin = passkey_origin(https_listen);
    Ok(Router::new()
        .merge(session_lifecycle_routes(
            local_state,
            authority,
            gateway,
            now,
            &passkey_origin,
            private_network,
        )?)
        .merge(authentication_method_routes(
            local_state,
            authority,
            gateway,
            now,
            passkey_origin,
            private_network,
        )?)
        .merge(authenticated_administration_routes(
            local_state,
            authority,
            gateway,
            now,
            private_network,
            storage_targets,
        )?))
}

fn session_lifecycle_routes(
    local_state: &DaemonLocalState,
    authority: &MetadataAuthorityHandle,
    gateway: GatewaySessionIdentity,
    now: UnixMicros,
    passkey_origin: &str,
    private_network: &Arc<PrivateConsensusRuntime>,
) -> Result<Router, DaemonProcessError> {
    Ok(Router::new()
        .merge(session_api_router(CreateSessionService::with_factors(
            open_authentication_authority(
                local_state,
                authority,
                Arc::clone(private_network),
                now,
            )?,
            PasskeySessionService::new(
                local_state.open_local_database(now)?,
                local_state.open_passkey_ceremony_key()?,
            ),
            ProtectedTotpFactorVerifier::new(
                open_authentication_authority(
                    local_state,
                    authority,
                    Arc::clone(private_network),
                    now,
                )?,
                local_state.open_wrapping_key()?,
            ),
        ))?)
        .merge(passkey_challenge_api_router(PasskeyChallengeService::new(
            local_state.open_local_database(now)?,
            OperatingSystemRandom,
            local_state.open_passkey_ceremony_key()?,
            PasskeyChallengeConfiguration::new(
                PASSKEY_RELYING_PARTY_ID.to_owned(),
                vec![passkey_origin.to_owned()],
                DurationMicros::new(PASSKEY_CEREMONY_LIFETIME_MICROS),
            )?,
        ))?)
        .merge(current_session_api_router(
            BrowserSessionAuthenticator::new(
                open_authentication_authority(
                    local_state,
                    authority,
                    Arc::clone(private_network),
                    now,
                )?,
                gateway,
            ),
        )?)
        .merge(revoke_current_session_api_router(
            RevokeCurrentSessionService::new(
                open_authentication_authority(
                    local_state,
                    authority,
                    Arc::clone(private_network),
                    now,
                )?,
                gateway,
            ),
        )?)
        .merge(step_up_current_session_api_router(
            StepUpCurrentSessionService::new(
                open_authentication_authority(
                    local_state,
                    authority,
                    Arc::clone(private_network),
                    now,
                )?,
                gateway,
                ProtectedTotpFactorVerifier::new(
                    open_authentication_authority(
                        local_state,
                        authority,
                        Arc::clone(private_network),
                        now,
                    )?,
                    local_state.open_wrapping_key()?,
                ),
            ),
        )?))
}

fn authentication_method_routes(
    local_state: &DaemonLocalState,
    authority: &MetadataAuthorityHandle,
    gateway: GatewaySessionIdentity,
    now: UnixMicros,
    passkey_origin: String,
    private_network: &Arc<PrivateConsensusRuntime>,
) -> Result<Router, DaemonProcessError> {
    Ok(Router::new()
        .merge(credential_management_routes(
            local_state,
            authority,
            gateway,
            now,
            private_network,
        )?)
        .merge(factor_registration_routes(
            local_state,
            authority,
            gateway,
            now,
            passkey_origin,
            private_network,
        )?))
}

fn credential_management_routes(
    local_state: &DaemonLocalState,
    authority: &MetadataAuthorityHandle,
    gateway: GatewaySessionIdentity,
    now: UnixMicros,
    private_network: &Arc<PrivateConsensusRuntime>,
) -> Result<Router, DaemonProcessError> {
    Ok(Router::new()
        .merge(api_key_issuance_api_router(
            ProtectedApiKeyIssuanceController::new(
                open_authentication_authority(
                    local_state,
                    authority,
                    Arc::clone(private_network),
                    now,
                )?,
                open_authentication_authority(
                    local_state,
                    authority,
                    Arc::clone(private_network),
                    now,
                )?,
                local_state.open_wrapping_key()?,
                gateway,
            ),
        )?)
        .merge(authentication_method_listing_api_router(
            AuthenticationMethodListingService::new(
                open_authentication_authority(
                    local_state,
                    authority,
                    Arc::clone(private_network),
                    now,
                )?,
                gateway,
            ),
        )?)
        .merge(authentication_method_revocation_api_router(
            AuthenticationMethodRevocationService::new(
                open_authentication_authority(
                    local_state,
                    authority,
                    Arc::clone(private_network),
                    now,
                )?,
                gateway,
            ),
        )?)
        .merge(recovery_code_issuance_api_router(
            ProtectedRecoveryCodeIssuanceController::new(
                open_authentication_authority(
                    local_state,
                    authority,
                    Arc::clone(private_network),
                    now,
                )?,
                open_authentication_authority(
                    local_state,
                    authority,
                    Arc::clone(private_network),
                    now,
                )?,
                local_state.open_wrapping_key()?,
                gateway,
            ),
        )?))
}

fn factor_registration_routes(
    local_state: &DaemonLocalState,
    authority: &MetadataAuthorityHandle,
    gateway: GatewaySessionIdentity,
    now: UnixMicros,
    passkey_origin: String,
    private_network: &Arc<PrivateConsensusRuntime>,
) -> Result<Router, DaemonProcessError> {
    Ok(Router::new()
        .merge(totp_registration_api_router(
            TotpRegistrationService::with_secret_protector(
                local_state.open_local_database(now)?,
                open_authentication_authority(
                    local_state,
                    authority,
                    Arc::clone(private_network),
                    now,
                )?,
                OperatingSystemRandom,
                local_state.open_totp_ceremony_key()?,
                ProtectedTotpRegistrationSecretProtector::new(
                    open_authentication_authority(
                        local_state,
                        authority,
                        Arc::clone(private_network),
                        now,
                    )?,
                    local_state.open_wrapping_key()?,
                ),
                TotpRegistrationConfiguration::new(
                    TOTP_ISSUER.to_owned(),
                    DurationMicros::new(TOTP_REGISTRATION_LIFETIME_MICROS),
                )?,
                gateway,
            ),
        )?)
        .merge(passkey_registration_api_router(
            PasskeyRegistrationService::new(
                local_state.open_local_database(now)?,
                open_authentication_authority(
                    local_state,
                    authority,
                    Arc::clone(private_network),
                    now,
                )?,
                OperatingSystemRandom,
                local_state.open_passkey_ceremony_key()?,
                PasskeyRegistrationConfiguration::new(
                    PASSKEY_RELYING_PARTY_ID.to_owned(),
                    PASSKEY_RELYING_PARTY_NAME.to_owned(),
                    vec![passkey_origin],
                    DurationMicros::new(PASSKEY_CEREMONY_LIFETIME_MICROS),
                )?,
                gateway,
            ),
        )?))
}

fn authenticated_administration_routes(
    local_state: &DaemonLocalState,
    authority: &MetadataAuthorityHandle,
    gateway: GatewaySessionIdentity,
    now: UnixMicros,
    private_network: &Arc<PrivateConsensusRuntime>,
    storage_targets: Arc<Mutex<StorageTargetRuntime>>,
) -> Result<Router, DaemonProcessError> {
    let security =
        security_administration_routes(local_state, authority, gateway, now, private_network)?;
    let resources = resource_administration_routes(
        local_state,
        authority,
        gateway,
        now,
        private_network,
        storage_targets,
    )?;
    Ok(security.merge(resources))
}

fn security_administration_routes(
    local_state: &DaemonLocalState,
    authority: &MetadataAuthorityHandle,
    gateway: GatewaySessionIdentity,
    now: UnixMicros,
    private_network: &Arc<PrivateConsensusRuntime>,
) -> Result<Router, DaemonProcessError> {
    Ok(Router::new()
        .merge(identity_administration_api_router(
            IdentityAdministrationService::new(
                open_authentication_authority(
                    local_state,
                    authority,
                    Arc::clone(private_network),
                    now,
                )?,
                gateway,
            ),
        )?)
        .merge(node_join_grant_api_router(
            NodeJoinGrantIssuanceService::new(
                open_authentication_authority(
                    local_state,
                    authority,
                    Arc::clone(private_network),
                    now,
                )?,
                open_authentication_authority(
                    local_state,
                    authority,
                    Arc::clone(private_network),
                    now,
                )?,
                local_state.open_wrapping_key()?,
                gateway,
                local_state.https_certificate_fingerprint(),
            ),
        )?)
        .merge(permission_administration_api_router(
            PermissionAdministrationService::new(
                open_authentication_authority(
                    local_state,
                    authority,
                    Arc::clone(private_network),
                    now,
                )?,
                gateway,
            ),
        )?)
        .merge(recovery_bundle_verification_api_router(
            RecoveryBundleVerificationService::new(
                open_authentication_authority(
                    local_state,
                    authority,
                    Arc::clone(private_network),
                    now,
                )?,
                gateway,
                local_state.pending_recovery_bundle_path(),
            ),
        )?))
}

fn resource_administration_routes(
    local_state: &DaemonLocalState,
    authority: &MetadataAuthorityHandle,
    gateway: GatewaySessionIdentity,
    now: UnixMicros,
    private_network: &Arc<PrivateConsensusRuntime>,
    storage_targets: Arc<Mutex<StorageTargetRuntime>>,
) -> Result<Router, DaemonProcessError> {
    Ok(Router::new()
        .merge(volume_administration_api_router(
            VolumeAdministrationService::new(
                open_authentication_authority(
                    local_state,
                    authority,
                    Arc::clone(private_network),
                    now,
                )?,
                gateway,
                OperatingSystemRandom,
            ),
        )?)
        .merge(smb_export_administration_api_router(
            SmbExportAdministrationService::new(
                open_authentication_authority(
                    local_state,
                    authority,
                    Arc::clone(private_network),
                    now,
                )?,
                gateway,
            ),
        )?)
        .merge(operation_status_api_router(OperationStatusService::new(
            open_authentication_authority(
                local_state,
                authority,
                Arc::clone(private_network),
                now,
            )?,
            gateway,
        ))?)
        .merge(storage_folder_administration_api_router(
            StorageFolderAdministrationService::new(
                open_authentication_authority(
                    local_state,
                    authority,
                    Arc::clone(private_network),
                    now,
                )?,
                storage_targets,
                gateway,
            ),
        )?)
        .merge(topology_administration_api_router(
            TopologyAdministrationService::new(
                open_authentication_authority(
                    local_state,
                    authority,
                    Arc::clone(private_network),
                    now,
                )?,
                gateway,
            ),
        )?))
}

fn open_authentication_authority(
    local_state: &DaemonLocalState,
    authority: &MetadataAuthorityHandle,
    private_network: Arc<PrivateConsensusRuntime>,
    now: UnixMicros,
) -> Result<ConsensusAuthenticationAuthority, DaemonProcessError> {
    Ok(ConsensusAuthenticationAuthority::new_routable(
        open_root_repository(local_state, now)?,
        authority.clone(),
        tokio::runtime::Handle::current(),
        private_network,
    ))
}

async fn handle_private_control(
    network: &ConsensusNetwork,
    authority: &MetadataAuthorityHandle,
    state_directory: &std::path::Path,
    runtime: &tokio::runtime::Handle,
    request: &PeerControlRequest,
) -> Result<ControlEnvelope, DaemonProcessError> {
    let envelope = request.envelope.as_inner();
    let header = envelope
        .header
        .as_ref()
        .ok_or(DaemonProcessError::PrivateNetworkState)?;
    let operation_id = OperationId::from_bytes(
        header
            .operation_id
            .as_slice()
            .try_into()
            .map_err(|_| DaemonProcessError::PrivateNetworkState)?,
    )
    .map_err(|_| DaemonProcessError::PrivateNetworkState)?;
    if let Some(Message::MetadataCommand(command)) = envelope.message.as_ref() {
        return crate::metadata_forwarding::handle(
            network,
            authority,
            operation_id,
            header.deadline_unix_micros,
            command,
        )
        .await
        .map_err(|_| DaemonProcessError::PrivateNetworkState);
    }
    if let Some(response) = crate::native_gateway_sync::handle(
        network,
        state_directory,
        request,
        operation_id,
        header,
        envelope
            .message
            .as_ref()
            .ok_or(DaemonProcessError::PrivateNetworkState)?,
    )
    .await
    .map_err(|_| DaemonProcessError::PrivateNetworkState)?
    {
        return Ok(response);
    }
    match envelope.message.as_ref() {
        Some(Message::NodeActivationRequest(activation)) => {
            handle_node_activation_control(
                network,
                authority,
                state_directory,
                runtime,
                request,
                operation_id,
                activation,
            )
            .await
        }
        Some(Message::NodeTopologyUpdate(update)) => {
            handle_topology_control(network, operation_id, header.deadline_unix_micros, update)
                .await
        }
        _ => Err(DaemonProcessError::PrivateNetworkState),
    }
}

async fn handle_node_activation_control(
    network: &ConsensusNetwork,
    authority: &MetadataAuthorityHandle,
    state_directory: &std::path::Path,
    runtime: &tokio::runtime::Handle,
    peer: &PeerControlRequest,
    operation_id: OperationId,
    activation: &meshspan_protocol::v1::NodeActivationRequest,
) -> Result<ControlEnvelope, DaemonProcessError> {
    let outcome = activate_private_node(
        network,
        authority,
        state_directory,
        runtime,
        peer,
        operation_id,
        activation,
    )
    .await;
    let outcome = match outcome {
        Ok((commit, actor_principal_id)) => {
            match redistribute_activated_gateway_secrets(
                authority,
                state_directory,
                runtime,
                actor_principal_id,
            )
            .await
            {
                Ok(()) => Ok(commit),
                Err(error) => Err(error.activation_error()),
            }
        }
        Err(error) => Err(error),
    };
    if let Ok(commit) = &outcome {
        spawn_learner_snapshot(
            network.clone(),
            state_directory.to_path_buf(),
            commit.record.node_id,
        );
        spawn_topology_broadcast(network.clone(), commit.record.revision.get());
    }
    let (result, active_revision) = activation_result(outcome);
    let deadline_unix_micros = peer
        .envelope
        .as_inner()
        .header
        .as_ref()
        .ok_or(DaemonProcessError::PrivateNetworkState)?
        .deadline_unix_micros;
    Ok(ControlEnvelope {
        header: Some(network.control_header(operation_id, deadline_unix_micros)?),
        message: Some(Message::NodeActivationResult(NodeActivationResult {
            result: Some(result),
            active_revision,
        })),
    })
}

async fn handle_topology_control(
    network: &ConsensusNetwork,
    operation_id: OperationId,
    deadline_unix_micros: i64,
    update: &NodeTopologyUpdate,
) -> Result<ControlEnvelope, DaemonProcessError> {
    apply_topology_update(network, update).await?;
    let result_digest = topology_result_digest(update.topology_revision);
    Ok(ControlEnvelope {
        header: Some(network.control_header(operation_id, deadline_unix_micros)?),
        message: Some(Message::NodeTopologyResult(NodeTopologyResult {
            result: Some(OperationResult {
                outcome: OperationOutcome::Durable.into(),
                committed_revision: Some(update.topology_revision),
                error: None,
                result: None,
                result_digest: result_digest.to_vec(),
            }),
            applied_revision: update.topology_revision,
        })),
    })
}

async fn apply_topology_update(
    network: &ConsensusNetwork,
    update: &NodeTopologyUpdate,
) -> Result<(), DaemonProcessError> {
    for route in &update.routes {
        let node_id = NodeId::from_bytes(
            route
                .node_id
                .as_slice()
                .try_into()
                .map_err(|_| DaemonProcessError::PrivateNetworkState)?,
        )
        .map_err(|_| DaemonProcessError::PrivateNetworkState)?;
        if node_id == network.local_node_id() {
            continue;
        }
        let address = tokio::net::lookup_host(&route.private_endpoint)
            .await
            .map_err(|_| DaemonProcessError::PrivateNetworkState)?
            .next()
            .ok_or(DaemonProcessError::PrivateNetworkState)?;
        network.upsert_peer(&ConsensusPeerConfig {
            node_id,
            incarnation: route.incarnation,
            address,
            certificate_der: route.certificate_der.clone(),
            certificate_name: certificate_name(node_id),
        })?;
    }
    Ok(())
}

fn spawn_topology_broadcast(network: ConsensusNetwork, topology_revision: u64) {
    tokio::spawn(async move {
        let Ok(peers) = network.peer_routes() else {
            return;
        };
        let routes = peers
            .iter()
            .map(|peer| NodeRoute {
                node_id: peer.node_id.as_bytes().to_vec(),
                incarnation: peer.incarnation,
                private_endpoint: peer.address.to_string(),
                certificate_der: peer.certificate_der.clone(),
            })
            .collect::<Vec<_>>();
        for peer in peers {
            let Ok(operation_id) = topology_operation_id(peer.node_id, topology_revision) else {
                continue;
            };
            let Ok(header) = network.control_header(operation_id, i64::MAX) else {
                continue;
            };
            let request = ControlEnvelope {
                header: Some(header),
                message: Some(Message::NodeTopologyUpdate(NodeTopologyUpdate {
                    topology_revision,
                    routes: routes.clone(),
                })),
            };
            let _response = network.request_control(peer.node_id, &request).await;
        }
    });
}

fn topology_operation_id(
    peer: NodeId,
    topology_revision: u64,
) -> Result<OperationId, DaemonProcessError> {
    let mut material = Vec::with_capacity(24);
    material.extend_from_slice(&peer.as_bytes());
    material.extend_from_slice(&topology_revision.to_be_bytes());
    let digest = Sha256::digest(&material);
    OperationId::from_bytes(
        digest[..16]
            .try_into()
            .map_err(|_| DaemonProcessError::PrivateNetworkState)?,
    )
    .map_err(|_| DaemonProcessError::PrivateNetworkState)
}

fn topology_result_digest(topology_revision: u64) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.node-topology-result.v1\0");
    digest.update(topology_revision.to_be_bytes());
    digest.finalize().into()
}

fn spawn_learner_snapshot(network: ConsensusNetwork, state_directory: PathBuf, learner: NodeId) {
    tokio::spawn(async move {
        let prepared = tokio::task::spawn_blocking(move || {
            prepare_learner_snapshot(&state_directory, learner)
        })
        .await;
        let Ok(Ok(snapshot)) = prepared else {
            return;
        };
        let snapshot_path = snapshot.path.clone();
        let _sent = network.send_snapshot(learner, &snapshot).await;
        let _removed = tokio::fs::remove_file(snapshot_path).await;
    });
}

fn prepare_learner_snapshot(
    state_directory: &std::path::Path,
    learner: NodeId,
) -> Result<OutboundConsensusSnapshot, DaemonProcessError> {
    const ATTEMPTS: usize = 200;
    for attempt in 0..ATTEMPTS {
        let repository = open_root_repository_at(state_directory, current_time()?)?;
        let active = repository
            .load_active_consensus_quorum_plan()?
            .ok_or(DaemonProcessError::PrivateNetworkState)?;
        if let ActiveQuorumPlan::Stable(plan) = active
            && plan.spec().learners.contains(&learner)
        {
            let snapshot_id = learner_snapshot_id(&plan, learner)?;
            let path = state_directory.join(format!(
                "learner-{}-epoch-{}.snapshot",
                learner,
                plan.spec().membership_epoch
            ));
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            let manifest =
                repository.create_snapshot(snapshot_id, &path, &plan, current_time()?)?;
            let quorum_plan = ActiveQuorumPlan::Stable(plan)
                .encode()
                .map_err(|_| DaemonProcessError::PrivateNetworkState)?;
            return Ok(OutboundConsensusSnapshot {
                path,
                manifest,
                quorum_plan,
            });
        }
        drop(repository);
        if attempt + 1 < ATTEMPTS {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
    Err(DaemonProcessError::PrivateNetworkState)
}

fn learner_snapshot_id(
    plan: &meshspan_consensus::CompiledQuorumPlan,
    learner: NodeId,
) -> Result<SnapshotId, DaemonProcessError> {
    let mut bytes: [u8; 16] = plan.proof_digest()[..16]
        .try_into()
        .map_err(|_| DaemonProcessError::PrivateNetworkState)?;
    for (target, source) in bytes.iter_mut().zip(learner.as_bytes()) {
        *target ^= source;
    }
    SnapshotId::from_bytes(bytes).map_err(|_| DaemonProcessError::PrivateNetworkState)
}

async fn activate_private_node(
    network: &ConsensusNetwork,
    authority: &MetadataAuthorityHandle,
    state_directory: &std::path::Path,
    runtime: &tokio::runtime::Handle,
    peer: &PeerControlRequest,
    operation_id: OperationId,
    request: &meshspan_protocol::v1::NodeActivationRequest,
) -> Result<(crate::NodeActivationCommit, PrincipalId), NodeActivationError> {
    let capability_digest: [u8; 32] = request
        .capability_digest
        .as_slice()
        .try_into()
        .map_err(|_| NodeActivationError::Rejected)?;
    if capability_digest != peer.capability_digest {
        return Err(NodeActivationError::Rejected);
    }
    let roles = activation_roles(&request.roles)?;
    network
        .probe_peer(peer.from)
        .await
        .map_err(|_| NodeActivationError::Unavailable)?;
    let now = current_time().map_err(|_| NodeActivationError::Unavailable)?;
    let repository = open_root_repository_at(state_directory, now)
        .map_err(|_| NodeActivationError::Unavailable)?;
    let actor_principal_id = repository
        .node_activation_candidate(peer.from)
        .map_err(|_| NodeActivationError::Failed)?
        .ok_or(NodeActivationError::Rejected)?
        .authorised_by;
    let mut service = NodeActivationService::new(ConsensusAuthenticationAuthority::new(
        repository,
        authority.clone(),
        runtime.clone(),
    ));
    let activation = NodeActivationRequest {
        operation_id,
        node_id: peer.from,
        incarnation: peer.sender_incarnation,
        certificate_fingerprint: peer.certificate_fingerprint,
        roles,
        capability_digest,
        endpoint_probe_passed: true,
        occurred_at: now,
    };
    let commit = tokio::task::spawn_blocking(move || service.activate(activation))
        .await
        .map_err(|_| NodeActivationError::Unavailable)??;
    Ok((commit, actor_principal_id))
}

async fn redistribute_activated_gateway_secrets(
    authority: &MetadataAuthorityHandle,
    state_directory: &std::path::Path,
    runtime: &tokio::runtime::Handle,
    actor_principal_id: PrincipalId,
) -> Result<(), crate::cluster_secret_redistribution::ClusterSecretRedistributionError> {
    let now = current_time().map_err(|_| {
        crate::cluster_secret_redistribution::ClusterSecretRedistributionError::MissingState
    })?;
    let repository =
        open_root_repository_at(state_directory, now).map_err(|error| match error {
            DaemonProcessError::Repository(error) => {
                crate::cluster_secret_redistribution::ClusterSecretRedistributionError::Repository(
                    error,
                )
            }
            _ => {
                crate::cluster_secret_redistribution::ClusterSecretRedistributionError::MissingState
            }
        })?;
    let wrapping_key =
        crate::LocalWrappingKey::open(&state_directory.join("secrets/node-wrapping-key.x25519"))?;
    let authority =
        ConsensusAuthenticationAuthority::new(repository, authority.clone(), runtime.clone());
    tokio::task::spawn_blocking(move || {
        crate::cluster_secret_redistribution::redistribute_cluster_secrets(
            &authority,
            &wrapping_key,
            actor_principal_id,
            now,
        )
    })
    .await
    .map_err(|_| {
        crate::cluster_secret_redistribution::ClusterSecretRedistributionError::MissingState
    })?
}

fn activation_roles(encoded: &[i32]) -> Result<JoinRoles, NodeActivationError> {
    let mut bits = 0_u8;
    for encoded_role in encoded {
        match NodeRole::try_from(*encoded_role).map_err(|_| NodeActivationError::Rejected)? {
            NodeRole::Storage => bits |= JoinRoles::STORAGE,
            NodeRole::Gateway => bits |= JoinRoles::GATEWAY,
            NodeRole::MetadataLearner => bits |= JoinRoles::METADATA_ELIGIBLE,
            NodeRole::Unspecified | NodeRole::MetadataVoter => {
                return Err(NodeActivationError::Rejected);
            }
        }
    }
    JoinRoles::new(bits).map_err(|_| NodeActivationError::Rejected)
}

fn activation_result(
    outcome: Result<crate::NodeActivationCommit, NodeActivationError>,
) -> (OperationResult, Option<u64>) {
    match outcome {
        Ok(commit) => {
            let revision = commit.record.revision.get();
            (
                OperationResult {
                    outcome: OperationOutcome::Durable.into(),
                    committed_revision: Some(revision),
                    error: None,
                    result: None,
                    result_digest: commit.result_digest.to_vec(),
                },
                Some(revision),
            )
        }
        Err(error) => {
            let (outcome, code, diagnostic_code) = match error {
                NodeActivationError::Rejected => {
                    (OperationOutcome::Rejected, ErrorCode::Unauthorised, 1)
                }
                NodeActivationError::Conflict => {
                    (OperationOutcome::Rejected, ErrorCode::Conflict, 2)
                }
                NodeActivationError::Unavailable => {
                    (OperationOutcome::Failed, ErrorCode::Unavailable, 3)
                }
                NodeActivationError::Failed => {
                    (OperationOutcome::Failed, ErrorCode::InternalContract, 4)
                }
            };
            (
                OperationResult {
                    outcome: outcome.into(),
                    committed_revision: None,
                    error: Some(WireError {
                        code: code.into(),
                        diagnostic_code,
                        retry_after_micros: None,
                    }),
                    result: None,
                    result_digest: Vec::new(),
                },
                None,
            )
        }
    }
}

fn passkey_origin(https_listen: SocketAddr) -> String {
    if https_listen.port() == 443 {
        format!("https://{PASSKEY_RELYING_PARTY_ID}")
    } else {
        format!("https://{PASSKEY_RELYING_PARTY_ID}:{}", https_listen.port())
    }
}

fn advertised_private_endpoint(
    config: &HeadlessDaemonConfig,
) -> Result<String, DaemonProcessError> {
    if let Some(endpoint) = config.private_endpoint() {
        return Ok(endpoint.to_owned());
    }
    let listen = config.private_listen();
    if !listen.ip().is_unspecified() {
        return Ok(listen.to_string().to_ascii_lowercase());
    }
    let probe_target = if listen.is_ipv4() {
        SocketAddr::from(([192, 0, 2, 1], 9))
    } else {
        SocketAddr::from(([0x2001, 0x0db8, 0, 0, 0, 0, 0, 1], 9))
    };
    let socket = std::net::UdpSocket::bind(SocketAddr::new(listen.ip(), 0))
        .map_err(|_| DaemonProcessError::PrivateEndpoint)?;
    socket
        .connect(probe_target)
        .map_err(|_| DaemonProcessError::PrivateEndpoint)?;
    let discovered = socket
        .local_addr()
        .map_err(|_| DaemonProcessError::PrivateEndpoint)?
        .ip();
    if discovered.is_unspecified() {
        return Err(DaemonProcessError::PrivateEndpoint);
    }
    Ok(SocketAddr::new(discovered, listen.port())
        .to_string()
        .to_ascii_lowercase())
}

fn native_file_routes(
    local_state: &DaemonLocalState,
    authority: &MetadataAuthorityHandle,
    gateway: GatewaySessionIdentity,
    now: UnixMicros,
    filesystem: NativeFilesystemRuntime,
) -> Result<Router, DaemonProcessError> {
    let runtime = tokio::runtime::Handle::current();
    let authentication_authority = || {
        Ok::<_, DaemonProcessError>(ConsensusAuthenticationAuthority::new(
            open_root_repository(local_state, now)?,
            authority.clone(),
            runtime.clone(),
        ))
    };
    let authenticator = || {
        Ok::<_, DaemonProcessError>(NativeApiAuthenticator::new(
            BrowserSessionAuthenticator::new(authentication_authority()?, gateway),
            NativeApiKeyAuthenticator::new(authentication_authority()?, gateway),
        ))
    };
    let upload_policy = NativeUploadServicePolicy::new(
        DurationMicros::new(UPLOAD_LIFETIME_MICROS),
        DurationMicros::new(CONTENT_OPERATION_DEADLINE_MICROS),
    )
    .ok_or(DaemonProcessError::NativeUploadPolicy)?;
    Ok(FileApiRoutes::new(
        directory_listing_api_router(DirectoryListingService::new(
            authenticator()?,
            filesystem.clone(),
            classify_native_filesystem_error,
        ))?,
        object_stat_api_router(ObjectStatService::new(
            authenticator()?,
            filesystem.clone(),
            classify_native_filesystem_error,
        ))?,
        file_read_api_router(FileReadService::new(
            authenticator()?,
            filesystem.clone(),
            classify_native_filesystem_error,
            OperatingSystemRandom,
        ))?,
        native_namespace_mutation_api_router(NativeNamespaceMutationService::new(
            authenticator()?,
            filesystem.clone(),
            classify_native_filesystem_error,
        ))?,
        native_upload_api_router(NativeUploadService::new(
            authenticator()?,
            filesystem,
            classify_native_filesystem_error,
            upload_policy,
        ))?,
        volume_inventory_api_router(VolumeInventoryService::new(
            authenticator()?,
            authentication_authority()?,
        ))?,
    )
    .into_router())
}

fn open_root_repository(
    local_state: &DaemonLocalState,
    now: UnixMicros,
) -> Result<AuthoritativeRepository, DaemonProcessError> {
    let database_path = local_state.state_directory().join(ROOT_AUTHORITY_DATABASE);
    if database_path.try_exists()? {
        return open_root_repository_at(local_state.state_directory(), now);
    }
    let database = PartitionDatabase::open(
        &database_path,
        InitialBootstrapMaterial::root_partition_id(local_state.node_id())?,
        now,
    )?;
    Ok(AuthoritativeRepository::new(database))
}

fn open_root_repository_at(
    state_directory: &std::path::Path,
    now: UnixMicros,
) -> Result<AuthoritativeRepository, DaemonProcessError> {
    let database_path = state_directory.join(ROOT_AUTHORITY_DATABASE);
    let database = if database_path.try_exists()? {
        PartitionDatabase::open_existing(&database_path, now)?
    } else {
        return Err(DaemonProcessError::PrivateNetworkState);
    };
    Ok(AuthoritativeRepository::new(database))
}

fn current_time() -> Result<UnixMicros, DaemonProcessError> {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_micros()).ok())
        .ok_or(DaemonProcessError::Clock)?;
    Ok(UnixMicros::new(micros))
}

#[derive(Default)]
struct RuntimeReadiness {
    degraded: AtomicBool,
}

impl RuntimeReadiness {
    fn store_degraded(&self, degraded: bool) {
        self.degraded.store(degraded, Ordering::Release);
    }
}

impl ReadinessSource for RuntimeReadiness {
    fn status(&self) -> HealthStatus {
        if self.degraded.load(Ordering::Acquire) {
            HealthStatus::Degraded
        } else {
            HealthStatus::Ready
        }
    }
}

struct StorageTargetRuntime {
    wrapping_registration:
        NodeWrappingKeyRegistrationService<ConsensusAuthenticationAuthority, OperatingSystemRandom>,
    registration:
        StorageTargetRegistrationService<ConsensusAuthenticationAuthority, OperatingSystemRandom>,
    opening: StorageProviderOpeningService<
        ConsensusAuthenticationAuthority,
        crate::LocalWrappingKey,
        OperatingSystemRandom,
    >,
    data_permits:
        StoragePermitLoadingService<ConsensusAuthenticationAuthority, crate::LocalWrappingKey>,
    maintenance_authority: ConsensusAuthenticationAuthority,
    maintenance_progress: LocalDatabase,
    local_node_id: NodeId,
    native_filesystem: NativeFilesystemRuntime,
    configured_paths: Vec<PathBuf>,
    active: BTreeMap<PathBuf, NativeStorageTarget>,
    scrub_admission_cursor: Option<meshspan_metadata::DueStorageScrubCursor>,
    next_scrub_admission_at: Option<UnixMicros>,
    readiness: Arc<RuntimeReadiness>,
}

struct StorageTargetRuntimeServices {
    wrapping_registration:
        NodeWrappingKeyRegistrationService<ConsensusAuthenticationAuthority, OperatingSystemRandom>,
    registration:
        StorageTargetRegistrationService<ConsensusAuthenticationAuthority, OperatingSystemRandom>,
    opening: StorageProviderOpeningService<
        ConsensusAuthenticationAuthority,
        crate::LocalWrappingKey,
        OperatingSystemRandom,
    >,
    data_permits:
        StoragePermitLoadingService<ConsensusAuthenticationAuthority, crate::LocalWrappingKey>,
    maintenance_authority: ConsensusAuthenticationAuthority,
    maintenance_progress: LocalDatabase,
}

impl StorageTargetRuntime {
    fn new(
        services: StorageTargetRuntimeServices,
        local_node_id: NodeId,
        native_filesystem: NativeFilesystemRuntime,
        configured_paths: Vec<PathBuf>,
        readiness: Arc<RuntimeReadiness>,
    ) -> Self {
        Self {
            wrapping_registration: services.wrapping_registration,
            registration: services.registration,
            opening: services.opening,
            data_permits: services.data_permits,
            maintenance_authority: services.maintenance_authority,
            maintenance_progress: services.maintenance_progress,
            local_node_id,
            native_filesystem,
            configured_paths,
            active: BTreeMap::new(),
            scrub_admission_cursor: None,
            next_scrub_admission_at: None,
            readiness,
        }
    }

    fn data_router(&self) -> Result<RemoteShardRouter<crate::LocalFolderStorageProvider>, ()> {
        if self.active.is_empty() {
            return Err(());
        }
        let mut services = Vec::with_capacity(self.active.len());
        for target in self.active.values() {
            let context = target.context();
            let permit_key = self
                .data_permits
                .load_latest(context.mesh_id)
                .map_err(|_| ())?;
            services.push(
                RemoteShardService::new(
                    target.provider(),
                    permit_key,
                    context.mesh_id,
                    self.local_node_id,
                    context.target_id,
                    context.generation,
                    crate::native_filesystem_runtime::MAXIMUM_NATIVE_SHARD_BYTES,
                )
                .map_err(|_| ())?,
            );
        }
        RemoteShardRouter::new(services, self.active.len()).map_err(|_| ())
    }

    fn run_maintenance_tick(&mut self, now: UnixMicros) -> Result<(), ()> {
        self.admit_periodic_scrubs(now)?;
        self.execute_one_scrub_page(now)
    }

    fn admit_periodic_scrubs(&mut self, now: UnixMicros) -> Result<(), ()> {
        if self
            .next_scrub_admission_at
            .is_some_and(|eligible_at| eligible_at > now)
        {
            return Ok(());
        }
        let actor = self.maintenance_actor(now)?;
        let mut random = OperatingSystemRandom;
        let page = PeriodicScrubScheduler::new(
            &self.maintenance_authority,
            &mut random,
            self.local_node_id,
            actor,
        )
        .admit_page(
            now,
            DurationMicros::new(SCRUB_MAXIMUM_AGE_MICROS),
            self.scrub_admission_cursor,
            64,
            SCRUB_PAGE_IN_FLIGHT_BYTES,
        )
        .map_err(|_| ())?;
        self.scrub_admission_cursor = page.next;
        self.next_scrub_admission_at = if page.next.is_some() {
            Some(now)
        } else {
            now.checked_add(DurationMicros::new(SCRUB_ADMISSION_INTERVAL_MICROS))
        };
        Ok(())
    }

    fn execute_one_scrub_page(&mut self, now: UnixMicros) -> Result<(), ()> {
        let budget = WorkBudget::new(1, SCRUB_PAGE_IN_FLIGHT_BYTES, None).map_err(|_| ())?;
        let batch = crate::MaintenanceDispatcher::new(&self.maintenance_authority)
            .prepare_batch_where(
                now,
                budget,
                WorkUsage {
                    active_jobs: 0,
                    in_flight_bytes: 0,
                },
                1_000,
                |subject| matches!(subject, WorkSubject::Scrub { .. }),
            )
            .map_err(|_| ())?;
        let Some(assignment) = batch.assignments.first().copied() else {
            return Ok(());
        };
        let WorkSubject::Scrub {
            target_id,
            target_generation,
        } = assignment.subject
        else {
            return Err(());
        };
        let mut provider = self
            .active
            .values()
            .find(|target| {
                let context = target.context();
                context.target_id == target_id && context.generation == target_generation
            })
            .map(NativeStorageTarget::provider)
            .ok_or(())?;
        let actor = self.maintenance_actor(now)?;
        let catalogue = self
            .native_filesystem
            .maintenance_catalogue(now)
            .map_err(|_| ())?;
        let mut finding_random = OperatingSystemRandom;
        let mut findings = crate::AutomaticScrubFindingScheduler::new(
            &self.maintenance_authority,
            &catalogue,
            &mut finding_random,
            actor,
        );
        let execution = maintenance_scrub_execution(assignment, self.local_node_id, actor, now)?;
        execute_resumable_storage_scrub(
            &self.maintenance_authority,
            &mut provider,
            &mut findings,
            &mut self.maintenance_progress,
            &execution,
        )
        .map(|_| ())
        .map_err(|_| ())
    }

    fn maintenance_actor(&self, now: UnixMicros) -> Result<PrincipalId, ()> {
        self.maintenance_authority
            .reader()
            .storage_target_registration_context(self.local_node_id, now)
            .map_err(|_| ())?
            .map(|context| context.actor_principal_id)
            .ok_or(())
    }

    fn reconcile(&mut self, now: UnixMicros) {
        let mut failures = 0_usize;
        if self.restore_persisted_paths().is_err() {
            failures = failures.saturating_add(1);
        }
        if self.wrapping_registration.ensure(now).is_err() {
            failures = failures.saturating_add(1);
        }
        for configured_path in &self.configured_paths {
            let Ok(canonical_path) = std::fs::canonicalize(configured_path) else {
                failures = failures.saturating_add(1);
                continue;
            };
            if self.active.contains_key(&canonical_path) {
                continue;
            }
            match self.registration.register(&canonical_path, now) {
                Ok(target) => {
                    let context = target.context();
                    match self.opening.open(target, now) {
                        Ok(provider) => {
                            self.active.insert(
                                canonical_path,
                                NativeStorageTarget::new(context, provider),
                            );
                        }
                        Err(_) => failures = failures.saturating_add(1),
                    }
                }
                Err(_) => failures = failures.saturating_add(1),
            }
        }
        if !self.active.is_empty() {
            let targets = self.active.values().cloned().collect::<Vec<_>>();
            if self.native_filesystem.ensure_open(&targets, now).is_err() {
                failures = failures.saturating_add(1);
            }
            if self.run_maintenance_tick(now).is_err() {
                failures = failures.saturating_add(1);
            }
        }
        self.readiness.store_degraded(failures > 0);
    }
}

fn maintenance_scrub_execution(
    assignment: crate::MaintenanceDispatchAssignment,
    worker_node_id: NodeId,
    actor_principal_id: PrincipalId,
    now: UnixMicros,
) -> Result<ResumableStorageScrubExecution, ()> {
    let WorkSubject::Scrub {
        target_id,
        target_generation,
    } = assignment.subject
    else {
        return Err(());
    };
    let lease_expires_at = now
        .checked_add(DurationMicros::new(MAINTENANCE_LEASE_MICROS))
        .ok_or(())?;
    let continuation_at = now.checked_add(DurationMicros::new(1)).ok_or(())?;
    let mut random = OperatingSystemRandom;
    let claim_context = random_maintenance_context(&mut random, actor_principal_id, now)?;
    let effect_context = random_maintenance_context(&mut random, actor_principal_id, now)?;
    let completion_context = random_maintenance_context(&mut random, actor_principal_id, now)?;
    let mut fence_bytes = [0_u8; 8];
    random.fill_bytes(&mut fence_bytes).map_err(|_| ())?;
    let fence = u64::from_be_bytes(fence_bytes);
    if fence == 0 {
        return Err(());
    }
    Ok(ResumableStorageScrubExecution {
        claim_context,
        effect_context,
        completion_context,
        claim: ClaimMaintenanceWork {
            work_id: assignment.work_id,
            claim_generation: assignment.claim_generation,
            worker_node_id,
            worker_incarnation: 1,
            fence,
            lease_expires_at,
        },
        target_id,
        target_generation,
        page_items: SCRUB_PAGE_ITEMS,
        observed_at: now,
        continuation_at,
    })
}

fn random_maintenance_context(
    random: &mut impl RandomSource,
    actor_principal_id: PrincipalId,
    now: UnixMicros,
) -> Result<CommandContext, ()> {
    let mut operation_bytes = [0_u8; 16];
    let mut audit_bytes = [0_u8; 16];
    random.fill_bytes(&mut operation_bytes).map_err(|_| ())?;
    random.fill_bytes(&mut audit_bytes).map_err(|_| ())?;
    Ok(CommandContext {
        operation_id: OperationId::from_bytes(uuid_v8(operation_bytes)).map_err(|_| ())?,
        actor_principal_id,
        audit_event_id: AuditEventId::from_bytes(uuid_v8(audit_bytes)).map_err(|_| ())?,
        occurred_at: now,
        expected_revision: None,
    })
}

struct SetupWithStorageTargets<C> {
    setup: C,
    storage_targets: Arc<Mutex<StorageTargetRuntime>>,
}

impl<C> CreateMeshSetupController for SetupWithStorageTargets<C>
where
    C: CreateMeshSetupController,
{
    fn create_mesh(
        &mut self,
        request: &CreateMeshSetupRequest,
        now: UnixMicros,
    ) -> Result<CreateMeshSetupResponse, CreateMeshSetupError> {
        let response = self.setup.create_mesh(request, now)?;
        reconcile_storage_targets(&self.storage_targets, now);
        Ok(response)
    }
}

fn reconcile_storage_targets(storage_targets: &Arc<Mutex<StorageTargetRuntime>>, now: UnixMicros) {
    match storage_targets.lock() {
        Ok(mut targets) => targets.reconcile(now),
        Err(poisoned) => poisoned.into_inner().readiness.store_degraded(true),
    }
}

fn spawn_storage_target_reconciler(storage_targets: Arc<Mutex<StorageTargetRuntime>>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let Ok(now) = current_time() else {
                if let Ok(targets) = storage_targets.lock() {
                    targets.readiness.store_degraded(true);
                }
                continue;
            };
            let targets = Arc::clone(&storage_targets);
            if tokio::task::spawn_blocking(move || reconcile_storage_targets(&targets, now))
                .await
                .is_err()
            {
                break;
            }
        }
    });
}

fn spawn_data_plane_runtime(
    storage_targets: Arc<Mutex<StorageTargetRuntime>>,
    mut streams: tokio::sync::mpsc::Receiver<PeerDataStream>,
) {
    tokio::spawn(async move {
        while let Some(stream) = streams.recv().await {
            let router = match storage_targets.lock() {
                Ok(targets) => targets.data_router(),
                Err(poisoned) => {
                    poisoned.into_inner().readiness.store_degraded(true);
                    Err(())
                }
            };
            let Ok(mut router) = router else {
                continue;
            };
            let Ok(observed_at) = current_time() else {
                continue;
            };
            tokio::spawn(async move {
                let _result = router
                    .serve_stream(stream.stream, stream.peer, stream.limits, observed_at)
                    .await;
            });
        }
    });
}

/// Closed headless-process failures which never expose claim, key or request material.
#[derive(Debug, Error)]
pub enum DaemonProcessError {
    /// Process arguments were invalid.
    #[error("daemon configuration failed")]
    Configuration(#[from] HeadlessDaemonConfigError),
    /// Daemon-local state could not be opened safely.
    #[error("daemon local state failed")]
    LocalState(#[from] DaemonLocalStateError),
    /// The daemon state directory could not be inspected safely.
    #[error("daemon state path inspection failed")]
    StatePath(#[from] std::io::Error),
    /// Authenticated private network construction or framing failed.
    #[error("daemon private network failed")]
    PrivateNetwork(#[from] ConsensusNetworkError),
    /// Required committed private-network material was absent or inconsistent.
    #[error("daemon private network state is invalid")]
    PrivateNetworkState,
    /// Stable root identities could not be derived.
    #[error("daemon root identity failed")]
    BootstrapIdentity(#[from] InitialBootstrapMaterialError),
    /// The initial quorum plan was invalid.
    #[error("daemon quorum plan failed")]
    QuorumPlan(#[from] QuorumPlanError),
    /// Consensus state was invalid.
    #[error("daemon consensus core failed")]
    Consensus(#[from] CoreError),
    /// Consensus persistence failed.
    #[error("daemon consensus persistence failed")]
    ConsensusStore(#[from] ConsensusStoreError),
    /// Root metadata storage failed.
    #[error("daemon metadata storage failed")]
    MetadataStore(#[from] MetadataStoreError),
    /// Root metadata queries failed.
    #[error("daemon metadata repository failed")]
    Repository(#[from] RepositoryError),
    /// The metadata authority could not start.
    #[error("daemon metadata authority configuration failed")]
    AuthorityStart(#[from] MetadataAuthorityStartError),
    /// The live authority rejected a lifecycle request.
    #[error("daemon metadata authority request failed")]
    AuthorityRequest(#[from] MetadataAuthorityRequestError),
    /// The metadata authority stopped after startup.
    #[error("daemon metadata authority stopped")]
    AuthorityRuntime(#[from] MetadataAuthorityRuntimeError),
    /// The public contract could not be built.
    #[error("daemon public contract failed")]
    PublicContract(#[from] PublicContractApiError),
    /// The setup API could not be built.
    #[error("daemon setup API failed")]
    SetupApi(#[from] SetupApiError),
    /// Durable local setup state was inconsistent.
    #[error("daemon setup lifecycle failed")]
    SetupLifecycle(#[from] SetupLifecycleError),
    /// Session creation API construction failed.
    #[error("daemon session API failed")]
    SessionApi(#[from] SessionApiError),
    /// Current-session API construction failed.
    #[error("daemon current-session API failed")]
    CurrentSessionApi(#[from] CurrentSessionApiError),
    /// Session-revocation API construction failed.
    #[error("daemon session-revocation API failed")]
    RevokeSessionApi(#[from] RevokeCurrentSessionApiError),
    /// Session step-up API construction failed.
    #[error("daemon session step-up API failed")]
    StepUpSessionApi(#[from] StepUpCurrentSessionApiError),
    /// Current-user API-key issuance construction failed.
    #[error("daemon API-key issuance API failed")]
    ApiKeyIssuanceApi(#[from] ApiKeyIssuanceApiError),
    /// Current-user authentication-method inventory construction failed.
    #[error("daemon authentication-method inventory API failed")]
    AuthenticationMethodListingApi(#[from] AuthenticationMethodListingApiError),
    /// Current-user authentication-method revocation construction failed.
    #[error("daemon authentication-method revocation API failed")]
    AuthenticationMethodRevocationApi(#[from] AuthenticationMethodRevocationApiError),
    /// Current-user TOTP registration API construction failed.
    #[error("daemon TOTP registration API failed")]
    TotpRegistrationApi(#[from] TotpRegistrationApiError),
    /// Current-user TOTP registration policy is invalid.
    #[error("daemon TOTP registration policy failed")]
    TotpRegistrationConfiguration(#[from] TotpRegistrationConfigurationError),
    /// Current-user recovery-code issuance API construction failed.
    #[error("daemon recovery-code issuance API failed")]
    RecoveryCodeIssuanceApi(#[from] RecoveryCodeIssuanceApiError),
    /// Passkey authentication challenge API construction failed.
    #[error("daemon passkey challenge API failed")]
    PasskeyChallengeApi(#[from] PasskeyChallengeApiError),
    /// Passkey authentication challenge policy is invalid.
    #[error("daemon passkey challenge policy failed")]
    PasskeyChallengeConfiguration(#[from] PasskeyChallengeConfigurationError),
    /// Current-user passkey registration API construction failed.
    #[error("daemon passkey registration API failed")]
    PasskeyRegistrationApi(#[from] PasskeyRegistrationApiError),
    /// Current-user passkey registration policy is invalid.
    #[error("daemon passkey registration policy failed")]
    PasskeyRegistrationConfiguration(#[from] PasskeyRegistrationConfigurationError),
    /// Identity-administration API construction failed.
    #[error("daemon identity-administration API failed")]
    IdentityAdministrationApi(#[from] IdentityAdministrationApiError),
    /// Manager-only node join-grant API construction failed.
    #[error("daemon node join-grant API failed")]
    NodeJoinGrantIssuanceApi(#[from] NodeJoinGrantIssuanceApiError),
    /// Anonymous pre-authorised node-enrolment API construction failed.
    #[error("daemon node-enrolment API failed")]
    NodeEnrolmentApi(#[from] NodeEnrolmentApiError),
    /// Headless admission into an existing mesh failed.
    #[error("daemon headless node join failed")]
    HeadlessNodeJoin,
    /// Interactive admission or its protected restart hand-off failed closed.
    #[error("daemon interactive node join failed")]
    InteractiveNodeJoin,
    /// HTTPS admission is durable but private activation and catch-up remain incomplete.
    #[error("daemon node admission is durable but private activation is pending")]
    NodeActivationPending,
    /// No reachable private endpoint could be derived or configured.
    #[error("daemon private endpoint is unavailable")]
    PrivateEndpoint,
    /// Permission-filtered volume inventory API construction failed.
    #[error("daemon volume-inventory API failed")]
    VolumeInventoryApi(#[from] VolumeInventoryApiError),
    /// Native directory-listing API construction failed.
    #[error("daemon native directory API failed")]
    DirectoryListingApi(#[from] DirectoryListingApiError),
    /// Native object-stat API construction failed.
    #[error("daemon native object API failed")]
    ObjectStatApi(#[from] ObjectStatApiError),
    /// Native file-read API construction failed.
    #[error("daemon native file-read API failed")]
    FileReadApi(#[from] FileReadApiError),
    /// Native namespace-mutation API construction failed.
    #[error("daemon native namespace API failed")]
    NamespaceMutationApi(#[from] NativeNamespaceMutationApiError),
    /// Native upload API construction failed.
    #[error("daemon native upload API failed")]
    NativeUploadApi(#[from] NativeUploadApiError),
    /// The production native filesystem configuration is invalid.
    #[error("daemon native filesystem configuration failed")]
    NativeFilesystemConfiguration,
    /// The compiled native upload lifetime or deadline is invalid.
    #[error("daemon native upload policy is invalid")]
    NativeUploadPolicy,
    /// Manager-only volume-administration API construction failed.
    #[error("daemon volume-administration API failed")]
    VolumeAdministrationApi(#[from] VolumeAdministrationApiError),
    /// Explicit SMB-export administration API construction failed.
    #[error("daemon SMB-export administration API failed")]
    SmbExportAdministrationApi(#[from] SmbExportAdministrationApiError),
    /// Manager-only permission-administration API construction failed.
    #[error("daemon permission-administration API failed")]
    PermissionAdministrationApi(#[from] PermissionAdministrationApiError),
    /// Authenticated durable-operation status API construction failed.
    #[error("daemon operation-status API failed")]
    OperationStatusApi(#[from] OperationStatusApiError),
    /// Manager-only local storage-folder API construction failed.
    #[error("daemon storage-folder administration API failed")]
    StorageFolderAdministrationApi(#[from] StorageFolderAdministrationApiError),
    /// Manager-only mesh-topology API construction failed.
    #[error("daemon topology administration API failed")]
    TopologyAdministrationApi(#[from] TopologyAdministrationApiError),
    /// Manager-only recovery-bundle verification API construction failed.
    #[error("daemon recovery-bundle verification API failed")]
    RecoveryBundleVerificationApi(#[from] RecoveryBundleVerificationApiError),
    /// The HTTPS listener failed.
    #[error("daemon HTTPS listener failed")]
    Https(#[from] HttpsServerError),
    /// The embedded SMB listener failed.
    #[error("daemon SMB listener failed")]
    Smb(#[from] SmbServerError),
    /// The embedded SMB listener policy is invalid.
    #[error("daemon SMB listener policy failed")]
    SmbConfiguration(#[from] SmbServerConfigurationError),
    /// A public listener task ended without a typed result.
    #[error("daemon listener task stopped unexpectedly")]
    ListenerTaskStopped,
    /// The authority task ended without a typed result.
    #[error("daemon metadata authority task stopped unexpectedly")]
    AuthorityTaskStopped,
    /// The blocking storage-target startup task ended without a typed result.
    #[error("daemon storage target task stopped unexpectedly")]
    StorageTargetTaskStopped,
    /// A registered folder could not be composed into a live provider safely.
    #[error("daemon storage provider failed")]
    StorageProvider(#[from] StorageProviderOpeningError),
    /// Gateway identity could not be represented safely.
    #[error("daemon gateway identity failed")]
    GatewayIdentity(#[from] BrowserAuthenticationError),
    /// The host clock cannot be represented safely.
    #[error("daemon host clock is unavailable")]
    Clock,
}
