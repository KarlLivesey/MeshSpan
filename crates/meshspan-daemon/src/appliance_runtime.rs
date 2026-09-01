// SPDX-License-Identifier: GPL-2.0-only

//! Headless process composition for the real HTTPS appliance runtime.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use meshspan_api_contract::{
    CreateMeshSetupRequest, CreateMeshSetupResponse, HealthStatus, SetupState,
};
use meshspan_cluster::{
    ConsensusNetwork, ConsensusNetworkConfig, ConsensusNetworkError, MetadataAuthorityConfig,
    MetadataAuthorityHandle, MetadataAuthorityRequestError, MetadataAuthorityRuntimeError,
    MetadataAuthorityStartError, PartitionConsensusDriver, PeerControlRequest,
    spawn_metadata_authority,
};
use meshspan_consensus::{
    ConsensusCore, CoreConfig, CoreError, MemberIncarnations, QuorumPlanError, compile_plan,
    flat_plan,
};
use meshspan_domain::{
    DurationMicros, InitialBootstrapMaterial, InitialBootstrapMaterialError, NodeId, OperationId,
    UnixMicros,
};
use meshspan_metadata::{
    AuthoritativeRepository, ConsensusStoreError, JoinRoles, MetadataStoreError, PartitionDatabase,
    RepositoryError,
};
use meshspan_protocol::v1::control_envelope::Message;
use meshspan_protocol::v1::{
    ControlEnvelope, ErrorCode, NodeActivationResult, NodeRole, OperationOutcome, OperationResult,
    WireError,
};
use thiserror::Error;
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use crate::headless_node_join::admit_headless_node;
use crate::private_consensus_runtime::{NetworkRegisteringEnrolment, PrivateConsensusRuntime};
use crate::{
    ApiKeyIssuanceApiError, AuthenticationMethodListingApiError,
    AuthenticationMethodListingService, AuthenticationMethodRevocationApiError,
    AuthenticationMethodRevocationService, BrowserAuthenticationError, BrowserSessionAuthenticator,
    ConsensusAuthenticationAuthority, ConsensusBootstrapAuthority, CreateMeshSetupController,
    CreateMeshSetupError, CreateMeshSetupService, CreateSessionService,
    CurrentNodeBootstrapPeerSource, CurrentSessionApiError, DaemonLocalState,
    DaemonLocalStateError, DirectoryListingApiError, DirectoryListingService, FileApiRoutes,
    FileReadApiError, FileReadService, GatewaySessionIdentity, HeadlessDaemonConfig,
    HeadlessDaemonConfigError, HttpsServer, HttpsServerError, IdentityAdministrationApiError,
    IdentityAdministrationService, NativeApiAuthenticator, NativeApiKeyAuthenticator,
    NativeFilesystemRuntime, NativeFilesystemRuntimeConfiguration, NativeNamespaceMutationApiError,
    NativeNamespaceMutationService, NativeStorageTarget, NativeUploadApiError, NativeUploadService,
    NativeUploadServicePolicy, NodeActivationError, NodeActivationRequest, NodeActivationService,
    NodeEnrolmentApiError, NodeEnrolmentService, NodeJoinGrantIssuanceApiError,
    NodeJoinGrantIssuanceService, NodeWrappingKeyRegistrationService, ObjectStatApiError,
    ObjectStatService, OperatingSystemRandom, PasskeyChallengeApiError,
    PasskeyChallengeConfiguration, PasskeyChallengeConfigurationError, PasskeyChallengeService,
    PasskeyRegistrationApiError, PasskeyRegistrationConfiguration,
    PasskeyRegistrationConfigurationError, PasskeyRegistrationService, PasskeySessionService,
    ProtectedApiKeyIssuanceController, ProtectedRecoveryCodeIssuanceController,
    ProtectedTotpFactorVerifier, ProtectedTotpRegistrationSecretProtector, PublicContractApiError,
    ReadinessSource, RecoveryBundleVerificationApiError, RecoveryBundleVerificationService,
    RecoveryCodeIssuanceApiError, RevokeCurrentSessionApiError, RevokeCurrentSessionService,
    SessionApiError, SetupApiError, SetupLifecycleError, SetupStateSnapshot, SetupStatusSource,
    StepUpCurrentSessionApiError, StepUpCurrentSessionService, StorageProviderOpeningError,
    StorageProviderOpeningService, StorageTargetRegistrationService, TotpRegistrationApiError,
    TotpRegistrationConfiguration, TotpRegistrationConfigurationError, TotpRegistrationService,
    VolumeAdministrationApiError, VolumeAdministrationService, VolumeInventoryApiError,
    VolumeInventoryService, api_key_issuance_api_router, authentication_method_listing_api_router,
    authentication_method_revocation_api_router, classify_native_filesystem_error,
    current_session_api_router, directory_listing_api_router, file_read_api_router,
    identity_administration_api_router, native_namespace_mutation_api_router,
    native_upload_api_router, node_enrolment_api_router, node_join_grant_api_router,
    object_stat_api_router, passkey_challenge_api_router, passkey_registration_api_router,
    public_contract_api_router, recovery_bundle_verification_api_router,
    recovery_code_issuance_api_router, revoke_current_session_api_router, session_api_router,
    setup_api_router_with_creation, step_up_current_session_api_router,
    totp_registration_api_router, volume_administration_api_router, volume_inventory_api_router,
};

const ROOT_AUTHORITY_DATABASE: &str = "root-authority.sqlite3";
const INITIAL_MEMBERSHIP_EPOCH: u64 = 1;
const UPLOAD_LIFETIME_MICROS: u64 = 24 * 60 * 60 * 1_000_000;
const CONTENT_OPERATION_DEADLINE_MICROS: u64 = 60 * 1_000_000;
const TOTP_REGISTRATION_LIFETIME_MICROS: u64 = 5 * 60 * 1_000_000;
const TOTP_ISSUER: &str = "MeshSpan";
const PASSKEY_RELYING_PARTY_ID: &str = "meshspan.local";
const PASSKEY_RELYING_PARTY_NAME: &str = "MeshSpan";
const PASSKEY_CEREMONY_LIFETIME_MICROS: u64 = 5 * 60 * 1_000_000;

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

#[derive(Clone)]
struct PrivateNetworkStarter {
    runtime: tokio::runtime::Handle,
    network: Arc<PrivateConsensusRuntime>,
    authority: MetadataAuthorityHandle,
    state_directory: PathBuf,
    local_node_id: NodeId,
    local_private_key_pkcs8: Arc<Zeroizing<Vec<u8>>>,
    listen_address: SocketAddr,
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
        };
        let network = {
            let _entered = self.runtime.enter();
            ConsensusNetwork::start_with_control(config, peer_messages, control_requests)?
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
        self.runtime.spawn(async move {
            while let Some(request) = requests.recv().await {
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
            }
        });
    }
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
    let started_at = current_time()?;
    let mut local_state = DaemonLocalState::open(&config, started_at)?;
    let setup_state = Arc::new(SetupStateSnapshot::new(SetupState::ClaimRequired));
    setup_state.reconcile(local_state.local_database())?;
    let private_endpoint = advertised_private_endpoint(&config)?;
    if setup_state.setup_state() != SetupState::Configured
        && admit_headless_node(&mut local_state, &config, &private_endpoint, started_at)
            .await
            .map_err(|_| DaemonProcessError::HeadlessNodeJoin)?
            .is_some()
    {
        return Err(DaemonProcessError::NodeActivationPending);
    }

    let private_network = Arc::new(PrivateConsensusRuntime::default());
    let consensus_transport: Arc<dyn meshspan_cluster::ConsensusMessageTransport> =
        private_network.clone();
    let (authority, authority_task, removal_authority_epoch) =
        start_root_authority(&local_state, started_at, consensus_transport)?;
    authority.begin_election().await?;
    let private_network_starter = PrivateNetworkStarter {
        runtime: tokio::runtime::Handle::current(),
        network: Arc::clone(&private_network),
        authority: authority.clone(),
        state_directory: local_state.state_directory().to_path_buf(),
        local_node_id: local_state.node_id(),
        local_private_key_pkcs8: Arc::new(Zeroizing::new(
            local_state.node_identity_private_key_pkcs8().to_vec(),
        )),
        listen_address: config.private_listen(),
    };
    if setup_state.setup_state() == SetupState::Configured {
        private_network_starter.start(started_at)?;
    }
    let StorageRuntimeComposition {
        readiness,
        targets: storage_targets,
        native_filesystem,
    } = compose_storage_runtime(
        &local_state,
        &authority,
        removal_authority_epoch,
        config.storage().storage_paths().to_vec(),
        started_at,
    )?;
    if setup_state.setup_state() == SetupState::Configured {
        let targets = Arc::clone(&storage_targets);
        tokio::task::spawn_blocking(move || reconcile_storage_targets(&targets, started_at))
            .await
            .map_err(|_| DaemonProcessError::StorageTargetTaskStopped)?;
    }
    let bootstrap =
        ConsensusBootstrapAuthority::new(authority.clone(), tokio::runtime::Handle::current());
    let setup = SetupWithStorageTargets {
        setup: NetworkStartingSetup::new(
            CreateMeshSetupService::new(
                local_state.open_local_database(started_at)?,
                bootstrap,
                local_state.claim_output_path().to_path_buf(),
                local_state.pending_recovery_bundle_path(),
                Arc::clone(&setup_state),
                local_state.wrapping_public_key(),
                local_state.node_identity_public_key().to_vec(),
                OperatingSystemRandom,
            ),
            private_network_starter,
        ),
        storage_targets,
    };
    let gateway = GatewaySessionIdentity::new(local_state.node_id(), 1)?;
    let enrolment = NetworkRegisteringEnrolment::new(
        NodeEnrolmentService::new(
            open_authentication_authority(&local_state, &authority, started_at)?,
            open_authentication_authority(&local_state, &authority, started_at)?,
            local_state.open_wrapping_key()?,
            CurrentNodeBootstrapPeerSource::new(
                open_authentication_authority(&local_state, &authority, started_at)?,
                local_state.node_id(),
                open_root_repository(&local_state, started_at)?.partition_id(),
                1,
                private_endpoint,
            ),
        ),
        private_network,
    );
    let router = Router::new()
        .merge(public_contract_api_router(readiness)?)
        .merge(setup_api_router_with_creation(setup_state, setup)?)
        .merge(node_enrolment_api_router(enrolment)?)
        .merge(authentication_session_routes(
            &local_state,
            &authority,
            gateway,
            started_at,
            config.https_listen(),
        )?)
        .merge(native_file_routes(
            &local_state,
            &authority,
            gateway,
            started_at,
            native_filesystem,
        )?);
    let server = HttpsServer::bind(
        config.https_listen(),
        local_state.bootstrap_server_config()?,
        router,
    )
    .await?;
    let server_result = server.run_until(shutdown).await;
    let shutdown_result = authority.shutdown().await;
    let authority_result = authority_task.await;
    server_result?;
    shutdown_result?;
    authority_result.map_err(|_| DaemonProcessError::AuthorityTaskStopped)??;
    Ok(())
}

fn compose_storage_runtime(
    local_state: &DaemonLocalState,
    authority: &MetadataAuthorityHandle,
    removal_authority_epoch: u64,
    configured_paths: Vec<PathBuf>,
    now: UnixMicros,
) -> Result<StorageRuntimeComposition, DaemonProcessError> {
    let runtime = tokio::runtime::Handle::current();
    let authentication_authority = || {
        Ok::<_, DaemonProcessError>(ConsensusAuthenticationAuthority::new(
            open_root_repository(local_state, now)?,
            authority.clone(),
            runtime.clone(),
        ))
    };
    let readiness = Arc::new(RuntimeReadiness::default());
    let native_filesystem = NativeFilesystemRuntime::new(
        NativeFilesystemRuntimeConfiguration::new(
            local_state.state_directory(),
            local_state.wrapping_key_path(),
            local_state.node_id(),
            authority.clone(),
            runtime.clone(),
        )
        .map_err(|_| DaemonProcessError::NativeFilesystemConfiguration)?,
    );
    let targets = StorageTargetRuntime::new(
        NodeWrappingKeyRegistrationService::new(
            local_state.node_id(),
            local_state.wrapping_public_key(),
            authentication_authority()?,
            OperatingSystemRandom,
        ),
        StorageTargetRegistrationService::new(
            local_state.open_local_database(now)?,
            authentication_authority()?,
            OperatingSystemRandom,
        ),
        StorageProviderOpeningService::new(
            authentication_authority()?,
            local_state.open_wrapping_key()?,
            local_state.state_directory().to_path_buf(),
            removal_authority_epoch,
            OperatingSystemRandom,
        )?,
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
    let partition_id = InitialBootstrapMaterial::root_partition_id(node_id)?;
    let plan = compile_plan(flat_plan(
        InitialBootstrapMaterial::initial_quorum_plan_id(node_id)?,
        INITIAL_MEMBERSHIP_EPOCH,
        BTreeSet::from([node_id]),
        BTreeSet::new(),
    )?)?;
    let mut repository = open_root_repository(local_state, now)?;
    let active_plan = match repository.load_active_consensus_quorum_plan()? {
        Some(active) => active,
        None => repository.initialise_consensus_quorum_plan(&plan, now)?,
    };
    let recovery_plan = active_plan.recovery_configuration_plan().clone();
    let incarnations =
        MemberIncarnations::for_members(BTreeMap::from([(node_id, 1)]), &active_plan.members())?;
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
) -> Result<Router, DaemonProcessError> {
    let passkey_origin = passkey_origin(https_listen);
    Ok(Router::new()
        .merge(session_lifecycle_routes(
            local_state,
            authority,
            gateway,
            now,
            &passkey_origin,
        )?)
        .merge(authentication_method_routes(
            local_state,
            authority,
            gateway,
            now,
            passkey_origin,
        )?)
        .merge(authenticated_administration_routes(
            local_state,
            authority,
            gateway,
            now,
        )?))
}

fn session_lifecycle_routes(
    local_state: &DaemonLocalState,
    authority: &MetadataAuthorityHandle,
    gateway: GatewaySessionIdentity,
    now: UnixMicros,
    passkey_origin: &str,
) -> Result<Router, DaemonProcessError> {
    Ok(Router::new()
        .merge(session_api_router(CreateSessionService::with_factors(
            open_authentication_authority(local_state, authority, now)?,
            PasskeySessionService::new(
                local_state.open_local_database(now)?,
                local_state.open_passkey_ceremony_key()?,
            ),
            ProtectedTotpFactorVerifier::new(
                open_authentication_authority(local_state, authority, now)?,
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
                open_authentication_authority(local_state, authority, now)?,
                gateway,
            ),
        )?)
        .merge(revoke_current_session_api_router(
            RevokeCurrentSessionService::new(
                open_authentication_authority(local_state, authority, now)?,
                gateway,
            ),
        )?)
        .merge(step_up_current_session_api_router(
            StepUpCurrentSessionService::new(
                open_authentication_authority(local_state, authority, now)?,
                gateway,
                ProtectedTotpFactorVerifier::new(
                    open_authentication_authority(local_state, authority, now)?,
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
) -> Result<Router, DaemonProcessError> {
    Ok(Router::new()
        .merge(api_key_issuance_api_router(
            ProtectedApiKeyIssuanceController::new(
                open_authentication_authority(local_state, authority, now)?,
                open_authentication_authority(local_state, authority, now)?,
                local_state.open_wrapping_key()?,
                gateway,
            ),
        )?)
        .merge(authentication_method_listing_api_router(
            AuthenticationMethodListingService::new(
                open_authentication_authority(local_state, authority, now)?,
                gateway,
            ),
        )?)
        .merge(authentication_method_revocation_api_router(
            AuthenticationMethodRevocationService::new(
                open_authentication_authority(local_state, authority, now)?,
                gateway,
            ),
        )?)
        .merge(totp_registration_api_router(
            TotpRegistrationService::with_secret_protector(
                local_state.open_local_database(now)?,
                open_authentication_authority(local_state, authority, now)?,
                OperatingSystemRandom,
                local_state.open_totp_ceremony_key()?,
                ProtectedTotpRegistrationSecretProtector::new(
                    open_authentication_authority(local_state, authority, now)?,
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
                open_authentication_authority(local_state, authority, now)?,
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
        )?)
        .merge(recovery_code_issuance_api_router(
            ProtectedRecoveryCodeIssuanceController::new(
                open_authentication_authority(local_state, authority, now)?,
                open_authentication_authority(local_state, authority, now)?,
                local_state.open_wrapping_key()?,
                gateway,
            ),
        )?))
}

fn authenticated_administration_routes(
    local_state: &DaemonLocalState,
    authority: &MetadataAuthorityHandle,
    gateway: GatewaySessionIdentity,
    now: UnixMicros,
) -> Result<Router, DaemonProcessError> {
    Ok(Router::new()
        .merge(identity_administration_api_router(
            IdentityAdministrationService::new(
                open_authentication_authority(local_state, authority, now)?,
                gateway,
            ),
        )?)
        .merge(node_join_grant_api_router(
            NodeJoinGrantIssuanceService::new(
                open_authentication_authority(local_state, authority, now)?,
                open_authentication_authority(local_state, authority, now)?,
                local_state.open_wrapping_key()?,
                gateway,
                local_state.https_certificate_fingerprint(),
            ),
        )?)
        .merge(volume_administration_api_router(
            VolumeAdministrationService::new(
                open_authentication_authority(local_state, authority, now)?,
                gateway,
                OperatingSystemRandom,
            ),
        )?)
        .merge(recovery_bundle_verification_api_router(
            RecoveryBundleVerificationService::new(
                open_authentication_authority(local_state, authority, now)?,
                gateway,
                local_state.pending_recovery_bundle_path(),
            ),
        )?))
}

fn open_authentication_authority(
    local_state: &DaemonLocalState,
    authority: &MetadataAuthorityHandle,
    now: UnixMicros,
) -> Result<ConsensusAuthenticationAuthority, DaemonProcessError> {
    Ok(ConsensusAuthenticationAuthority::new(
        open_root_repository(local_state, now)?,
        authority.clone(),
        tokio::runtime::Handle::current(),
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
    let outcome = match envelope.message.as_ref() {
        Some(Message::NodeActivationRequest(activation)) => {
            activate_private_node(
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
        _ => Err(NodeActivationError::Rejected),
    };
    let (result, active_revision) = activation_result(outcome);
    Ok(ControlEnvelope {
        header: Some(network.control_header(operation_id, header.deadline_unix_micros)?),
        message: Some(Message::NodeActivationResult(NodeActivationResult {
            result: Some(result),
            active_revision,
        })),
    })
}

async fn activate_private_node(
    network: &ConsensusNetwork,
    authority: &MetadataAuthorityHandle,
    state_directory: &std::path::Path,
    runtime: &tokio::runtime::Handle,
    peer: &PeerControlRequest,
    operation_id: OperationId,
    request: &meshspan_protocol::v1::NodeActivationRequest,
) -> Result<crate::NodeActivationCommit, NodeActivationError> {
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
    tokio::task::spawn_blocking(move || service.activate(activation))
        .await
        .map_err(|_| NodeActivationError::Unavailable)?
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
    native_filesystem: NativeFilesystemRuntime,
    configured_paths: Vec<PathBuf>,
    active: BTreeMap<PathBuf, NativeStorageTarget>,
    readiness: Arc<RuntimeReadiness>,
}

impl StorageTargetRuntime {
    fn new(
        wrapping_registration: NodeWrappingKeyRegistrationService<
            ConsensusAuthenticationAuthority,
            OperatingSystemRandom,
        >,
        registration: StorageTargetRegistrationService<
            ConsensusAuthenticationAuthority,
            OperatingSystemRandom,
        >,
        opening: StorageProviderOpeningService<
            ConsensusAuthenticationAuthority,
            crate::LocalWrappingKey,
            OperatingSystemRandom,
        >,
        native_filesystem: NativeFilesystemRuntime,
        configured_paths: Vec<PathBuf>,
        readiness: Arc<RuntimeReadiness>,
    ) -> Self {
        Self {
            wrapping_registration,
            registration,
            opening,
            native_filesystem,
            configured_paths,
            active: BTreeMap::new(),
            readiness,
        }
    }

    fn reconcile(&mut self, now: UnixMicros) {
        let mut failures = 0_usize;
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
        if let Some(target) = self.active.values().min_by_key(|target| target.target_id())
            && self.native_filesystem.ensure_open(target, now).is_err()
        {
            failures = failures.saturating_add(1);
        }
        self.readiness.store_degraded(failures > 0);
    }
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
    /// Manager-only recovery-bundle verification API construction failed.
    #[error("daemon recovery-bundle verification API failed")]
    RecoveryBundleVerificationApi(#[from] RecoveryBundleVerificationApiError),
    /// The HTTPS listener failed.
    #[error("daemon HTTPS listener failed")]
    Https(#[from] HttpsServerError),
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
