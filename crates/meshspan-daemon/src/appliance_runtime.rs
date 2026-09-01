// SPDX-License-Identifier: GPL-2.0-only

//! Headless process composition for the real HTTPS appliance runtime.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::future::Future;
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
    MetadataAuthorityConfig, MetadataAuthorityHandle, MetadataAuthorityRequestError,
    MetadataAuthorityRuntimeError, MetadataAuthorityStartError, PartitionConsensusDriver,
    spawn_metadata_authority,
};
use meshspan_consensus::{
    ConsensusCore, CoreConfig, CoreError, MemberIncarnations, QuorumPlanError, compile_plan,
    flat_plan,
};
use meshspan_domain::{
    DurationMicros, InitialBootstrapMaterial, InitialBootstrapMaterialError, UnixMicros,
};
use meshspan_metadata::{
    AuthoritativeRepository, ConsensusStoreError, MetadataStoreError, PartitionDatabase,
    RepositoryError,
};
use thiserror::Error;
use tokio::task::JoinHandle;

use crate::{
    ApiKeyIssuanceApiError, AuthenticationMethodListingApiError,
    AuthenticationMethodListingService, AuthenticationMethodRevocationApiError,
    AuthenticationMethodRevocationService, BrowserAuthenticationError, BrowserSessionAuthenticator,
    ConsensusAuthenticationAuthority, ConsensusBootstrapAuthority, CreateMeshSetupController,
    CreateMeshSetupError, CreateMeshSetupService, CreateSessionService, CurrentSessionApiError,
    DaemonLocalState, DaemonLocalStateError, DirectoryListingApiError, DirectoryListingService,
    DisabledPasskeySessions, FileApiRoutes, FileReadApiError, FileReadService,
    GatewaySessionIdentity, HeadlessDaemonConfig, HeadlessDaemonConfigError, HttpsServer,
    HttpsServerError, IdentityAdministrationApiError, IdentityAdministrationService,
    NativeApiAuthenticator, NativeApiKeyAuthenticator, NativeFilesystemRuntime,
    NativeFilesystemRuntimeConfiguration, NativeNamespaceMutationApiError,
    NativeNamespaceMutationService, NativeStorageTarget, NativeUploadApiError, NativeUploadService,
    NativeUploadServicePolicy, NodeWrappingKeyRegistrationService, ObjectStatApiError,
    ObjectStatService, OperatingSystemRandom, ProtectedApiKeyIssuanceController,
    ProtectedRecoveryCodeIssuanceController, ProtectedTotpFactorVerifier,
    ProtectedTotpRegistrationSecretProtector, PublicContractApiError, ReadinessSource,
    RecoveryBundleVerificationApiError, RecoveryBundleVerificationService,
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
    native_upload_api_router, object_stat_api_router, public_contract_api_router,
    recovery_bundle_verification_api_router, recovery_code_issuance_api_router,
    revoke_current_session_api_router, session_api_router, setup_api_router_with_creation,
    step_up_current_session_api_router, totp_registration_api_router,
    volume_administration_api_router, volume_inventory_api_router,
};

const ROOT_AUTHORITY_DATABASE: &str = "root-authority.sqlite3";
const INITIAL_MEMBERSHIP_EPOCH: u64 = 1;
const UPLOAD_LIFETIME_MICROS: u64 = 24 * 60 * 60 * 1_000_000;
const CONTENT_OPERATION_DEADLINE_MICROS: u64 = 60 * 1_000_000;
const TOTP_REGISTRATION_LIFETIME_MICROS: u64 = 5 * 60 * 1_000_000;
const TOTP_ISSUER: &str = "MeshSpan";

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
    let local_state = DaemonLocalState::open(&config, started_at)?;
    let setup_state = Arc::new(SetupStateSnapshot::new(SetupState::ClaimRequired));
    setup_state.reconcile(local_state.local_database())?;

    let (authority, authority_task, removal_authority_epoch) =
        start_root_authority(&local_state, started_at)?;
    authority.begin_election().await?;
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
        setup: CreateMeshSetupService::new(
            local_state.open_local_database(started_at)?,
            bootstrap,
            local_state.claim_output_path().to_path_buf(),
            local_state.pending_recovery_bundle_path(),
            Arc::clone(&setup_state),
            local_state.wrapping_public_key(),
            OperatingSystemRandom,
        ),
        storage_targets,
    };
    let gateway = GatewaySessionIdentity::new(local_state.node_id(), 1)?;
    let router = Router::new()
        .merge(public_contract_api_router(readiness)?)
        .merge(setup_api_router_with_creation(setup_state, setup)?)
        .merge(authentication_session_routes(
            &local_state,
            &authority,
            gateway,
            started_at,
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
    let (handle, task) = spawn_metadata_authority(
        driver,
        Arc::new(|_, _| {}),
        MetadataAuthorityConfig::default(),
    )
    .map_err(DaemonProcessError::from)?;
    Ok((handle, task, authority_epoch))
}

fn authentication_session_routes(
    local_state: &DaemonLocalState,
    authority: &MetadataAuthorityHandle,
    gateway: GatewaySessionIdentity,
    now: UnixMicros,
) -> Result<Router, DaemonProcessError> {
    let runtime = tokio::runtime::Handle::current();
    let authentication_authority = || {
        Ok::<_, DaemonProcessError>(ConsensusAuthenticationAuthority::new(
            open_root_repository(local_state, now)?,
            authority.clone(),
            runtime.clone(),
        ))
    };
    Ok(Router::new()
        .merge(session_api_router(CreateSessionService::with_factors(
            authentication_authority()?,
            DisabledPasskeySessions,
            ProtectedTotpFactorVerifier::new(
                authentication_authority()?,
                local_state.open_wrapping_key()?,
            ),
        ))?)
        .merge(current_session_api_router(
            BrowserSessionAuthenticator::new(authentication_authority()?, gateway),
        )?)
        .merge(revoke_current_session_api_router(
            RevokeCurrentSessionService::new(authentication_authority()?, gateway),
        )?)
        .merge(step_up_current_session_api_router(
            StepUpCurrentSessionService::new(
                authentication_authority()?,
                gateway,
                ProtectedTotpFactorVerifier::new(
                    authentication_authority()?,
                    local_state.open_wrapping_key()?,
                ),
            ),
        )?)
        .merge(api_key_issuance_api_router(
            ProtectedApiKeyIssuanceController::new(
                authentication_authority()?,
                authentication_authority()?,
                local_state.open_wrapping_key()?,
                gateway,
            ),
        )?)
        .merge(authentication_method_listing_api_router(
            AuthenticationMethodListingService::new(authentication_authority()?, gateway),
        )?)
        .merge(authentication_method_revocation_api_router(
            AuthenticationMethodRevocationService::new(authentication_authority()?, gateway),
        )?)
        .merge(totp_registration_api_router(
            TotpRegistrationService::with_secret_protector(
                local_state.open_local_database(now)?,
                authentication_authority()?,
                OperatingSystemRandom,
                local_state.open_totp_ceremony_key()?,
                ProtectedTotpRegistrationSecretProtector::new(
                    authentication_authority()?,
                    local_state.open_wrapping_key()?,
                ),
                TotpRegistrationConfiguration::new(
                    TOTP_ISSUER.to_owned(),
                    DurationMicros::new(TOTP_REGISTRATION_LIFETIME_MICROS),
                )?,
                gateway,
            ),
        )?)
        .merge(recovery_code_issuance_api_router(
            ProtectedRecoveryCodeIssuanceController::new(
                authentication_authority()?,
                authentication_authority()?,
                local_state.open_wrapping_key()?,
                gateway,
            ),
        )?)
        .merge(identity_administration_api_router(
            IdentityAdministrationService::new(authentication_authority()?, gateway),
        )?)
        .merge(volume_administration_api_router(
            VolumeAdministrationService::new(
                authentication_authority()?,
                gateway,
                OperatingSystemRandom,
            ),
        )?)
        .merge(recovery_bundle_verification_api_router(
            RecoveryBundleVerificationService::new(
                authentication_authority()?,
                gateway,
                local_state.pending_recovery_bundle_path(),
            ),
        )?))
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
    let partition_id = InitialBootstrapMaterial::root_partition_id(local_state.node_id())?;
    let database = PartitionDatabase::open(
        &local_state.state_directory().join(ROOT_AUTHORITY_DATABASE),
        partition_id,
        now,
    )?;
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
    /// Identity-administration API construction failed.
    #[error("daemon identity-administration API failed")]
    IdentityAdministrationApi(#[from] IdentityAdministrationApiError),
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
