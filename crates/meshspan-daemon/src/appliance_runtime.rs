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
use meshspan_domain::{InitialBootstrapMaterial, InitialBootstrapMaterialError, UnixMicros};
use meshspan_metadata::{
    AuthoritativeRepository, ConsensusStoreError, MetadataStoreError, PartitionDatabase,
    RepositoryError,
};
use meshspan_storage::RegisteredFolder;
use thiserror::Error;
use tokio::task::JoinHandle;

use crate::{
    BrowserAuthenticationError, BrowserSessionAuthenticator, ConsensusAuthenticationAuthority,
    ConsensusBootstrapAuthority, CreateMeshSetupController, CreateMeshSetupError,
    CreateMeshSetupService, CreateSessionService, CurrentSessionApiError, DaemonLocalState,
    DaemonLocalStateError, DisabledTotpFactors, GatewaySessionIdentity, HeadlessDaemonConfig,
    HeadlessDaemonConfigError, HttpsServer, HttpsServerError, IdentityAdministrationApiError,
    IdentityAdministrationService, NativeApiAuthenticator, NativeApiKeyAuthenticator,
    NodeWrappingKeyRegistrationService, OperatingSystemRandom, PublicContractApiError,
    ReadinessSource, RecoveryBundleVerificationApiError, RecoveryBundleVerificationService,
    RevokeCurrentSessionApiError, RevokeCurrentSessionService, SessionApiError, SetupApiError,
    SetupLifecycleError, SetupStateSnapshot, SetupStatusSource, StepUpCurrentSessionApiError,
    StepUpCurrentSessionService, StorageTargetRegistrationService, VolumeAdministrationApiError,
    VolumeAdministrationService, VolumeInventoryApiError, VolumeInventoryService,
    current_session_api_router, identity_administration_api_router, public_contract_api_router,
    recovery_bundle_verification_api_router, revoke_current_session_api_router, session_api_router,
    setup_api_router_with_creation, step_up_current_session_api_router,
    volume_administration_api_router, volume_inventory_api_router,
};

const ROOT_AUTHORITY_DATABASE: &str = "root-authority.sqlite3";
const INITIAL_MEMBERSHIP_EPOCH: u64 = 1;

type AuthorityTask = (
    MetadataAuthorityHandle,
    JoinHandle<Result<(), MetadataAuthorityRuntimeError>>,
);

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

    let (authority, authority_task) = start_root_authority(&local_state, started_at)?;
    authority.begin_election().await?;
    let readiness = Arc::new(RuntimeReadiness::default());
    let storage_targets = Arc::new(Mutex::new(StorageTargetRuntime::new(
        NodeWrappingKeyRegistrationService::new(
            local_state.node_id(),
            local_state.wrapping_public_key(),
            ConsensusAuthenticationAuthority::new(
                open_root_repository(&local_state, started_at)?,
                authority.clone(),
                tokio::runtime::Handle::current(),
            ),
            OperatingSystemRandom,
        ),
        StorageTargetRegistrationService::new(
            local_state.open_local_database(started_at)?,
            ConsensusAuthenticationAuthority::new(
                open_root_repository(&local_state, started_at)?,
                authority.clone(),
                tokio::runtime::Handle::current(),
            ),
            OperatingSystemRandom,
        ),
        config.storage().storage_paths().to_vec(),
        Arc::clone(&readiness),
    )));
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
    spawn_metadata_authority(
        driver,
        Arc::new(|_, _| {}),
        MetadataAuthorityConfig::default(),
    )
    .map_err(Into::into)
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
        .merge(session_api_router(CreateSessionService::new(
            authentication_authority()?,
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
                DisabledTotpFactors,
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
        )?)
        .merge(volume_inventory_api_router(VolumeInventoryService::new(
            NativeApiAuthenticator::new(
                BrowserSessionAuthenticator::new(authentication_authority()?, gateway),
                NativeApiKeyAuthenticator::new(authentication_authority()?, gateway),
            ),
            authentication_authority()?,
        ))?))
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
    configured_paths: Vec<PathBuf>,
    active: BTreeMap<PathBuf, RegisteredFolder>,
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
        configured_paths: Vec<PathBuf>,
        readiness: Arc<RuntimeReadiness>,
    ) -> Self {
        Self {
            wrapping_registration,
            registration,
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
                Ok(folder) => {
                    self.active.insert(canonical_path, folder);
                }
                Err(_) => failures = failures.saturating_add(1),
            }
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
    /// Identity-administration API construction failed.
    #[error("daemon identity-administration API failed")]
    IdentityAdministrationApi(#[from] IdentityAdministrationApiError),
    /// Permission-filtered volume inventory API construction failed.
    #[error("daemon volume-inventory API failed")]
    VolumeInventoryApi(#[from] VolumeInventoryApiError),
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
    /// Gateway identity could not be represented safely.
    #[error("daemon gateway identity failed")]
    GatewayIdentity(#[from] BrowserAuthenticationError),
    /// The host clock cannot be represented safely.
    #[error("daemon host clock is unavailable")]
    Clock,
}
