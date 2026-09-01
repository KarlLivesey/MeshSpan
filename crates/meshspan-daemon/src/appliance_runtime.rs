// SPDX-License-Identifier: GPL-2.0-only

//! Headless process composition for the real HTTPS appliance runtime.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::future::Future;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use meshspan_api_contract::{HealthStatus, SetupState};
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
use thiserror::Error;
use tokio::task::JoinHandle;

use crate::{
    ConsensusBootstrapAuthority, CreateMeshSetupService, DaemonLocalState, DaemonLocalStateError,
    HeadlessDaemonConfig, HeadlessDaemonConfigError, HttpsServer, HttpsServerError,
    PublicContractApiError, ReadinessSource, SetupApiError, SetupLifecycleError,
    SetupStateSnapshot, public_contract_api_router, setup_api_router_with_creation,
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
    let bootstrap =
        ConsensusBootstrapAuthority::new(authority.clone(), tokio::runtime::Handle::current());
    let setup = CreateMeshSetupService::new(
        local_state.open_local_database(started_at)?,
        bootstrap,
        local_state.claim_output_path().to_path_buf(),
        Arc::clone(&setup_state),
    );
    let router = Router::new()
        .merge(public_contract_api_router(Arc::new(Ready))?)
        .merge(setup_api_router_with_creation(setup_state, setup)?);
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
    let database = PartitionDatabase::open(
        &local_state.state_directory().join(ROOT_AUTHORITY_DATABASE),
        partition_id,
        now,
    )?;
    let mut repository = AuthoritativeRepository::new(database);
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

fn current_time() -> Result<UnixMicros, DaemonProcessError> {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_micros()).ok())
        .ok_or(DaemonProcessError::Clock)?;
    Ok(UnixMicros::new(micros))
}

struct Ready;

impl ReadinessSource for Ready {
    fn status(&self) -> HealthStatus {
        HealthStatus::Ready
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
    /// The HTTPS listener failed.
    #[error("daemon HTTPS listener failed")]
    Https(#[from] HttpsServerError),
    /// The authority task ended without a typed result.
    #[error("daemon metadata authority task stopped unexpectedly")]
    AuthorityTaskStopped,
    /// The host clock cannot be represented safely.
    #[error("daemon host clock is unavailable")]
    Clock,
}
