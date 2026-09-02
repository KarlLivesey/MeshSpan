// SPDX-License-Identifier: GPL-2.0-only

//! One restart-safe production filesystem shared by every native HTTPS route.

mod adapter;
mod classification;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use meshspan_cluster::{MetadataAuthorityHandle, MetadataFilesystemAuthorityError};
use meshspan_domain::{
    AuditEventId, BranchId, FileVersionId, InitialBootstrapMaterial, NamespaceCommitId,
    OperationId, PartitionId, UnixMicros,
};
use meshspan_filesystem::{
    AuthorisedFilesystemError, AuthorisedFilesystemService, BoundFilesystemAdapter,
    ContentAcknowledgementClass, ContentChunkLimits, ContentPublicationError,
    FilesystemAdapterConfigurationError, FilesystemAdapterPolicy, FilesystemCommitError,
    FilesystemCommitService, NamespacePublicationReceipt, ProtectedContentAccess,
    ProtectedContentPublisher, ProtectedShardRepairer, PublicationAcknowledgement,
    VerifiedPublicationHead, VersionPublicationStore,
};
use meshspan_metadata::{
    AuthoritativeCommand, AuthoritativeRepository, CommandContext, CommitConvergedVolumeHead,
    ConvergedHeadEvidence, EntityKind, MetadataStoreError, PartitionDatabase,
    StorageTargetProviderContext,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::cluster_storage_provider::ClusterShardRouter;
use crate::native_protection::NativeProtectionPolicySource;
use crate::private_consensus_runtime::PrivateConsensusRuntime;
use crate::{
    ConsensusAuthenticationAuthority, LocalFolderStorageProvider, LocalWrappingKey,
    LocalWrappingKeyError, OperatingSystemRandom, StoragePermitLoadingError,
    StoragePermitLoadingService, VolumeKeyLoadingService,
};

pub(crate) use classification::classify_native_filesystem_error;

const CONTENT_CHUNK_BYTES: usize = 4 * 1024 * 1024;
const HEAD_PUBLICATION_ATTEMPTS: usize = 32;
const HEAD_PUBLICATION_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(50);
const HEAD_AUDIT_ID_DOMAIN: &[u8] = b"meshspan.native.converged-head-audit.v1\0";
pub(crate) const MAXIMUM_NATIVE_SHARD_BYTES: usize = CONTENT_CHUNK_BYTES + 16;

type ProductionPublisher = ProtectedContentPublisher<
    ClusterShardRouter,
    meshspan_coding::ReedSolomonCoding,
    meshspan_placement::FaultAwarePlacement,
    OperatingSystemRandom,
    VolumeKeyLoadingService<ConsensusAuthenticationAuthority, LocalWrappingKey>,
    NativeProtectionPolicySource,
>;
type ProductionFilesystem =
    BoundFilesystemAdapter<ProductionPublisher, ConsensusAuthenticationAuthority>;
pub(crate) type ProductionShardRepairer =
    ProtectedShardRepairer<ClusterShardRouter, meshspan_coding::ReedSolomonCoding>;
pub(super) type ProductionFilesystemError =
    AuthorisedFilesystemError<MetadataFilesystemAuthorityError>;

/// One currently active provider target admitted to the initial single-target content layout.
#[derive(Clone)]
pub(crate) struct NativeStorageTarget {
    context: StorageTargetProviderContext,
    provider: LocalFolderStorageProvider,
}

impl NativeStorageTarget {
    /// Keeps the replicated target identity beside the cloneable live provider.
    #[must_use]
    pub(crate) const fn new(
        context: StorageTargetProviderContext,
        provider: LocalFolderStorageProvider,
    ) -> Self {
        Self { context, provider }
    }

    /// Returns the committed storage route bound to this live provider incarnation.
    #[must_use]
    pub(crate) const fn context(&self) -> StorageTargetProviderContext {
        self.context
    }

    /// Shares this target's ordered provider owner with the private data-plane service.
    #[must_use]
    pub(crate) fn provider(&self) -> LocalFolderStorageProvider {
        self.provider.clone()
    }
}

/// Immutable paths and authority handles needed to open the production filesystem after setup.
pub(crate) struct NativeFilesystemRuntimeConfiguration {
    authority_database: PathBuf,
    filesystem_state_directory: PathBuf,
    wrapping_key_path: PathBuf,
    partition_id: PartitionId,
    branch_id: BranchId,
    authority: MetadataAuthorityHandle,
    network: Arc<PrivateConsensusRuntime>,
    runtime: tokio::runtime::Handle,
    policy: FilesystemAdapterPolicy,
    chunk_limits: ContentChunkLimits,
}

impl NativeFilesystemRuntimeConfiguration {
    /// Builds one restart-stable node-local branch configuration.
    ///
    /// # Errors
    ///
    /// Rejects invalid derived identities or compiled publication policy.
    pub(crate) fn new(
        daemon_state_directory: &Path,
        wrapping_key_path: PathBuf,
        node_id: meshspan_domain::NodeId,
        partition_id: PartitionId,
        authority: MetadataAuthorityHandle,
        network: Arc<PrivateConsensusRuntime>,
        runtime: tokio::runtime::Handle,
    ) -> Result<Self, NativeFilesystemRuntimeConfigurationError> {
        Ok(Self {
            authority_database: daemon_state_directory.join("root-authority.sqlite3"),
            filesystem_state_directory: daemon_state_directory.join("filesystem"),
            wrapping_key_path,
            partition_id,
            branch_id: InitialBootstrapMaterial::local_branch_id(node_id)?,
            authority,
            network,
            runtime,
            policy: FilesystemAdapterPolicy::new(true, 1, 2)?,
            chunk_limits: ContentChunkLimits::new(CONTENT_CHUNK_BYTES)
                .map_err(|_| NativeFilesystemRuntimeConfigurationError::ChunkSize)?,
        })
    }

    fn authority(
        &self,
        now: UnixMicros,
    ) -> Result<ConsensusAuthenticationAuthority, NativeFilesystemOpeningError> {
        Ok(ConsensusAuthenticationAuthority::new_routable(
            self.repository(now)?,
            self.authority.clone(),
            self.runtime.clone(),
            Arc::clone(&self.network),
        ))
    }

    fn repository(
        &self,
        now: UnixMicros,
    ) -> Result<AuthoritativeRepository, NativeFilesystemOpeningError> {
        let database = PartitionDatabase::open(&self.authority_database, self.partition_id, now)?;
        Ok(AuthoritativeRepository::new(database))
    }

    fn wrapping_key(&self) -> Result<LocalWrappingKey, NativeFilesystemOpeningError> {
        LocalWrappingKey::open(&self.wrapping_key_path).map_err(Into::into)
    }

    fn open(
        &self,
        targets: &[NativeStorageTarget],
        now: UnixMicros,
    ) -> Result<ProductionFilesystem, NativeFilesystemOpeningError> {
        let primary = targets
            .first()
            .ok_or(NativeFilesystemOpeningError::Unavailable)?;
        if targets
            .iter()
            .any(|target| target.context.mesh_id != primary.context.mesh_id)
        {
            return Err(NativeFilesystemOpeningError::Unavailable);
        }
        let authority = self.repository(now)?;
        let permit_key =
            StoragePermitLoadingService::new(self.authority(now)?, self.wrapping_key()?)
                .load_latest(primary.context.mesh_id)?;
        let read_permit_key =
            StoragePermitLoadingService::new(self.authority(now)?, self.wrapping_key()?)
                .load_latest(primary.context.mesh_id)?;
        let content_access = ProtectedContentAccess::new(primary.context.mesh_id, read_permit_key);
        let key_service = VolumeKeyLoadingService::new(self.authority(now)?, self.wrapping_key()?);
        let router = ClusterShardRouter::new(
            primary.context.mesh_id,
            targets
                .iter()
                .map(|target| (target.context(), target.provider())),
            permit_key,
            authority,
            Arc::clone(&self.network),
            self.runtime.clone(),
        );
        let policies = NativeProtectionPolicySource::new(
            self.repository(now)?,
            targets.iter().map(NativeStorageTarget::context).collect(),
        );
        let publisher = ProtectedContentPublisher::open(
            &self.filesystem_state_directory,
            now,
            router,
            meshspan_coding::ReedSolomonCoding::new(),
            meshspan_placement::FaultAwarePlacement::new(),
            policies,
            OperatingSystemRandom,
            key_service,
            self.chunk_limits,
            content_access,
        )?;
        let filesystem =
            FilesystemCommitService::open(&self.filesystem_state_directory, now, publisher)?;
        Ok(BoundFilesystemAdapter::new(
            AuthorisedFilesystemService::new(filesystem, self.authority(now)?),
            self.branch_id,
            self.policy,
        ))
    }

    fn repairer(
        &self,
        targets: &[NativeStorageTarget],
        now: UnixMicros,
    ) -> Result<ProductionShardRepairer, NativeFilesystemOpeningError> {
        let primary = targets
            .first()
            .ok_or(NativeFilesystemOpeningError::Unavailable)?;
        if targets
            .iter()
            .any(|target| target.context.mesh_id != primary.context.mesh_id)
        {
            return Err(NativeFilesystemOpeningError::Unavailable);
        }
        let authority = self.repository(now)?;
        let permit_key =
            StoragePermitLoadingService::new(self.authority(now)?, self.wrapping_key()?)
                .load_latest(primary.context.mesh_id)?;
        let read_permit_key =
            StoragePermitLoadingService::new(self.authority(now)?, self.wrapping_key()?)
                .load_latest(primary.context.mesh_id)?;
        let router = ClusterShardRouter::new(
            primary.context.mesh_id,
            targets
                .iter()
                .map(|target| (target.context(), target.provider())),
            permit_key,
            authority,
            Arc::clone(&self.network),
            self.runtime.clone(),
        );
        Ok(ProtectedShardRepairer::new(
            router,
            meshspan_coding::ReedSolomonCoding::new(),
            primary.context.mesh_id,
            read_permit_key,
        ))
    }
}

struct NativeFilesystemRuntimeState {
    configuration: NativeFilesystemRuntimeConfiguration,
    filesystem: Option<ProductionFilesystem>,
    active_targets: Vec<StorageTargetProviderContext>,
}

/// Cloneable connector boundary backed by exactly one production filesystem state machine.
#[derive(Clone)]
pub(crate) struct NativeFilesystemRuntime {
    inner: Arc<Mutex<NativeFilesystemRuntimeState>>,
}

impl NativeFilesystemRuntime {
    /// Creates a closed runtime which becomes callable only after [`Self::ensure_open`].
    #[must_use]
    pub(crate) fn new(configuration: NativeFilesystemRuntimeConfiguration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(NativeFilesystemRuntimeState {
                configuration,
                filesystem: None,
                active_targets: Vec::new(),
            })),
        }
    }

    /// Opens the durable namespace, content catalogue and publisher once a provider is live.
    ///
    /// Exact retries are no-ops after success. Failed attempts leave the runtime closed so the
    /// storage reconciler can retry without exposing a partly composed service.
    pub(crate) fn ensure_open(
        &self,
        targets: &[NativeStorageTarget],
        now: UnixMicros,
    ) -> Result<(), NativeFilesystemOpeningError> {
        let mut state = self.lock_opening()?;
        let contexts = targets
            .iter()
            .map(NativeStorageTarget::context)
            .collect::<Vec<_>>();
        if state.filesystem.is_some() && state.active_targets == contexts {
            return Ok(());
        }
        let filesystem = state.configuration.open(targets, now)?;
        state.filesystem = Some(filesystem);
        state.active_targets = contexts;
        Ok(())
    }

    /// Opens an independent hardened content-catalogue connection for maintenance planning.
    pub(crate) fn maintenance_catalogue(
        &self,
        now: UnixMicros,
    ) -> Result<meshspan_filesystem::DurableContentCatalog, NativeFilesystemRuntimeError> {
        let state_directory = self
            .lock()?
            .configuration
            .filesystem_state_directory
            .clone();
        meshspan_filesystem::DurableContentCatalog::open(&state_directory, now)
            .map_err(|_| NativeFilesystemRuntimeError::Unavailable)
    }

    /// Builds an independent cluster-routed repair executor without holding the filesystem lock
    /// during provider IO.
    pub(crate) fn maintenance_repairer(
        &self,
        targets: &[NativeStorageTarget],
        now: UnixMicros,
    ) -> Result<ProductionShardRepairer, NativeFilesystemRuntimeError> {
        self.lock()?
            .configuration
            .repairer(targets, now)
            .map_err(|_| NativeFilesystemRuntimeError::Unavailable)
    }

    /// Resolves one fixed-revision repair policy from the same authority and target snapshot used
    /// by foreground protected writes.
    pub(crate) fn maintenance_protection_configuration(
        &self,
        targets: &[NativeStorageTarget],
        volume_id: meshspan_domain::VolumeId,
        now: UnixMicros,
    ) -> Result<meshspan_filesystem::ProtectionConfiguration, NativeFilesystemRuntimeError> {
        let state = self.lock()?;
        NativeProtectionPolicySource::new(
            state
                .configuration
                .repository(now)
                .map_err(|_| NativeFilesystemRuntimeError::Unavailable)?,
            targets.iter().map(NativeStorageTarget::context).collect(),
        )
        .current_configuration(volume_id)
        .map_err(|_| NativeFilesystemRuntimeError::Unavailable)
    }

    fn lock_opening(
        &self,
    ) -> Result<MutexGuard<'_, NativeFilesystemRuntimeState>, NativeFilesystemOpeningError> {
        self.inner
            .lock()
            .map_err(|_| NativeFilesystemOpeningError::Unavailable)
    }

    fn lock(
        &self,
    ) -> Result<MutexGuard<'_, NativeFilesystemRuntimeState>, NativeFilesystemRuntimeError> {
        self.inner
            .lock()
            .map_err(|_| NativeFilesystemRuntimeError::Unavailable)
    }

    fn with_mut<T>(
        &self,
        operation: impl FnOnce(&mut ProductionFilesystem) -> Result<T, ProductionFilesystemError>,
    ) -> Result<T, NativeFilesystemRuntimeError> {
        let mut state = self.lock()?;
        let filesystem = state
            .filesystem
            .as_mut()
            .ok_or(NativeFilesystemRuntimeError::Unavailable)?;
        operation(filesystem).map_err(Into::into)
    }

    fn with_ref<T>(
        &self,
        operation: impl FnOnce(&ProductionFilesystem) -> Result<T, ProductionFilesystemError>,
    ) -> Result<T, NativeFilesystemRuntimeError> {
        let state = self.lock()?;
        let filesystem = state
            .filesystem
            .as_ref()
            .ok_or(NativeFilesystemRuntimeError::Unavailable)?;
        operation(filesystem).map_err(Into::into)
    }

    fn publish_namespace_head(
        &self,
        namespace_commit_id: NamespaceCommitId,
        file_version_id: Option<FileVersionId>,
        observed_at: UnixMicros,
    ) -> Result<(), NativeFilesystemRuntimeError> {
        let (state_directory, target, network, runtime) = {
            let state = self.lock()?;
            (
                state.configuration.filesystem_state_directory.clone(),
                state
                    .active_targets
                    .first()
                    .copied()
                    .ok_or(NativeFilesystemRuntimeError::Unavailable)?,
                Arc::clone(&state.configuration.network),
                state.configuration.runtime.clone(),
            )
        };
        let store = VersionPublicationStore::open(&state_directory, observed_at)
            .map_err(|_| NativeFilesystemRuntimeError::Unavailable)?;
        let (volume_id, root_object_revision_id) = store
            .namespace_commit_coordinates(namespace_commit_id)
            .map_err(|_| NativeFilesystemRuntimeError::Unavailable)?;
        let content_routes = file_version_id
            .map(|version_id| {
                store
                    .published_content_for_version(version_id)
                    .map_err(|_| NativeFilesystemRuntimeError::Unavailable)?
                    .map(|content| meshspan_protocol::v1::NativeContentRoute {
                        publication_operation_id: content
                            .publication_operation_id
                            .as_bytes()
                            .to_vec(),
                        manifest_id: content.manifest.manifest_id.as_bytes().to_vec(),
                        target_id: target.target_id.as_bytes().to_vec(),
                        target_generation: target.generation,
                    })
                    .ok_or(NativeFilesystemRuntimeError::Unavailable)
            })
            .transpose()?
            .into_iter()
            .collect();
        let message = meshspan_protocol::v1::PublishNamespaceHead {
            volume_id: volume_id.as_bytes().to_vec(),
            namespace_commit_id: namespace_commit_id.as_bytes().to_vec(),
            root_object_revision_id: root_object_revision_id.as_bytes().to_vec(),
            content_routes,
        };
        let network = network
            .network()
            .map_err(|()| NativeFilesystemRuntimeError::Unavailable)?;
        let peers = network
            .peer_routes()
            .map_err(|_| NativeFilesystemRuntimeError::Unavailable)?;
        for peer in peers {
            spawn_head_publication(
                &runtime,
                network.clone(),
                peer.node_id,
                namespace_commit_id,
                observed_at,
                message.clone(),
            )?;
        }
        Ok(())
    }

    fn publish_file_head(
        &self,
        receipt: NamespacePublicationReceipt,
        observed_at: UnixMicros,
    ) -> Result<PublicationAcknowledgement, NativeFilesystemRuntimeError> {
        let state_directory = self
            .lock()?
            .configuration
            .filesystem_state_directory
            .clone();
        let store = VersionPublicationStore::open(&state_directory, observed_at)
            .map_err(|_| NativeFilesystemRuntimeError::Unavailable)?;
        let verified = store
            .verify_publication_head(receipt)
            .map_err(|_| NativeFilesystemRuntimeError::StrongBarrierFailed)?;
        let content = store
            .published_content_for_version(receipt.file_version_id)
            .map_err(|_| NativeFilesystemRuntimeError::StrongBarrierFailed)?
            .ok_or(NativeFilesystemRuntimeError::StrongBarrierFailed)?;
        let acknowledgement =
            meshspan_filesystem::DurableContentCatalog::open(&state_directory, observed_at)
                .map_err(|_| NativeFilesystemRuntimeError::Unavailable)?
                .committed_acknowledgement_evidence(content)
                .map_err(|_| NativeFilesystemRuntimeError::StrongBarrierFailed)?
                .branch_committed();
        self.publish_namespace_head(
            receipt.namespace_commit_id,
            Some(receipt.file_version_id),
            observed_at,
        )?;
        if acknowledgement.acknowledged_class == ContentAcknowledgementClass::Strong {
            self.commit_converged_head(verified, observed_at)?;
            acknowledgement
                .globally_converged()
                .ok_or(NativeFilesystemRuntimeError::StrongBarrierFailed)
        } else {
            Ok(acknowledgement)
        }
    }

    fn commit_converged_head(
        &self,
        verified: VerifiedPublicationHead,
        observed_at: UnixMicros,
    ) -> Result<(), NativeFilesystemRuntimeError> {
        let authority = self
            .lock()?
            .configuration
            .authority(observed_at)
            .map_err(|_| NativeFilesystemRuntimeError::Unavailable)?;
        let receipt = verified.receipt();
        let command = AuthoritativeCommand::CommitConvergedVolumeHead(CommitConvergedVolumeHead {
            volume_id: verified.volume_id(),
            expected_namespace_commit_id: verified.expected_namespace_commit_id(),
            namespace_commit_id: receipt.namespace_commit_id,
            root_object_revision_id: verified.root_object_revision_id(),
            evidence: ConvergedHeadEvidence::Publication {
                operation_id: receipt.operation_id,
                request_digest: receipt.request_digest,
                result_digest: receipt.result_digest,
            },
        });
        let context = CommandContext {
            operation_id: receipt.operation_id,
            actor_principal_id: verified.created_by(),
            audit_event_id: head_audit_event_id(receipt.operation_id)?,
            occurred_at: verified.created_at(),
            expected_revision: None,
        };
        let expected_digest = command.request_digest(context);
        let committed = authority
            .commit_authoritative(context, &command)
            .map_err(|error| match error {
                meshspan_cluster::MetadataAuthorityRequestError::NotLeader { .. }
                | meshspan_cluster::MetadataAuthorityRequestError::Unavailable
                | meshspan_cluster::MetadataAuthorityRequestError::Conflict
                | meshspan_cluster::MetadataAuthorityRequestError::Rejected => {
                    NativeFilesystemRuntimeError::StrongBarrierPending
                }
                meshspan_cluster::MetadataAuthorityRequestError::Unsupported
                | meshspan_cluster::MetadataAuthorityRequestError::Failed => {
                    NativeFilesystemRuntimeError::StrongBarrierFailed
                }
            })?;
        if committed.entity.kind != EntityKind::Volume
            || committed.entity.id != verified.volume_id().as_bytes()
            || committed.request_digest != expected_digest
        {
            return Err(NativeFilesystemRuntimeError::StrongBarrierFailed);
        }
        let head = authority
            .reader()
            .converged_volume_head(verified.volume_id())
            .map_err(|_| NativeFilesystemRuntimeError::StrongBarrierFailed)?
            .ok_or(NativeFilesystemRuntimeError::StrongBarrierFailed)?;
        if head.namespace_commit_id != receipt.namespace_commit_id
            || head.root_object_revision_id != verified.root_object_revision_id()
            || head.metadata_operation_id != receipt.operation_id
        {
            return Err(NativeFilesystemRuntimeError::StrongBarrierFailed);
        }
        Ok(())
    }
}

fn head_audit_event_id(
    operation_id: OperationId,
) -> Result<AuditEventId, NativeFilesystemRuntimeError> {
    let mut digest = Sha256::new();
    digest.update(HEAD_AUDIT_ID_DOMAIN);
    digest.update(operation_id.as_bytes());
    let bytes: [u8; 16] = digest.finalize()[..16]
        .try_into()
        .map(meshspan_domain::uuid_v8)
        .map_err(|_| NativeFilesystemRuntimeError::StrongBarrierFailed)?;
    AuditEventId::from_bytes(bytes).map_err(|_| NativeFilesystemRuntimeError::StrongBarrierFailed)
}

fn spawn_head_publication(
    runtime: &tokio::runtime::Handle,
    network: meshspan_cluster::ConsensusNetwork,
    peer: meshspan_domain::NodeId,
    namespace_commit_id: NamespaceCommitId,
    observed_at: UnixMicros,
    message: meshspan_protocol::v1::PublishNamespaceHead,
) -> Result<(), NativeFilesystemRuntimeError> {
    let deadline = observed_at
        .get()
        .checked_add(60 * 60 * 1_000_000)
        .ok_or(NativeFilesystemRuntimeError::Unavailable)?;
    let operation_id = publication_operation_id(namespace_commit_id, peer, observed_at)?;
    let envelope = meshspan_protocol::v1::ControlEnvelope {
        header: Some(
            network
                .control_header(operation_id, deadline)
                .map_err(|_| NativeFilesystemRuntimeError::Unavailable)?,
        ),
        message: Some(
            meshspan_protocol::v1::control_envelope::Message::PublishNamespaceHead(message),
        ),
    };
    runtime.spawn(async move {
        for attempt in 0..HEAD_PUBLICATION_ATTEMPTS {
            if network
                .request_control(peer, &envelope)
                .await
                .is_ok_and(|response| namespace_head_was_accepted(&response))
            {
                return;
            }
            if attempt + 1 < HEAD_PUBLICATION_ATTEMPTS {
                tokio::time::sleep(HEAD_PUBLICATION_RETRY_DELAY).await;
            }
        }
    });
    Ok(())
}

fn namespace_head_was_accepted(response: &meshspan_protocol::ValidatedControlEnvelope) -> bool {
    let Some(meshspan_protocol::v1::control_envelope::Message::NamespaceHeadAccepted(accepted)) =
        response.as_inner().message.as_ref()
    else {
        return false;
    };
    accepted.result.as_ref().is_some_and(|result| {
        result.outcome == i32::from(meshspan_protocol::v1::OperationOutcome::Durable)
            && result.result_digest.len() == 32
            && result.result_digest.iter().any(|byte| *byte != 0)
    })
}

fn publication_operation_id(
    namespace_commit_id: NamespaceCommitId,
    peer: meshspan_domain::NodeId,
    observed_at: UnixMicros,
) -> Result<OperationId, NativeFilesystemRuntimeError> {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.native.publish-head.v1\0");
    digest.update(namespace_commit_id.as_bytes());
    digest.update(peer.as_bytes());
    digest.update(observed_at.get().to_be_bytes());
    let bytes: [u8; 32] = digest.finalize().into();
    let mut identity = [0_u8; 16];
    identity.copy_from_slice(&bytes[..16]);
    OperationId::from_bytes(meshspan_domain::uuid_v8(identity))
        .map_err(|_| NativeFilesystemRuntimeError::Unavailable)
}

/// Closed runtime operation failures exposed only to native service classifiers.
#[derive(Debug, Error)]
pub(crate) enum NativeFilesystemRuntimeError {
    /// Setup, storage or the shared runtime lock is not currently available.
    #[error("native filesystem runtime is unavailable")]
    Unavailable,
    /// A strong publication is durably staged but metadata authority cannot currently commit it.
    #[error("strong publication is waiting for metadata authority")]
    StrongBarrierPending,
    /// Strong-publication evidence or its committed metadata result was invalid.
    #[error("strong publication verification failed")]
    StrongBarrierFailed,
    /// The composed authority or filesystem rejected the operation.
    #[error("native filesystem operation failed")]
    Operation(#[from] ProductionFilesystemError),
}

/// Failures while atomically composing the production filesystem after provider activation.
#[derive(Debug, Error)]
pub(crate) enum NativeFilesystemOpeningError {
    /// The runtime lock or another required local capability is unavailable.
    #[error("native filesystem opening is unavailable")]
    Unavailable,
    /// Root metadata could not be opened safely.
    #[error("native filesystem metadata failed")]
    Metadata(#[from] MetadataStoreError),
    /// The protected node wrapping key could not be reopened safely.
    #[error("native filesystem wrapping key failed")]
    WrappingKey(#[from] LocalWrappingKeyError),
    /// The protected storage-permit generation could not be loaded safely.
    #[error("native filesystem storage permit failed")]
    StoragePermit(#[from] StoragePermitLoadingError),
    /// The content publisher or catalogue could not be opened safely.
    #[error("native filesystem content publisher failed")]
    Content(#[from] ContentPublicationError),
    /// Namespace, stage, upload or handle state could not be opened safely.
    #[error("native filesystem state failed")]
    Filesystem(#[from] FilesystemCommitError),
}

/// Invalid compiled production filesystem configuration.
#[derive(Debug, Error)]
pub(crate) enum NativeFilesystemRuntimeConfigurationError {
    /// The local branch or partition identity could not be derived.
    #[error("native filesystem identity is invalid")]
    Identity(#[from] meshspan_domain::InitialBootstrapMaterialError),
    /// The publication policy is invalid.
    #[error("native filesystem publication policy is invalid")]
    Policy(#[from] FilesystemAdapterConfigurationError),
    /// The compiled content chunk ceiling is invalid.
    #[error("native filesystem content chunk size is invalid")]
    ChunkSize,
}
