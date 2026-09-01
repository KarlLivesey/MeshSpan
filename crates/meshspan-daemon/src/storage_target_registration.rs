// SPDX-License-Identifier: GPL-2.0-only

//! Restart-safe composition of local folder ownership and authoritative target registration.

use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use meshspan_domain::{
    AuditEventId, ComponentInstanceId, EntropyError, NodeId, OperationId, RandomSource, TargetId,
    UnixMicros, uuid_v8,
};
use meshspan_metadata::{
    AuthoritativeCommand, CommandReceipt, CreateComponent, EntityKind, LocalDatabase,
    LocalTargetError, LocalTargetState, NewLocalTarget, RecordName, RepositoryError,
    StorageTargetProviderContext, StorageTargetRegistrationContext, StorageUsageLimit,
};
use meshspan_storage::{FolderRegistration, RegisteredFolder, StorageFolderError, UsageLimit};
use sha2::{Digest, Sha256};
use thiserror::Error;

const PROVIDER_CONFIGURATION: &[u8] = b"{\"format\":\"meshspan-folder-v1\"}";
const INITIAL_TARGET_GENERATION: u64 = 1;

/// Replicated reads and consensus mutation needed to register one local storage folder.
pub trait StorageTargetRegistrationAuthority {
    /// Resolves the sole mesh, exact local topology and a current configuration authority.
    ///
    /// # Errors
    ///
    /// Fails closed when the current projection cannot be trusted.
    fn registration_context(
        &self,
        node_id: NodeId,
        now: UnixMicros,
    ) -> Result<Option<StorageTargetRegistrationContext>, StorageTargetRegistrationAuthorityError>;

    /// Commits or exactly resolves one storage-target registration through consensus.
    ///
    /// # Errors
    ///
    /// Rejects changed operation reuse and never invents success from a transport outcome.
    fn commit_or_resolve_registration(
        &self,
        context: meshspan_metadata::CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, StorageTargetRegistrationAuthorityError>;

    /// Returns the current active replicated provider configuration after registration.
    ///
    /// # Errors
    ///
    /// Fails closed when the target is absent, inactive, foreign or malformed.
    fn provider_context(
        &self,
        node_id: NodeId,
        target_id: TargetId,
    ) -> Result<Option<StorageTargetProviderContext>, StorageTargetRegistrationAuthorityError>;
}

/// One exclusively owned folder joined to its current replicated provider configuration.
pub struct RegisteredStorageTarget {
    folder: RegisteredFolder,
    context: StorageTargetProviderContext,
}

impl RegisteredStorageTarget {
    pub(crate) const fn from_validated_parts(
        folder: RegisteredFolder,
        context: StorageTargetProviderContext,
    ) -> Self {
        Self { folder, context }
    }

    /// Returns the marker identity proven by both the folder and replicated context.
    #[must_use]
    pub const fn marker(&self) -> meshspan_storage::TargetMarker {
        self.folder.marker()
    }

    /// Returns the current replicated provider configuration.
    #[must_use]
    pub const fn context(&self) -> StorageTargetProviderContext {
        self.context
    }

    /// Transfers exclusive folder ownership into a provider-opening boundary.
    #[must_use]
    pub fn into_parts(self) -> (RegisteredFolder, StorageTargetProviderContext) {
        (self.folder, self.context)
    }
}

/// Durable node-local target registration joined to one authoritative metadata command.
pub struct StorageTargetRegistrationService<A, R> {
    local: LocalDatabase,
    authority: A,
    random: R,
}

impl<A, R> StorageTargetRegistrationService<A, R> {
    /// Binds the identity-scoped local journal, root authority and cryptographic entropy source.
    #[must_use]
    pub const fn new(local: LocalDatabase, authority: A, random: R) -> Self {
        Self {
            local,
            authority,
            random,
        }
    }
}

impl<A, R> StorageTargetRegistrationService<A, R>
where
    A: StorageTargetRegistrationAuthority,
    R: RandomSource,
{
    /// Registers or resumes one configured existing folder without touching sibling files.
    ///
    /// The local intent is durable before `.meshspan` is created. Marker creation, consensus
    /// registration and final activation are separately replayable so a process or host loss at
    /// any boundary resumes the same target rather than inventing another identity.
    ///
    /// # Errors
    ///
    /// Fails this target only for unsafe paths, unavailable setup/authority, conflicting durable
    /// evidence, entropy failure or folder capability/ownership failure.
    pub fn register(
        &mut self,
        storage_path: &Path,
        now: UnixMicros,
    ) -> Result<RegisteredStorageTarget, StorageTargetRegistrationError> {
        let canonical_path = fs::canonicalize(storage_path)?;
        let canonical_bytes = canonical_path.as_os_str().as_bytes().to_vec();
        let record = if let Some(record) = self.local.local_target_by_path(&canonical_bytes)? {
            record
        } else {
            let context = self
                .authority
                .registration_context(self.local.node_id(), now)?
                .ok_or(StorageTargetRegistrationError::NotConfigured)?;
            let intent = new_intent(context, canonical_bytes, now, &mut self.random)?;
            self.local.prepare_local_target(&intent)?;
            self.local
                .local_target(intent.target_id)?
                .ok_or(StorageTargetRegistrationError::Conflict)?
        };
        let registration = folder_registration(&record)?;
        let folder = open_for_state(storage_path, registration, &record, &mut self.random)?;
        if record.state == LocalTargetState::Prepared {
            self.local.record_local_target_marker(
                record.intent.target_id,
                folder.marker().fingerprint().as_bytes(),
                now,
            )?;
        }
        let mut current = self
            .local
            .local_target(record.intent.target_id)?
            .ok_or(StorageTargetRegistrationError::Conflict)?;
        if current.state == LocalTargetState::MarkerWritten {
            let (context, command) = current.authority_input()?;
            let expected_digest = command.request_digest(context);
            let receipt = self
                .authority
                .commit_or_resolve_registration(context, &command)?;
            validate_receipt(&current, expected_digest, receipt)?;
            self.local.record_local_target_authority_commit(
                current.intent.target_id,
                receipt.result_digest,
                now,
            )?;
            current = self
                .local
                .local_target(current.intent.target_id)?
                .ok_or(StorageTargetRegistrationError::Conflict)?;
        }
        if current.state == LocalTargetState::AuthorityCommitted {
            self.local
                .activate_local_target(current.intent.target_id, now)?;
        }
        let provider = self
            .authority
            .provider_context(self.local.node_id(), current.intent.target_id)?
            .ok_or(StorageTargetRegistrationError::Conflict)?;
        validate_provider_context(&folder, &current, provider)?;
        Ok(RegisteredStorageTarget::from_validated_parts(
            folder, provider,
        ))
    }
}

fn validate_provider_context(
    folder: &RegisteredFolder,
    record: &meshspan_metadata::LocalTargetRecord,
    context: StorageTargetProviderContext,
) -> Result<(), StorageTargetRegistrationError> {
    let marker = folder.marker();
    if context.mesh_id != marker.mesh_id()
        || context.node_id != record.intent.node_id
        || context.target_id != marker.target_id()
        || context.generation != marker.generation()
        || context.policy_revision == meshspan_domain::Revision::ZERO
        || context.catalogue_revision < context.policy_revision
    {
        Err(StorageTargetRegistrationError::Conflict)
    } else {
        Ok(())
    }
}

fn new_intent(
    context: StorageTargetRegistrationContext,
    canonical_path: Vec<u8>,
    now: UnixMicros,
    random: &mut impl RandomSource,
) -> Result<NewLocalTarget, StorageTargetRegistrationError> {
    let target_id = TargetId::from_bytes(random_identifier(random)?)?;
    let operation_id = OperationId::from_bytes(random_identifier(random)?)?;
    let audit_event_id = AuditEventId::from_bytes(random_identifier(random)?)?;
    let provider_id = ComponentInstanceId::from_bytes(random_identifier(random)?)?;
    let suffix = target_id.to_string();
    let provider_configuration = PROVIDER_CONFIGURATION.to_vec();
    Ok(NewLocalTarget {
        target_id,
        registration_operation_id: operation_id,
        mesh_id: context.mesh_id,
        node_id: context.node_id,
        host_id: context.host_id,
        actor_principal_id: context.actor_principal_id,
        audit_event_id,
        provider: CreateComponent {
            instance_id: provider_id,
            component_kind: 1,
            name: RecordName::new(&format!("Folder provider {suffix}"))?,
            implementation_id: "meshspan-folder".to_owned(),
            contract_major: 1,
            contract_minor: 0,
            schema_version: 1,
            configuration_digest: Sha256::digest(&provider_configuration).into(),
            canonical_configuration: provider_configuration,
        },
        target_name: RecordName::new(&format!("Storage folder {suffix}"))?,
        canonical_path,
        generation: INITIAL_TARGET_GENERATION,
        usage_limit: StorageUsageLimit::Percent(95),
        prepared_at: now,
    })
}

fn folder_registration(
    record: &meshspan_metadata::LocalTargetRecord,
) -> Result<FolderRegistration, StorageTargetRegistrationError> {
    let usage_limit = match record.intent.usage_limit {
        StorageUsageLimit::Percent(value) => UsageLimit::percent(value)?,
        StorageUsageLimit::Bytes(value) => UsageLimit::bytes(value)?,
    };
    Ok(FolderRegistration {
        mesh_id: record.intent.mesh_id,
        target_id: record.intent.target_id,
        generation: record.intent.generation,
        usage_limit,
    })
}

fn open_for_state(
    storage_path: &Path,
    registration: FolderRegistration,
    record: &meshspan_metadata::LocalTargetRecord,
    random: &mut impl RandomSource,
) -> Result<RegisteredFolder, StorageTargetRegistrationError> {
    if record.state == LocalTargetState::Prepared {
        return match RegisteredFolder::register_new(storage_path, registration, random) {
            Ok(folder) => Ok(folder),
            Err(StorageFolderError::PrivateDirectoryNotEmpty) => {
                RegisteredFolder::reopen_pending(storage_path, registration).map_err(Into::into)
            }
            Err(error) => Err(error.into()),
        };
    }
    let fingerprint = record
        .marker_fingerprint
        .ok_or(StorageTargetRegistrationError::Conflict)?;
    RegisteredFolder::reopen(
        storage_path,
        registration,
        meshspan_storage::MarkerFingerprint::from_bytes(fingerprint),
    )
    .map_err(Into::into)
}

fn validate_receipt(
    record: &meshspan_metadata::LocalTargetRecord,
    expected_digest: [u8; 32],
    receipt: CommandReceipt,
) -> Result<(), StorageTargetRegistrationError> {
    if receipt.operation_id != record.intent.registration_operation_id
        || receipt.request_digest != expected_digest
        || receipt.result_digest == [0; 32]
        || receipt.entity.kind != EntityKind::StorageTarget
        || receipt.entity.id != record.intent.target_id.as_bytes()
    {
        Err(StorageTargetRegistrationError::Conflict)
    } else {
        Ok(())
    }
}

fn random_identifier(
    random: &mut impl RandomSource,
) -> Result<[u8; 16], StorageTargetRegistrationError> {
    let mut bytes = [0_u8; 16];
    random.fill_bytes(&mut bytes)?;
    Ok(uuid_v8(bytes))
}

/// Closed replicated-authority failure for local target setup.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum StorageTargetRegistrationAuthorityError {
    /// Current consensus projection or leader is unavailable.
    #[error("storage target authority is unavailable")]
    Unavailable,
    /// Operation identity or authoritative state conflicts with the request.
    #[error("storage target authority conflicts with the request")]
    Conflict,
    /// Persisted evidence or an invariant failed closed.
    #[error("storage target authority failed closed")]
    Failed,
}

impl From<RepositoryError> for StorageTargetRegistrationAuthorityError {
    fn from(error: RepositoryError) -> Self {
        if error.is_command_rejection() || matches!(error, RepositoryError::OperationConflict) {
            return Self::Conflict;
        }
        match error {
            RepositoryError::Store(_) | RepositoryError::Sqlite(_) | RepositoryError::Io(_) => {
                Self::Unavailable
            }
            _ => Self::Failed,
        }
    }
}

/// Target-local registration failure which never echoes attacker-controlled paths.
#[derive(Debug, Error)]
pub enum StorageTargetRegistrationError {
    /// Mesh setup or an active local topology is not yet available.
    #[error("storage target registration requires completed mesh setup")]
    NotConfigured,
    /// Durable local or authoritative evidence conflicts with this folder.
    #[error("storage target registration conflicts with durable state")]
    Conflict,
    /// Canonicalising or reading the configured folder failed.
    #[error("storage target path is unavailable")]
    Path(#[from] std::io::Error),
    /// Cryptographic target identity or marker entropy was unavailable.
    #[error("storage target entropy is unavailable")]
    Entropy(#[from] EntropyError),
    /// A generated identity was structurally invalid.
    #[error("storage target identity generation failed")]
    Identifier(#[from] meshspan_domain::IdentifierError),
    /// A generated display record was invalid.
    #[error("storage target record generation failed")]
    Name(#[from] meshspan_metadata::RecordNameError),
    /// Node-local restart evidence failed closed.
    #[error("storage target local journal failed")]
    Local(#[from] LocalTargetError),
    /// The folder marker, ownership or capability boundary failed closed.
    #[error("storage target folder failed")]
    Folder(#[from] StorageFolderError),
    /// The configured capacity ceiling was invalid.
    #[error("storage target capacity policy failed")]
    Capacity(#[from] meshspan_storage::StorageConfigError),
    /// Replicated registration could not be trusted or completed.
    #[error("storage target authority failed")]
    Authority(#[from] StorageTargetRegistrationAuthorityError),
}
