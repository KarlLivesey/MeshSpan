// SPDX-License-Identifier: GPL-2.0-only

//! Composition of one registered folder and protected mesh authority into a live provider.

use std::path::PathBuf;

use meshspan_domain::{RandomSource, UnixMicros};
use meshspan_metadata::StorageUsageLimit;
use meshspan_storage::{
    CapacityPolicy, FolderShardStore, FolderShardStoreError, SharedStorageProvider,
    StorageConfigError, StoragePermitVerifier, UsageLimit,
};
use thiserror::Error;

use crate::{
    RegisteredStorageTarget, SecretGenerationDecryptor, StoragePermitAuthority,
    StoragePermitLoadingError, StoragePermitLoadingService,
};

/// Cloneable target provider installed into filesystem and transport services.
pub type LocalFolderStorageProvider = SharedStorageProvider<FolderShardStore>;

/// Opens registered folders only after every replicated and secret safety input is present.
pub struct StorageProviderOpeningService<A, D, R> {
    permits: StoragePermitLoadingService<A, D>,
    daemon_state_directory: PathBuf,
    removal_authority_epoch: u64,
    random: R,
}

impl<A, D, R> StorageProviderOpeningService<A, D, R> {
    /// Binds one daemon state directory and current consensus authority epoch.
    ///
    /// # Errors
    ///
    /// Rejects the reserved zero authority epoch.
    pub fn new(
        authority: A,
        decryptor: D,
        daemon_state_directory: PathBuf,
        removal_authority_epoch: u64,
        random: R,
    ) -> Result<Self, StorageProviderOpeningError> {
        if removal_authority_epoch == 0 {
            return Err(StorageProviderOpeningError::InvalidConfiguration);
        }
        Ok(Self {
            permits: StoragePermitLoadingService::new(authority, decryptor),
            daemon_state_directory,
            removal_authority_epoch,
            random,
        })
    }
}

impl<A, D, R> StorageProviderOpeningService<A, D, R>
where
    A: StoragePermitAuthority,
    D: SecretGenerationDecryptor,
    R: RandomSource,
{
    /// Opens one exact folder generation with durable capacity and permit fences.
    ///
    /// # Errors
    ///
    /// Rejects stale target context, unavailable key authority, invalid policy, journal/pack
    /// corruption, target substitution and unavailable filesystem operations.
    pub fn open(
        &mut self,
        target: RegisteredStorageTarget,
        now: UnixMicros,
    ) -> Result<LocalFolderStorageProvider, StorageProviderOpeningError> {
        let (folder, context) = target.into_parts();
        let marker = folder.marker();
        if marker.mesh_id() != context.mesh_id
            || marker.target_id() != context.target_id
            || marker.generation() != context.generation
            || context.policy_revision > context.catalogue_revision
        {
            return Err(StorageProviderOpeningError::InvalidTarget);
        }
        let usage_limit = usage_limit(context.usage_limit)?;
        let permit_key = self.permits.load_latest(context.mesh_id)?;
        let verifier = StoragePermitVerifier::new(
            context.mesh_id,
            self.removal_authority_epoch,
            context.catalogue_revision,
            permit_key,
        )?;
        let provider = FolderShardStore::open(
            folder,
            &self.daemon_state_directory,
            CapacityPolicy {
                usage_limit,
                repair_reserve_bytes: 0,
                revision: context.policy_revision,
            },
            verifier,
            now,
            &mut self.random,
        )?;
        Ok(SharedStorageProvider::new(provider))
    }
}

fn usage_limit(limit: StorageUsageLimit) -> Result<UsageLimit, StorageConfigError> {
    match limit {
        StorageUsageLimit::Percent(value) => UsageLimit::percent(value),
        StorageUsageLimit::Bytes(value) => UsageLimit::bytes(value),
    }
}

/// Closed live-provider opening failures with no local path or secret detail.
#[derive(Debug, Error)]
pub enum StorageProviderOpeningError {
    /// The current consensus authority epoch is invalid.
    #[error("storage provider runtime configuration is invalid")]
    InvalidConfiguration,
    /// Folder identity and replicated target configuration disagree.
    #[error("storage provider target identity is invalid")]
    InvalidTarget,
    /// Current replicated permit authority cannot be loaded safely.
    #[error("storage provider permit authority failed")]
    Permit(#[from] StoragePermitLoadingError),
    /// Current replicated target capacity policy is invalid.
    #[error("storage provider capacity policy is invalid")]
    Capacity(#[from] StorageConfigError),
    /// The folder journal or packed-byte provider failed closed.
    #[error("storage provider failed to open")]
    Provider(#[from] FolderShardStoreError),
}
