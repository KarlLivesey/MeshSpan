// SPDX-License-Identifier: GPL-2.0-only

//! Native allocation namespaces share live folder accounting and one catalogue owner.

use crate::{LocalFolderStorageProvider, NativeStorageTarget, OperatingSystemClock};
use meshspan_backup::{
    DirectoryBackupProvider, IntersectedBackupCapacity, NamespacedBackupProvider,
};
use meshspan_contracts::{
    BackupObjectIdentity, BackupProvider, FederatedBackupScope, federated_provider_backup_identity,
};
use meshspan_domain::{BackupDestinationId, NodeId, TargetId, UnixMicros};
use meshspan_metadata::{
    AuthoritativeRepository, FederatedBackupCapacityBudget, LocalDatabase, PartitionDatabase,
};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use super::FederationSessionRuntimeError;
type Result<T> = std::result::Result<T, FederationSessionRuntimeError>;
type Slots = BTreeMap<BackupDestinationId, Arc<Mutex<Option<OpenedProvider>>>>;

/// The maintenance owner publishes handles only; request workers never lock maintenance IO.
#[derive(Clone, Default)]
pub(crate) struct FederationBackupTargets(Arc<Mutex<BTreeMap<TargetId, FolderTarget>>>);

#[derive(Clone)]
struct FolderTarget {
    path: PathBuf,
    target: NativeStorageTarget,
}

impl FederationBackupTargets {
    pub(crate) fn replace<'a>(
        &self,
        targets: impl IntoIterator<Item = (&'a PathBuf, &'a NativeStorageTarget)>,
    ) -> Result<()> {
        let mut next = BTreeMap::new();
        for (path, target) in targets {
            if next
                .insert(
                    target.context().target_id,
                    FolderTarget {
                        path: path.clone(),
                        target: target.clone(),
                    },
                )
                .is_some()
            {
                return Err(FederationSessionRuntimeError::Unavailable);
            }
        }
        *self
            .0
            .lock()
            .map_err(|_| FederationSessionRuntimeError::Unavailable)? = next;
        Ok(())
    }

    fn resolve(&self, scope: FederatedBackupScope) -> Result<FolderTarget> {
        let target = self
            .0
            .lock()
            .map_err(|_| FederationSessionRuntimeError::Unavailable)?
            .get(&scope.target_id)
            .cloned()
            .ok_or(FederationSessionRuntimeError::Unavailable)?;
        let context = target.target.context();
        if context.mesh_id != scope.provider_mesh_id
            || context.node_id != scope.provider_node_id
            || context.generation != scope.target_generation
        {
            return Err(FederationSessionRuntimeError::Unavailable);
        }
        target
            .target
            .check_health()
            .map_err(|_| FederationSessionRuntimeError::Unavailable)?;
        Ok(target)
    }
}

pub(crate) struct FederationBackupProviderConfiguration {
    pub(crate) targets: FederationBackupTargets,
    pub(crate) authority_database: PathBuf,
    pub(crate) local_database: PathBuf,
    pub(crate) node: NodeId,
}

pub(super) struct FederationBackupProviders {
    configuration: FederationBackupProviderConfiguration,
    slots: Mutex<Slots>,
    maximum_resident: usize,
}

struct OpenedProvider {
    scope: FederatedBackupScope,
    target: LocalFolderStorageProvider,
    provider: NamespacedBackupProvider<DirectoryBackupProvider>,
}

impl FederationBackupProviders {
    pub(super) fn new(configuration: FederationBackupProviderConfiguration) -> Self {
        let workers = std::thread::available_parallelism().map_or(4, std::num::NonZeroUsize::get);
        Self {
            configuration,
            slots: Mutex::new(BTreeMap::new()),
            maximum_resident: workers.saturating_mul(8),
        }
    }

    /// Release idle catalogues for withdrawn targets so returning folders can regain ownership.
    /// Active transfers retain their owner until completion; the next lifecycle pass retries.
    pub(super) fn retire_unavailable_targets(&self) -> Result<()> {
        let targets = self
            .configuration
            .targets
            .0
            .lock()
            .map_err(|_| FederationSessionRuntimeError::Unavailable)?
            .clone();
        let retired = {
            let mut slots = self
                .slots
                .lock()
                .map_err(|_| FederationSessionRuntimeError::Unavailable)?;
            slots
                .extract_if(.., |_, slot| {
                    if Arc::strong_count(slot) > 1 {
                        return false;
                    }
                    let Ok(opened) = slot.try_lock() else {
                        return false;
                    };
                    !opened.as_ref().is_some_and(|opened| {
                        targets.get(&opened.scope.target_id).is_some_and(|target| {
                            target.target.provider().shares_owner_with(&opened.target)
                        })
                    })
                })
                .collect::<Vec<_>>()
        };
        // Catalogue destruction may checkpoint SQL; never hold the inventory guard for that IO.
        drop(retired);
        Ok(())
    }

    /// Runs on a bounded bulk worker. Only this namespace's owner spans transfer IO.
    /// Busy namespaces reject admission rather than occupying workers waiting on another transfer.
    pub(super) fn with_provider<T>(
        &self,
        scope: FederatedBackupScope,
        object: BackupObjectIdentity,
        work: impl FnOnce(&mut dyn BackupProvider) -> Result<T>,
    ) -> Result<T> {
        if scope.provider_node_id != self.configuration.node {
            return Err(FederationSessionRuntimeError::Unavailable);
        }
        let physical = federated_provider_backup_identity(scope, object)
            .map_err(|_| FederationSessionRuntimeError::Unavailable)?;
        let target = self.configuration.targets.resolve(scope)?;
        let slot = self.slot(physical.destination_id)?;
        let mut opened = slot
            .try_lock()
            .map_err(|_| FederationSessionRuntimeError::Unavailable)?;
        if !opened.as_ref().is_some_and(|entry| {
            entry.scope == scope && entry.target.shares_owner_with(&target.target.provider())
        }) {
            // Permission revisions never create another physical namespace. Retire the old
            // catalogue under its exclusive slot before reopening with current accounting.
            *opened = None;
            *opened = Some(self.open(scope, object, &target)?);
        }
        let entry = opened
            .as_mut()
            .ok_or(FederationSessionRuntimeError::Unavailable)?;
        work(&mut entry.provider)
    }

    fn slot(&self, destination: BackupDestinationId) -> Result<Arc<Mutex<Option<OpenedProvider>>>> {
        let mut slots = self
            .slots
            .lock()
            .map_err(|_| FederationSessionRuntimeError::Unavailable)?;
        if let Some(slot) = slots.get(&destination) {
            return Ok(Arc::clone(slot));
        }
        // Bounded resident catalogues, not a limit on configured destinations. Retained
        // callers keep their slots; eviction can never open a competing live catalogue.
        let retired = if slots.len() >= self.maximum_resident {
            slots
                .extract_if(.., |_, slot| Arc::strong_count(slot) == 1)
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        if slots.len() >= self.maximum_resident {
            return Err(FederationSessionRuntimeError::Unavailable);
        }
        let slot = Arc::new(Mutex::new(None));
        slots.insert(destination, Arc::clone(&slot));
        drop(slots);
        drop(retired);
        Ok(slot)
    }

    fn open(
        &self,
        scope: FederatedBackupScope,
        object: BackupObjectIdentity,
        target: &FolderTarget,
    ) -> Result<OpenedProvider> {
        let now =
            crate::api_http::current_time().ok_or(FederationSessionRuntimeError::Unavailable)?;
        let physical = federated_provider_backup_identity(scope, object)
            .map_err(|_| FederationSessionRuntimeError::Unavailable)?;
        let allocation = self.allocation_budget(scope, object, now)?;
        let folder = target.target.provider();
        let provider = DirectoryBackupProvider::open(
            &target.path,
            physical.destination_id,
            physical.provider_generation,
            i64::MAX.unsigned_abs(),
            now,
        )
        .and_then(|provider| {
            provider.with_capacity_budget(Box::new(IntersectedBackupCapacity::new(
                Box::new(allocation),
                Box::new(folder.clone()),
            )))
        })
        .map_err(|_| FederationSessionRuntimeError::Unavailable)?;
        Ok(OpenedProvider {
            scope,
            target: folder,
            provider: NamespacedBackupProvider::new(scope, object, provider)
                .map_err(|_| FederationSessionRuntimeError::Unavailable)?,
        })
    }

    fn allocation_budget(
        &self,
        scope: FederatedBackupScope,
        object: BackupObjectIdentity,
        now: UnixMicros,
    ) -> Result<FederatedBackupCapacityBudget> {
        let repository = AuthoritativeRepository::new(
            PartitionDatabase::open_existing(&self.configuration.authority_database, now)
                .map_err(|_| FederationSessionRuntimeError::Unavailable)?,
        );
        let local = LocalDatabase::open_existing(&self.configuration.local_database, now)
            .map_err(|_| FederationSessionRuntimeError::Unavailable)?;
        FederatedBackupCapacityBudget::new(
            scope,
            object,
            repository,
            local,
            Box::new(OperatingSystemClock),
        )
        .map_err(|_| FederationSessionRuntimeError::Unavailable)
    }
}
