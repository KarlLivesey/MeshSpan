// SPDX-License-Identifier: GPL-2.0-only

//! Folder ownership for a node without a filesystem gateway or local consensus reactor.

use super::storage_node_authority::StorageNodeAuthority;
use super::{DaemonNodeRuntime, DaemonProcessError, ProductionDataRouter, open_root_repository};
use crate::{
    NativeStorageTarget, OperatingSystemRandom, StoragePermitLoadingService,
    StorageProviderOpeningService, StorageTargetRegistrationService,
};
use crate::{StoragePermitAuthority as _, StorageTargetRegistrationAuthority as _};
use meshspan_data_plane::{RemoteDataRouter, RemoteShardRouter, RemoteShardService};
use meshspan_domain::{NodeId, UnixMicros};
use std::os::unix::ffi::OsStringExt as _;
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    path::PathBuf,
    sync::Arc,
};

pub(super) struct StorageNodeProviders {
    registration: StorageTargetRegistrationService<StorageNodeAuthority, OperatingSystemRandom>,
    opening: StorageProviderOpeningService<
        StorageNodeAuthority,
        crate::LocalWrappingKey,
        OperatingSystemRandom,
    >,
    permits: StoragePermitLoadingService<StorageNodeAuthority, crate::LocalWrappingKey>,
    authority: StorageNodeAuthority,
    paths: BTreeSet<PathBuf>,
    active: BTreeMap<PathBuf, OpenProvider>,
    directory: PathBuf,
    node: NodeId,
}

struct OpenProvider {
    target: NativeStorageTarget,
    permit_generation: u64,
    membership_epoch: u64,
}

impl StorageNodeProviders {
    pub(super) fn new(
        node: &DaemonNodeRuntime,
        paths: Vec<PathBuf>,
        runtime: &tokio::runtime::Handle,
        now: UnixMicros,
    ) -> Result<Self, DaemonProcessError> {
        let local = &node.local_state;
        let authority = || {
            StorageNodeAuthority::open(
                local.state_directory(),
                Arc::clone(&node.private_network),
                runtime.clone(),
                now,
            )
        };
        let epoch = open_root_repository(local, now)?
            .load_active_consensus_quorum_plan()?
            .ok_or(DaemonProcessError::PrivateNetworkState)?
            .membership_epoch();
        Ok(Self {
            registration: StorageTargetRegistrationService::new(
                local.open_local_database(now)?,
                authority()?,
                OperatingSystemRandom,
            ),
            opening: StorageProviderOpeningService::new(
                authority()?,
                local.open_wrapping_key()?,
                local.state_directory().to_path_buf(),
                epoch,
                OperatingSystemRandom,
            )?,
            permits: StoragePermitLoadingService::new(authority()?, local.open_wrapping_key()?),
            authority: authority()?,
            paths: paths.into_iter().collect(),
            active: BTreeMap::new(),
            directory: local.state_directory().to_path_buf(),
            node: local.node_id(),
        })
    }

    /// Reopens retained media first; one failed registration cannot remove another provider.
    pub(super) fn reconcile(&mut self, now: UnixMicros) -> Result<(), ()> {
        let membership_epoch = self.authority.membership_epoch()?;
        self.opening
            .advance_removal_epoch(membership_epoch)
            .map_err(|_| ())?;
        for record in self.registration.local_targets().map_err(|_| ())? {
            self.paths.insert(PathBuf::from(OsString::from_vec(
                record.intent.canonical_path,
            )));
        }
        for record in self.registration.recovered_targets().map_err(|_| ())? {
            self.paths
                .insert(PathBuf::from(OsString::from_vec(record.canonical_path)));
        }
        let authority = &self.authority;
        let node = self.node;
        // A changed key/policy or failed probe removes only that provider from routing.
        // In-flight clones retain ownership until drained; reopening then retries normally.
        self.active
            .retain(|_, provider| matches!(installed_matches(authority, node, provider), Ok(true)));
        let mut failed = false;
        for path in &self.paths {
            let Ok(canonical) = std::fs::canonicalize(path) else {
                failed = true;
                continue;
            };
            if canonical.starts_with(&self.directory) || self.directory.starts_with(&canonical) {
                failed = true;
                continue;
            }
            if self.active.contains_key(&canonical) {
                continue;
            }
            let Ok(target) = self.registration.register(&canonical, now) else {
                failed = true;
                continue;
            };
            let context = target.context();
            let permit_generation = self
                .authority
                .latest_generation(context.mesh_id)
                .map_err(|_| ())?
                .ok_or(())?;
            match self.opening.open(target, now) {
                Ok(provider) => {
                    self.active.insert(
                        canonical,
                        OpenProvider {
                            target: NativeStorageTarget::new(context, provider),
                            permit_generation,
                            membership_epoch,
                        },
                    );
                }
                Err(_) => failed = true,
            }
        }
        if failed { Err(()) } else { Ok(()) }
    }

    /// Capability validation remains in the existing shard service; a folder path grants nothing.
    pub(super) fn router(&self) -> Result<ProductionDataRouter, ()> {
        let mut services = Vec::new();
        for provider in self.active.values() {
            if !installed_matches(&self.authority, self.node, provider)? {
                continue;
            }
            let target = &provider.target;
            let context = target.context();
            services.push(
                RemoteShardService::new(
                    target.provider(),
                    self.permits.load_latest(context.mesh_id).map_err(|_| ())?,
                    context.mesh_id,
                    self.node,
                    context.target_id,
                    context.generation,
                    crate::native_filesystem_runtime::MAXIMUM_NATIVE_SHARD_BYTES,
                )
                .map_err(|_| ())?,
            );
        }
        let count = services.len();
        let shards = RemoteShardRouter::new(services, count).map_err(|_| ())?;
        RemoteDataRouter::new(Some(shards), None).map_err(|_| ())
    }
}

/// Matches the applied projection only, never a substitute for live privileged authority.
fn installed_matches(
    authority: &StorageNodeAuthority,
    node: NodeId,
    provider: &OpenProvider,
) -> Result<bool, ()> {
    let context = provider.target.context();
    let Some(current) = authority
        .provider_context(node, context.target_id)
        .map_err(|_| ())?
    else {
        return Ok(false);
    };
    let mut installed = context;
    installed.catalogue_revision = current.catalogue_revision;
    Ok(current == installed
        && authority.membership_epoch()? == provider.membership_epoch
        && current.catalogue_revision >= context.catalogue_revision
        && authority
            .latest_generation(context.mesh_id)
            .map_err(|_| ())?
            == Some(provider.permit_generation)
        && provider.target.check_health().is_ok())
}
