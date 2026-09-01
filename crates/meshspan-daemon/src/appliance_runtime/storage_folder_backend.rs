// SPDX-License-Identifier: GPL-2.0-only

//! Adapter between local storage-folder administration and the live appliance runtime.

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use meshspan_api_contract::{StorageFolderState, StorageFolderSummary, StorageFolderUsageLimit};
use meshspan_domain::{OperationId, UnixMicros};
use meshspan_metadata::{LocalTargetState, StorageUsageLimit};

use super::StorageTargetRuntime;
use crate::{
    NativeStorageTarget, StorageFolderAdministrationBackend,
    StorageFolderAdministrationBackendError, StorageProviderOpeningError,
    StorageTargetRegistrationAuthorityError, StorageTargetRegistrationError,
    create_mesh_setup::format_uuid,
};

impl StorageTargetRuntime {
    pub(super) fn restore_persisted_paths(
        &mut self,
    ) -> Result<(), StorageFolderAdministrationBackendError> {
        for record in self
            .registration
            .local_targets()
            .map_err(|error| map_registration_error(&error))?
        {
            let path = PathBuf::from(OsString::from_vec(record.intent.canonical_path));
            if !self.configured_paths.contains(&path) {
                self.configured_paths.push(path);
            }
        }
        Ok(())
    }

    fn folder_summaries(
        &self,
    ) -> Result<Vec<StorageFolderSummary>, StorageFolderAdministrationBackendError> {
        self.registration
            .local_targets()
            .map_err(|error| map_registration_error(&error))?
            .into_iter()
            .map(|record| {
                let path = PathBuf::from(OsString::from_vec(record.intent.canonical_path));
                let state = local_folder_state(self.active.contains_key(&path), record.state);
                Ok(StorageFolderSummary {
                    target_id: format_uuid(record.intent.target_id.as_bytes()),
                    node_id: format_uuid(record.intent.node_id.as_bytes()),
                    path: path.into_os_string().into_string().ok(),
                    generation: record.intent.generation.to_string(),
                    usage_limit: api_usage_limit(record.intent.usage_limit),
                    state,
                })
            })
            .collect()
    }

    fn register_folder(
        &mut self,
        path: &Path,
        operation_id: OperationId,
        usage_limit: StorageUsageLimit,
        now: UnixMicros,
    ) -> Result<StorageFolderSummary, StorageFolderAdministrationBackendError> {
        let canonical_path = std::fs::canonicalize(path)
            .map_err(|_| StorageFolderAdministrationBackendError::Unavailable)?;
        let target = self
            .registration
            .register_with_limit(&canonical_path, operation_id, usage_limit, now)
            .map_err(|error| map_registration_error(&error))?;
        let context = target.context();
        let provider = self
            .opening
            .open(target, now)
            .map_err(|error| map_opening_error(&error))?;
        self.active.insert(
            canonical_path.clone(),
            NativeStorageTarget::new(context, provider),
        );
        if !self.configured_paths.contains(&canonical_path) {
            self.configured_paths.push(canonical_path);
        }
        let public_target_id = format_uuid(context.target_id.as_bytes());
        self.folder_summaries()?
            .into_iter()
            .find(|folder| folder.target_id == public_target_id)
            .ok_or(StorageFolderAdministrationBackendError::Failed)
    }
}

impl StorageFolderAdministrationBackend for Arc<Mutex<StorageTargetRuntime>> {
    fn storage_folders(
        &self,
    ) -> Result<Vec<StorageFolderSummary>, StorageFolderAdministrationBackendError> {
        self.lock()
            .map_err(|_| StorageFolderAdministrationBackendError::Unavailable)?
            .folder_summaries()
    }

    fn register_storage_folder(
        &mut self,
        path: PathBuf,
        operation_id: OperationId,
        usage_limit: StorageUsageLimit,
        now: UnixMicros,
    ) -> Result<StorageFolderSummary, StorageFolderAdministrationBackendError> {
        self.lock()
            .map_err(|_| StorageFolderAdministrationBackendError::Unavailable)?
            .register_folder(&path, operation_id, usage_limit, now)
    }
}

const fn local_folder_state(active: bool, durable: LocalTargetState) -> StorageFolderState {
    if active {
        StorageFolderState::Active
    } else if matches!(durable, LocalTargetState::Active) {
        StorageFolderState::Unavailable
    } else {
        StorageFolderState::Configuring
    }
}

fn api_usage_limit(value: StorageUsageLimit) -> StorageFolderUsageLimit {
    match value {
        StorageUsageLimit::Percent(percent) => StorageFolderUsageLimit::Percent { percent },
        StorageUsageLimit::Bytes(bytes) => StorageFolderUsageLimit::Bytes {
            bytes: bytes.to_string(),
        },
    }
}

const fn map_registration_error(
    error: &StorageTargetRegistrationError,
) -> StorageFolderAdministrationBackendError {
    match error {
        StorageTargetRegistrationError::Conflict => {
            StorageFolderAdministrationBackendError::Conflict
        }
        StorageTargetRegistrationError::Path(_)
        | StorageTargetRegistrationError::NotConfigured
        | StorageTargetRegistrationError::Authority(
            StorageTargetRegistrationAuthorityError::Unavailable,
        ) => StorageFolderAdministrationBackendError::Unavailable,
        StorageTargetRegistrationError::Folder(_) | StorageTargetRegistrationError::Capacity(_) => {
            StorageFolderAdministrationBackendError::InvalidInput
        }
        StorageTargetRegistrationError::Entropy(_)
        | StorageTargetRegistrationError::Identifier(_)
        | StorageTargetRegistrationError::Name(_)
        | StorageTargetRegistrationError::Local(_)
        | StorageTargetRegistrationError::Authority(_) => {
            StorageFolderAdministrationBackendError::Failed
        }
    }
}

const fn map_opening_error(
    error: &StorageProviderOpeningError,
) -> StorageFolderAdministrationBackendError {
    match error {
        StorageProviderOpeningError::Permit(_) => {
            StorageFolderAdministrationBackendError::Unavailable
        }
        StorageProviderOpeningError::Capacity(_) => {
            StorageFolderAdministrationBackendError::InvalidInput
        }
        StorageProviderOpeningError::InvalidConfiguration
        | StorageProviderOpeningError::InvalidTarget
        | StorageProviderOpeningError::Provider(_) => {
            StorageFolderAdministrationBackendError::Failed
        }
    }
}
