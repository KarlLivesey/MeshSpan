// SPDX-License-Identifier: GPL-2.0-only

//! Export orchestration; keys and provider paths never cross the public boundary.

use crate::private_consensus_runtime::PrivateConsensusRuntime;
use crate::{
    ConsensusAuthenticationAuthority, GatewaySessionIdentity, MetadataBackupProviderResolver,
    RegisteredBackupTarget, RegisteredTargetBackupProviderResolver,
    SystemManagerAuthenticationError, authenticate_system_manager_read,
};
use axum::http::HeaderMap;
use meshspan_backup::{BackupFileEvidence, VerifiedBackupExport};
use meshspan_contracts::{
    BackupObjectIdentity, BackupObjectReference, BackupReadReceipt, BackupReadRequest,
    ContractVersion, RequestContext,
};
use meshspan_domain::{BackupId, OperationId, UnixMicros};
use meshspan_metadata::{
    BackupCopyRecord, BackupCopyState, BackupDestinationState, MetadataBackupState, PageLimit,
};
use std::{
    io::Write,
    sync::{Arc, Mutex},
};
use thiserror::Error;

/// Immutable export input. Deliberately not Debug: request headers can contain credentials.
pub struct BackupExportRequest {
    /// Current caller credentials, rechecked before final completion.
    pub headers: HeaderMap,
    /// Exact authorised container and embedded source state.
    pub evidence: BackupFileEvidence,
    /// Unique read operation shared by source retries.
    pub operation_id: OperationId,
    /// Absolute transfer deadline.
    pub deadline: UnixMicros,
}

/// Native export boundary independent of the HTTP body implementation.
pub trait BackupExportController: Send + Sync + 'static {
    /// Rejects unauthorised requests before parsing identifiers or looking up backups.
    ///
    /// # Errors
    /// Rejects missing, revoked or insufficient credentials and unavailable authority.
    fn authenticate(&self, headers: &HeaderMap, now: UnixMicros) -> Result<(), BackupExportError>;
    /// Returns authoritative encrypted-byte evidence, not optimistic restore readiness.
    ///
    /// # Errors
    /// Rejects absent, retired, incomplete or malformed backup records.
    fn prepare(
        &self,
        headers: &HeaderMap,
        backup_id: BackupId,
        now: UnixMicros,
    ) -> Result<BackupFileEvidence, BackupExportError>;
    /// Streams an exact copy, trying other providers only before any prefix has escaped.
    ///
    /// # Errors
    /// Rejects unavailable copies, elapsed deadlines, revoked authority and changed evidence.
    fn stream(
        &self,
        request: &BackupExportRequest,
        sink: &mut VerifiedBackupExport<&mut dyn Write>,
    ) -> Result<BackupReadReceipt, BackupExportError>;
}

pub(crate) trait BackupExportProviders: Send + Sync {
    fn snapshot(&self) -> Result<Vec<RegisteredBackupTarget>, BackupExportError>;
}

pub(crate) struct BackupExportService {
    authority: Mutex<ConsensusAuthenticationAuthority>,
    gateway: GatewaySessionIdentity,
    providers: Arc<dyn BackupExportProviders>,
    network: Arc<PrivateConsensusRuntime>,
    runtime: tokio::runtime::Handle,
}

impl BackupExportService {
    pub(crate) fn new(
        authority: ConsensusAuthenticationAuthority,
        gateway: GatewaySessionIdentity,
        providers: Arc<dyn BackupExportProviders>,
        network: Arc<PrivateConsensusRuntime>,
    ) -> Self {
        Self {
            authority: Mutex::new(authority),
            gateway,
            providers,
            network,
            runtime: tokio::runtime::Handle::current(),
        }
    }

    fn read_copy(
        &self,
        request: &BackupExportRequest,
        copy: &BackupCopyRecord,
        sink: &mut VerifiedBackupExport<&mut dyn Write>,
    ) -> Result<Option<BackupReadReceipt>, BackupExportError> {
        if copy.state != BackupCopyState::Verified {
            return Ok(None);
        }
        let now = crate::api_http::current_time().ok_or(BackupExportError::Unavailable)?;
        if now >= request.deadline {
            return Err(BackupExportError::Unavailable);
        }
        let local = RegisteredTargetBackupProviderResolver::new(self.providers.snapshot()?)
            .map_err(|_| BackupExportError::Unavailable)?;
        let provider = {
            let authority = self
                .authority
                .lock()
                .map_err(|_| BackupExportError::Failed)?;
            let destination = authority
                .reader()
                .backup_destination(copy.destination_id)
                .map_err(|_| BackupExportError::Failed)?
                .ok_or(BackupExportError::Unavailable)?;
            if destination.state == BackupDestinationState::Retired
                || destination.binding.provider_generation() != copy.provider_generation
            {
                return Ok(None);
            }
            let backup = authority
                .reader()
                .metadata_backup(request.evidence.source.backup_id)
                .map_err(|_| BackupExportError::Failed)?
                .ok_or(BackupExportError::Unavailable)?;
            let manifest = crate::backup_restore_readiness::validate_catalogue(
                backup,
                copy,
                copy.destination_id,
            )
            .map_err(|_| BackupExportError::Unavailable)?;
            if manifest.encrypted != request.evidence {
                return Err(BackupExportError::Failed);
            }
            let mut resolver = crate::cluster_backup_provider::ClusterBackupProviderResolver::new(
                request.evidence.source.mesh_id,
                self.gateway.node_id,
                authority.reader(),
                local,
                Arc::clone(&self.network),
                self.runtime.clone(),
            );
            match resolver.resolve(&destination) {
                Ok(provider) => provider,
                Err(_) => return Ok(None),
            }
        };
        let read = BackupReadRequest {
            context: RequestContext {
                contract_version: ContractVersion::V1_0,
                operation_id: request.operation_id,
                deadline: request.deadline,
                expected_revision: Some(copy.revision),
            },
            object: BackupObjectIdentity {
                backup_id: copy.backup_id,
                destination_id: copy.destination_id,
                provider_generation: copy.provider_generation,
                byte_length: copy.byte_length,
                digest: copy.copy_digest,
            },
            object_reference: BackupObjectReference::new(copy.object_reference.clone())
                .map_err(|_| BackupExportError::Failed)?,
        };
        match provider.read_exact(&read, sink, now) {
            Ok(receipt) => Ok(Some(receipt)),
            Err(_) if sink.can_restart() => {
                sink.restart().map_err(|_| BackupExportError::Failed)?;
                Ok(None)
            }
            Err(_) => Err(BackupExportError::Unavailable),
        }
    }
}

impl BackupExportController for BackupExportService {
    fn authenticate(&self, headers: &HeaderMap, now: UnixMicros) -> Result<(), BackupExportError> {
        let authority = self
            .authority
            .lock()
            .map_err(|_| BackupExportError::Failed)?;
        authenticate_system_manager_read(&*authority, self.gateway, headers, now)
            .map(|_| ())
            .map_err(authentication_error)
    }

    fn prepare(
        &self,
        headers: &HeaderMap,
        backup_id: BackupId,
        now: UnixMicros,
    ) -> Result<BackupFileEvidence, BackupExportError> {
        self.authenticate(headers, now)?;
        let authority = self
            .authority
            .lock()
            .map_err(|_| BackupExportError::Failed)?;
        let backup = authority
            .reader()
            .metadata_backup(backup_id)
            .map_err(|_| BackupExportError::Failed)?
            .ok_or(BackupExportError::NotReady)?;
        if backup.state != MetadataBackupState::Verified {
            return Err(BackupExportError::NotReady);
        }
        let source = meshspan_backup::BackupSourceManifest {
            backup_id,
            partition_id: backup.partition_id,
            mesh_id: backup.mesh_id,
            last_log_index: backup.last_log_index,
            last_log_term: backup.last_log_term,
            state_revision: backup.state_revision.get(),
            schema_version: backup.schema_version,
            byte_length: backup.source_byte_length,
            digest: backup.source_digest,
            created_at: backup.created_at,
        };
        source.validate().map_err(|_| BackupExportError::Failed)?;
        if source.catalogue_digest() != backup.manifest_digest
            || backup.encrypted_byte_length == 0
            || backup.encrypted_digest == [0; 32]
        {
            return Err(BackupExportError::Failed);
        }
        Ok(BackupFileEvidence {
            source,
            byte_length: backup.encrypted_byte_length,
            digest: backup.encrypted_digest,
        })
    }

    fn stream(
        &self,
        request: &BackupExportRequest,
        sink: &mut VerifiedBackupExport<&mut dyn Write>,
    ) -> Result<BackupReadReceipt, BackupExportError> {
        let mut after = None;
        loop {
            let now = crate::api_http::current_time().ok_or(BackupExportError::Unavailable)?;
            if now >= request.deadline {
                return Err(BackupExportError::Unavailable);
            }
            self.authenticate(&request.headers, now)?;
            let page = self
                .authority
                .lock()
                .map_err(|_| BackupExportError::Failed)?
                .reader()
                .backup_copies(
                    request.evidence.source.backup_id,
                    after,
                    PageLimit::new(32).map_err(|_| BackupExportError::Failed)?,
                )
                .map_err(|_| BackupExportError::Failed)?;
            for copy in page.items {
                if let Some(receipt) = self.read_copy(request, &copy, sink)? {
                    let now = crate::api_http::current_time()
                        .filter(|now| *now < request.deadline)
                        .ok_or(BackupExportError::Unavailable)?;
                    if self.prepare(&request.headers, copy.backup_id, now)? != request.evidence {
                        return Err(BackupExportError::Unavailable);
                    }
                    let destination = self
                        .authority
                        .lock()
                        .map_err(|_| BackupExportError::Failed)?
                        .reader()
                        .backup_destination(copy.destination_id)
                        .map_err(|_| BackupExportError::Failed)?
                        .ok_or(BackupExportError::Unavailable)?;
                    if destination.state == BackupDestinationState::Retired
                        || destination.binding.provider_generation() != copy.provider_generation
                    {
                        return Err(BackupExportError::Unavailable);
                    }
                    let current = self
                        .authority
                        .lock()
                        .map_err(|_| BackupExportError::Failed)?
                        .reader()
                        .backup_copy(copy.backup_id, copy.destination_id)
                        .map_err(|_| BackupExportError::Failed)?;
                    if current.as_ref() != Some(&copy) {
                        return Err(BackupExportError::Unavailable);
                    }
                    return Ok(receipt);
                }
            }
            let Some(next) = page.next else {
                return Err(BackupExportError::Unavailable);
            };
            after = Some(next);
        }
    }
}

fn authentication_error(error: SystemManagerAuthenticationError) -> BackupExportError {
    match error {
        SystemManagerAuthenticationError::Rejected => BackupExportError::Unauthenticated,
        SystemManagerAuthenticationError::Forbidden => BackupExportError::Forbidden,
        SystemManagerAuthenticationError::Unavailable => BackupExportError::Unavailable,
        SystemManagerAuthenticationError::Failed => BackupExportError::Failed,
    }
}

/// Closed export failures, without credentials, paths or internal provider details.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BackupExportError {
    /// Invalid path, query, limits or outgoing transfer evidence.
    #[error("backup export input is invalid")]
    InvalidInput,
    /// Caller credentials were rejected.
    #[error("backup export authentication rejected")]
    Unauthenticated,
    /// Current manager authority is required.
    #[error("backup export requires system-manager authority")]
    Forbidden,
    /// The selected generation is absent or not exportable.
    #[error("backup export generation is not ready")]
    NotReady,
    /// A required provider or authority is unavailable.
    #[error("backup export is unavailable")]
    Unavailable,
    /// Retained evidence or a component contract was contradictory.
    #[error("backup export failed closed")]
    Failed,
}
