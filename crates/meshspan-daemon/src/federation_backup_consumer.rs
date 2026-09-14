// SPDX-License-Identifier: GPL-2.0-only

//! Blocking backup-provider facade over the lifecycle-owned native federation session.

use super::{FederationSessions, NativeFederationSession};
use crate::cluster_backup_provider::{
    BlockingAsyncReader, BlockingAsyncWriter, map_backup_plane_error,
};
use crate::metadata_backup_provider_resolution::MetadataBackupProviderResolutionError as ResolutionError;
use meshspan_contracts::{
    BackupDeleteReceipt, BackupDeleteRequest, BackupObjectReceipt, BackupProvider,
    BackupReadReceipt, BackupReadRequest, BackupStoreRequest, BackupVerifyRequest,
    ContractError as Error, ContractKind, ContractLimits, ContractVersion, FederatedBackupRequest,
    ImplementationDescriptor,
};
use meshspan_data_plane::{
    FederatedBackupClient, FederatedBackupIo, FederatedBackupReceipt, PreparedFederatedBackupUpload,
};
use meshspan_domain::{BackupDestinationId, Clock, MeshId, UnixMicros};
use meshspan_metadata::{BackupDestinationBinding, BackupDestinationRecord};
use meshspan_transport::FederationPeerRegistry;
use std::{
    io::{Read, Write},
    sync::{Arc, OnceLock, Weak},
};

/// Shared only after listener binding; weak ownership cannot keep a stopped listener alive.
#[derive(Clone, Default)]
pub(crate) struct FederationBackupConsumer(Arc<OnceLock<Weak<FederationSessions>>>);

impl FederationBackupConsumer {
    pub(crate) fn prepare_publication(
        &self,
        destination: &BackupDestinationRecord,
        request: &crate::BackupPublicationRequest<'_>,
        authority: &dyn crate::BackupPublicationAuthority,
        runtime: &tokio::runtime::Handle,
    ) -> Result<Box<dyn BackupProvider>, crate::BackupPublicationError> {
        use crate::BackupPublicationError as PublicationError;
        use crate::backup_publication::evidence::{
            PublicationStep, command_context, object_identity, provider_context,
        };
        crate::backup_publication::validate_request(request)?;
        let BackupDestinationBinding::FederatedMesh {
            remote_mesh_id,
            provider_generation,
        } = destination.binding
        else {
            return Err(PublicationError::InvalidProjection);
        };
        let current = authority
            .backup_destination(destination.destination_id)?
            .ok_or(PublicationError::InvalidProjection)?;
        if current != *destination
            || current.state != meshspan_metadata::BackupDestinationState::Active
            || request.destination_id != destination.destination_id
        {
            return Err(PublicationError::Conflict);
        }
        let sessions = self
            .0
            .get()
            .and_then(Weak::upgrade)
            .ok_or(Error::Unavailable)?;
        let object = object_identity(
            request.evidence,
            request.destination_id,
            provider_generation,
        );
        let existing = sessions
            .bulk_readers
            .with_reader(|reader| {
                reader
                    .federated_backup_route(object.backup_id, object.destination_id)
                    .map_err(|_| super::FederationSessionRuntimeError::Unavailable)
            })
            .map_err(|_| Error::Unavailable)?;
        if let Some(existing) = existing {
            if existing.binding.object != object
                || existing.binding.scope.provider_mesh_id != remote_mesh_id
            {
                return Err(PublicationError::Conflict);
            }
            return self
                .resolve(destination, runtime.clone())
                .map_err(Into::into);
        }
        let store = BackupStoreRequest {
            context: provider_context(
                PublicationStep::StoreProvider,
                request.evidence,
                request.destination_id,
                request.now,
                request.deadline,
                destination.revision,
            )?,
            object,
        };
        let prepared =
            runtime.block_on(sessions.select_backup_allocation(remote_mesh_id, store))?;
        let command = meshspan_metadata::AuthoritativeCommand::BindFederatedBackupRoute(
            meshspan_metadata::BindFederatedBackupRoute {
                object,
                scope: prepared.scope(),
                claim: request.claim,
                expected_destination_revision: destination.revision,
            },
        );
        let context = command_context(
            PublicationStep::BindFederatedRoute,
            request.evidence,
            request.destination_id,
            request.actor_principal_id,
            crate::OperatingSystemClock.now(),
        )?;
        let receipt = authority.commit_backup_publication(context, &command)?;
        if receipt.entity.kind != meshspan_metadata::EntityKind::FederatedBackupRoute
            || receipt.entity.id != object.backup_id.as_bytes()
            || receipt.operation_id != context.operation_id
            || receipt.request_digest != command.request_digest(context)
        {
            return Err(PublicationError::InvalidReceipt);
        }
        Ok(Box::new(FederatedBackupProvider {
            sessions,
            runtime: runtime.clone(),
            destination: destination.destination_id,
            remote: remote_mesh_id,
            generation: provider_generation,
            pending: Some(prepared),
        }))
    }

    pub(crate) fn attach(&self, sessions: &Arc<FederationSessions>) -> Result<(), Error> {
        self.0
            .set(Arc::downgrade(sessions))
            .map_err(|_| Error::InternalContract)
    }

    pub(crate) fn resolve(
        &self,
        destination: &BackupDestinationRecord,
        runtime: tokio::runtime::Handle,
    ) -> Result<Box<dyn BackupProvider>, ResolutionError> {
        let BackupDestinationBinding::FederatedMesh {
            remote_mesh_id,
            provider_generation,
        } = destination.binding
        else {
            return Err(ResolutionError::Unsupported);
        };
        let sessions = self
            .0
            .get()
            .and_then(Weak::upgrade)
            .ok_or(ResolutionError::Unavailable)?;
        Ok(Box::new(FederatedBackupProvider {
            sessions,
            runtime,
            destination: destination.destination_id,
            remote: remote_mesh_id,
            generation: provider_generation,
            pending: None,
        }))
    }
}

struct FederatedBackupProvider {
    sessions: Arc<FederationSessions>,
    runtime: tokio::runtime::Handle,
    destination: BackupDestinationId,
    remote: MeshId,
    generation: u64,
    pending: Option<PreparedFederatedBackupUpload>,
}

impl FederatedBackupProvider {
    // Called only by the existing bounded blocking backup/export workers. SQL lookups and live
    // connection guards are released before network IO; this never dials a competing session.
    fn execute(
        &self,
        request: &FederatedBackupRequest,
        io: FederatedBackupIo<'_>,
        observed_at: UnixMicros,
        prepared: Option<PreparedFederatedBackupUpload>,
    ) -> Result<FederatedBackupReceipt, Error> {
        request.validate(observed_at)?;
        let object = request.object();
        if object.destination_id != self.destination
            || object.provider_generation != self.generation
        {
            return Err(Error::InvalidInput);
        }
        let scope = self
            .sessions
            .bulk_readers
            .with_reader(|reader| {
                let record = reader
                    .federated_backup_route(object.backup_id, self.destination)
                    .map_err(|_| super::FederationSessionRuntimeError::Unavailable)?
                    .ok_or(super::FederationSessionRuntimeError::Unavailable)?;
                if record.binding.object != object
                    || record.binding.scope.provider_mesh_id != self.remote
                {
                    return Err(super::FederationSessionRuntimeError::Unavailable);
                }
                Ok(record.binding.scope)
            })
            .map_err(|_| Error::Unavailable)?;
        let now = crate::OperatingSystemClock.now();
        let route = self
            .sessions
            .authority
            .route(scope.relationship_id, now)
            .map_err(|_| Error::Unavailable)?
            .ok_or(Error::Unauthorized)?;
        if route.authority.local_identity.local_mesh_id != scope.remote_mesh_id
            || route.authority.local_identity.remote_mesh_id != self.remote
        {
            return Err(Error::Unauthorized);
        }
        let session = self.sessions.live_session(&route)?;
        let runtime = self
            .sessions
            .session_runtime_with_limits(session.limits)
            .map_err(|_| Error::Unavailable)?;
        let identity = runtime
            .local_identity(&route.authority, now)
            .map_err(|_| Error::Unauthorized)?;
        let peers =
            FederationPeerRegistry::new([route.authority.peer]).map_err(|_| Error::Unauthorized)?;
        let mut client = FederatedBackupClient::new(
            &session.connection,
            &identity,
            &peers,
            session.limits.wire,
            &crate::OperatingSystemClock,
        )
        .map_err(|error| map_backup_plane_error(&error))?;
        if let Some(prepared) = prepared {
            if prepared.scope() != scope
                || *request != FederatedBackupRequest::Store(prepared.request())
            {
                return Err(Error::InvalidInput);
            }
            let FederatedBackupIo::Upload(source) = io else {
                return Err(Error::InvalidInput);
            };
            return self
                .runtime
                .block_on(client.finish_upload(prepared, source))
                .map(FederatedBackupReceipt::Stored)
                .map_err(|error| map_backup_plane_error(&error));
        }
        let scope = self.runtime.block_on(
            self.sessions
                .refresh_backup_scope(&session, &route, scope, request),
        )?;
        self.runtime
            .block_on(client.execute(scope, request, io, &mut crate::OperatingSystemRandom))
            .map_err(|error| map_backup_plane_error(&error))
    }
}

impl FederationSessions {
    pub(super) fn live_session(
        &self,
        route: &super::PairedRoute,
    ) -> Result<NativeFederationSession, Error> {
        let live = self.live.lock().map_err(|_| Error::Unavailable)?;
        let relationship = route.authority.peer.relationship_id;
        let current = live.get(&relationship).ok_or(Error::Unavailable)?;
        if !super::same_authority(&current.route, route)
            || current.connection.close_reason().is_some()
        {
            return Err(Error::Stale);
        }
        Ok(NativeFederationSession {
            relationship,
            connection: current.connection.clone(),
            limits: current.limits,
        })
    }
}

impl BackupProvider for FederatedBackupProvider {
    fn lookup_exact(
        &self,
        request: &meshspan_contracts::BackupLookupRequest,
        observed_at: UnixMicros,
    ) -> Result<BackupObjectReceipt, Error> {
        match self.execute(
            &FederatedBackupRequest::Lookup(*request),
            FederatedBackupIo::None,
            observed_at,
            None,
        )? {
            FederatedBackupReceipt::LookedUp(receipt) => Ok(receipt),
            _ => Err(Error::InternalContract),
        }
    }

    fn describe(&self) -> ImplementationDescriptor {
        ImplementationDescriptor {
            implementation_id: "meshspan-federated-quic-backup",
            contract: ContractKind::BackupProvider,
            versions: &[ContractVersion::V1_0],
            limits: ContractLimits {
                maximum_control_bytes: 64 * 1024,
                maximum_items: 1,
                maximum_concurrency: 1,
            },
        }
    }

    fn store_exact(
        &mut self,
        request: BackupStoreRequest,
        source: &mut dyn Read,
        observed_at: UnixMicros,
    ) -> Result<BackupObjectReceipt, Error> {
        let pending = self.pending.take();
        let receipt = self.execute(
            &FederatedBackupRequest::Store(request),
            FederatedBackupIo::Upload(&mut BlockingAsyncReader(source)),
            observed_at,
            pending,
        )?;
        if let FederatedBackupReceipt::Stored(value) = receipt {
            Ok(value)
        } else {
            Err(Error::InternalContract)
        }
    }

    fn read_exact(
        &self,
        request: &BackupReadRequest,
        destination: &mut dyn Write,
        observed_at: UnixMicros,
    ) -> Result<BackupReadReceipt, Error> {
        let receipt = self.execute(
            &FederatedBackupRequest::Read(request.clone()),
            FederatedBackupIo::Download(&mut BlockingAsyncWriter(destination)),
            observed_at,
            None,
        )?;
        if let FederatedBackupReceipt::Read(value) = receipt {
            Ok(value)
        } else {
            Err(Error::InternalContract)
        }
    }

    fn verify_exact(
        &self,
        request: &BackupVerifyRequest,
        observed_at: UnixMicros,
    ) -> Result<BackupObjectReceipt, Error> {
        let receipt = self.execute(
            &FederatedBackupRequest::Verify(request.clone()),
            FederatedBackupIo::None,
            observed_at,
            None,
        )?;
        if let FederatedBackupReceipt::Verified(value) = receipt {
            Ok(value)
        } else {
            Err(Error::InternalContract)
        }
    }

    fn delete_exact(
        &mut self,
        request: &BackupDeleteRequest,
        observed_at: UnixMicros,
    ) -> Result<BackupDeleteReceipt, Error> {
        let receipt = self.execute(
            &FederatedBackupRequest::Delete(request.clone()),
            FederatedBackupIo::None,
            observed_at,
            None,
        )?;
        if let FederatedBackupReceipt::Deleted(value) = receipt {
            Ok(value)
        } else {
            Err(Error::InternalContract)
        }
    }
}
