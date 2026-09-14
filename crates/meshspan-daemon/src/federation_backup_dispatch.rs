// SPDX-License-Identifier: GPL-2.0-only

//! Native signed backup admission and execution, with separate owned bulk workers.

use super::{FederationSessionRuntimeError, FederationSessions, NativeFederationSession};
use meshspan_cluster::{
    FederationBackupCapabilityService, FederationBackupIssueRequest, FederationBackupStreamContext,
    federation_connection_authority,
};
use meshspan_contracts::MAXIMUM_FEDERATED_BACKUP_PERMIT_LIFETIME_MICROS;
use meshspan_domain::UnixMicros;
use meshspan_metadata::AuthoritativeRepository;
use meshspan_protocol::{
    ValidatedFederationEnvelope,
    v1::{FederationEnvelope, federation_envelope::Message},
};
use meshspan_transport::FederationPeerRegistry;
use std::sync::Arc;

impl FederationSessions {
    fn forward_backup(
        &self,
        service: &FederationBackupCapabilityService<'_, '_>,
        authenticated: &meshspan_transport::AuthenticatedFederationBackupRequest,
        stream: meshspan_transport::AcceptedStream,
        io: FederationBackupStreamContext<'_>,
    ) -> Result<(), FederationSessionRuntimeError> {
        let now = io.clock.now();
        let admitted = service.authorise_gateway(authenticated, now)?;
        let network = self
            .private_network
            .network()
            .map_err(|()| FederationSessionRuntimeError::Unavailable)?;
        let remaining = u64::try_from(
            admitted
                .permit()
                .expires_at
                .get()
                .checked_sub(now.get())
                .ok_or(FederationSessionRuntimeError::Unavailable)?,
        )
        .map_err(|_| FederationSessionRuntimeError::Unavailable)?;
        let connection = io.runtime.block_on(async {
            tokio::time::timeout(
                std::time::Duration::from_micros(remaining),
                network.connect_data_peer(admitted.scope().provider_node_id),
            )
            .await
            .map_err(|_| FederationSessionRuntimeError::Unavailable)?
            .map_err(|_| FederationSessionRuntimeError::Unavailable)
        })?;
        let header = network
            .control_header(
                admitted.request().context().operation_id,
                admitted.permit().expires_at.get(),
            )
            .map_err(|_| FederationSessionRuntimeError::Unavailable)?;
        service
            .forward_stream(
                authenticated,
                stream,
                &meshspan_cluster::FederationBackupForwardContext {
                    io,
                    connection: &connection,
                    header,
                    limits: network.wire_limits(),
                },
            )
            .map_err(Into::into)
    }

    pub(super) async fn execute_backup(
        self: Arc<Self>,
        session: NativeFederationSession,
        stream: meshspan_transport::AcceptedStream,
        envelope: ValidatedFederationEnvelope,
    ) -> Result<(), FederationSessionRuntimeError> {
        // Bulk admission never consumes the control metadata budget. Once spawned, this
        // bounded, deadline-aware worker is observed even if its peer closes the stream.
        let permit = Arc::clone(&self.backup_admission)
            .try_acquire_owned()
            .map_err(|_| FederationSessionRuntimeError::Unavailable)?;
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            self.bulk_readers.with_reader(|reader| {
                let now = crate::api_http::current_time()
                    .ok_or(FederationSessionRuntimeError::Unavailable)?;
                let current = federation_connection_authority(reader, session.relationship, now)?
                    .ok_or(FederationSessionRuntimeError::Unavailable)?;
                let authenticated = self.replay.authenticate_backup_request(
                    &FederationPeerRegistry::new([current.peer])?,
                    &session.connection,
                    &envelope,
                    now,
                )?;
                let session_runtime = self.session_runtime_with_limits(session.limits)?;
                let identity = session_runtime.local_identity(&current, now)?;
                let service = FederationBackupCapabilityService::new(
                    reader,
                    self.node,
                    &identity,
                    &self.backup_permit_key,
                );
                let admitted = service.authorise_gateway(&authenticated, now)?;
                let io = FederationBackupStreamContext {
                    runtime: &runtime,
                    clock: &crate::OperatingSystemClock,
                    limits: session.limits.wire,
                    ready_nonce: super::random()?,
                    result_nonce: super::random()?,
                };
                if admitted.scope().provider_node_id != self.node {
                    return self.forward_backup(&service, &authenticated, stream, io);
                }
                self.backup_providers.with_provider(
                    admitted.scope(),
                    admitted.request().object(),
                    |provider| {
                        service
                            .execute_stream(&authenticated, provider, stream, &io)
                            .map_err(Into::into)
                    },
                )
            })
        })
        .await
        .map_err(|_| FederationSessionRuntimeError::Unavailable)?
    }

    pub(super) fn prepare_backup_capability(
        &self,
        reader: &AuthoritativeRepository,
        session: &NativeFederationSession,
        envelope: &ValidatedFederationEnvelope,
    ) -> Result<FederationEnvelope, FederationSessionRuntimeError> {
        let now =
            crate::api_http::current_time().ok_or(FederationSessionRuntimeError::Unavailable)?;
        let current = federation_connection_authority(reader, session.relationship, now)?
            .ok_or(FederationSessionRuntimeError::Unavailable)?;
        let authenticated = self.replay.authenticate_backup_request(
            &FederationPeerRegistry::new([current.peer])?,
            &session.connection,
            envelope,
            now,
        )?;
        let Message::RequestBackupCapability(request) = authenticated.message() else {
            return Err(FederationSessionRuntimeError::Unavailable);
        };
        let (scope, request) = meshspan_data_plane::decode_federated_backup_request(request, now)
            .map_err(|_| FederationSessionRuntimeError::Unavailable)?;
        let authority = reader
            .require_federated_backup_authority(scope, request.object().byte_length, now)
            .map_err(|_| FederationSessionRuntimeError::Unavailable)?;
        let response_nonce = super::random()?;
        let expires_at = UnixMicros::new(
            now.get()
                .checked_add(MAXIMUM_FEDERATED_BACKUP_PERMIT_LIFETIME_MICROS)
                .ok_or(FederationSessionRuntimeError::Unavailable)?,
        )
        .min(authority.allocation().valid_until())
        .min(request.context().deadline)
        .min(authenticated.response_context(response_nonce)?.deadline);
        let runtime = self.session_runtime_with_limits(session.limits)?;
        let identity = runtime.local_identity(&current, now)?;
        let service = FederationBackupCapabilityService::new(
            reader,
            self.node,
            &identity,
            &self.backup_permit_key,
        );
        let issued = service.issue(&FederationBackupIssueRequest {
            authenticated: &authenticated,
            response_nonce,
            capability_nonce: super::random()?,
            expires_at,
            observed_at: now,
            limits: session.limits.wire,
        })?;
        Ok(issued.outbound().envelope().clone())
    }
}
