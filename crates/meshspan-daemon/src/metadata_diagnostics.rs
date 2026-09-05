// SPDX-License-Identifier: GPL-2.0-only

//! Read-only local diagnostics over existing identity, metadata and reactor boundaries.

use axum::http::HeaderMap;
use meshspan_api_contract::{
    DiagnosticCounter, DiagnosticIdentifier, MetadataDiagnosticsResponse,
    RuntimeDiagnosticsResponse,
};
use meshspan_cluster::MetadataAuthorityHandle;
use meshspan_domain::UnixMicros;
use thiserror::Error;

use crate::{
    ConsensusAuthenticationAuthority, GatewaySessionIdentity, SystemManagerAuthenticationError,
    authenticate_system_manager_read,
};

#[path = "metadata_diagnostics_projection.rs"]
mod projection;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum DiagnosticsError {
    #[error("diagnostic input is invalid")]
    InvalidInput,
    #[error("authentication is required")]
    Unauthenticated,
    #[error("system-manager authority is required")]
    Forbidden,
    #[error("diagnostic collection is unavailable")]
    Unavailable,
    #[error("diagnostic evidence failed validation")]
    Failed,
}

/// Replaceable read model; the HTTP owner supplies admission, cancellation and output validation.
pub(crate) trait MetadataDiagnosticsController: Send + 'static {
    fn authenticate(&self, headers: &HeaderMap, now: UnixMicros) -> Result<(), DiagnosticsError>;
    fn collect(
        &self,
        now: UnixMicros,
        check: &dyn Fn() -> Result<(), DiagnosticsError>,
    ) -> Result<MetadataDiagnosticsResponse, DiagnosticsError>;

    fn collect_runtime(&self) -> Option<RuntimeDiagnosticsResponse> {
        None
    }
}

pub(crate) struct MetadataDiagnosticsService {
    authority: ConsensusAuthenticationAuthority,
    gateway: GatewaySessionIdentity,
    reactor: MetadataAuthorityHandle,
    runtime: tokio::runtime::Handle,
    observations: std::sync::Arc<dyn crate::runtime_observations::RuntimeObservationSource>,
}

impl MetadataDiagnosticsService {
    pub(crate) fn new(
        authority: ConsensusAuthenticationAuthority,
        gateway: GatewaySessionIdentity,
        reactor: MetadataAuthorityHandle,
        observations: std::sync::Arc<dyn crate::runtime_observations::RuntimeObservationSource>,
    ) -> Self {
        Self {
            authority,
            gateway,
            reactor,
            runtime: tokio::runtime::Handle::current(),
            observations,
        }
    }
}

impl MetadataDiagnosticsController for MetadataDiagnosticsService {
    fn collect_runtime(&self) -> Option<RuntimeDiagnosticsResponse> {
        self.observations
            .snapshot()
            .map(|snapshot| snapshot.project())
    }

    fn authenticate(&self, headers: &HeaderMap, now: UnixMicros) -> Result<(), DiagnosticsError> {
        authenticate_system_manager_read(&self.authority, self.gateway, headers, now)
            .map(|_| ())
            .map_err(|error| match error {
                SystemManagerAuthenticationError::Rejected => DiagnosticsError::Unauthenticated,
                SystemManagerAuthenticationError::Forbidden => DiagnosticsError::Forbidden,
                SystemManagerAuthenticationError::Unavailable => DiagnosticsError::Unavailable,
                SystemManagerAuthenticationError::Failed => DiagnosticsError::Failed,
            })
    }

    fn collect(
        &self,
        now: UnixMicros,
        check: &dyn Fn() -> Result<(), DiagnosticsError>,
    ) -> Result<MetadataDiagnosticsResponse, DiagnosticsError> {
        check()?;
        let repository = self.authority.reader();
        let mesh = repository
            .local_mesh_id()
            .map_err(|_| DiagnosticsError::Failed)?
            .ok_or(DiagnosticsError::Failed)?;
        let before = repository
            .current_revision()
            .map_err(|_| DiagnosticsError::Failed)?;
        let consensus = match self.runtime.block_on(self.reactor.observe()) {
            Ok(observation) => Some(projection::consensus(observation)),
            Err(meshspan_cluster::MetadataAuthorityRequestError::Unavailable) => None,
            Err(_) => return Err(DiagnosticsError::Failed),
        };
        check()?;
        let nodes = projection::nodes(repository)?;
        check()?;
        let targets = projection::targets(repository)?;
        check()?;
        let recent_operations = projection::operations(repository)?;
        check()?;
        let after = repository
            .current_revision()
            .map_err(|_| DiagnosticsError::Failed)?;
        Ok(MetadataDiagnosticsResponse {
            mesh_id: DiagnosticIdentifier(crate::create_mesh_setup::format_uuid(mesh.as_bytes())),
            partition_id: DiagnosticIdentifier(crate::create_mesh_setup::format_uuid(
                repository.partition_id().as_bytes(),
            )),
            node_id: DiagnosticIdentifier(crate::create_mesh_setup::format_uuid(
                self.gateway.node_id.as_bytes(),
            )),
            daemon_version: env!("CARGO_PKG_VERSION").to_owned(),
            collected_at_epoch_micros: now.get(),
            revision_before: DiagnosticCounter(before.get().to_string()),
            revision_after: DiagnosticCounter(after.get().to_string()),
            consensus,
            nodes,
            targets,
            recent_operations,
        })
    }
}
