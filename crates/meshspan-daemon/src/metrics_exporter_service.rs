// SPDX-License-Identifier: GPL-2.0-only

//! Current identity and immutable configuration authority, independent of measurement collection.

use axum::http::HeaderMap;
use meshspan_api_contract::{
    ConfigureMetricsExporterRequest, ConfigureMetricsExporterResponse, MetricsExporterResponse,
    MetricsExporterStatus,
};
use meshspan_contracts::{RuntimeMetricSnapshot, RuntimeMetricSource};
use meshspan_domain::{AuditEventId, OperationId, PrincipalId, UnixMicros, uuid_v8};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, CommandReceipt, ConfigureMetricsExporter, EntityKind,
    MetricsExporterPolicy, RepositoryError,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::{
    ConsensusAuthenticationAuthority, GatewaySessionIdentity, IdentityAdministrator,
    NativeApiKeyAuthenticator, SystemManagerAuthenticationError, authenticate_system_manager,
    authenticate_system_manager_read,
};

#[derive(Clone, Copy)]
pub(crate) enum MetricsAccess {
    ReadConfiguration,
    Configure,
    Scrape,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum MetricsError {
    #[error("metrics policy body exceeds its bound")]
    BodyTooLarge,
    #[error("metrics policy requires JSON")]
    UnsupportedMediaType,
    #[error("metrics request is invalid")]
    InvalidInput,
    #[error("metrics authentication is required")]
    Unauthenticated,
    #[error("metrics access is not granted")]
    Forbidden,
    #[error("metrics configuration conflicts")]
    Conflict,
    #[error("metrics authority or observation source is unavailable")]
    Unavailable,
    #[error("metrics evidence failed validation")]
    Failed,
}

pub(crate) trait MetricsExporterController: Send + 'static {
    fn authenticate(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
        access: MetricsAccess,
    ) -> Result<(), MetricsError>;
    fn configuration(&self) -> Result<MetricsExporterResponse, MetricsError>;
    fn configure(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
        request: ConfigureMetricsExporterRequest,
    ) -> Result<ConfigureMetricsExporterResponse, MetricsError>;
    fn collect(&self) -> Result<RuntimeMetricSnapshot, MetricsError>;
}

pub(crate) struct MetricsExporterService {
    authority: ConsensusAuthenticationAuthority,
    gateway: GatewaySessionIdentity,
    source: Arc<dyn RuntimeMetricSource>,
}

impl MetricsExporterService {
    pub(crate) fn new(
        authority: ConsensusAuthenticationAuthority,
        gateway: GatewaySessionIdentity,
        source: Arc<dyn RuntimeMetricSource>,
    ) -> Self {
        Self {
            authority,
            gateway,
            source,
        }
    }

    fn authenticate_consumer(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<(), MetricsError> {
        if headers.contains_key(axum::http::header::COOKIE) {
            return Err(MetricsError::Unauthenticated);
        }
        let principal = NativeApiKeyAuthenticator::new(&self.authority, self.gateway)
            .authenticate_principal(headers, now)
            .map_err(|error| match error {
                crate::FileApiAuthenticationError::Rejected => MetricsError::Unauthenticated,
                crate::FileApiAuthenticationError::AuthorityUnavailable => {
                    MetricsError::Unavailable
                }
                _ => MetricsError::Failed,
            })?;
        let policy = self
            .authority
            .reader()
            .metrics_exporter_configuration()
            .map_err(|error| map_repository(&error))?;
        policy
            .filter(|value| {
                value.policy.enabled
                    && value
                        .policy
                        .allowed_principals
                        .binary_search(&principal)
                        .is_ok()
            })
            .map(|_| ())
            .ok_or(MetricsError::Forbidden)
    }

    fn commit_configuration(
        &self,
        administrator: IdentityAdministrator,
        request: &ConfigureMetricsExporterRequest,
    ) -> Result<ConfigureMetricsExporterResponse, MetricsError> {
        // Independently reject malformed callers which bypass the HTTP adapter.
        meshspan_api_contract::decode_configure_metrics_exporter_request(
            &serde_json::to_vec(request).map_err(|_| MetricsError::InvalidInput)?,
        )
        .map_err(|_| MetricsError::InvalidInput)?;
        let operation = OperationId::from_bytes(
            crate::create_mesh_setup::parse_uuid(request.operation_id.as_str())
                .map_err(|_| MetricsError::InvalidInput)?,
        )
        .map_err(|_| MetricsError::InvalidInput)?;
        if let Some(receipt) = self.resolve(administrator, operation, request)? {
            return Ok(receipt);
        }
        let (context, command) = command(administrator, operation, request)?;
        match self.authority.commit_authoritative(context, &command) {
            Ok(receipt) => self.receipt(request, context, &command, receipt),
            Err(error) => self
                .resolve(administrator, operation, request)?
                .map_or_else(|| Err(map_commit(error)), Ok),
        }
    }

    fn resolve(
        &self,
        mut administrator: IdentityAdministrator,
        operation: OperationId,
        request: &ConfigureMetricsExporterRequest,
    ) -> Result<Option<ConfigureMetricsExporterResponse>, MetricsError> {
        let Some(receipt) = self
            .authority
            .reader()
            .resolve_operation(operation)
            .map_err(|error| map_repository(&error))?
        else {
            return Ok(None);
        };
        let original = self
            .authority
            .reader()
            .operation_status(operation)
            .map_err(|error| map_repository(&error))?
            .ok_or(MetricsError::Failed)?;
        if original.actor_principal_id != Some(administrator.principal_id) {
            return Err(MetricsError::Conflict);
        }
        administrator.now = original.started_at;
        let (context, command) = command(administrator, operation, request)?;
        self.receipt(request, context, &command, receipt).map(Some)
    }

    fn receipt(
        &self,
        request: &ConfigureMetricsExporterRequest,
        context: CommandContext,
        command: &AuthoritativeCommand,
        receipt: CommandReceipt,
    ) -> Result<ConfigureMetricsExporterResponse, MetricsError> {
        let mesh = self
            .authority
            .reader()
            .local_mesh_id()
            .map_err(|error| map_repository(&error))?
            .ok_or(MetricsError::Failed)?;
        let identity = meshspan_metadata::metrics_exporter_instance_id(mesh)
            .map_err(|_| MetricsError::Failed)?;
        if receipt.operation_id != context.operation_id
            || receipt.request_digest != command.request_digest(context)
            || receipt.entity.kind != EntityKind::ComponentInstance
            || receipt.entity.id != identity.as_bytes()
        {
            return Err(MetricsError::Conflict);
        }
        if receipt.result_digest == [0; 32] {
            return Err(MetricsError::Failed);
        }
        let response = ConfigureMetricsExporterResponse {
            operation_id: request.operation_id.clone(),
            sequence: request
                .expected_sequence
                .checked_add(1)
                .ok_or(MetricsError::Failed)?,
            committed_revision: receipt.committed_revision.get(),
        };
        meshspan_api_contract::encode_configure_metrics_exporter_response(&response)
            .map_err(|_| MetricsError::Failed)?;
        Ok(response)
    }
}

impl MetricsExporterController for MetricsExporterService {
    fn authenticate(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
        access: MetricsAccess,
    ) -> Result<(), MetricsError> {
        match access {
            MetricsAccess::ReadConfiguration => {
                authenticate_system_manager_read(&self.authority, self.gateway, headers, now)
                    .map(|_| ())
                    .map_err(map_authentication)
            }
            MetricsAccess::Configure => {
                authenticate_system_manager(&self.authority, self.gateway, headers, now)
                    .map(|_| ())
                    .map_err(map_authentication)
            }
            MetricsAccess::Scrape => self.authenticate_consumer(headers, now),
        }
    }

    fn configuration(&self) -> Result<MetricsExporterResponse, MetricsError> {
        let configuration = self
            .authority
            .reader()
            .metrics_exporter_configuration()
            .map_err(|error| map_repository(&error))?
            .map(|value| {
                let allowed_principals = value
                    .policy
                    .allowed_principals
                    .iter()
                    .map(|id| {
                        meshspan_api_contract::PrincipalId::from_uuid_bytes(id.as_bytes())
                            .ok_or(MetricsError::Failed)
                    })
                    .collect::<Result<_, _>>()?;
                Ok(MetricsExporterStatus {
                    sequence: value.sequence,
                    committed_revision: value.revision.get(),
                    policy: meshspan_api_contract::MetricsExporterPolicy {
                        enabled: value.policy.enabled,
                        allowed_principals,
                    },
                })
            })
            .transpose()?;
        Ok(MetricsExporterResponse { configuration })
    }

    fn configure(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
        request: ConfigureMetricsExporterRequest,
    ) -> Result<ConfigureMetricsExporterResponse, MetricsError> {
        let administrator =
            authenticate_system_manager(&self.authority, self.gateway, headers, now)
                .map_err(map_authentication)?;
        self.commit_configuration(administrator, &request)
    }

    fn collect(&self) -> Result<RuntimeMetricSnapshot, MetricsError> {
        self.source.collect_metrics().map_err(|error| match error {
            meshspan_contracts::ContractError::Unavailable
            | meshspan_contracts::ContractError::ResourceExhausted => MetricsError::Unavailable,
            _ => MetricsError::Failed,
        })
    }
}

fn command(
    administrator: IdentityAdministrator,
    operation: OperationId,
    request: &ConfigureMetricsExporterRequest,
) -> Result<(CommandContext, AuthoritativeCommand), MetricsError> {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.metrics-exporter.audit.v1\0");
    digest.update(operation.as_bytes());
    let mut audit = [0; 16];
    audit.copy_from_slice(&digest.finalize()[..16]);
    let mut allowed_principals = request
        .policy
        .allowed_principals
        .iter()
        .map(|principal| {
            PrincipalId::from_bytes(
                crate::create_mesh_setup::parse_uuid(principal.as_str())
                    .map_err(|_| MetricsError::InvalidInput)?,
            )
            .map_err(|_| MetricsError::InvalidInput)
        })
        .collect::<Result<Vec<_>, _>>()?;
    allowed_principals.sort_unstable();
    Ok((
        CommandContext {
            operation_id: operation,
            actor_principal_id: administrator.principal_id,
            audit_event_id: AuditEventId::from_bytes(uuid_v8(audit))
                .map_err(|_| MetricsError::Failed)?,
            occurred_at: administrator.now,
            expected_revision: None,
        },
        AuthoritativeCommand::ConfigureMetricsExporter(ConfigureMetricsExporter {
            expected_sequence: request.expected_sequence,
            policy: MetricsExporterPolicy {
                enabled: request.policy.enabled,
                allowed_principals,
            },
        }),
    ))
}

fn map_authentication(error: SystemManagerAuthenticationError) -> MetricsError {
    match error {
        SystemManagerAuthenticationError::Rejected => MetricsError::Unauthenticated,
        SystemManagerAuthenticationError::Forbidden => MetricsError::Forbidden,
        SystemManagerAuthenticationError::Unavailable => MetricsError::Unavailable,
        SystemManagerAuthenticationError::Failed => MetricsError::Failed,
    }
}

fn map_repository(error: &RepositoryError) -> MetricsError {
    match error {
        RepositoryError::Sqlite(_) | RepositoryError::Store(_) | RepositoryError::Io(_) => {
            MetricsError::Unavailable
        }
        _ => MetricsError::Failed,
    }
}

fn map_commit(error: meshspan_cluster::MetadataAuthorityRequestError) -> MetricsError {
    use meshspan_cluster::MetadataAuthorityRequestError as Error;
    match error {
        Error::Rejected | Error::Conflict => MetricsError::Conflict,
        Error::NotLeader { .. } | Error::Unavailable => MetricsError::Unavailable,
        Error::Unsupported | Error::Failed => MetricsError::Failed,
    }
}
