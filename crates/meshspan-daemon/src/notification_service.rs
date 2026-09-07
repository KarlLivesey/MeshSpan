// SPDX-License-Identifier: GPL-2.0-only

//! Authenticated administration over the same encrypted, replicated channel commands as workers.

use crate::notification_runtime::NotificationHealth;
use crate::{
    ConsensusAuthenticationAuthority, GatewaySessionIdentity, IdentityAdministrator,
    LocalWrappingKey, SystemManagerAuthenticationError, authenticate_system_manager,
    authenticate_system_manager_read,
};
use axum::http::HeaderMap;
use meshspan_api_contract::{
    ConfigureNotificationRequest, ConfigureNotificationResponse, NotificationChannelStatus,
    NotificationKind, NotificationSettingsUpdate, NotificationWorkerStatus, NotificationsResponse,
};
use meshspan_domain::{AuditEventId, ComponentInstanceId, OperationId, UnixMicros, uuid_v8};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, CommandReceipt, CommitSecretGeneration,
    ConfigureNotificationChannel, EntityKind, NOTIFICATION_SETTINGS_SECRET_KIND,
    NotificationChannelKind, NotificationChannelRecord, RecordName,
};
use meshspan_secret_envelope::SecretContext;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum NotificationError {
    #[error("notification input is invalid")]
    Invalid,
    #[error("notification authentication is required")]
    Unauthenticated,
    #[error("notification administration is not granted")]
    Forbidden,
    #[error("notification configuration conflicts with current state")]
    Conflict,
    #[error("notification authority is unavailable")]
    Unavailable,
    #[error("notification evidence failed validation")]
    Failed,
    #[error("notification body exceeds its limit")]
    BodyTooLarge,
    #[error("notification configuration requires JSON")]
    MediaType,
}

pub(crate) struct NotificationService {
    authority: ConsensusAuthenticationAuthority,
    gateway: GatewaySessionIdentity,
    key: LocalWrappingKey,
    health: NotificationHealth,
}

impl NotificationService {
    pub(crate) const fn new(
        authority: ConsensusAuthenticationAuthority,
        gateway: GatewaySessionIdentity,
        key: LocalWrappingKey,
        health: NotificationHealth,
    ) -> Self {
        Self {
            authority,
            gateway,
            key,
            health,
        }
    }

    pub(crate) fn authenticate(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
        mutation: bool,
    ) -> Result<IdentityAdministrator, NotificationError> {
        let result = if mutation {
            authenticate_system_manager(&self.authority, self.gateway, headers, now)
        } else {
            authenticate_system_manager_read(&self.authority, self.gateway, headers, now)
        };
        result.map_err(|error| match error {
            SystemManagerAuthenticationError::Rejected => NotificationError::Unauthenticated,
            SystemManagerAuthenticationError::Forbidden => NotificationError::Forbidden,
            SystemManagerAuthenticationError::Unavailable => NotificationError::Unavailable,
            SystemManagerAuthenticationError::Failed => NotificationError::Failed,
        })
    }

    pub(crate) fn status(&self) -> Result<NotificationsResponse, NotificationError> {
        let channels = self
            .authority
            .reader()
            .notification_channels()
            .map_err(|_| NotificationError::Unavailable)?
            .into_iter()
            .map(|channel| {
                let counts = self
                    .authority
                    .reader()
                    .notification_delivery_counts(channel.channel_id)
                    .map_err(|_| NotificationError::Unavailable)?;
                Ok(NotificationChannelStatus {
                    channel_id: crate::create_mesh_setup::format_uuid(
                        channel.channel_id.as_bytes(),
                    ),
                    sequence: channel.sequence,
                    display_name: channel.display_name.display().to_owned(),
                    kind: match channel.kind {
                        NotificationChannelKind::Webhook => NotificationKind::Webhook,
                        NotificationChannelKind::Email => NotificationKind::Email,
                    },
                    enabled: channel.enabled,
                    event_filter: channel.event_filter,
                    deliveries: meshspan_api_contract::NotificationDeliveryCounts {
                        pending: counts.pending.to_string(),
                        accepted: counts.accepted.to_string(),
                        rejected: counts.rejected.to_string(),
                        cancelled: counts.cancelled.to_string(),
                    },
                })
            })
            .collect::<Result<_, NotificationError>>()?;
        let worker = match self.health.code() {
            0 => NotificationWorkerStatus::Running,
            1 => NotificationWorkerStatus::Retrying,
            _ => NotificationWorkerStatus::Stopped,
        };
        Ok(NotificationsResponse { channels, worker })
    }

    pub(crate) fn configure(
        &self,
        administrator: IdentityAdministrator,
        request: &ConfigureNotificationRequest,
    ) -> Result<ConfigureNotificationResponse, NotificationError> {
        let encoded = zeroize::Zeroizing::new(
            serde_json::to_vec(request).map_err(|_| NotificationError::Invalid)?,
        );
        meshspan_api_contract::decode_configure_notification_request(&encoded)
            .map_err(|_| NotificationError::Invalid)?;
        let operation = OperationId::from_bytes(parse(request.operation_id.as_str())?)
            .map_err(|_| NotificationError::Invalid)?;
        if let Some(receipt) = self
            .authority
            .reader()
            .resolve_operation(operation)
            .map_err(|_| NotificationError::Unavailable)?
        {
            return self.retry(administrator, operation, request, receipt);
        }
        let command = self.configuration(operation, request, None)?;
        let context = context(administrator, operation)?;
        let Ok(receipt) = self.authority.commit_authoritative(context, &command) else {
            if let Some(receipt) = self
                .authority
                .reader()
                .resolve_operation(operation)
                .map_err(|_| NotificationError::Unavailable)?
            {
                return self.retry(administrator, operation, request, receipt);
            }
            return Err(NotificationError::Conflict);
        };
        verify_receipt(request, context, &command, receipt)
    }

    fn retry(
        &self,
        mut administrator: IdentityAdministrator,
        operation: OperationId,
        request: &ConfigureNotificationRequest,
        receipt: CommandReceipt,
    ) -> Result<ConfigureNotificationResponse, NotificationError> {
        let original = self
            .authority
            .reader()
            .operation_status(operation)
            .map_err(|_| NotificationError::Unavailable)?
            .ok_or(NotificationError::Failed)?;
        if original.actor_principal_id != Some(administrator.principal_id) {
            return Err(NotificationError::Conflict);
        }
        administrator.now = original.started_at;
        let channel = ComponentInstanceId::from_bytes(parse(&request.channel_id)?)
            .map_err(|_| NotificationError::Invalid)?;
        let original = self
            .authority
            .reader()
            .notification_configuration(channel, request.expected_sequence + 1)
            .map_err(|_| NotificationError::Unavailable)?
            .ok_or(NotificationError::Conflict)?;
        let command = self.configuration(operation, request, Some(original))?;
        verify_receipt(
            request,
            context(administrator, operation)?,
            &command,
            receipt,
        )
    }

    fn configuration(
        &self,
        operation: OperationId,
        request: &ConfigureNotificationRequest,
        original: Option<NotificationChannelRecord>,
    ) -> Result<AuthoritativeCommand, NotificationError> {
        let channel_id = ComponentInstanceId::from_bytes(parse(&request.channel_id)?)
            .map_err(|_| NotificationError::Invalid)?;
        let record = match original {
            Some(record) => Some(record),
            None => self
                .authority
                .reader()
                .notification_channel(channel_id)
                .map_err(|_| NotificationError::Unavailable)?,
        };
        let (settings, commitment, new_settings, kind) = match &request.settings {
            NotificationSettingsUpdate::Retain => {
                let record = record.ok_or(NotificationError::Conflict)?;
                (
                    record.settings,
                    record.settings_commitment,
                    None,
                    record.kind,
                )
            }
            NotificationSettingsUpdate::Replace { destination } => {
                let prepared = if let Some(record) =
                    record.filter(|record| record.settings.secret_id == operation.as_bytes())
                {
                    self.recover_settings(&record, destination)?
                } else {
                    crate::notification_settings::prepare(
                        &self.authority,
                        operation.as_bytes(),
                        destination,
                    )
                    .map_err(|_| NotificationError::Failed)?
                };
                let kind = match destination {
                    meshspan_api_contract::NotificationDestination::Webhook { .. } => {
                        NotificationChannelKind::Webhook
                    }
                    meshspan_api_contract::NotificationDestination::Email { .. } => {
                        NotificationChannelKind::Email
                    }
                };
                (
                    prepared.reference,
                    prepared.commitment,
                    Some(prepared.generation),
                    kind,
                )
            }
        };
        Ok(AuthoritativeCommand::ConfigureNotificationChannel(
            ConfigureNotificationChannel {
                channel_id,
                expected_sequence: request.expected_sequence,
                display_name: RecordName::new(&request.display_name)
                    .map_err(|_| NotificationError::Invalid)?,
                kind,
                settings,
                settings_commitment: commitment,
                new_settings,
                enabled: request.enabled,
                event_filter: request.event_filter,
            },
        ))
    }

    fn recover_settings(
        &self,
        record: &NotificationChannelRecord,
        destination: &meshspan_api_contract::NotificationDestination,
    ) -> Result<crate::notification_settings::PreparedSettings, NotificationError> {
        let plaintext = crate::notification_settings::load(&self.authority, &self.key, record)
            .map_err(|_| NotificationError::Failed)?;
        if &plaintext != destination {
            return Err(NotificationError::Conflict);
        }
        let secret_context = SecretContext::new(
            NOTIFICATION_SETTINGS_SECRET_KIND,
            record.settings.secret_id,
            record.settings.generation,
        )
        .map_err(|_| NotificationError::Failed)?;
        let original = self
            .authority
            .reader()
            .secret_generation(secret_context)
            .map_err(|_| NotificationError::Unavailable)?
            .ok_or(NotificationError::Failed)?;
        Ok(crate::notification_settings::PreparedSettings {
            reference: record.settings,
            commitment: record.settings_commitment,
            generation: Box::new(CommitSecretGeneration {
                secret: original.secret.parts(),
                recipients: original
                    .recipients
                    .into_iter()
                    .map(|value| value.parts())
                    .collect(),
            }),
        })
    }
}

fn parse(value: &str) -> Result<[u8; 16], NotificationError> {
    crate::create_mesh_setup::parse_uuid(value).map_err(|_| NotificationError::Invalid)
}

fn context(
    administrator: IdentityAdministrator,
    operation: OperationId,
) -> Result<CommandContext, NotificationError> {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.notification.configure.audit.v1\0");
    digest.update(operation.as_bytes());
    let audit = digest.finalize()[..16]
        .try_into()
        .map_err(|_| NotificationError::Failed)?;
    Ok(CommandContext {
        operation_id: operation,
        actor_principal_id: administrator.principal_id,
        audit_event_id: AuditEventId::from_bytes(uuid_v8(audit))
            .map_err(|_| NotificationError::Failed)?,
        occurred_at: administrator.now,
        expected_revision: None,
    })
}

fn verify_receipt(
    request: &ConfigureNotificationRequest,
    context: CommandContext,
    command: &AuthoritativeCommand,
    receipt: CommandReceipt,
) -> Result<ConfigureNotificationResponse, NotificationError> {
    if receipt.operation_id != context.operation_id
        || receipt.request_digest != command.request_digest(context)
        || receipt.entity.kind != EntityKind::NotificationChannel
        || receipt.entity.id != parse(&request.channel_id)?
        || receipt.result_digest == [0; 32]
    {
        return Err(NotificationError::Conflict);
    }
    Ok(ConfigureNotificationResponse {
        operation_id: request.operation_id.clone(),
        sequence: request.expected_sequence + 1,
        committed_revision: receipt.committed_revision.get(),
    })
}
