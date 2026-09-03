// SPDX-License-Identifier: GPL-2.0-only

//! Conversion between public drain messages and authoritative commands.

use std::fmt::Write;

use meshspan_api_contract::{
    BeginStorageDrainRequest, BeginStorageDrainResponse, ListStorageDrainsResponse,
    OperationId as ApiOperationId, StorageDrainCursor as ApiStorageDrainCursor,
    StorageDrainScope as ApiStorageDrainScope, StorageDrainState as ApiStorageDrainState,
    StorageDrainSummary,
};
use meshspan_domain::{FaultGroupId, NodeId, OperationId, TargetId, UnixMicros, WorkId};
use meshspan_metadata::{
    AuthoritativeCommand, BeginStorageScopeDrain, BeginStorageTargetDrain, CommandContext,
    PageLimit, QueueMaintenanceWork, StorageDrainCursor, StorageDrainRecord,
    StorageDrainState as MetadataStorageDrainState, StorageDrainStatusPage,
};
use meshspan_work::{DrainScope, WorkDemand, WorkSignals, WorkSubject};
use sha2::{Digest, Sha256};

use super::StorageDrainAdministrationError;
use crate::IdentityAdministrator;
use crate::create_mesh_setup::parse_uuid;

const CURSOR_VERSION: &str = "v1";

pub(super) fn request_command(
    administrator: IdentityAdministrator,
    request: &BeginStorageDrainRequest,
) -> Result<
    (OperationId, WorkId, CommandContext, AuthoritativeCommand),
    StorageDrainAdministrationError,
> {
    let bytes = parse_uuid(request.operation_id.as_str())
        .map_err(|_| StorageDrainAdministrationError::InvalidInput)?;
    let operation_id = OperationId::from_bytes(bytes)
        .map_err(|_| StorageDrainAdministrationError::InvalidInput)?;
    let drain_id =
        WorkId::from_bytes(bytes).map_err(|_| StorageDrainAdministrationError::InvalidInput)?;
    let scope = domain_scope(&request.scope)?;
    let command = match scope {
        DrainScope::Target { .. } => {
            AuthoritativeCommand::BeginStorageTargetDrain(BeginStorageTargetDrain {
                work: QueueMaintenanceWork {
                    work_id: drain_id,
                    deduplication_key: deduplication_key(
                        scope,
                        request.allow_temporary_degraded,
                        request.cleanup_requested,
                    ),
                    subject: WorkSubject::Drain(scope),
                    signals: WorkSignals {
                        data_unavailable: false,
                        remaining_recovery_margin: 0,
                        protection_debt: 0,
                        locality_debt: 0,
                        instability: 0,
                        access_heat: 0,
                        created_at: administrator.now,
                        due_at: Some(administrator.now),
                    },
                    demand: WorkDemand { in_flight_bytes: 1 },
                    next_attempt_at: administrator.now,
                },
                allow_temporary_degraded: request.allow_temporary_degraded,
                cleanup_requested: request.cleanup_requested,
            })
        }
        DrainScope::Node { .. } | DrainScope::FaultGroup { .. } => {
            AuthoritativeCommand::BeginStorageScopeDrain(BeginStorageScopeDrain {
                drain_id,
                scope,
                allow_temporary_degraded: request.allow_temporary_degraded,
                cleanup_requested: request.cleanup_requested,
            })
        }
    };
    let context = command_context(administrator, operation_id)?;
    Ok((operation_id, drain_id, context, command))
}

pub(super) fn begin_response(
    operation_id: ApiOperationId,
    record: StorageDrainRecord,
) -> Result<BeginStorageDrainResponse, StorageDrainAdministrationError> {
    Ok(BeginStorageDrainResponse {
        operation_id,
        drain: public_summary(record)?,
    })
}

pub(super) fn public_summary(
    record: StorageDrainRecord,
) -> Result<StorageDrainSummary, StorageDrainAdministrationError> {
    let drain_id = uuid(record.drain_id.as_bytes());
    Ok(StorageDrainSummary {
        status_url: format!("/api/latest/admin/storage-drains/{drain_id}"),
        drain_id,
        scope: public_scope(record.scope),
        allow_temporary_degraded: record.allow_temporary_degraded,
        cleanup_requested: record.cleanup_requested,
        state: match record.state {
            MetadataStorageDrainState::Evacuating => ApiStorageDrainState::Evacuating,
            MetadataStorageDrainState::MembershipFenced => ApiStorageDrainState::MembershipFenced,
            MetadataStorageDrainState::SafeToDetach => ApiStorageDrainState::SafeToDetach,
        },
        requested_at_epoch_micros: safe_instant(record.requested_at)?,
        safe_at_epoch_micros: record.safe_at.map(safe_instant).transpose()?,
        revision: record.revision.get(),
    })
}

pub(super) fn list_response(
    page: StorageDrainStatusPage,
    limit: u16,
) -> Result<ListStorageDrainsResponse, StorageDrainAdministrationError> {
    let drains = page
        .items
        .into_iter()
        .map(public_summary)
        .collect::<Result<Vec<_>, _>>()?;
    let next_page_url = page
        .next
        .map(|cursor| {
            let cursor = encode_cursor(cursor)?;
            Ok(format!(
                "/api/latest/admin/storage-drains?limit={limit}&cursor={}",
                cursor.as_str()
            ))
        })
        .transpose()?;
    Ok(ListStorageDrainsResponse {
        drains,
        next_page_url,
    })
}

pub(super) fn decode_cursor(
    cursor: &ApiStorageDrainCursor,
) -> Result<StorageDrainCursor, StorageDrainAdministrationError> {
    let mut fields = cursor.as_str().split('.');
    if fields.next() != Some(CURSOR_VERSION) {
        return Err(StorageDrainAdministrationError::InvalidInput);
    }
    let requested_at = fields
        .next()
        .ok_or(StorageDrainAdministrationError::InvalidInput)?
        .parse::<i64>()
        .ok()
        .filter(|value| *value >= 0)
        .ok_or(StorageDrainAdministrationError::InvalidInput)?;
    let scope_order = fields
        .next()
        .ok_or(StorageDrainAdministrationError::InvalidInput)?
        .parse::<u8>()
        .ok()
        .filter(|value| (1..=3).contains(value))
        .ok_or(StorageDrainAdministrationError::InvalidInput)?;
    let drain_id = fields
        .next()
        .filter(|_| fields.next().is_none())
        .ok_or(StorageDrainAdministrationError::InvalidInput)
        .and_then(|value| {
            parse_uuid(value).map_err(|_| StorageDrainAdministrationError::InvalidInput)
        })
        .and_then(|value| {
            WorkId::from_bytes(value).map_err(|_| StorageDrainAdministrationError::InvalidInput)
        })?;
    Ok(StorageDrainCursor::new(
        UnixMicros::new(requested_at),
        scope_order,
        drain_id,
    ))
}

pub(super) fn page_limit(limit: u16) -> Result<PageLimit, StorageDrainAdministrationError> {
    PageLimit::new(usize::from(limit)).map_err(|_| StorageDrainAdministrationError::InvalidInput)
}

pub(super) fn parse_drain_id(value: &str) -> Result<WorkId, StorageDrainAdministrationError> {
    parse_uuid(value)
        .map_err(|_| StorageDrainAdministrationError::InvalidInput)
        .and_then(|bytes| {
            WorkId::from_bytes(bytes).map_err(|_| StorageDrainAdministrationError::InvalidInput)
        })
}

fn domain_scope(
    value: &ApiStorageDrainScope,
) -> Result<DrainScope, StorageDrainAdministrationError> {
    match value {
        ApiStorageDrainScope::Target {
            target_id,
            generation,
        } => Ok(DrainScope::Target {
            target_id: TargetId::from_bytes(parse_identifier(target_id)?)
                .map_err(|_| StorageDrainAdministrationError::InvalidInput)?,
            target_generation: positive(generation)?,
        }),
        ApiStorageDrainScope::Node {
            node_id,
            incarnation,
        } => Ok(DrainScope::Node {
            node_id: NodeId::from_bytes(parse_identifier(node_id)?)
                .map_err(|_| StorageDrainAdministrationError::InvalidInput)?,
            node_incarnation: positive(incarnation)?,
        }),
        ApiStorageDrainScope::FaultGroup { fault_group_id } => Ok(DrainScope::FaultGroup {
            fault_group_id: FaultGroupId::from_bytes(parse_identifier(fault_group_id)?)
                .map_err(|_| StorageDrainAdministrationError::InvalidInput)?,
        }),
    }
}

fn public_scope(scope: DrainScope) -> ApiStorageDrainScope {
    match scope {
        DrainScope::Target {
            target_id,
            target_generation,
        } => ApiStorageDrainScope::Target {
            target_id: uuid(target_id.as_bytes()),
            generation: target_generation.to_string(),
        },
        DrainScope::Node {
            node_id,
            node_incarnation,
        } => ApiStorageDrainScope::Node {
            node_id: uuid(node_id.as_bytes()),
            incarnation: node_incarnation.to_string(),
        },
        DrainScope::FaultGroup { fault_group_id } => ApiStorageDrainScope::FaultGroup {
            fault_group_id: uuid(fault_group_id.as_bytes()),
        },
    }
}

fn command_context(
    administrator: IdentityAdministrator,
    operation_id: OperationId,
) -> Result<CommandContext, StorageDrainAdministrationError> {
    Ok(CommandContext {
        operation_id,
        actor_principal_id: administrator.principal_id,
        audit_event_id: meshspan_domain::AuditEventId::from_bytes(operation_id.as_bytes())
            .map_err(|_| StorageDrainAdministrationError::InvalidInput)?,
        occurred_at: administrator.now,
        expected_revision: None,
    })
}

fn deduplication_key(scope: DrainScope, degraded: bool, cleanup: bool) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"meshspan-storage-drain-v1\0");
    digest.update(WorkSubject::Drain(scope).encode());
    digest.update([u8::from(degraded), u8::from(cleanup)]);
    digest.finalize().into()
}

fn parse_identifier(value: &str) -> Result<[u8; 16], StorageDrainAdministrationError> {
    parse_uuid(value).map_err(|_| StorageDrainAdministrationError::InvalidInput)
}

fn positive(value: &str) -> Result<u64, StorageDrainAdministrationError> {
    value
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0 && i64::try_from(*value).is_ok())
        .ok_or(StorageDrainAdministrationError::InvalidInput)
}

fn safe_instant(value: UnixMicros) -> Result<i64, StorageDrainAdministrationError> {
    (0..=9_007_199_254_740_991)
        .contains(&value.get())
        .then_some(value.get())
        .ok_or(StorageDrainAdministrationError::Failed)
}

fn encode_cursor(
    cursor: StorageDrainCursor,
) -> Result<ApiStorageDrainCursor, StorageDrainAdministrationError> {
    let encoded = format!(
        "{CURSOR_VERSION}.{}.{}.{}",
        cursor.requested_at().get(),
        cursor.scope_order(),
        uuid(cursor.drain_id().as_bytes())
    );
    ApiStorageDrainCursor::from_encoded(encoded).ok_or(StorageDrainAdministrationError::Failed)
}

fn uuid(bytes: [u8; 16]) -> String {
    let mut value = String::with_capacity(36);
    for (index, byte) in bytes.into_iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            value.push('-');
        }
        let _ = write!(value, "{byte:02x}");
    }
    value
}

pub(super) fn operation_matches(
    receipt: &meshspan_metadata::CommandReceipt,
    expected_digest: [u8; 32],
    command: &AuthoritativeCommand,
) -> bool {
    let expected = match command {
        AuthoritativeCommand::BeginStorageTargetDrain(value) => {
            let WorkSubject::Drain(DrainScope::Target { target_id, .. }) = value.work.subject
            else {
                return false;
            };
            (
                meshspan_metadata::EntityKind::StorageTarget,
                target_id.as_bytes(),
            )
        }
        AuthoritativeCommand::BeginStorageScopeDrain(value) => (
            meshspan_metadata::EntityKind::MaintenanceWork,
            value.drain_id.as_bytes(),
        ),
        _ => return false,
    };
    receipt.request_digest == expected_digest
        && receipt.entity.kind == expected.0
        && receipt.entity.id == expected.1
}

pub(super) fn api_operation_id(
    operation_id: OperationId,
) -> Result<ApiOperationId, StorageDrainAdministrationError> {
    ApiOperationId::from_uuid_bytes(operation_id.as_bytes())
        .ok_or(StorageDrainAdministrationError::Failed)
}

pub(super) fn request_digest(command: &AuthoritativeCommand, context: CommandContext) -> [u8; 32] {
    command.request_digest(context)
}
