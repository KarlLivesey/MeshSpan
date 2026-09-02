// SPDX-License-Identifier: GPL-2.0-only

//! Idempotent coordinator actions composing scope drains from target drains and membership fences.

use meshspan_domain::{AuditEventId, OperationId, UnixMicros, WorkId, uuid_v8};
use meshspan_metadata::{
    AuthoritativeCommand, BeginStorageTargetDrain, CommandContext, CompleteStorageScopeDrain,
    EntityKind, FenceStorageNodeDrainMembership, QueueMaintenanceWork, StorageScopeDrainAction,
};
use meshspan_work::{DrainScope, WorkDemand, WorkSignals, WorkSubject};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::MaintenanceMetadataAuthority;

const CHILD_IN_FLIGHT_BYTES: u64 = 64 * 1024 * 1024;

/// Closed failures while committing one deterministic scope-drain transition.
#[derive(Debug, Error)]
pub enum ScopeDrainCoordinatorError {
    /// Consensus could not commit or resolve the exact transition.
    #[error("scope drain authority transition failed")]
    Authority(#[from] meshspan_cluster::MetadataAuthorityRequestError),
    /// Derived identities or returned authority evidence contradicted the action.
    #[error("scope drain action was invalid")]
    Invalid,
}

/// Commits one exact actionable step for a node or fault-group drain.
///
/// Every identifier and timestamp is derived from replicated action state, so concurrent
/// coordinators submit one byte-identical operation instead of racing distinct mutations.
///
/// # Errors
///
/// Rejects invalid derived identities, a mismatched receipt or any authority failure.
pub fn execute_scope_drain_action<Authority: MaintenanceMetadataAuthority>(
    authority: &Authority,
    action: StorageScopeDrainAction,
) -> Result<(), ScopeDrainCoordinatorError> {
    let (context, command) = command_for_action(action)?;
    let expected = match &command {
        AuthoritativeCommand::BeginStorageTargetDrain(_) => EntityKind::StorageTarget,
        AuthoritativeCommand::FenceStorageNodeDrainMembership(_)
        | AuthoritativeCommand::CompleteStorageScopeDrain(_) => EntityKind::MaintenanceWork,
        _ => return Err(ScopeDrainCoordinatorError::Invalid),
    };
    let receipt = authority.commit(context, &command)?;
    if receipt.entity.kind == expected {
        Ok(())
    } else {
        Err(ScopeDrainCoordinatorError::Invalid)
    }
}

fn command_for_action(
    action: StorageScopeDrainAction,
) -> Result<(CommandContext, AuthoritativeCommand), ScopeDrainCoordinatorError> {
    match action {
        StorageScopeDrainAction::BeginTarget {
            drain_id,
            target_id,
            target_generation,
            allow_temporary_degraded,
            cleanup_requested,
            requested_by,
            requested_at,
        } => {
            let subject = WorkSubject::Drain(DrainScope::Target {
                target_id,
                target_generation,
            });
            let work_id = derived_work_id(b"target-work", drain_id, target_id.as_bytes())?;
            let command = AuthoritativeCommand::BeginStorageTargetDrain(BeginStorageTargetDrain {
                work: QueueMaintenanceWork {
                    work_id,
                    deduplication_key: action_digest(
                        b"target-dedup",
                        drain_id,
                        target_id.as_bytes(),
                    ),
                    subject,
                    signals: WorkSignals {
                        data_unavailable: false,
                        remaining_recovery_margin: 0,
                        protection_debt: 1,
                        locality_debt: 0,
                        instability: 0,
                        access_heat: 0,
                        created_at: requested_at,
                        due_at: Some(requested_at),
                    },
                    demand: WorkDemand {
                        in_flight_bytes: CHILD_IN_FLIGHT_BYTES,
                    },
                    next_attempt_at: requested_at,
                },
                allow_temporary_degraded,
                cleanup_requested,
            });
            Ok((
                action_context(
                    b"target",
                    drain_id,
                    target_id.as_bytes(),
                    requested_by,
                    requested_at,
                )?,
                command,
            ))
        }
        StorageScopeDrainAction::FenceNodeMembership {
            drain_id,
            node_id,
            node_incarnation,
            requested_by,
            requested_at,
        } => Ok((
            action_context(
                b"fence",
                drain_id,
                node_id.as_bytes(),
                requested_by,
                requested_at,
            )?,
            AuthoritativeCommand::FenceStorageNodeDrainMembership(
                FenceStorageNodeDrainMembership {
                    drain_id,
                    node_id,
                    node_incarnation,
                },
            ),
        )),
        StorageScopeDrainAction::Complete {
            drain_id,
            safety_evidence_digest,
            requested_by,
            requested_at,
        } => Ok((
            action_context(
                b"complete",
                drain_id,
                safety_evidence_digest[..16]
                    .try_into()
                    .map_err(|_| ScopeDrainCoordinatorError::Invalid)?,
                requested_by,
                requested_at,
            )?,
            AuthoritativeCommand::CompleteStorageScopeDrain(CompleteStorageScopeDrain {
                drain_id,
                safety_evidence_digest,
            }),
        )),
    }
}

fn action_context(
    phase: &[u8],
    drain_id: WorkId,
    subject_id: [u8; 16],
    actor_principal_id: meshspan_domain::PrincipalId,
    occurred_at: UnixMicros,
) -> Result<CommandContext, ScopeDrainCoordinatorError> {
    let operation = derived_identifier(b"operation", phase, drain_id, subject_id);
    let audit = derived_identifier(b"audit", phase, drain_id, subject_id);
    Ok(CommandContext {
        operation_id: OperationId::from_bytes(operation)
            .map_err(|_| ScopeDrainCoordinatorError::Invalid)?,
        actor_principal_id,
        audit_event_id: AuditEventId::from_bytes(audit)
            .map_err(|_| ScopeDrainCoordinatorError::Invalid)?,
        occurred_at,
        expected_revision: None,
    })
}

fn derived_work_id(
    phase: &[u8],
    drain_id: WorkId,
    subject_id: [u8; 16],
) -> Result<WorkId, ScopeDrainCoordinatorError> {
    WorkId::from_bytes(derived_identifier(b"work", phase, drain_id, subject_id))
        .map_err(|_| ScopeDrainCoordinatorError::Invalid)
}

fn derived_identifier(
    domain: &[u8],
    phase: &[u8],
    drain_id: WorkId,
    subject_id: [u8; 16],
) -> [u8; 16] {
    let digest = action_digest_parts(domain, phase, drain_id, subject_id);
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    uuid_v8(bytes)
}

fn action_digest(domain: &[u8], drain_id: WorkId, subject_id: [u8; 16]) -> [u8; 32] {
    action_digest_parts(domain, b"target", drain_id, subject_id)
}

fn action_digest_parts(
    domain: &[u8],
    phase: &[u8],
    drain_id: WorkId,
    subject_id: [u8; 16],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.scope-drain-coordinator.v1");
    digest.update((domain.len() as u64).to_be_bytes());
    digest.update(domain);
    digest.update((phase.len() as u64).to_be_bytes());
    digest.update(phase);
    digest.update(drain_id.as_bytes());
    digest.update(subject_id);
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use meshspan_metadata::{CommandReceipt, EntityReference};

    use super::*;

    struct RecordingAuthority(Mutex<Vec<(CommandContext, AuthoritativeCommand)>>);

    impl MaintenanceMetadataAuthority for RecordingAuthority {
        fn commit(
            &self,
            context: CommandContext,
            command: &AuthoritativeCommand,
        ) -> Result<CommandReceipt, meshspan_cluster::MetadataAuthorityRequestError> {
            let Ok(mut commands) = self.0.lock() else {
                return Err(meshspan_cluster::MetadataAuthorityRequestError::Unavailable);
            };
            commands.push((context, command.clone()));
            let (kind, id) = match command {
                AuthoritativeCommand::BeginStorageTargetDrain(value) => (
                    EntityKind::StorageTarget,
                    match value.work.subject {
                        WorkSubject::Drain(DrainScope::Target { target_id, .. }) => {
                            target_id.as_bytes()
                        }
                        _ => [0; 16],
                    },
                ),
                AuthoritativeCommand::FenceStorageNodeDrainMembership(value) => {
                    (EntityKind::MaintenanceWork, value.drain_id.as_bytes())
                }
                AuthoritativeCommand::CompleteStorageScopeDrain(value) => {
                    (EntityKind::MaintenanceWork, value.drain_id.as_bytes())
                }
                _ => (EntityKind::Mesh, [0; 16]),
            };
            Ok(CommandReceipt {
                disposition: meshspan_metadata::ApplyDisposition::Applied,
                operation_id: context.operation_id,
                request_digest: command.request_digest(context),
                committed_revision: meshspan_domain::Revision::new(1),
                committed_position: meshspan_metadata::LogPosition { index: 1, term: 1 },
                applied_position: meshspan_metadata::LogPosition { index: 1, term: 1 },
                entity: EntityReference { kind, id },
                result_digest: [1; 32],
            })
        }
    }

    #[test]
    fn duplicate_coordinators_submit_byte_identical_target_drain_commands()
    -> Result<(), Box<dyn std::error::Error>> {
        let authority = RecordingAuthority(Mutex::new(Vec::new()));
        let action = StorageScopeDrainAction::BeginTarget {
            drain_id: WorkId::from_bytes([1; 16])?,
            target_id: meshspan_domain::TargetId::from_bytes([2; 16])?,
            target_generation: 3,
            allow_temporary_degraded: true,
            cleanup_requested: false,
            requested_by: meshspan_domain::PrincipalId::from_bytes([4; 16])?,
            requested_at: UnixMicros::new(5),
        };
        execute_scope_drain_action(&authority, action)?;
        execute_scope_drain_action(&authority, action)?;
        let commands = authority.0.into_inner()?;
        assert_eq!(commands.len(), 2);
        assert_eq!(commands[0], commands[1]);
        Ok(())
    }
}
