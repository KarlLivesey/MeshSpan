// SPDX-License-Identifier: GPL-2.0-only

//! Startup and topology-change composition for appliance-managed backup defaults.

use meshspan_domain::{AuditEventId, OperationId, PrincipalId, RandomSource, UnixMicros, uuid_v8};
use meshspan_metadata::{AuthoritativeCommand, CommandContext, EntityKind};

use crate::ConsensusAuthenticationAuthority;

/// Returns whether a defaults transition committed; ordinary file IO does not trigger one.
pub(crate) fn reconcile(
    authority: &ConsensusAuthenticationAuthority,
    random: &mut impl RandomSource,
    actor: PrincipalId,
    now: UnixMicros,
) -> Result<bool, ()> {
    let Some(candidate) = authority
        .reader()
        .metadata_backup_defaults_candidate()
        .map_err(|_| ())?
    else {
        return Ok(false);
    };
    let mut operation = [0; 16];
    let mut audit = [0; 16];
    random.fill_bytes(&mut operation).map_err(|_| ())?;
    random.fill_bytes(&mut audit).map_err(|_| ())?;
    if operation == audit {
        return Err(());
    }
    let context = CommandContext {
        operation_id: OperationId::from_bytes(uuid_v8(operation)).map_err(|_| ())?,
        actor_principal_id: actor,
        audit_event_id: AuditEventId::from_bytes(uuid_v8(audit)).map_err(|_| ())?,
        occurred_at: now,
        expected_revision: None,
    };
    let command = AuthoritativeCommand::ReconcileMetadataBackupDefaults(candidate);
    let receipt = authority
        .commit_authoritative(context, &command)
        .map_err(|_| ())?;
    if receipt.operation_id != context.operation_id
        || receipt.request_digest != command.request_digest(context)
        || receipt.entity.kind != EntityKind::MetadataBackupSchedule
        || receipt.entity.id != candidate.partition_id.as_bytes()
        || receipt.result_digest == [0; 32]
        || receipt.committed_revision.get() == 0
    {
        return Err(());
    }
    Ok(true)
}
