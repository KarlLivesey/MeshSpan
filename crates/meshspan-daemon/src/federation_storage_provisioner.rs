// SPDX-License-Identifier: GPL-2.0-only

//! Provider-owned allocation reconciliation: one grant/target decision per maintenance tick.

use crate::{ConsensusAuthenticationAuthority, NativeStorageTarget, OperatingSystemRandom};
use meshspan_contracts::{StorageUsageObservation, StorageUsageSource};
use meshspan_domain::{
    AuditEventId, FederationGrantId, OperationId, RandomSource, TargetId, UnixMicros, uuid_v8,
};
use meshspan_metadata::{AuthoritativeCommand, CommandContext, EntityKind, PageLimit};

/// Restart may rescan; deterministic allocation identities and consensus fences prevent duplicates.
#[derive(Default)]
pub(crate) struct FederationStorageProvisioner {
    after_grant: Option<FederationGrantId>,
    last_target: Option<(FederationGrantId, TargetId)>,
}

impl FederationStorageProvisioner {
    /// Runs on the existing storage maintenance worker, never a discovery or transfer request.
    pub(crate) fn tick<'a>(
        &mut self,
        authority: &ConsensusAuthenticationAuthority,
        targets: impl IntoIterator<Item = &'a NativeStorageTarget>,
        now: UnixMicros,
    ) -> Result<(), ()> {
        let page = authority
            .reader()
            .federation_storage_grants_for_provisioning(
                self.after_grant,
                PageLimit::new(1).map_err(|_| ())?,
                now,
            )
            .map_err(|_| ())?;
        let Some(grant) = page.items.first() else {
            self.after_grant = page.next;
            self.last_target = None;
            return Ok(());
        };
        let grant_id = grant.grant.grant_id();
        let after_target = self
            .last_target
            .filter(|(id, _)| *id == grant_id)
            .map(|(_, target)| target);
        let target = targets
            .into_iter()
            .filter(|target| after_target.is_none_or(|after| target.context().target_id > after))
            .min_by_key(|target| target.context().target_id);
        let Some(target) = target else {
            self.after_grant = Some(grant_id);
            self.last_target = None;
            return Ok(());
        };
        // A broken target cannot starve other folders/grants; failures are reported by the
        // maintenance owner and retried on the next complete scan, not hidden as free space.
        self.last_target = Some((grant_id, target.context().target_id));
        target.check_health().map_err(|_| ())?;
        let available = available_bytes(target.provider().observe_usage().map_err(|_| ())?)?;
        let Some(proposal) = authority
            .reader()
            .federation_storage_allocation_proposal(grant_id, target.context(), available, now)
            .map_err(|_| ())?
        else {
            return Ok(());
        };
        let actor = authority
            .reader()
            .storage_target_registration_context(target.context().node_id, now)
            .map_err(|_| ())?
            .ok_or(())?
            .actor_principal_id;
        let command = AuthoritativeCommand::IssueFederationStorageAllocation(proposal.command);
        let mut operation = [0; 16];
        let mut audit = [0; 16];
        OperatingSystemRandom
            .fill_bytes(&mut operation)
            .map_err(|_| ())?;
        OperatingSystemRandom
            .fill_bytes(&mut audit)
            .map_err(|_| ())?;
        let context = CommandContext {
            operation_id: OperationId::from_bytes(uuid_v8(operation)).map_err(|_| ())?,
            audit_event_id: AuditEventId::from_bytes(uuid_v8(audit)).map_err(|_| ())?,
            actor_principal_id: actor,
            occurred_at: now,
            expected_revision: Some(proposal.expected_revision),
        };
        let receipt = authority
            .commit_authoritative(context, &command)
            .map_err(|_| ())?;
        if receipt.operation_id != context.operation_id
            || receipt.request_digest != command.request_digest(context)
            || receipt.entity.kind != EntityKind::FederationStorageAllocation
            || receipt.entity.id != proposal.command.allocation.allocation_id().as_bytes()
            || receipt.committed_revision <= proposal.expected_revision
            || receipt.result_digest == [0; 32]
        {
            return Err(());
        }
        Ok(())
    }
}

pub(super) fn available_bytes(usage: StorageUsageObservation) -> Result<u64, ()> {
    let filesystem = usage.filesystem.ok_or(())?;
    if filesystem.available_bytes > filesystem.total_bytes {
        return Err(());
    }
    let unavailable = u128::from(usage.committed_bytes)
        + u128::from(usage.reserved_bytes)
        + u128::from(usage.repair_reserve_bytes);
    let remaining = u128::from(usage.configured_limit_bytes).saturating_sub(unavailable);
    u64::try_from(remaining.min(u128::from(filesystem.available_bytes))).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshspan_contracts::FilesystemSpaceObservation;

    #[test]
    fn provisioning_capacity_intersects_accounting_headroom_and_physical_space() {
        let usage = StorageUsageObservation {
            pack: None,
            filesystem: Some(FilesystemSpaceObservation {
                identity: 1,
                total_bytes: 1000,
                available_bytes: 80,
            }),
            committed_bytes: 50,
            reserved_bytes: 20,
            configured_limit_bytes: 200,
            repair_reserve_bytes: 30,
        };
        assert_eq!(available_bytes(usage), Ok(80));
        assert_eq!(
            available_bytes(StorageUsageObservation {
                configured_limit_bytes: 150,
                ..usage
            }),
            Ok(50)
        );
        assert_eq!(
            available_bytes(StorageUsageObservation {
                committed_bytes: u64::MAX,
                reserved_bytes: u64::MAX,
                ..usage
            }),
            Ok(0)
        );
        assert_eq!(
            available_bytes(StorageUsageObservation {
                filesystem: None,
                ..usage
            }),
            Err(())
        );
        assert_eq!(
            available_bytes(StorageUsageObservation {
                filesystem: Some(FilesystemSpaceObservation {
                    identity: 1,
                    total_bytes: 10,
                    available_bytes: 11
                }),
                ..usage
            }),
            Err(())
        );
    }
}
