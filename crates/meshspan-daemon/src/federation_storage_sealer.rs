// SPDX-License-Identifier: GPL-2.0-only

//! Provider-owned capacity withdrawal and restart-safe submission of permanent fences.

use crate::{
    ConsensusAuthenticationAuthority, NativeStorageTarget, OperatingSystemRandom,
    local_federation_identity::LocalFederationIdentity,
};
use meshspan_contracts::StorageUsageSource;
use meshspan_domain::{
    AuditEventId, NodeId, OperationId, RandomSource, Revision, UnixMicros, uuid_v8,
};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, EntityKind, FederationStorageMaintenanceCursor,
    FederationStorageMaintenanceItem, LocalDatabase, NodeAttestationContext,
    RecordFederationStorageSeal, RegisterCleanupAttestationKey,
};
use std::path::PathBuf;

pub(crate) struct FederationStorageSealer {
    identity_file: PathBuf,
    identity: Option<LocalFederationIdentity>,
    after: Option<FederationStorageMaintenanceCursor>,
}

impl FederationStorageSealer {
    pub(crate) fn new(identity_file: PathBuf) -> Self {
        Self {
            identity_file,
            identity: None,
            after: None,
        }
    }

    /// Examines one provider-local allocation per tick. Failed submissions retain the local
    /// fence and its uncertain charges; a restart rescan retries the same immutable allocation.
    pub(crate) fn tick<'a>(
        &mut self,
        authority: &ConsensusAuthenticationAuthority,
        ledger: &mut LocalDatabase,
        targets: impl IntoIterator<Item = &'a NativeStorageTarget>,
        now: UnixMicros,
    ) -> Result<(), ()> {
        let page = authority
            .reader()
            .federation_storage_maintenance_page(ledger.node_id(), self.after, now)
            .map_err(|_| ())?;
        self.after = page.next;
        let Some(item) = page.items.first() else {
            return Ok(());
        };
        let allocation = item.authority.allocation();
        let locally_sealed = ledger
            .federated_storage_capacity_is_sealed(allocation.allocation_id())
            .map_err(|_| ())?;
        // Losing local fence evidence cannot turn accepted retained bytes into unused quota.
        if item.accepted_seal.is_some() && !locally_sealed {
            return Err(());
        }
        let target = targets.into_iter().find(|target| {
            let context = target.context();
            context.node_id == ledger.node_id()
                && context.target_id == allocation.target_id()
                && context.generation == allocation.target_generation()
        });
        if !locally_sealed && !needs_seal(item, ledger, target)? {
            return Ok(());
        }
        let key = self.ensure_key(authority, ledger.node_id(), now)?;
        let seal = ledger
            .seal_federated_storage_capacity(item.authority)
            .map_err(|_| ())?;
        if item.accepted_seal == Some((seal.ceiling_bytes, seal.sequence)) {
            return Ok(());
        }
        let statement = RecordFederationStorageSeal {
            provider_mesh_id: item.authority.provider_mesh_id(),
            seal,
            node_incarnation: key.incarnation,
            key_generation: key.key.ok_or(())?.0,
            signature: [0; 64],
        };
        let command = AuthoritativeCommand::RecordFederationStorageSeal(
            self.identity
                .as_ref()
                .ok_or(())?
                .signing
                .sign_storage_seal(statement),
        );
        let context = context(authority, ledger.node_id(), now, key.revision)?;
        commit(
            authority,
            context,
            &command,
            (
                EntityKind::FederationStorageAllocation,
                allocation.allocation_id().as_bytes(),
            ),
        )
    }

    fn ensure_key(
        &mut self,
        authority: &ConsensusAuthenticationAuthority,
        node: NodeId,
        now: UnixMicros,
    ) -> Result<NodeAttestationContext, ()> {
        if self.identity.is_none() {
            self.identity = Some(
                LocalFederationIdentity::open_or_create(&self.identity_file, now)
                    .map_err(|_| ())?,
            );
        }
        let public = self.identity.as_ref().ok_or(())?.signing.verifying_key();
        let current = authority
            .reader()
            .node_attestation_context(node)
            .map_err(|_| ())?;
        if let Some((_, registered)) = current.key {
            return if registered == public {
                Ok(current)
            } else {
                Err(())
            };
        }
        let command =
            AuthoritativeCommand::RegisterCleanupAttestationKey(RegisterCleanupAttestationKey {
                node_id: node,
                generation: 1,
                verifying_key: public,
            });
        commit(
            authority,
            context(authority, node, now, current.revision)?,
            &command,
            (EntityKind::CleanupAttestationKey, node.as_bytes()),
        )?;
        let registered = authority
            .reader()
            .node_attestation_context(node)
            .map_err(|_| ())?;
        if registered.key != Some((1, public)) {
            return Err(());
        }
        Ok(registered)
    }
}

fn needs_seal(
    item: &FederationStorageMaintenanceItem,
    ledger: &LocalDatabase,
    target: Option<&NativeStorageTarget>,
) -> Result<bool, ()> {
    let allocation = item.authority.allocation();
    let charged = ledger
        .federated_storage_usage(allocation.allocation_id())
        .map_err(|_| ())?
        .map_or(Some(0), |usage| {
            usage.committed_bytes.checked_add(usage.reserved_bytes)
        })
        .ok_or(())?;
    if charged > allocation.maximum_bytes() {
        return Err(());
    }
    if item.authority.write_limit_bytes() < allocation.maximum_bytes() {
        return Ok(true);
    }
    let available = match target {
        Some(target) if target.check_health().is_ok() => {
            crate::federation_storage_provisioner::available_bytes(
                target.provider().observe_usage().map_err(|_| ())?,
            )?
        }
        Some(_) | None => 0,
    };
    Ok(available < allocation.maximum_bytes().saturating_sub(charged))
}

fn context(
    authority: &ConsensusAuthenticationAuthority,
    node: NodeId,
    now: UnixMicros,
    revision: Revision,
) -> Result<CommandContext, ()> {
    let actor = authority
        .reader()
        .storage_target_registration_context(node, now)
        .map_err(|_| ())?
        .ok_or(())?
        .actor_principal_id;
    let mut operation = [0; 16];
    let mut audit = [0; 16];
    OperatingSystemRandom
        .fill_bytes(&mut operation)
        .map_err(|_| ())?;
    OperatingSystemRandom
        .fill_bytes(&mut audit)
        .map_err(|_| ())?;
    Ok(CommandContext {
        operation_id: OperationId::from_bytes(uuid_v8(operation)).map_err(|_| ())?,
        audit_event_id: AuditEventId::from_bytes(uuid_v8(audit)).map_err(|_| ())?,
        actor_principal_id: actor,
        occurred_at: now,
        expected_revision: Some(revision),
    })
}

fn commit(
    authority: &ConsensusAuthenticationAuthority,
    context: CommandContext,
    command: &AuthoritativeCommand,
    entity: (EntityKind, [u8; 16]),
) -> Result<(), ()> {
    let receipt = authority
        .commit_authoritative(context, command)
        .map_err(|_| ())?;
    if receipt.operation_id != context.operation_id
        || receipt.request_digest != command.request_digest(context)
        || receipt.entity.kind != entity.0
        || receipt.entity.id != entity.1
        || receipt.result_digest == [0; 32]
        || context
            .expected_revision
            .is_none_or(|revision| receipt.committed_revision <= revision)
    {
        return Err(());
    }
    Ok(())
}
