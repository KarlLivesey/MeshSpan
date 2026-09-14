// SPDX-License-Identifier: GPL-2.0-only

//! Grant succession over retained native backup bytes and immutable consumer routing.

use super::{RunningAuthority, TestResult, authority, context_for, routing};
use crate::federation_sessions::FederationSessions;
use meshspan_contracts::{BackupObjectReference, BoundedItems, FederatedBackupScope};
use meshspan_domain::{Clock, DurationMicros, FederationGrant, FederationGrantId};
use meshspan_metadata::{
    AuthoritativeCommand, BindFederatedBackupRoute, LocalDatabase, ReplaceFederationGrant,
};
use std::sync::Arc;

pub(super) fn verify(
    provider: &RunningAuthority,
    consumer: &RunningAuthority,
    sessions: &Arc<FederationSessions>,
    binding: &BindFederatedBackupRoute,
    reference: &BackupObjectReference,
) -> TestResult<FederatedBackupScope> {
    tokio::task::block_in_place(|| {
        let scope = binding.scope;
        let physical =
            meshspan_contracts::federated_provider_backup_identity(scope, binding.object)?;
        let local = LocalDatabase::open_existing(
            &provider.directory.path().join("local.sqlite3"),
            crate::OperatingSystemClock.now(),
        )?;
        let before = local
            .federated_storage_usage(scope.allocation_id)?
            .ok_or("usage")?;
        assert_eq!(
            (before.committed_bytes, before.reserved_bytes),
            (binding.object.byte_length, 0)
        );
        let fresh = replace_permission(provider, scope)
            .map_err(|error| format!("replace stored-backup permission: {error}"))?;
        assert_ne!(fresh.grant_id, scope.grant_id);
        assert_eq!(fresh.namespace_grant_id, scope.namespace_grant_id);
        assert_eq!(
            meshspan_contracts::federated_provider_backup_identity(fresh, binding.object)?,
            physical
        );

        // This opens the real blocking consumer facade. Its saved route still has the retired
        // permission; only signed remote discovery can restore store/read/verify access.
        routing::verify_provider(consumer, sessions, binding.object, reference, 185)
            .map_err(|error| format!("consumer access after renewal: {error}"))?;
        let after = local
            .federated_storage_usage(scope.allocation_id)?
            .ok_or("renewed usage")?;
        assert_eq!(
            (after.committed_bytes, after.reserved_bytes),
            (before.committed_bytes, 0)
        );
        let retained = authority(consumer)?
            .reader()
            .federated_backup_route(binding.object.backup_id, binding.object.destination_id)?
            .ok_or("retained route")?;
        assert_eq!(
            retained.binding, *binding,
            "renewal rewrote physical routing intent"
        );
        Ok(fresh)
    })
}

fn replace_permission(
    provider: &RunningAuthority,
    scope: FederatedBackupScope,
) -> TestResult<FederatedBackupScope> {
    let authority = authority(provider)?;
    let previous = authority
        .reader()
        .federation_grant(scope.grant_id)?
        .ok_or("predecessor")?;
    let grant = &previous.grant;
    let successor = FederationGrantId::from_bytes([224; 16])?;
    let replacement = FederationGrant::new(
        successor,
        grant.relationship_id(),
        grant.route().clone(),
        grant.upstream_grant_id(),
        grant.resource(),
        grant.policy(),
        grant.authority_epoch(),
        grant.valid_from(),
        Some(
            grant
                .valid_until()
                .ok_or("grant expiry")?
                .checked_add(DurationMicros::new(60_000_000))
                .ok_or("renewal expiry")?,
        ),
    )?;
    let receipt = authority.commit_authoritative(
        context_for(provider, 224)?,
        &AuthoritativeCommand::ReplaceFederationGrant(ReplaceFederationGrant {
            predecessor_grant_id: scope.grant_id,
            grant: replacement,
            restrictions: BoundedItems::new(previous.restrictions, 2)?,
            restricts_authority: false,
            reason: "Renew authority without copying retained backup bytes".into(),
        }),
    )?;
    Ok(FederatedBackupScope {
        grant_id: successor,
        grant_revision: receipt.committed_revision,
        ..scope
    })
}
