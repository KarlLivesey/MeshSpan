// SPDX-License-Identifier: GPL-2.0-only

//! Provider seal and reclaimed allowance travel through the real consensus command adapter.

use super::{ConsensusAuthenticationAuthority, RunningAuthority, TestResult};
use crate::{
    NativeStorageTarget, federation_storage_provisioner::FederationStorageProvisioner,
    federation_storage_sealer::FederationStorageSealer,
};
use meshspan_domain::{BackupDestinationId, BackupId, FederationStorageAllocation, UnixMicros};
use meshspan_metadata::{FederationStorageAuthorityRequest, LocalDatabase};

pub(super) fn verify_reassignment(
    fixture: &RunningAuthority,
    authority: &ConsensusAuthenticationAuthority,
    target: &NativeStorageTarget,
    allocation: FederationStorageAllocation,
) -> TestResult<()> {
    let grant = authority
        .reader()
        .federation_grant(allocation.grant_id())?
        .ok_or("allocation grant")?;
    let request = FederationStorageAuthorityRequest {
        relationship_id: grant.grant.relationship_id(),
        remote_mesh_id: grant.grant.recipient_mesh_id(),
        provider_node_id: fixture.node_id,
        allocation_id: allocation.allocation_id(),
        grant_id: allocation.grant_id(),
        target_id: allocation.target_id(),
        target_generation: allocation.target_generation(),
        requested_bytes: 128,
        observed_at: UnixMicros::new(400),
    };
    let current = authority
        .reader()
        .active_federation_storage_allocation_authority(request)?
        .ok_or("storage authority")?;
    let mut local = LocalDatabase::open(
        &fixture.directory.path().join("local.sqlite3"),
        fixture.node_id,
        UnixMicros::new(400),
    )?;
    local.reserve_federated_backup_capacity(
        current,
        meshspan_contracts::BackupObjectIdentity {
            destination_id: BackupDestinationId::from_bytes([129; 16])?,
            backup_id: BackupId::from_bytes([130; 16])?,
            provider_generation: 1,
            byte_length: 128,
            digest: [131; 32],
        },
    )?;
    verify_provider_withdrawal(fixture, authority, target, &mut local)?;
    verify_missing_ledger(fixture, authority)?;
    assert_eq!(
        authority
            .reader()
            .active_federation_storage_allocation_authority(request)?
            .ok_or("sealed read authority")?
            .write_limit_bytes(),
        0
    );

    let replacement = verify_automatic_replacement(authority, target, allocation)?;
    verify_pending_submission(fixture, authority, target, &mut local, replacement)?;
    verify_key_mismatch(fixture, authority, &mut local)
}

fn verify_provider_withdrawal(
    fixture: &RunningAuthority,
    authority: &ConsensusAuthenticationAuthority,
    target: &NativeStorageTarget,
    local: &mut LocalDatabase,
) -> TestResult<()> {
    let now = UnixMicros::new(400);
    let identity = fixture.directory.path().join("federation-identity.v1");
    let mut worker = FederationStorageSealer::new(identity.clone());
    let before = authority.reader().current_revision()?;
    worker
        .tick(authority, local, [target], now)
        .map_err(|()| "healthy seal scan")?;
    assert_eq!(authority.reader().current_revision()?, before);
    assert!(
        authority
            .reader()
            .node_attestation_context(fixture.node_id)?
            .key
            .is_none()
    );
    // Withdraw the opened-folder snapshot; the production worker owns key registration,
    // local sealing and consensus submission. This is not a physical unplug test.
    worker
        .tick(authority, local, [], now)
        .map_err(|()| "withdrawn folder seal")?;
    let page =
        authority
            .reader()
            .federation_storage_maintenance_page(fixture.node_id, None, now)?;
    let item = page.items.first().ok_or("sealed allocation")?;
    assert_eq!(item.accepted_seal, Some((128, 1)));
    let usage = local
        .federated_storage_usage(item.authority.allocation().allocation_id())?
        .ok_or("retained usage")?;
    assert_eq!((usage.committed_bytes, usage.reserved_bytes), (0, 128));
    let sealed_revision = authority.reader().current_revision()?;
    assert_eq!(sealed_revision.get(), before.get() + 2);
    let mut restarted = FederationStorageSealer::new(identity);
    restarted
        .tick(authority, local, [target], now)
        .map_err(|()| "seal worker restart")?;
    assert_eq!(authority.reader().current_revision()?, sealed_revision);
    Ok(())
}

fn verify_automatic_replacement(
    authority: &ConsensusAuthenticationAuthority,
    target: &NativeStorageTarget,
    allocation: FederationStorageAllocation,
) -> TestResult<FederationStorageAllocation> {
    let now = UnixMicros::new(400);
    let replacement = authority
        .reader()
        .federation_storage_allocation_proposal(allocation.grant_id(), target.context(), 1024, now)?
        .ok_or("sealed target must be eligible for reassignment")?
        .command
        .allocation;
    assert_ne!(replacement.allocation_id(), allocation.allocation_id());
    assert_eq!(replacement.maximum_bytes(), 896);
    let mut worker = FederationStorageProvisioner::default();
    worker
        .tick(authority, [target], now)
        .map_err(|()| "automatic reassignment")?;
    assert_eq!(
        authority
            .reader()
            .federation_storage_allocation(allocation.allocation_id())?
            .ok_or("retained allocation")?
            .allocation,
        allocation
    );
    assert_eq!(
        authority
            .reader()
            .federation_storage_allocation(replacement.allocation_id())?
            .ok_or("reassigned allocation")?
            .allocation,
        replacement
    );
    let revision = authority.reader().current_revision()?;
    let mut restarted = FederationStorageProvisioner::default();
    for _ in 0..4 {
        restarted
            .tick(authority, [target], now)
            .map_err(|()| "reassignment rescan")?;
    }
    assert_eq!(authority.reader().current_revision()?, revision);
    Ok(replacement)
}

fn verify_pending_submission(
    fixture: &RunningAuthority,
    authority: &ConsensusAuthenticationAuthority,
    target: &NativeStorageTarget,
    local: &mut LocalDatabase,
    allocation: FederationStorageAllocation,
) -> TestResult<()> {
    let now = UnixMicros::new(400);
    let mut cursor = None;
    let mut pending = None;
    for _ in 0..2 {
        let page =
            authority
                .reader()
                .federation_storage_maintenance_page(fixture.node_id, cursor, now)?;
        cursor = page.next;
        for item in page.items {
            if item.authority.allocation().allocation_id() == allocation.allocation_id() {
                pending = Some(item.authority);
            }
        }
    }
    let pending = pending.ok_or("successor maintenance authority")?;
    // Inject the precise crash window: local fence durable, no consensus submission yet.
    let seal = local.seal_federated_storage_capacity(pending)?;
    assert_eq!((seal.ceiling_bytes, seal.sequence), (0, 1));
    let before = authority.reader().current_revision()?;
    let mut reopened = LocalDatabase::open(
        &fixture.directory.path().join("local.sqlite3"),
        fixture.node_id,
        now,
    )?;
    let mut restarted =
        FederationStorageSealer::new(fixture.directory.path().join("federation-identity.v1"));
    for _ in 0..4 {
        restarted
            .tick(authority, &mut reopened, [target], now)
            .map_err(|()| "pending seal recovery")?;
    }
    assert_eq!(
        authority.reader().current_revision()?.get(),
        before.get() + 1
    );
    assert_eq!(
        authority
            .reader()
            .node_attestation_context(fixture.node_id)?
            .key
            .ok_or("registered key")?
            .0,
        1
    );
    let replacement = verify_automatic_replacement(authority, target, allocation)?;
    assert_ne!(
        replacement.allocation_id(),
        pending.allocation().allocation_id()
    );
    Ok(())
}

fn verify_key_mismatch(
    fixture: &RunningAuthority,
    authority: &ConsensusAuthenticationAuthority,
    local: &mut LocalDatabase,
) -> TestResult<()> {
    let before = authority
        .reader()
        .node_attestation_context(fixture.node_id)?;
    let mut wrong = FederationStorageSealer::new(
        fixture
            .directory
            .path()
            .join("wrong-federation-identity.v1"),
    );
    assert!(
        wrong
            .tick(authority, local, [], UnixMicros::new(400))
            .is_err()
    );
    let after = authority
        .reader()
        .node_attestation_context(fixture.node_id)?;
    assert_eq!(after.revision, before.revision);
    assert_eq!(after.key, before.key);
    Ok(())
}

fn verify_missing_ledger(
    fixture: &RunningAuthority,
    authority: &ConsensusAuthenticationAuthority,
) -> TestResult<()> {
    let before = authority.reader().current_revision()?;
    let mut missing_ledger = LocalDatabase::open(
        &fixture.directory.path().join("missing-ledger.sqlite3"),
        fixture.node_id,
        UnixMicros::new(400),
    )?;
    let mut recovered_identity =
        FederationStorageSealer::new(fixture.directory.path().join("federation-identity.v1"));
    // The sole allocation has an accepted 128-byte seal. A blank replacement
    // ledger cannot replace that retained charge with an invented zero-byte seal.
    assert!(
        recovered_identity
            .tick(authority, &mut missing_ledger, [], UnixMicros::new(400))
            .is_err()
    );
    assert_eq!(authority.reader().current_revision()?, before);
    Ok(())
}
