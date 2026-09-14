// SPDX-License-Identifier: GPL-2.0-only

//! Permission succession must retain physical allocations and their disjoint capacity.

use super::*;
use crate::ReplaceFederationGrant;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn renewal_keeps_existing_allocation_under_successor_authority() -> TestResult {
    let mut fixture = Fixture::open()?;
    prepare_storage_authority(&mut fixture.repository, fixture.ids)?;
    let original = allocation(fixture.ids, 30, 31, 1, 50, 10, 100)?;
    apply_allocation(&mut fixture.repository, 5, 34, fixture.ids, original)?;
    let successor = renew(&mut fixture, 6, 50)?;
    let mut request = authority_request(fixture.ids, original, 20, 20);
    request.grant_id = successor;
    let authority = fixture
        .repository
        .active_federation_storage_allocation_authority(request)?
        .ok_or("renewal stranded an existing allocation")?;
    assert_eq!(authority.allocation(), original);
    assert_eq!(authority.grant_revision(), Revision::new(6));
    assert!(
        fixture
            .repository
            .active_federation_storage_allocation_authority(authority_request(
                fixture.ids,
                original,
                20,
                20
            ))?
            .is_none(),
        "the retired permission still authorises access"
    );
    apply(
        &mut fixture.repository,
        7,
        context(38, fixture.ids.administrator, 50, 6)?,
        &AuthoritativeCommand::RevokeFederationGrant(crate::RevokeFederationGrant {
            grant_id: successor,
            expected_authority_epoch: 1,
            reason: "Withdraw renewed access".into(),
        }),
    )?;
    assert!(
        fixture
            .repository
            .active_federation_storage_allocation_authority(request)?
            .is_none()
    );
    Ok(())
}

#[test]
fn renewal_does_not_mint_another_quota_budget() -> TestResult {
    let mut fixture = Fixture::open()?;
    prepare_storage_authority(&mut fixture.repository, fixture.ids)?;
    let original = allocation(fixture.ids, 30, 31, 1, 50, 10, 100)?;
    apply_allocation(&mut fixture.repository, 5, 34, fixture.ids, original)?;
    let successor = renew(&mut fixture, 6, 50)?;
    let extra = allocation(
        FixtureIds {
            grant: successor,
            ..fixture.ids
        },
        32,
        33,
        1,
        1,
        10,
        100,
    )?;
    assert!(matches!(
        fixture.repository.apply_committed(
            position(7),
            context(37, fixture.ids.administrator, 7, 6)?,
            &AuthoritativeCommand::IssueFederationStorageAllocation(
                IssueFederationStorageAllocation {
                    allocation: extra,
                    expected_grant_revision: Revision::new(6),
                }
            )
        ),
        Err(RepositoryError::CapacityExceeded)
    ));
    assert_eq!(fixture.repository.current_revision()?, Revision::new(6));
    Ok(())
}

#[test]
fn discovery_follows_renewal_but_namespace_substitution_is_rejected() -> TestResult {
    let mut fixture = Fixture::open()?;
    prepare_storage_authority(&mut fixture.repository, fixture.ids)?;
    let original = allocation(fixture.ids, 30, 31, 1, 50, 10, 100)?;
    apply_allocation(&mut fixture.repository, 5, 34, fixture.ids, original)?;
    let successor = renew(&mut fixture, 6, 20)?;
    let page = fixture.repository.federation_storage_allocations_page(
        crate::FederationAllocationQuery {
            relationship_id: fixture.ids.relationship,
            remote_mesh_id: fixture.ids.remote_mesh,
            grant_id: successor,
            required_bytes: 30,
            observed_at: UnixMicros::new(150),
            snapshot_revision: Revision::new(6),
            after: None,
            limit: PageLimit::new(1)?,
        },
    )?;
    // Existing larger objects remain discoverable for recovery, despite a lower write ceiling.
    assert_eq!(page.items.len(), 1);
    assert!(page.next.is_none());
    let authority = page.items.first().ok_or("renewed allocation")?;
    assert_eq!(authority.allocation(), original);
    assert_eq!(authority.grant_id(), successor);
    assert_eq!(authority.valid_until(), UnixMicros::new(200));
    let scope = meshspan_contracts::FederatedBackupScope {
        relationship_id: fixture.ids.relationship,
        remote_mesh_id: fixture.ids.remote_mesh,
        provider_mesh_id: fixture.ids.local_mesh,
        allocation_id: original.allocation_id(),
        grant_id: successor,
        namespace_grant_id: original.grant_id(),
        provider_node_id: original.provider_node_id(),
        target_id: original.target_id(),
        target_generation: original.target_generation(),
        relationship_authority_epoch: authority.relationship_authority_epoch(),
        grant_revision: authority.grant_revision(),
        allocation_revision: authority.allocation_revision(),
    };
    fixture
        .repository
        .require_federated_backup_authority(scope, 30, UnixMicros::new(150))?;
    let forged = meshspan_contracts::FederatedBackupScope {
        namespace_grant_id: successor,
        ..scope
    };
    assert!(matches!(
        fixture
            .repository
            .require_federated_backup_authority(forged, 30, UnixMicros::new(150)),
        Err(meshspan_contracts::ContractError::Stale)
    ));
    Ok(())
}

#[test]
fn narrowing_preserves_charges_and_fences_new_reservations_after_restart() -> TestResult {
    let mut fixture = Fixture::open()?;
    prepare_storage_authority(&mut fixture.repository, fixture.ids)?;
    let original = allocation(fixture.ids, 30, 31, 1, 50, 10, 100)?;
    apply_allocation(&mut fixture.repository, 5, 34, fixture.ids, original)?;
    let local_path = fixture.file_path.with_file_name("local.sqlite3");
    let mut local =
        crate::LocalDatabase::open(&local_path, fixture.ids.provider_node, UnixMicros::new(20))?;
    let old = fixture
        .repository
        .active_federation_storage_allocation_authority(authority_request(
            fixture.ids,
            original,
            30,
            20,
        ))?
        .ok_or("original authority")?;
    let object = ledger_object(40, 30)?;
    local.reserve_federated_backup_capacity(old, object)?;
    local.commit_federated_backup_capacity(
        original.allocation_id(),
        object,
        UnixMicros::new(21),
    )?;
    let successor = renew(&mut fixture, 6, 20)?;
    let mut request = authority_request(fixture.ids, original, 1, 150);
    request.grant_id = successor;
    let fresh = fixture
        .repository
        .active_federation_storage_allocation_authority(request)?
        .ok_or("renewed authority after original expiry")?;
    assert_eq!(fresh.write_limit_bytes(), 20);
    assert_eq!(fresh.valid_until(), UnixMicros::new(200));
    drop(local);
    let reopened = AuthoritativeRepository::new(PartitionDatabase::open_existing(
        &fixture.file_path,
        UnixMicros::new(150),
    )?);
    let fresh = reopened
        .active_federation_storage_allocation_authority(request)?
        .ok_or("reopened authority")?;
    let mut local = crate::LocalDatabase::open_existing(&local_path, UnixMicros::new(150))?;
    assert!(matches!(
        local.reserve_federated_backup_capacity(fresh, ledger_object(41, 1)?),
        Err(crate::FederationStorageQuotaError::CapacityExceeded)
    ));
    let usage = local
        .federated_storage_usage(original.allocation_id())?
        .ok_or("retained usage")?;
    assert_eq!((usage.committed_bytes, usage.reserved_bytes), (30, 0));
    assert_eq!(
        local.federated_backup_capacity_state(original.allocation_id(), object)?,
        Some(crate::FederatedBackupCapacityState::Stored)
    );
    Ok(())
}

#[test]
fn renewal_does_not_extend_an_independent_allocation_deadline() -> TestResult {
    let mut fixture = Fixture::open()?;
    prepare_storage_authority(&mut fixture.repository, fixture.ids)?;
    let original = allocation(fixture.ids, 30, 31, 1, 50, 10, 80)?;
    apply_allocation(&mut fixture.repository, 5, 34, fixture.ids, original)?;
    let successor = renew(&mut fixture, 6, 50)?;
    let mut request = authority_request(fixture.ids, original, 1, 150);
    request.grant_id = successor;
    assert!(
        fixture
            .repository
            .active_federation_storage_allocation_authority(request)?
            .is_none()
    );
    Ok(())
}

fn ledger_object(marker: u8, bytes: u64) -> TestResult<meshspan_contracts::BackupObjectIdentity> {
    Ok(meshspan_contracts::BackupObjectIdentity {
        backup_id: meshspan_domain::BackupId::from_bytes([marker; 16])?,
        destination_id: meshspan_domain::BackupDestinationId::from_bytes([42; 16])?,
        provider_generation: 1,
        byte_length: bytes,
        digest: [marker; 32],
    })
}

#[test]
fn renewal_authority_rolls_back_with_grant_replacement() -> TestResult {
    let mut fixture = Fixture::open()?;
    prepare_storage_authority(&mut fixture.repository, fixture.ids)?;
    let original = allocation(fixture.ids, 30, 31, 1, 50, 10, 100)?;
    apply_allocation(&mut fixture.repository, 5, 34, fixture.ids, original)?;
    let command = AuthoritativeCommand::ReplaceFederationGrant(replacement(fixture.ids, 20)?);
    for fault in [
        ApplyFaultPoint::AfterCommand,
        ApplyFaultPoint::AfterOperation,
        ApplyFaultPoint::AfterAudit,
        ApplyFaultPoint::BeforeCommit,
    ] {
        assert!(matches!(
            fixture.repository.apply_committed_with_fault(
                position(6),
                context(36, fixture.ids.administrator, 30, 5)?,
                &command,
                fault
            ),
            Err(RepositoryError::InjectedFault)
        ));
        let authority = fixture
            .repository
            .active_federation_storage_allocation_authority(authority_request(
                fixture.ids,
                original,
                1,
                50,
            ))?
            .ok_or("original permission lost on rollback")?;
        assert_eq!(authority.grant_id(), fixture.ids.grant);
        assert_eq!(authority.write_limit_bytes(), 50);
        assert_eq!(authority.valid_until(), UnixMicros::new(100));
        assert_eq!(fixture.repository.current_revision()?, Revision::new(5));
    }
    Ok(())
}

#[test]
fn authority_backfill_preserves_succession_and_rejects_rebinding() -> TestResult {
    let mut fixture = Fixture::open()?;
    prepare_storage_authority(&mut fixture.repository, fixture.ids)?;
    let original = allocation(fixture.ids, 30, 31, 1, 50, 10, 100)?;
    apply_allocation(&mut fixture.repository, 5, 34, fixture.ids, original)?;
    let successor = renew(&mut fixture, 6, 20)?;
    // Rebuild only the new projection from the pre-existing immutable allocation/grant history.
    let connection = fixture.repository.database.connection();
    connection.execute_batch("DROP TABLE federation_storage_authority;")?;
    connection.execute_batch(include_str!(
        "../../../schema/partition/098_federation_storage_authority.sql"
    ))?;
    let mut request = authority_request(fixture.ids, original, 1, 150);
    request.grant_id = successor;
    let authority = fixture
        .repository
        .active_federation_storage_allocation_authority(request)?
        .ok_or("backfilled authority")?;
    assert_eq!(authority.allocation(), original);
    assert_eq!(authority.write_limit_bytes(), 20);
    assert_eq!(authority.valid_until(), UnixMicros::new(200));
    assert!(
        connection
            .execute(
                "UPDATE federation_storage_authority SET grant_id = ?1",
                [fixture.ids.grant.as_bytes().as_slice()]
            )
            .is_err()
    );
    Ok(())
}

pub(super) fn renew(
    fixture: &mut Fixture,
    index: u64,
    maximum: u64,
) -> TestResult<FederationGrantId> {
    let command = replacement(fixture.ids, maximum)?;
    let successor = command.grant.grant_id();
    apply(
        &mut fixture.repository,
        index,
        context(36, fixture.ids.administrator, 30, index - 1)?,
        &AuthoritativeCommand::ReplaceFederationGrant(command),
    )?;
    Ok(successor)
}

fn replacement(ids: FixtureIds, maximum: u64) -> TestResult<ReplaceFederationGrant> {
    let successor = FederationGrantId::from_bytes([35; 16])?;
    let policy = storage_policy(maximum, false)?;
    Ok(ReplaceFederationGrant {
        predecessor_grant_id: ids.grant,
        grant: FederationGrant::new(
            successor,
            ids.relationship,
            FederationGrantRoute::direct(ids.local_mesh, ids.remote_mesh)?,
            None,
            FederationResourceScope::StorageCapacity {
                provider_mesh_id: ids.local_mesh,
            },
            policy,
            1,
            UnixMicros::new(4),
            Some(UnixMicros::new(200)),
        )?,
        restrictions: BoundedItems::new(
            vec![
                FederationGrantRestriction {
                    imposing_mesh_id: ids.local_mesh,
                    policy,
                },
                FederationGrantRestriction {
                    imposing_mesh_id: ids.remote_mesh,
                    policy,
                },
            ],
            2,
        )?,
        restricts_authority: maximum < 50,
        reason: "Renew storage without replacing its bytes or quota".into(),
    })
}
