// SPDX-License-Identifier: GPL-2.0-only

//! Real backup-provider IO composed with the allocation ledger, not a remote-wire proof.

use std::io::Cursor;

use meshspan_backup::DirectoryBackupProvider;
use meshspan_contracts::{
    BackupCapacityBudget, BackupDeleteRequest, BackupObjectIdentity, BackupProvider,
    BackupReadRequest, BackupStoreRequest, BackupVerifyRequest, ContractError, ContractVersion,
    FederatedBackupScope, RequestContext, federated_provider_backup_identity,
};
use meshspan_domain::{BackupDestinationId, BackupId, Clock, OperationId, Revision, UnixMicros};
use sha2::{Digest, Sha256};

use super::{QuotaFixture, assert_usage};
use crate::{
    AuthoritativeCommand, AuthoritativeRepository, FederatedBackupCapacityBudget,
    FederatedBackupCapacityState, LocalDatabase, PartitionDatabase,
    RevokeFederationStorageAllocation,
};

const PAYLOAD: &[u8] = b"opaque backup container bytes";
type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn real_backup_cycle_accounts_exact_bytes_and_reopen_preserves_revocation() -> TestResult<()> {
    let mut fixture = QuotaFixture::open()?;
    let logical = logical_object(101)?;
    let scope = scope(&fixture)?;
    let physical = federated_provider_backup_identity(scope, logical)?;
    let mut provider = provider(&fixture, logical, scope, 15)?;
    let store = BackupStoreRequest {
        context: context(102)?,
        object: physical,
    };
    let receipt = provider.store_exact(store, &mut Cursor::new(PAYLOAD), UnixMicros::new(15))?;
    assert_eq!(receipt.object, physical);
    assert_usage(&fixture, 50, PAYLOAD.len() as u64, 0)?;
    // Sealing preserves exact stored retries and subsequent owner recovery/deletion.
    let seal = fixture
        .local
        .seal_federated_storage_capacity(fixture.authority(1)?)?;
    assert_eq!(seal.ceiling_bytes, PAYLOAD.len() as u64);
    assert_eq!(
        provider.store_exact(store, &mut Cursor::new([]), UnixMicros::new(16))?,
        receipt
    );
    drop(provider);

    // Revoke through the real replicated command projection while the provider is closed.
    let ids = fixture.repository_ids;
    fixture.repository.apply_committed(
        super::super::position(6),
        super::super::context(103, ids.administrator, 16, 5)?,
        &AuthoritativeCommand::RevokeFederationStorageAllocation(
            RevokeFederationStorageAllocation {
                allocation_id: fixture.allocation.allocation_id(),
                expected_allocation_revision: scope.allocation_revision,
                reason: "Stop admitting new backup bytes".into(),
            },
        ),
    )?;
    let mut reopened = self::provider(&fixture, logical, scope, 17)?;
    let mut denied = Cursor::new(PAYLOAD);
    assert_eq!(
        reopened.store_exact(store, &mut denied, UnixMicros::new(17)),
        Err(ContractError::Unauthorized)
    );
    assert_eq!(denied.position(), 0);
    let mut output = Vec::new();
    let read = BackupReadRequest {
        context: context(104)?,
        object: physical,
        object_reference: receipt.object_reference.clone(),
    };
    let result = reopened.read_exact(&read, &mut output, UnixMicros::new(17))?;
    assert_eq!(output, PAYLOAD);
    assert_eq!(
        (result.byte_length, result.digest),
        (PAYLOAD.len() as u64, Sha256::digest(PAYLOAD).into())
    );
    assert_eq!(
        reopened
            .verify_exact(
                &BackupVerifyRequest {
                    context: context(105)?,
                    object: physical,
                    object_reference: receipt.object_reference.clone(),
                },
                UnixMicros::new(17)
            )?
            .object,
        physical
    );
    // Trusted provider-owner retirement, NOT remote permission after revocation. The future
    // dispatcher must deny revoked read/delete requests before reaching this IO interface.
    let deletion = BackupDeleteRequest {
        context: context(106)?,
        object: physical,
        object_reference: receipt.object_reference,
        retirement_revision: Revision::new(1),
    };
    reopened.delete_exact(&deletion, UnixMicros::new(18))?;
    reopened.delete_exact(&deletion, UnixMicros::new(19))?;
    assert_usage(&fixture, 50, 0, 0)?;
    assert_eq!(
        reopened.read_exact(&read, &mut Vec::new(), UnixMicros::new(19)),
        Err(ContractError::NotFound)
    );
    Ok(())
}

#[test]
fn short_upload_retains_charge_until_exclusive_reopen_proves_absence() -> TestResult<()> {
    let fixture = QuotaFixture::open()?;
    let logical = logical_object(111)?;
    let scope = scope(&fixture)?;
    let physical = federated_provider_backup_identity(scope, logical)?;
    let mut provider = provider(&fixture, logical, scope, 15)?;
    assert_eq!(
        provider.store_exact(
            BackupStoreRequest {
                context: context(112)?,
                object: physical
            },
            &mut Cursor::new(b"short"),
            UnixMicros::new(15),
        ),
        Err(ContractError::Corrupt)
    );
    assert_usage(&fixture, 50, 0, PAYLOAD.len() as u64)?;
    drop(provider);
    // Allocation expiry does not itself release capacity; local recovery may still settle it.
    let _reopened = self::provider(&fixture, logical, scope, 100)?;
    assert_usage(&fixture, 50, 0, 0)?;
    assert_eq!(
        fixture
            .local
            .federated_backup_capacity_state(scope.allocation_id, physical)?,
        Some(FederatedBackupCapacityState::Cancelled)
    );
    Ok(())
}

#[test]
fn budget_rechecks_current_authority_and_rejects_namespace_substitution() -> TestResult<()> {
    let fixture = QuotaFixture::open()?;
    let logical = logical_object(121)?;
    let scope = scope(&fixture)?;
    let physical = federated_provider_backup_identity(scope, logical)?;
    let mut capacity = budget(&fixture, logical, scope, 15)?;
    assert_eq!(capacity.reserve(logical), Err(ContractError::Stale));
    capacity.reserve(physical)?;
    let oversized = BackupObjectIdentity {
        backup_id: BackupId::from_bytes([122; 16])?,
        ..physical
    };
    assert_eq!(
        capacity.reserve(oversized),
        Err(ContractError::ResourceExhausted)
    );
    assert_usage(&fixture, 50, 0, PAYLOAD.len() as u64)?;
    assert_eq!(
        budget(&fixture, logical, scope, 90)?.reserve(physical),
        Err(ContractError::Unauthorized)
    );
    let stale = FederatedBackupScope {
        grant_revision: Revision::new(100),
        ..scope
    };
    assert_eq!(
        budget(&fixture, logical, stale, 15)?.reserve(physical),
        Err(ContractError::Stale)
    );
    Ok(())
}

fn scope(fixture: &QuotaFixture) -> TestResult<FederatedBackupScope> {
    let authority = fixture.authority(PAYLOAD.len() as u64)?;
    let allocation = authority.allocation();
    Ok(FederatedBackupScope {
        relationship_id: authority.relationship_id(),
        remote_mesh_id: authority.remote_mesh_id(),
        provider_mesh_id: authority.provider_mesh_id(),
        allocation_id: allocation.allocation_id(),
        grant_id: allocation.grant_id(),
        namespace_grant_id: allocation.grant_id(),
        provider_node_id: allocation.provider_node_id(),
        target_id: allocation.target_id(),
        target_generation: allocation.target_generation(),
        relationship_authority_epoch: authority.relationship_authority_epoch(),
        grant_revision: authority.grant_revision(),
        allocation_revision: authority.allocation_revision(),
    })
}

fn budget(
    fixture: &QuotaFixture,
    logical: BackupObjectIdentity,
    scope: FederatedBackupScope,
    now: i64,
) -> TestResult<FederatedBackupCapacityBudget> {
    Ok(FederatedBackupCapacityBudget::new(
        scope,
        logical,
        AuthoritativeRepository::new(PartitionDatabase::open_existing(
            &fixture.directory.path().join("federation-storage.sqlite3"),
            UnixMicros::new(now),
        )?),
        LocalDatabase::open(
            &fixture.local_path,
            fixture.repository_ids.provider_node,
            UnixMicros::new(now),
        )?,
        Box::new(FixedClock(now)),
    )?)
}

fn provider(
    fixture: &QuotaFixture,
    logical: BackupObjectIdentity,
    scope: FederatedBackupScope,
    now: i64,
) -> TestResult<DirectoryBackupProvider> {
    let physical = federated_provider_backup_identity(scope, logical)?;
    Ok(DirectoryBackupProvider::open(
        fixture.directory.path(),
        physical.destination_id,
        physical.provider_generation,
        i64::MAX.unsigned_abs(),
        UnixMicros::new(now),
    )?
    .with_capacity_budget(Box::new(budget(fixture, logical, scope, now)?))?)
}

fn logical_object(marker: u8) -> TestResult<BackupObjectIdentity> {
    Ok(BackupObjectIdentity {
        backup_id: BackupId::from_bytes([marker; 16])?,
        destination_id: BackupDestinationId::from_bytes([100; 16])?,
        provider_generation: 7,
        byte_length: PAYLOAD.len() as u64,
        digest: Sha256::digest(PAYLOAD).into(),
    })
}

fn context(marker: u8) -> TestResult<RequestContext> {
    Ok(RequestContext {
        contract_version: ContractVersion::V1_0,
        operation_id: OperationId::from_bytes([marker; 16])?,
        deadline: UnixMicros::new(70),
        expected_revision: Some(Revision::new(1)),
    })
}

struct FixedClock(i64);
impl Clock for FixedClock {
    fn now(&self) -> UnixMicros {
        UnixMicros::new(self.0)
    }
}
