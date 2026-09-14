// SPDX-License-Identifier: GPL-2.0-only

//! Real folder and allocation budgets compose under the existing consensus test authority.

use std::io::Cursor;

use meshspan_backup::{
    DirectoryBackupProvider, IntersectedBackupCapacity, NamespacedBackupProvider,
};
use meshspan_contracts::{
    BackupDeleteRequest, BackupObjectIdentity, BackupProvider, BackupReadRequest,
    BackupStoreRequest, BackupVerifyRequest, ContractError, ContractVersion, FederatedBackupScope,
    RequestContext, StoragePermitMacKey, federated_provider_backup_identity,
};
use meshspan_domain::{
    BackupDestinationId, BackupId, Clock, FederationRelationshipId, FederationStorageAllocation,
    FederationStorageAllocationId, OperationId, Revision, UnixMicros,
};
use meshspan_metadata::{
    AuthoritativeCommand, AuthoritativeRepository, FederatedBackupCapacityBudget,
    IssueFederationStorageAllocation, LocalDatabase, PartitionDatabase,
};
use meshspan_storage::{
    CapacityPolicy, FolderRegistration, FolderShardStore, RegisteredFolder, SharedStorageProvider,
    StoragePermitVerifier, UsageLimit,
};
use sha2::{Digest, Sha256};

use super::{RunningAuthority, TestResult, commit, definition};
use crate::ConsensusAuthenticationAuthority;

const PAYLOAD: &[u8] = b"exact opaque federated backup bytes";
type Target = SharedStorageProvider<FolderShardStore>;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn federated_backup_respects_folder_limit_and_recovers_partial_admission() -> TestResult<()> {
    let mut fixture = RunningAuthority::start().await?;
    super::super::backup_destination_service_tests::register_target(&fixture).await?;
    let authority = ConsensusAuthenticationAuthority::new(
        fixture.reader.take().ok_or("reader")?,
        fixture.handle.clone(),
        tokio::runtime::Handle::current(),
    );
    let result = tokio::task::block_in_place(|| -> TestResult<()> {
        let scope = prepare_allocation(&fixture, &authority)?;
        let logical = logical_object()?;
        let target = target(&fixture, scope)?;
        let mut provider = provider(&fixture, scope, logical, target.clone())?;
        let store = BackupStoreRequest {
            context: context(120)?,
            object: logical,
        };
        let receipt =
            provider.store_exact(store, &mut Cursor::new(PAYLOAD), UnixMicros::new(400))?;
        assert_eq!(receipt.object, logical);
        assert_usage(&fixture, scope, PAYLOAD.len() as u64, 0)?;
        let next = BackupStoreRequest {
            context: context(121)?,
            object: BackupObjectIdentity {
                backup_id: BackupId::from_bytes([121; 16])?,
                ..logical
            },
        };
        let mut untouched = Cursor::new(PAYLOAD);
        assert_eq!(
            provider.store_exact(next, &mut untouched, UnixMicros::new(400)),
            Err(ContractError::ResourceExhausted)
        );
        assert_eq!(untouched.position(), 0);
        // The allocation admitted the second object, but the physical folder did not. Retain
        // that half-admission until the exclusively reopened provider proves absence.
        assert_usage(&fixture, scope, PAYLOAD.len() as u64, PAYLOAD.len() as u64)?;
        drop(provider);
        let mut reopened = self::provider(&fixture, scope, logical, target)?;
        assert_usage(&fixture, scope, PAYLOAD.len() as u64, 0)?;
        let mut output = Vec::new();
        reopened.read_exact(
            &BackupReadRequest {
                context: context(122)?,
                object: logical,
                object_reference: receipt.object_reference.clone(),
            },
            &mut output,
            UnixMicros::new(400),
        )?;
        assert_eq!(output, PAYLOAD);
        let verified = reopened.verify_exact(
            &BackupVerifyRequest {
                context: context(124)?,
                object: logical,
                object_reference: receipt.object_reference.clone(),
            },
            UnixMicros::new(400),
        )?;
        assert_eq!(verified.object, logical);
        assert_eq!(verified.object_reference, receipt.object_reference);
        let delete = BackupDeleteRequest {
            context: context(123)?,
            object: logical,
            object_reference: receipt.object_reference,
            retirement_revision: Revision::new(1),
        };
        let retired = reopened.delete_exact(&delete, UnixMicros::new(400))?;
        assert_eq!(retired.object, logical);
        assert_eq!(retired.retirement_revision, Revision::new(1));
        assert_eq!(
            reopened.delete_exact(&delete, UnixMicros::new(400))?,
            retired
        );
        assert_usage(&fixture, scope, 0, 0)?;
        // Both budgets released exactly once: the previously rejected object now fits.
        assert_eq!(
            reopened
                .store_exact(next, &mut Cursor::new(PAYLOAD), UnixMicros::new(400))?
                .object,
            next.object
        );
        assert_usage(&fixture, scope, PAYLOAD.len() as u64, 0)
    });
    fixture.shutdown().await?;
    result
}

fn prepare_allocation(
    fixture: &RunningAuthority,
    authority: &ConsensusAuthenticationAuthority,
) -> TestResult<FederatedBackupScope> {
    let relationship_id = FederationRelationshipId::from_bytes([30; 16])?;
    for (index, (command, _, _)) in
        super::super::federation_relationship::lifecycle(relationship_id)?
            .into_iter()
            .take(2)
            .enumerate()
    {
        commit(fixture, authority, 100 + u8::try_from(index)?, &command)?;
    }
    let grant = definition(relationship_id, 70, 1024)?;
    let grant_receipt = commit(
        fixture,
        authority,
        110,
        &AuthoritativeCommand::IssueFederationGrant(grant.clone()),
    )?;
    let allocation = FederationStorageAllocation::new(
        FederationStorageAllocationId::from_bytes([72; 16])?,
        grant.grant.grant_id(),
        fixture.node_id,
        meshspan_domain::TargetId::from_bytes(meshspan_domain::uuid_v8([32; 16]))?,
        1,
        512,
        UnixMicros::new(100),
        UnixMicros::new(900),
    )?;
    let receipt = commit(
        fixture,
        authority,
        111,
        &AuthoritativeCommand::IssueFederationStorageAllocation(IssueFederationStorageAllocation {
            allocation,
            expected_grant_revision: grant_receipt.committed_revision,
        }),
    )?;
    Ok(FederatedBackupScope {
        relationship_id,
        remote_mesh_id: grant.grant.recipient_mesh_id(),
        provider_mesh_id: meshspan_domain::MeshId::from_bytes([9; 16])?,
        allocation_id: allocation.allocation_id(),
        grant_id: grant.grant.grant_id(),
        namespace_grant_id: allocation.grant_id(),
        provider_node_id: fixture.node_id,
        target_id: allocation.target_id(),
        target_generation: 1,
        relationship_authority_epoch: 1,
        grant_revision: grant_receipt.committed_revision,
        allocation_revision: receipt.committed_revision,
    })
}

fn provider(
    fixture: &RunningAuthority,
    scope: FederatedBackupScope,
    logical: BackupObjectIdentity,
    target: Target,
) -> TestResult<NamespacedBackupProvider<DirectoryBackupProvider>> {
    let physical = federated_provider_backup_identity(scope, logical)?;
    let allocation = FederatedBackupCapacityBudget::new(
        scope,
        logical,
        AuthoritativeRepository::new(PartitionDatabase::open_existing(
            &fixture.directory.path().join("partition.sqlite3"),
            UnixMicros::new(400),
        )?),
        LocalDatabase::open(
            &fixture.directory.path().join("local.sqlite3"),
            fixture.node_id,
            UnixMicros::new(400),
        )?,
        Box::new(FixedClock),
    )?;
    let provider = DirectoryBackupProvider::open(
        &fixture.directory.path().join("provider"),
        physical.destination_id,
        physical.provider_generation,
        i64::MAX.unsigned_abs(),
        UnixMicros::new(400),
    )?
    .with_capacity_budget(Box::new(IntersectedBackupCapacity::new(
        Box::new(allocation),
        Box::new(target),
    )))?;
    Ok(NamespacedBackupProvider::new(scope, logical, provider)?)
}

fn target(fixture: &RunningAuthority, scope: FederatedBackupScope) -> TestResult<Target> {
    let folder_path = fixture.directory.path().join("provider");
    std::fs::create_dir(&folder_path)?;
    let limit = UsageLimit::Bytes(PAYLOAD.len() as u64);
    let folder = RegisteredFolder::register_new(
        &folder_path,
        FolderRegistration {
            mesh_id: scope.provider_mesh_id,
            target_id: scope.target_id,
            generation: 1,
            usage_limit: limit,
        },
        &mut super::super::SequentialRandom(30),
    )?;
    Ok(SharedStorageProvider::new(FolderShardStore::open(
        folder,
        &fixture.directory.path().join("target-state"),
        CapacityPolicy {
            usage_limit: limit,
            repair_reserve_bytes: 0,
            revision: Revision::new(1),
        },
        StoragePermitVerifier::new(
            scope.provider_mesh_id,
            1,
            Revision::new(1),
            StoragePermitMacKey::from_bytes([42; 32])?,
        )?,
        UnixMicros::new(400),
        &mut super::super::SequentialRandom(60),
    )?))
}

fn assert_usage(
    fixture: &RunningAuthority,
    scope: FederatedBackupScope,
    committed: u64,
    reserved: u64,
) -> TestResult<()> {
    let local = LocalDatabase::open(
        &fixture.directory.path().join("local.sqlite3"),
        fixture.node_id,
        UnixMicros::new(400),
    )?;
    let usage = local
        .federated_storage_usage(scope.allocation_id)?
        .ok_or("usage")?;
    assert_eq!(
        (
            usage.maximum_bytes,
            usage.committed_bytes,
            usage.reserved_bytes
        ),
        (512, committed, reserved)
    );
    Ok(())
}

fn logical_object() -> TestResult<BackupObjectIdentity> {
    Ok(BackupObjectIdentity {
        backup_id: BackupId::from_bytes([119; 16])?,
        destination_id: BackupDestinationId::from_bytes([118; 16])?,
        provider_generation: 7,
        byte_length: PAYLOAD.len() as u64,
        digest: Sha256::digest(PAYLOAD).into(),
    })
}

fn context(marker: u8) -> TestResult<RequestContext> {
    Ok(RequestContext {
        contract_version: ContractVersion::V1_0,
        operation_id: OperationId::from_bytes([marker; 16])?,
        deadline: UnixMicros::new(800),
        expected_revision: Some(Revision::new(1)),
    })
}

struct FixedClock;
impl Clock for FixedClock {
    fn now(&self) -> UnixMicros {
        UnixMicros::new(400)
    }
}
