// SPDX-License-Identifier: GPL-2.0-only

use std::fs;

use meshspan_contracts::{
    BoundedBytes, ContractError, ContractVersion, PutShardRequest, ReclamationReceipt,
    RemovalPermit, RequestContext, ReservationClass, ReserveStorageRequest, ShardIdentity,
    StoragePermitMacKey, StorageProvider, TombstoneReceipt, removal_permit_mac,
};
use meshspan_domain::{
    EntropyError, MeshId, NodeId, OperationId, RandomSource, Revision, TargetId, UnixMicros,
};
use meshspan_metadata::{
    AuthoritativeCommand, VersionCleanupItem, VersionCleanupItemCompletion,
    VersionCleanupPermitAttempt,
};
use meshspan_storage::{
    CapacityPolicy, FolderRegistration, FolderShardStore, RegisteredFolder, StoragePermitVerifier,
    UsageLimit,
};
use tempfile::tempdir;

use crate::{
    CleanupProviderDispatch, CleanupWorkAction, CleanupWorkEntry, CleanupWorkerError,
    CleanupWorkerOutcome, execute_cleanup_work,
};

const MESH_ID: [u8; 16] = [1; 16];
const TARGET_ID: [u8; 16] = [2; 16];
const REPORTER_ID: [u8; 16] = [3; 16];
const PERMIT_KEY: [u8; 32] = [4; 32];
const TARGET_GENERATION: u64 = 5;
const AUTHORITY_EPOCH: u64 = 6;
const CATALOGUE_REVISION: Revision = Revision::new(7);

struct FixedRandom;

impl RandomSource for FixedRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        destination.fill(8);
        Ok(())
    }
}

struct LocalDispatch {
    store: FolderShardStore,
}

impl CleanupProviderDispatch for LocalDispatch {
    fn tombstone(
        &mut self,
        target_id: TargetId,
        permit: RemovalPermit,
        observed_at: UnixMicros,
    ) -> Result<TombstoneReceipt, ContractError> {
        if target_id != TargetId::from_bytes(TARGET_ID).map_err(|_| ContractError::InvalidInput)? {
            return Err(ContractError::InvalidInput);
        }
        StorageProvider::tombstone(&mut self.store, permit, observed_at)
    }

    fn reclaim(
        &mut self,
        target_id: TargetId,
        receipt: TombstoneReceipt,
        observed_at: UnixMicros,
    ) -> Result<ReclamationReceipt, ContractError> {
        if target_id != TargetId::from_bytes(TARGET_ID).map_err(|_| ContractError::InvalidInput)? {
            return Err(ContractError::InvalidInput);
        }
        StorageProvider::unlink_tombstoned(&mut self.store, receipt, observed_at)
    }
}

#[test]
fn real_provider_replays_both_lost_worker_responses_across_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let storage_path = directory.path().join("target");
    let state_path = directory.path().join("state");
    fs::create_dir(&storage_path)?;
    let registration = registration()?;
    let mut random = FixedRandom;
    let folder = RegisteredFolder::register_new(&storage_path, registration, &mut random)?;
    let fingerprint = folder.marker().fingerprint();
    let mut dispatch = LocalDispatch {
        store: open_store(folder, &state_path, registration, &mut random)?,
    };
    let item = install_shard(&mut dispatch.store, registration)?;
    let cleanup_operation_id = OperationId::from_bytes([9; 16])?;
    let attempt = permit_attempt(cleanup_operation_id, item)?;
    let tombstone_entry = CleanupWorkEntry {
        cleanup_operation_id,
        item,
        action: CleanupWorkAction::Tombstone {
            inventory_sealed_revision: Revision::new(10),
            attempt,
        },
    };
    let reporter = NodeId::from_bytes(REPORTER_ID)?;
    let first_tombstone = execute_cleanup_work(
        &mut dispatch,
        tombstone_entry,
        reporter,
        1,
        UnixMicros::new(30),
    )?;
    drop(dispatch);

    let folder = RegisteredFolder::reopen(&storage_path, registration, fingerprint)?;
    let mut dispatch = LocalDispatch {
        store: open_store(folder, &state_path, registration, &mut random)?,
    };
    let replayed_tombstone = execute_cleanup_work(
        &mut dispatch,
        tombstone_entry,
        reporter,
        1,
        UnixMicros::new(31),
    )?;
    assert_eq!(replayed_tombstone, first_tombstone);
    let completion = completion(&first_tombstone, cleanup_operation_id, reporter)?;
    let reclaim_entry = CleanupWorkEntry {
        cleanup_operation_id,
        item,
        action: CleanupWorkAction::Reclaim(completion),
    };
    let first_reclamation = execute_cleanup_work(
        &mut dispatch,
        reclaim_entry,
        reporter,
        1,
        UnixMicros::new(40),
    )?;
    assert_eq!(dispatch.store.inventory(None, 10)?.entries.len(), 0);
    drop(dispatch);

    let folder = RegisteredFolder::reopen(&storage_path, registration, fingerprint)?;
    let mut dispatch = LocalDispatch {
        store: open_store(folder, &state_path, registration, &mut random)?,
    };
    let replayed_reclamation = execute_cleanup_work(
        &mut dispatch,
        reclaim_entry,
        reporter,
        1,
        UnixMicros::new(41),
    )?;
    assert_eq!(replayed_reclamation, first_reclamation);
    assert_eq!(dispatch.store.inventory(None, 10)?.entries.len(), 0);
    Ok(())
}

#[test]
fn substituted_dispatch_authority_fails_before_provider_io()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let storage_path = directory.path().join("target");
    let state_path = directory.path().join("state");
    fs::create_dir(&storage_path)?;
    let registration = registration()?;
    let mut random = FixedRandom;
    let folder = RegisteredFolder::register_new(&storage_path, registration, &mut random)?;
    let mut dispatch = LocalDispatch {
        store: open_store(folder, &state_path, registration, &mut random)?,
    };
    let item = install_shard(&mut dispatch.store, registration)?;
    let cleanup_operation_id = OperationId::from_bytes([9; 16])?;
    let attempt = permit_attempt(cleanup_operation_id, item)?;
    let mut substituted = item;
    substituted.target_generation += 1;
    let result = execute_cleanup_work(
        &mut dispatch,
        CleanupWorkEntry {
            cleanup_operation_id,
            item: substituted,
            action: CleanupWorkAction::Tombstone {
                inventory_sealed_revision: Revision::new(10),
                attempt,
            },
        },
        NodeId::from_bytes(REPORTER_ID)?,
        1,
        UnixMicros::new(30),
    );
    assert!(matches!(
        result,
        Err(CleanupWorkerError::InconsistentAuthority)
    ));
    assert_eq!(dispatch.store.inventory(None, 10)?.entries.len(), 1);
    let result = execute_cleanup_work(
        &mut dispatch,
        CleanupWorkEntry {
            cleanup_operation_id,
            item,
            action: CleanupWorkAction::Tombstone {
                inventory_sealed_revision: Revision::new(10),
                attempt,
            },
        },
        NodeId::from_bytes([99; 16])?,
        1,
        UnixMicros::new(30),
    );
    assert!(matches!(
        result,
        Err(CleanupWorkerError::InconsistentAuthority)
    ));
    assert_eq!(dispatch.store.inventory(None, 10)?.entries.len(), 1);
    Ok(())
}

fn open_store(
    folder: RegisteredFolder,
    state_path: &std::path::Path,
    registration: FolderRegistration,
    random: &mut FixedRandom,
) -> Result<FolderShardStore, Box<dyn std::error::Error>> {
    Ok(FolderShardStore::open(
        folder,
        state_path,
        CapacityPolicy {
            usage_limit: UsageLimit::DEFAULT,
            repair_reserve_bytes: 100,
            revision: Revision::new(1),
        },
        StoragePermitVerifier::new(
            registration.mesh_id,
            AUTHORITY_EPOCH,
            CATALOGUE_REVISION,
            StoragePermitMacKey::from_bytes(PERMIT_KEY)?,
        )?,
        UnixMicros::new(1),
        random,
    )?)
}

fn install_shard(
    store: &mut FolderShardStore,
    registration: FolderRegistration,
) -> Result<VersionCleanupItem, Box<dyn std::error::Error>> {
    let context = RequestContext {
        contract_version: ContractVersion::V1_0,
        operation_id: OperationId::from_bytes([11; 16])?,
        deadline: UnixMicros::new(1_000),
        expected_revision: Some(Revision::new(2)),
    };
    let bytes = BoundedBytes::copy_from(b"encrypted cleanup worker shard", 1_024)?;
    let reservation = StorageProvider::reserve(
        store,
        ReserveStorageRequest {
            context,
            target_id: registration.target_id,
            target_generation: registration.generation,
            class: ReservationClass::ForegroundWrite,
            bytes: u64::try_from(bytes.len())?,
            observed_at: UnixMicros::new(10),
        },
    )?;
    let shard = ShardIdentity {
        manifest_digest: [12; 32],
        stripe_index: 13,
        shard_index: 14,
        generation: 15,
    };
    let length = u64::try_from(bytes.len())?;
    let digest = blake3::hash(bytes.as_slice()).into();
    StorageProvider::put_exact(
        store,
        PutShardRequest {
            context,
            reservation,
            shard,
            expected_length: length,
            expected_digest: digest,
            bytes,
        },
        UnixMicros::new(20),
    )?;
    Ok(VersionCleanupItem {
        item_index: 0,
        removal_operation_id: OperationId::from_bytes([16; 16])?,
        shard,
        target_id: registration.target_id,
        target_generation: registration.generation,
        storage_node_id: NodeId::from_bytes(REPORTER_ID)?,
        revision: Revision::new(8),
    })
}

fn permit_attempt(
    cleanup_operation_id: OperationId,
    item: VersionCleanupItem,
) -> Result<VersionCleanupPermitAttempt, Box<dyn std::error::Error>> {
    let mut permit = RemovalPermit {
        operation_id: item.removal_operation_id,
        mesh_id: MeshId::from_bytes(MESH_ID)?,
        target_id: item.target_id,
        shard: item.shard,
        target_generation: item.target_generation,
        authority_epoch: AUTHORITY_EPOCH,
        catalogue_revision: CATALOGUE_REVISION,
        expires_at: UnixMicros::new(1_000),
        permit_digest: [0; 32],
    };
    permit.permit_digest =
        removal_permit_mac(&StoragePermitMacKey::from_bytes(PERMIT_KEY)?, permit);
    Ok(VersionCleanupPermitAttempt {
        cleanup_operation_id,
        item_index: item.item_index,
        attempt_sequence: 1,
        permit,
        issue_operation_id: OperationId::from_bytes([17; 16])?,
        issued_at: UnixMicros::new(25),
        revision: CATALOGUE_REVISION,
    })
}

fn completion(
    outcome: &CleanupWorkerOutcome,
    cleanup_operation_id: OperationId,
    reporter_node_id: NodeId,
) -> Result<VersionCleanupItemCompletion, Box<dyn std::error::Error>> {
    let CleanupWorkerOutcome::CommandReady(AuthoritativeCommand::CompleteVersionCleanupItem(
        command,
    )) = outcome
    else {
        return Err("worker did not produce a tombstone completion".into());
    };
    Ok(VersionCleanupItemCompletion {
        cleanup_operation_id,
        item_index: command.item_index,
        permit_attempt_sequence: command.permit_attempt_sequence,
        receipt: command.receipt,
        reporter_node_id,
        reporter_incarnation: command.reporter_incarnation,
        completion_operation_id: OperationId::from_bytes([18; 16])?,
        completed_at: UnixMicros::new(32),
        revision: Revision::new(11),
    })
}

fn registration() -> Result<FolderRegistration, Box<dyn std::error::Error>> {
    Ok(FolderRegistration {
        mesh_id: MeshId::from_bytes(MESH_ID)?,
        target_id: TargetId::from_bytes(TARGET_ID)?,
        generation: TARGET_GENERATION,
        usage_limit: UsageLimit::DEFAULT,
    })
}
