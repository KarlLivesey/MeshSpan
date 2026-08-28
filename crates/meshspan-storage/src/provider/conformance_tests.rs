// SPDX-License-Identifier: GPL-2.0-only

//! Reusable-boundary vectors executed through `StorageProvider` over real folders.

use std::collections::VecDeque;
use std::fs;
use std::path::Path;

use meshspan_contracts::{
    BoundedBytes, ConformanceCase, ContractError, ContractVersion, PutShardRequest, RemovalPermit,
    RequestContext, ReservationClass, ReserveStorageRequest, ScrubOutcome, ShardIdentity,
    ShardReadPermit, StoragePermitMacKey, StorageProvider, read_permit_mac, removal_permit_mac,
    run_storage_provider_suite,
};
use meshspan_domain::{
    EntropyError, MeshId, OperationId, RandomSource, Revision, TargetId, UnixMicros,
};
use tempfile::tempdir;

use super::{FolderShardStore, StoragePermitVerifier};
use crate::{CapacityPolicy, FolderRegistration, RegisteredFolder, UsageLimit};

const PERMIT_KEY: [u8; 32] = [42; 32];
const REMOVAL_EPOCH: u64 = 7;

#[derive(Clone, Copy)]
enum ProviderCase {
    EmptyInventory,
    ExactPutRead,
    ForgedRead,
    GuardedRemoval,
    HealthyScrub,
    ZeroPage,
}

#[derive(Debug, Eq, PartialEq)]
enum ProviderOutput {
    Count(usize),
    Digest([u8; 32]),
    Outcome(ScrubOutcome),
}

struct FixedRandom;

impl RandomSource for FixedRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        destination.fill(9);
        Ok(())
    }
}

#[test]
fn folder_store_passes_exact_storage_provider_vectors() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let cases = [
        ConformanceCase {
            name: "empty inventory is an exact empty page",
            input: ProviderCase::EmptyInventory,
            expected: Ok(ProviderOutput::Count(0)),
        },
        ConformanceCase {
            name: "reserved exact bytes round trip under a read permit",
            input: ProviderCase::ExactPutRead,
            expected: Ok(ProviderOutput::Digest(payload_digest())),
        },
        ConformanceCase {
            name: "one-bit forged read permit is rejected",
            input: ProviderCase::ForgedRead,
            expected: Err(ContractError::Unauthorized),
        },
        ConformanceCase {
            name: "authenticated tombstone precedes guarded unlink",
            input: ProviderCase::GuardedRemoval,
            expected: Ok(ProviderOutput::Count(0)),
        },
        ConformanceCase {
            name: "scrub independently revalidates complete bytes",
            input: ProviderCase::HealthyScrub,
            expected: Ok(ProviderOutput::Outcome(ScrubOutcome::Healthy)),
        },
        ConformanceCase {
            name: "zero inventory page bound is rejected",
            input: ProviderCase::ZeroPage,
            expected: Err(ContractError::InvalidInput),
        },
    ];
    let instance_count = 1_usize.saturating_add(cases.len().saturating_mul(2));
    let mut stores = VecDeque::with_capacity(instance_count);
    for instance in 1..=instance_count {
        stores.push_back(open_store(directory.path(), u8::try_from(instance)?)?);
    }
    let failures = run_storage_provider_suite(
        &cases,
        || stores.pop_front().unwrap_or_else(fixture_exhausted),
        execute_case,
    )?;
    assert!(stores.is_empty());
    assert!(failures.is_empty(), "{failures:?}");
    Ok(())
}

fn fixture_exhausted() -> FolderShardStore {
    std::process::abort()
}

fn execute_case(
    store: &mut FolderShardStore,
    case: ProviderCase,
) -> Result<ProviderOutput, ContractError> {
    match case {
        ProviderCase::EmptyInventory => {
            let count = StorageProvider::inventory(store, None, 10)?.entries.len();
            Ok(ProviderOutput::Count(count))
        }
        ProviderCase::ExactPutRead => {
            let installed = install_shard(store)?;
            let bytes = StorageProvider::get_exact(
                store,
                installed.read_context,
                installed.read_permit,
                UnixMicros::new(30),
            )?;
            Ok(ProviderOutput::Digest(
                blake3::hash(bytes.as_slice()).into(),
            ))
        }
        ProviderCase::ForgedRead => {
            let mut installed = install_shard(store)?;
            installed.read_permit.permit_digest[0] ^= 1;
            StorageProvider::get_exact(
                store,
                installed.read_context,
                installed.read_permit,
                UnixMicros::new(30),
            )?;
            Ok(ProviderOutput::Count(1))
        }
        ProviderCase::GuardedRemoval => {
            let installed = install_shard(store)?;
            let permit = removal_permit(installed.shard)?;
            let receipt = StorageProvider::tombstone(store, permit, UnixMicros::new(30))?;
            StorageProvider::unlink_tombstoned(store, receipt, UnixMicros::new(31))?;
            let count = StorageProvider::inventory(store, None, 10)?.entries.len();
            Ok(ProviderOutput::Count(count))
        }
        ProviderCase::HealthyScrub => {
            install_shard(store)?;
            let page = StorageProvider::scrub(store, None, 10, UnixMicros::new(30))?;
            let outcome = page
                .observations
                .as_slice()
                .first()
                .ok_or(ContractError::InternalContract)?
                .outcome;
            Ok(ProviderOutput::Outcome(outcome))
        }
        ProviderCase::ZeroPage => {
            StorageProvider::inventory(store, None, 0)?;
            Ok(ProviderOutput::Count(0))
        }
    }
}

struct InstalledShard {
    shard: ShardIdentity,
    read_context: RequestContext,
    read_permit: ShardReadPermit,
}

fn install_shard(store: &mut FolderShardStore) -> Result<InstalledShard, ContractError> {
    let mesh_id = mesh_id()?;
    let target_id = target_id()?;
    let write_context = request_context(4, 1_000, 5)?;
    let bytes = BoundedBytes::copy_from(b"conformance encrypted shard", 1_024)
        .map_err(|_| ContractError::InvalidInput)?;
    let reservation = StorageProvider::reserve(
        store,
        ReserveStorageRequest {
            context: write_context,
            target_id,
            target_generation: 3,
            class: ReservationClass::ForegroundWrite,
            bytes: u64::try_from(bytes.len()).map_err(|_| ContractError::InvalidInput)?,
            observed_at: UnixMicros::new(10),
        },
    )?;
    let shard = ShardIdentity {
        manifest_digest: [6; 32],
        stripe_index: 7,
        shard_index: 8,
        generation: 9,
    };
    StorageProvider::put_exact(
        store,
        PutShardRequest {
            context: write_context,
            reservation,
            shard,
            expected_length: u64::try_from(bytes.len()).map_err(|_| ContractError::InvalidInput)?,
            expected_digest: blake3::hash(bytes.as_slice()).into(),
            bytes,
        },
        UnixMicros::new(20),
    )?;
    let read_context = request_context(10, 200, 11)?;
    let mut read_permit = ShardReadPermit {
        operation_id: read_context.operation_id,
        mesh_id,
        target_id,
        target_generation: 3,
        shard,
        authorization_revision: Revision::new(11),
        expires_at: UnixMicros::new(250),
        permit_digest: [0; 32],
    };
    let key = StoragePermitMacKey::from_bytes(PERMIT_KEY)?;
    read_permit.permit_digest = read_permit_mac(&key, read_permit);
    Ok(InstalledShard {
        shard,
        read_context,
        read_permit,
    })
}

fn removal_permit(shard: ShardIdentity) -> Result<RemovalPermit, ContractError> {
    let mut permit = RemovalPermit {
        operation_id: OperationId::from_bytes([12; 16]).map_err(|_| ContractError::InvalidInput)?,
        mesh_id: mesh_id()?,
        target_id: target_id()?,
        shard,
        target_generation: 3,
        authority_epoch: REMOVAL_EPOCH,
        catalogue_revision: Revision::new(13),
        expires_at: UnixMicros::new(300),
        permit_digest: [0; 32],
    };
    let key = StoragePermitMacKey::from_bytes(PERMIT_KEY)?;
    permit.permit_digest = removal_permit_mac(&key, permit);
    Ok(permit)
}

fn open_store(root: &Path, instance: u8) -> Result<FolderShardStore, Box<dyn std::error::Error>> {
    let storage_path = root.join(format!("storage-{instance}"));
    let state_path = root.join(format!("state-{instance}"));
    fs::create_dir(&storage_path)?;
    let mut random = FixedRandom;
    let folder = RegisteredFolder::register_new(
        &storage_path,
        FolderRegistration {
            mesh_id: mesh_id()?,
            target_id: target_id()?,
            generation: 3,
            usage_limit: UsageLimit::DEFAULT,
        },
        &mut random,
    )?;
    Ok(FolderShardStore::open(
        folder,
        &state_path,
        CapacityPolicy {
            usage_limit: UsageLimit::DEFAULT,
            repair_reserve_bytes: 100,
            revision: Revision::new(1),
        },
        StoragePermitVerifier::new(
            mesh_id()?,
            REMOVAL_EPOCH,
            Revision::new(1),
            StoragePermitMacKey::from_bytes(PERMIT_KEY)?,
        )?,
        UnixMicros::new(1),
        &mut random,
    )?)
}

fn request_context(
    operation: u8,
    deadline: i64,
    revision: u64,
) -> Result<RequestContext, ContractError> {
    Ok(RequestContext {
        contract_version: ContractVersion::V1_0,
        operation_id: OperationId::from_bytes([operation; 16])
            .map_err(|_| ContractError::InvalidInput)?,
        deadline: UnixMicros::new(deadline),
        expected_revision: Some(Revision::new(revision)),
    })
}

fn mesh_id() -> Result<MeshId, ContractError> {
    MeshId::from_bytes([1; 16]).map_err(|_| ContractError::InvalidInput)
}

fn target_id() -> Result<TargetId, ContractError> {
    TargetId::from_bytes([2; 16]).map_err(|_| ContractError::InvalidInput)
}

fn payload_digest() -> [u8; 32] {
    blake3::hash(b"conformance encrypted shard").into()
}
