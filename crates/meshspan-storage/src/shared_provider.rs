// SPDX-License-Identifier: GPL-2.0-only

//! Cloneable ownership of one synchronous storage target across filesystem services.

use std::sync::{Arc, Mutex, MutexGuard};

use meshspan_contracts::{
    BoundedBytes, ContractError, ImplementationDescriptor, InventoryEntry, InventoryPage,
    PutShardRequest, ReclamationReceipt, RemovalAuthorityFence, RemovalPermit, RequestContext,
    ReserveStorageRequest, ScrubObservation, ScrubPage, ShardIdentity, ShardReadPermit,
    ShardReceipt, StorageProvider, StorageReservation, TombstoneReceipt,
};
use meshspan_domain::UnixMicros;

use crate::{FolderShardStore, FolderShardStoreError};
use meshspan_contracts::{StorageIoCounts, StorageIoKind, StorageIoObserver};
#[path = "io_observation.rs"]
mod io_observation;
use io_observation::{IoAttempt, scrub_counts};

impl<P: StorageProvider + meshspan_contracts::BackupCapacityBudget>
    meshspan_contracts::BackupCapacityBudget for SharedStorageProvider<P>
{
    fn pending_holds(
        &self,
        destination: meshspan_domain::BackupDestinationId,
        generation: u64,
        after: Option<meshspan_domain::BackupId>,
    ) -> Result<Vec<meshspan_contracts::BackupObjectIdentity>, ContractError> {
        self.lock()?.pending_holds(destination, generation, after)
    }

    fn cancel_unpublished(
        &mut self,
        object: meshspan_contracts::BackupObjectIdentity,
    ) -> Result<(), ContractError> {
        self.lock()?.cancel_unpublished(object)
    }

    fn reserve(
        &mut self,
        object: meshspan_contracts::BackupObjectIdentity,
    ) -> Result<(), ContractError> {
        meshspan_contracts::BackupCapacityBudget::reserve(&mut *self.lock()?, object)
    }

    fn commit(
        &mut self,
        object: meshspan_contracts::BackupObjectIdentity,
    ) -> Result<(), ContractError> {
        self.lock()?.commit(object)
    }

    fn reconcile_existing(
        &mut self,
        object: meshspan_contracts::BackupObjectIdentity,
    ) -> Result<(), ContractError> {
        self.lock()?.reconcile_existing(object)
    }

    fn release(
        &mut self,
        object: meshspan_contracts::BackupObjectIdentity,
    ) -> Result<(), ContractError> {
        self.lock()?.release(object)
    }
}

/// One target-local provider shared by independently opened filesystem service connections.
///
/// A registered target owns one journal and active pack writer, so its mutations must be ordered.
/// The lock is deliberately per target rather than per filesystem or daemon: separate targets and
/// SQLite-backed namespace services can still make progress concurrently. Callers execute these
/// synchronous operations on their existing bounded blocking workers.
pub struct SharedStorageProvider<P> {
    inner: Arc<Mutex<P>>,
    descriptor: ImplementationDescriptor,
    removal_fence: RemovalAuthorityFence,
    observer: Option<Arc<dyn StorageIoObserver>>,
}

impl<P> SharedStorageProvider<P>
where
    P: StorageProvider,
{
    /// Shares one already opened, exclusively owned storage target.
    #[must_use]
    pub fn new(provider: P) -> Self {
        let descriptor = provider.describe();
        let removal_fence = provider.removal_authority_fence();
        Self {
            inner: Arc::new(Mutex::new(provider)),
            descriptor,
            removal_fence,
            observer: None,
        }
    }

    /// Whether two handles borrow the same live target and policy owner.
    #[must_use]
    pub fn shares_owner_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    fn lock(&self) -> Result<MutexGuard<'_, P>, ContractError> {
        self.inner.lock().map_err(|_| ContractError::Unavailable)
    }

    /// Attaches the daemon's non-blocking process-lifetime observer before sharing this handle.
    #[must_use]
    pub fn with_io_observer(mut self, observer: Arc<dyn StorageIoObserver>) -> Self {
        self.observer = Some(observer);
        self
    }
}

impl<P> Clone for SharedStorageProvider<P> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            descriptor: self.descriptor,
            removal_fence: self.removal_fence,
            observer: self.observer.clone(),
        }
    }
}

impl<P: meshspan_contracts::StorageUsageSource> meshspan_contracts::StorageUsageSource
    for SharedStorageProvider<P>
{
    fn observe_usage(&self) -> Result<meshspan_contracts::StorageUsageObservation, ContractError> {
        // Monitoring skips a busy target rather than queuing ahead of foreground IO.
        self.inner
            .try_lock()
            .map_err(|_| ContractError::Unavailable)?
            .observe_usage()
    }
}

impl SharedStorageProvider<FolderShardStore> {
    /// Compacts at most one eligible pack, skipping a target already serving foreground IO.
    ///
    /// All borrowed reads finish under this same lock before a physical cutover.
    /// Returns reclaimed database extent, not filesystem/device free-space attribution.
    ///
    /// # Errors
    /// Reports copy, verification or replacement failure without invalidating sibling targets.
    pub fn maintain_packs(&self, now: UnixMicros) -> Result<Option<u64>, FolderShardStoreError> {
        match self.inner.try_lock() {
            Ok(mut provider) => provider.compact_next_pack(now),
            Err(std::sync::TryLockError::WouldBlock) => Ok(None),
            Err(std::sync::TryLockError::Poisoned(_)) => Err(FolderShardStoreError::Unavailable),
        }
    }

    /// Revalidates the owned folder and both target-local databases under the target lock.
    ///
    /// # Errors
    ///
    /// Reports target-local capability, identity or integrity failure without poisoning sibling
    /// providers.
    pub fn check_health(&self) -> Result<(), FolderShardStoreError> {
        self.inner
            .lock()
            .map_err(|_| FolderShardStoreError::Unavailable)?
            .check_health()
    }

    /// Returns the configured physical-byte ceiling under the same target lock as shard IO.
    ///
    /// # Errors
    ///
    /// Fails closed when the provider lock, filesystem measurement or target policy is invalid.
    pub fn capacity_ceiling(&self) -> Result<u64, FolderShardStoreError> {
        self.inner
            .lock()
            .map_err(|_| FolderShardStoreError::Unavailable)?
            .capacity_ceiling()
    }
}

impl<P> StorageProvider for SharedStorageProvider<P>
where
    P: StorageProvider,
{
    fn describe(&self) -> ImplementationDescriptor {
        self.descriptor
    }

    fn reserve(
        &mut self,
        request: ReserveStorageRequest,
    ) -> Result<StorageReservation, ContractError> {
        self.lock()?.reserve(request)
    }

    fn put_exact(
        &mut self,
        request: PutShardRequest,
        observed_at: UnixMicros,
    ) -> Result<ShardReceipt, ContractError> {
        let attempt = IoAttempt::new(self.observer.clone(), StorageIoKind::Write);
        let result = self
            .lock()
            .and_then(|mut provider| provider.put_exact(request, observed_at));
        let bytes = result.as_ref().map_or(0, |receipt| receipt.length);
        attempt.finish(
            &result,
            Some(StorageIoCounts {
                payload_bytes: bytes,
                corruption_reports: 0,
            }),
        );
        result
    }

    fn get_exact(
        &self,
        context: RequestContext,
        permit: ShardReadPermit,
        observed_at: UnixMicros,
    ) -> Result<BoundedBytes, ContractError> {
        let attempt = IoAttempt::new(self.observer.clone(), StorageIoKind::Read);
        let result = self
            .lock()
            .and_then(|provider| provider.get_exact(context, permit, observed_at));
        let bytes = match &result {
            Ok(bytes) => u64::try_from(bytes.len()).ok(),
            Err(_) => Some(0),
        };
        attempt.finish(
            &result,
            bytes.map(|payload_bytes| StorageIoCounts {
                payload_bytes,
                corruption_reports: 0,
            }),
        );
        result
    }

    fn removal_authority_fence(&self) -> RemovalAuthorityFence {
        self.removal_fence
    }

    fn tombstone(
        &mut self,
        permit: RemovalPermit,
        observed_at: UnixMicros,
    ) -> Result<TombstoneReceipt, ContractError> {
        self.lock()?.tombstone(permit, observed_at)
    }

    fn unlink_tombstoned(
        &mut self,
        receipt: TombstoneReceipt,
        observed_at: UnixMicros,
    ) -> Result<ReclamationReceipt, ContractError> {
        self.lock()?.unlink_tombstoned(receipt, observed_at)
    }

    fn inventory(
        &self,
        cursor: Option<&BoundedBytes>,
        limit: usize,
    ) -> Result<InventoryPage, ContractError> {
        self.lock()?.inventory(cursor, limit)
    }

    fn inventory_exact(
        &self,
        shard: ShardIdentity,
    ) -> Result<Option<InventoryEntry>, ContractError> {
        self.lock()?.inventory_exact(shard)
    }

    fn scrub_exact(
        &mut self,
        expected: InventoryEntry,
        observed_at: UnixMicros,
    ) -> Result<ScrubObservation, ContractError> {
        let attempt = IoAttempt::new(self.observer.clone(), StorageIoKind::Scrub);
        let result = self
            .lock()
            .and_then(|mut provider| provider.scrub_exact(expected, observed_at));
        let counts = match &result {
            Ok(observation) => scrub_counts(std::slice::from_ref(observation)),
            Err(_) => Some(StorageIoCounts::default()),
        };
        attempt.finish(&result, counts);
        result
    }

    fn scrub(
        &mut self,
        cursor: Option<&BoundedBytes>,
        limit: usize,
        observed_at: UnixMicros,
    ) -> Result<ScrubPage, ContractError> {
        let attempt = IoAttempt::new(self.observer.clone(), StorageIoKind::Scrub);
        let result = self
            .lock()
            .and_then(|mut provider| provider.scrub(cursor, limit, observed_at));
        let counts = match &result {
            Ok(page) => scrub_counts(page.observations.as_slice()),
            Err(_) => Some(StorageIoCounts::default()),
        };
        attempt.finish(&result, counts);
        result
    }
}

#[cfg(test)]
mod tests {
    use meshspan_contracts::{
        ContractVersion, PutShardRequest, RequestContext, ReservationClass, ReserveStorageRequest,
        ShardIdentity, ShardReadPermit, StoragePermitMacKey, StorageProvider, StorageUsageSource,
        read_permit_mac,
    };
    use meshspan_contracts::{StorageIoKind, StorageIoObservation, StorageIoObserver};
    use meshspan_domain::{
        EntropyError, MeshId, OperationId, RandomSource, Revision, TargetId, UnixMicros,
    };
    use std::sync::{Arc, mpsc};
    use tempfile::tempdir;

    use crate::{
        CapacityPolicy, FolderRegistration, FolderShardStore, RegisteredFolder,
        StoragePermitVerifier, UsageLimit,
    };

    use super::SharedStorageProvider;

    const PERMIT_KEY: [u8; 32] = [19; 32];

    struct Observer(mpsc::Sender<StorageIoObservation>);
    impl StorageIoObserver for Observer {
        fn observe_storage_io(&self, observation: StorageIoObservation) {
            assert!(self.0.send(observation).is_ok());
        }
    }

    #[test]
    fn clones_share_one_target_and_return_exact_verified_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let (directory, store, registration) = provider()?;
        let (sender, receiver) = mpsc::channel();
        let mut writer =
            SharedStorageProvider::new(store).with_io_observer(Arc::new(Observer(sender)));
        let reader = writer.clone();
        let filesystem = reader
            .observe_usage()?
            .filesystem
            .ok_or("filesystem observation absent")?;
        assert!(filesystem.total_bytes > 0);
        assert!(filesystem.available_bytes <= filesystem.total_bytes);
        let (_other_directory, other_provider, _) = provider()?;
        let other_filesystem = other_provider
            .observe_usage()?
            .filesystem
            .ok_or("second filesystem observation absent")?;
        assert_eq!(filesystem.identity, other_filesystem.identity);
        let context = request_context()?;
        let shard = ShardIdentity {
            manifest_digest: [7; 32],
            stripe_index: 0,
            shard_index: 0,
            generation: 1,
        };
        let bytes = meshspan_contracts::BoundedBytes::copy_from(b"shared target", 64)?;
        let reservation = writer.reserve(ReserveStorageRequest {
            context,
            target_id: registration.target_id,
            target_generation: registration.generation,
            class: ReservationClass::ForegroundWrite,
            bytes: u64::try_from(bytes.len())?,
            observed_at: UnixMicros::new(2),
        })?;
        assert_eq!(reader.observe_usage()?.reserved_bytes, 13);
        assert_eq!(reader.observe_usage()?.committed_bytes, 0);
        writer.put_exact(
            PutShardRequest {
                context,
                reservation,
                shard,
                expected_length: u64::try_from(bytes.len())?,
                expected_digest: blake3::hash(bytes.as_slice()).into(),
                bytes,
            },
            UnixMicros::new(3),
        )?;
        assert_eq!(reader.observe_usage()?.committed_bytes, 13);
        assert_eq!(reader.observe_usage()?.reserved_bytes, 0);
        let mut permit = ShardReadPermit {
            operation_id: context.operation_id,
            mesh_id: registration.mesh_id,
            target_id: registration.target_id,
            target_generation: registration.generation,
            shard,
            authorization_revision: Revision::new(1),
            expires_at: UnixMicros::new(100),
            permit_digest: [0; 32],
        };
        permit.permit_digest =
            read_permit_mac(&StoragePermitMacKey::from_bytes(PERMIT_KEY)?, permit);

        assert_eq!(
            reader
                .get_exact(context, permit, UnixMicros::new(4))?
                .as_slice(),
            b"shared target"
        );
        verify_corruption_observations(directory.path(), &mut writer, permit)?;
        let observed = receiver
            .try_iter()
            .map(|value| {
                let counts = value.counts.ok_or("missing IO counts")?;
                Ok((
                    value.kind,
                    value.failed,
                    counts.payload_bytes,
                    counts.corruption_reports,
                ))
            })
            .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
        assert_eq!(
            observed,
            vec![
                (StorageIoKind::Write, false, 13, 0),
                (StorageIoKind::Read, false, 13, 0),
                (StorageIoKind::Scrub, false, 13, 0),
                (StorageIoKind::Read, true, 0, 1),
                (StorageIoKind::Scrub, false, 13, 1),
            ]
        );
        Ok(())
    }

    fn verify_corruption_observations(
        directory: &std::path::Path,
        provider: &mut SharedStorageProvider<FolderShardStore>,
        permit: ShardReadPermit,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let healthy = provider.scrub(None, 16, UnixMicros::new(5))?;
        assert_eq!(
            healthy.observations.as_slice()[0].outcome,
            meshspan_contracts::ScrubOutcome::Healthy
        );
        let database = rusqlite::Connection::open(
            directory.join("storage/.meshspan/packs/0000000000000001.sqlite3"),
        )?;
        assert_eq!(
            database.execute(
                "UPDATE shards SET stored_bytes = ?1",
                [b"broken target".as_slice()]
            )?,
            1
        );
        assert!(matches!(
            provider.get_exact(request_context()?, permit, UnixMicros::new(6)),
            Err(meshspan_contracts::ContractError::Corrupt)
        ));
        let corrupted = provider.scrub(None, 16, UnixMicros::new(7))?;
        assert_eq!(
            corrupted.observations.as_slice()[0].outcome,
            meshspan_contracts::ScrubOutcome::Corrupt
        );
        Ok(())
    }

    #[test]
    fn shared_target_exposes_the_configured_capacity_ceiling()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_directory, provider, _) = provider()?;
        let shared = SharedStorageProvider::new(provider);

        assert!(shared.capacity_ceiling()? > 0);
        let usage = shared.observe_usage()?;
        assert_eq!(usage.configured_limit_bytes, shared.capacity_ceiling()?);
        assert_eq!(
            (
                usage.committed_bytes,
                usage.reserved_bytes,
                usage.repair_reserve_bytes
            ),
            (0, 0, 0)
        );
        let locked = shared.inner.lock().map_err(|_| "poisoned provider")?;
        assert_eq!(
            shared.observe_usage(),
            Err(meshspan_contracts::ContractError::Unavailable)
        );
        drop(locked);
        let mut resumed = shared.observe_usage()?;
        let mut initial = usage;
        let before = initial
            .filesystem
            .take()
            .ok_or("missing initial filesystem")?;
        let after = resumed
            .filesystem
            .take()
            .ok_or("missing resumed filesystem")?;
        assert_eq!(
            (after.identity, after.total_bytes),
            (before.identity, before.total_bytes)
        );
        // Other parallel tests/processes can legitimately change filesystem free space.
        assert!(before.available_bytes <= before.total_bytes);
        assert!(after.available_bytes <= after.total_bytes);
        assert_eq!(resumed, initial);
        assert!(shared.shares_owner_with(&shared.clone()));
        Ok(())
    }

    #[test]
    #[allow(
        clippy::expect_used,
        clippy::panic,
        reason = "a deliberate panic while holding the test mutex proves poison fails closed"
    )]
    fn poisoned_target_fails_closed_without_losing_static_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_directory, provider, _) = provider()?;
        let shared = SharedStorageProvider::new(provider);
        let poison = shared.clone();
        let descriptor = shared.describe();
        let fence = shared.removal_authority_fence();
        let _panic = std::panic::catch_unwind(move || {
            let _guard = poison.inner.lock().expect("new target mutex is available");
            panic!("deliberately poison the target mutex");
        });

        assert_eq!(shared.describe(), descriptor);
        assert_eq!(shared.removal_authority_fence(), fence);
        assert!(matches!(
            shared.check_health(),
            Err(crate::FolderShardStoreError::Unavailable)
        ));
        assert!(matches!(
            shared.inventory(None, 1),
            Err(meshspan_contracts::ContractError::Unavailable)
        ));
        Ok(())
    }

    #[test]
    fn shared_usage_includes_backup_holds_and_committed_payloads()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_directory, provider, _) = provider()?;
        let mut shared = SharedStorageProvider::new(provider);
        let object = meshspan_contracts::BackupObjectIdentity {
            destination_id: meshspan_domain::BackupDestinationId::from_bytes([8; 16])?,
            backup_id: meshspan_domain::BackupId::from_bytes([9; 16])?,
            provider_generation: 1,
            byte_length: 7,
            digest: [3; 32],
        };
        meshspan_contracts::BackupCapacityBudget::reserve(&mut shared, object)?;
        assert_eq!(shared.observe_usage()?.reserved_bytes, 7);
        assert_eq!(shared.observe_usage()?.committed_bytes, 0);
        meshspan_contracts::BackupCapacityBudget::commit(&mut shared, object)?;
        assert_eq!(shared.observe_usage()?.reserved_bytes, 0);
        assert_eq!(shared.observe_usage()?.committed_bytes, 7);
        meshspan_contracts::BackupCapacityBudget::release(&mut shared, object)?;
        assert_eq!(shared.observe_usage()?.committed_bytes, 0);
        Ok(())
    }

    fn provider() -> Result<ProviderFixture, Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let storage = directory.path().join("storage");
        let state = directory.path().join("state");
        std::fs::create_dir(&storage)?;
        std::fs::create_dir(&state)?;
        let registration = FolderRegistration {
            mesh_id: MeshId::from_bytes([1; 16])?,
            target_id: TargetId::from_bytes([2; 16])?,
            generation: 1,
            usage_limit: UsageLimit::DEFAULT,
        };
        let mut random = FixedRandom;
        let folder = RegisteredFolder::register_new(&storage, registration, &mut random)?;
        let provider = FolderShardStore::open(
            folder,
            &state,
            CapacityPolicy {
                usage_limit: UsageLimit::DEFAULT,
                repair_reserve_bytes: 0,
                revision: Revision::new(1),
            },
            StoragePermitVerifier::new(
                registration.mesh_id,
                1,
                Revision::new(1),
                StoragePermitMacKey::from_bytes(PERMIT_KEY)?,
            )?,
            UnixMicros::new(1),
            &mut random,
        )?;
        Ok((directory, provider, registration))
    }

    fn request_context() -> Result<RequestContext, Box<dyn std::error::Error>> {
        Ok(RequestContext {
            contract_version: ContractVersion::V1_0,
            operation_id: OperationId::from_bytes([3; 16])?,
            deadline: UnixMicros::new(100),
            expected_revision: Some(Revision::new(1)),
        })
    }

    struct FixedRandom;

    type ProviderFixture = (tempfile::TempDir, FolderShardStore, FolderRegistration);

    impl RandomSource for FixedRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
            destination.fill(31);
            Ok(())
        }
    }
}
