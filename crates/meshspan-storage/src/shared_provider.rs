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
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, P>, ContractError> {
        self.inner.lock().map_err(|_| ContractError::Unavailable)
    }
}

impl<P> Clone for SharedStorageProvider<P> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            descriptor: self.descriptor,
            removal_fence: self.removal_fence,
        }
    }
}

impl SharedStorageProvider<FolderShardStore> {
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
        self.lock()?.put_exact(request, observed_at)
    }

    fn get_exact(
        &self,
        context: RequestContext,
        permit: ShardReadPermit,
        observed_at: UnixMicros,
    ) -> Result<BoundedBytes, ContractError> {
        self.lock()?.get_exact(context, permit, observed_at)
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
        self.lock()?.scrub_exact(expected, observed_at)
    }

    fn scrub(
        &mut self,
        cursor: Option<&BoundedBytes>,
        limit: usize,
        observed_at: UnixMicros,
    ) -> Result<ScrubPage, ContractError> {
        self.lock()?.scrub(cursor, limit, observed_at)
    }
}

#[cfg(test)]
mod tests {
    use meshspan_contracts::{
        ContractVersion, PutShardRequest, RequestContext, ReservationClass, ReserveStorageRequest,
        ShardIdentity, ShardReadPermit, StoragePermitMacKey, StorageProvider, read_permit_mac,
    };
    use meshspan_domain::{
        EntropyError, MeshId, OperationId, RandomSource, Revision, TargetId, UnixMicros,
    };
    use tempfile::tempdir;

    use crate::{
        CapacityPolicy, FolderRegistration, FolderShardStore, RegisteredFolder,
        StoragePermitVerifier, UsageLimit,
    };

    use super::SharedStorageProvider;

    const PERMIT_KEY: [u8; 32] = [19; 32];

    #[test]
    fn clones_share_one_target_and_return_exact_verified_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_directory, provider, registration) = provider()?;
        let mut writer = SharedStorageProvider::new(provider);
        let reader = writer.clone();
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
