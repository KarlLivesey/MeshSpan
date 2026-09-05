// SPDX-License-Identifier: GPL-2.0-only

//! Shared ownership of one synchronously accessed backup destination.

use std::io::{Read, Write};
use std::sync::{Arc, Mutex, MutexGuard};

use meshspan_contracts::{
    BackupDeleteReceipt, BackupDeleteRequest, BackupObjectReceipt, BackupProvider,
    BackupReadReceipt, BackupReadRequest, BackupStoreRequest, BackupVerifyRequest, ContractError,
    ImplementationDescriptor,
};
use meshspan_domain::UnixMicros;

/// Cloneable access to one already opened destination and its exclusive catalogue lock.
///
/// Local workers and remote adapters share this owner rather than reopening its files. Each
/// synchronous operation holds only this destination's lock, including its bounded stream;
/// unrelated destinations remain independent. Callers must use their blocking worker pool.
/// This adapter does not grant authority: callers still validate the exact operation and the
/// underlying provider still validates identity, integrity, revisions and replay.
pub struct SharedBackupProvider<P> {
    inner: Arc<Mutex<P>>,
    descriptor: ImplementationDescriptor,
}

impl<P: BackupProvider> SharedBackupProvider<P> {
    /// Shares an exclusively opened provider without changing its persistent format.
    #[must_use]
    pub fn new(provider: P) -> Self {
        Self {
            descriptor: provider.describe(),
            inner: Arc::new(Mutex::new(provider)),
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, P>, ContractError> {
        self.inner.lock().map_err(|_| ContractError::Unavailable)
    }
}

impl<P> Clone for SharedBackupProvider<P> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            descriptor: self.descriptor,
        }
    }
}

impl<P: BackupProvider> BackupProvider for SharedBackupProvider<P> {
    fn describe(&self) -> ImplementationDescriptor {
        self.descriptor
    }

    fn store_exact(
        &mut self,
        request: BackupStoreRequest,
        source: &mut dyn Read,
        observed_at: UnixMicros,
    ) -> Result<BackupObjectReceipt, ContractError> {
        self.lock()?.store_exact(request, source, observed_at)
    }

    fn read_exact(
        &self,
        request: &BackupReadRequest,
        destination: &mut dyn Write,
        observed_at: UnixMicros,
    ) -> Result<BackupReadReceipt, ContractError> {
        self.lock()?.read_exact(request, destination, observed_at)
    }

    fn verify_exact(
        &self,
        request: &BackupVerifyRequest,
        observed_at: UnixMicros,
    ) -> Result<BackupObjectReceipt, ContractError> {
        self.lock()?.verify_exact(request, observed_at)
    }

    fn delete_exact(
        &mut self,
        request: &BackupDeleteRequest,
        observed_at: UnixMicros,
    ) -> Result<BackupDeleteReceipt, ContractError> {
        self.lock()?.delete_exact(request, observed_at)
    }
}
