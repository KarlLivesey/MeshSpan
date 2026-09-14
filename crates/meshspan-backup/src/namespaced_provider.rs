// SPDX-License-Identifier: GPL-2.0-only

//! Logical consumer identities mapped onto isolated provider-owned backup catalogues.

use std::io::{Read, Write};

use meshspan_contracts::{
    BackupDeleteReceipt, BackupDeleteRequest, BackupObjectIdentity, BackupObjectReceipt,
    BackupProvider, BackupReadReceipt, BackupReadRequest, BackupStoreRequest, BackupVerifyRequest,
    ContractError, FederatedBackupScope, ImplementationDescriptor,
    federated_provider_backup_identity,
};
use meshspan_domain::{BackupDestinationId, UnixMicros};

/// Maps one consumer destination onto its allocation-isolated physical provider namespace.
///
/// This is routing, not authorisation. The federation dispatcher must validate the current
/// signed request and peer before invoking any operation, including reads and deletion.
/// Provider receipts are checked before converting them back into consumer identities.
pub struct NamespacedBackupProvider<P> {
    scope: FederatedBackupScope,
    logical_destination: BackupDestinationId,
    logical_generation: u64,
    provider: P,
}

impl<P: BackupProvider> NamespacedBackupProvider<P> {
    /// Binds a provider already opened for the physical identity derived from this scope.
    ///
    /// The example object selects a destination incarnation, not a single backup. Other backups
    /// in that destination use the same catalogue. No bytes or decryption keys are changed.
    ///
    /// # Errors
    /// Rejects invalid scope or object dimensions. Each IO call also checks its provider receipt.
    pub fn new(
        scope: FederatedBackupScope,
        logical_object: BackupObjectIdentity,
        provider: P,
    ) -> Result<Self, ContractError> {
        federated_provider_backup_identity(scope, logical_object)?;
        Ok(Self {
            scope,
            logical_destination: logical_object.destination_id,
            logical_generation: logical_object.provider_generation,
            provider,
        })
    }

    fn physical(
        &self,
        logical: BackupObjectIdentity,
    ) -> Result<BackupObjectIdentity, ContractError> {
        if logical.destination_id != self.logical_destination
            || logical.provider_generation != self.logical_generation
        {
            return Err(ContractError::Stale);
        }
        federated_provider_backup_identity(self.scope, logical)
    }

    fn logical_receipt(
        &self,
        mut receipt: BackupObjectReceipt,
        request: BackupStoreRequest,
    ) -> Result<BackupObjectReceipt, ContractError> {
        if receipt.operation_id != request.context.operation_id
            || receipt.object != self.physical(request.object)?
        {
            return Err(ContractError::InternalContract);
        }
        receipt.object = request.object;
        Ok(receipt)
    }
}

impl<P: BackupProvider> BackupProvider for NamespacedBackupProvider<P> {
    fn lookup_exact(
        &self,
        request: &meshspan_contracts::BackupLookupRequest,
        observed_at: UnixMicros,
    ) -> Result<BackupObjectReceipt, ContractError> {
        let physical = meshspan_contracts::BackupLookupRequest {
            object: self.physical(request.object)?,
            ..*request
        };
        let receipt = self.provider.lookup_exact(&physical, observed_at)?;
        self.logical_receipt(
            receipt,
            BackupStoreRequest {
                context: request.context,
                object: request.object,
            },
        )
    }

    fn describe(&self) -> ImplementationDescriptor {
        self.provider.describe()
    }

    fn store_exact(
        &mut self,
        request: BackupStoreRequest,
        source: &mut dyn Read,
        observed_at: UnixMicros,
    ) -> Result<BackupObjectReceipt, ContractError> {
        let physical = BackupStoreRequest {
            object: self.physical(request.object)?,
            ..request
        };
        let receipt = self.provider.store_exact(physical, source, observed_at)?;
        self.logical_receipt(receipt, request)
    }

    fn read_exact(
        &self,
        request: &BackupReadRequest,
        destination: &mut dyn Write,
        observed_at: UnixMicros,
    ) -> Result<BackupReadReceipt, ContractError> {
        let physical = BackupReadRequest {
            object: self.physical(request.object)?,
            ..request.clone()
        };
        let receipt = self
            .provider
            .read_exact(&physical, destination, observed_at)?;
        if receipt.operation_id != request.context.operation_id
            || receipt.byte_length != request.object.byte_length
            || receipt.digest != request.object.digest
        {
            return Err(ContractError::InternalContract);
        }
        Ok(receipt)
    }

    fn verify_exact(
        &self,
        request: &BackupVerifyRequest,
        observed_at: UnixMicros,
    ) -> Result<BackupObjectReceipt, ContractError> {
        let physical = BackupVerifyRequest {
            object: self.physical(request.object)?,
            ..request.clone()
        };
        let receipt = self.provider.verify_exact(&physical, observed_at)?;
        if receipt.object_reference != request.object_reference {
            return Err(ContractError::InternalContract);
        }
        self.logical_receipt(
            receipt,
            BackupStoreRequest {
                context: request.context,
                object: request.object,
            },
        )
    }

    fn delete_exact(
        &mut self,
        request: &BackupDeleteRequest,
        observed_at: UnixMicros,
    ) -> Result<BackupDeleteReceipt, ContractError> {
        let physical = BackupDeleteRequest {
            object: self.physical(request.object)?,
            ..request.clone()
        };
        let mut receipt = self.provider.delete_exact(&physical, observed_at)?;
        if receipt.operation_id != request.context.operation_id
            || receipt.object != physical.object
            || receipt.retirement_revision != request.retirement_revision
        {
            return Err(ContractError::InternalContract);
        }
        receipt.object = request.object;
        Ok(receipt)
    }
}
