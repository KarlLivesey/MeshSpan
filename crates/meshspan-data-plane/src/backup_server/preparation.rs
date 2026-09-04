// SPDX-License-Identifier: GPL-2.0-only

//! Authority-bound preparation before remote backup provider IO.

use meshspan_contracts::{
    BackupDeleteRequest, BackupObjectIdentity, BackupProvider, BackupReadRequest,
    BackupStoreRequest, BackupVerifyRequest, ContractError, validate_backup_delete_request,
    validate_backup_read_request, validate_backup_store_request, validate_backup_verify_request,
};
use meshspan_domain::{Revision, UnixMicros};
use meshspan_protocol::v1::{
    DeleteBackupRequest, ReadBackupRequest as WireReadBackupRequest, RequestHeader,
    StoreBackupBegin, VerifyBackupRequest as WireVerifyBackupRequest,
};
use meshspan_transport::AuthenticatedPeer;

use super::{RemoteBackupAuthority, RemoteBackupService};
use crate::backup_wire::{object, read_request_parts, request_context, verify_request_parts};

impl<Provider, Authority> RemoteBackupService<Provider, Authority>
where
    Provider: BackupProvider + Send + 'static,
    Authority: RemoteBackupAuthority,
{
    pub(super) fn prepare_store(
        &self,
        peer: AuthenticatedPeer,
        value: &StoreBackupBegin,
        observed_at: UnixMicros,
    ) -> Result<BackupStoreRequest, ContractError> {
        let header = value.header.as_ref().ok_or(ContractError::InvalidInput)?;
        self.validate_sender(header, peer)?;
        let request = BackupStoreRequest {
            context: request_context(header, Revision::new(value.authority_revision))
                .map_err(|_| ContractError::InvalidInput)?,
            object: required_object(value.object.as_ref())?,
        };
        validate_backup_store_request(request, observed_at)?;
        self.validate_binding(request.object)?;
        Ok(request)
    }

    pub(super) fn prepare_read(
        &self,
        peer: AuthenticatedPeer,
        value: &WireReadBackupRequest,
        observed_at: UnixMicros,
    ) -> Result<BackupReadRequest, ContractError> {
        let header = value.header.as_ref().ok_or(ContractError::InvalidInput)?;
        self.validate_sender(header, peer)?;
        let request = read_request_parts(
            request_context(header, Revision::new(value.authority_revision))
                .map_err(|_| ContractError::InvalidInput)?,
            required_object(value.object.as_ref())?,
            value.object_reference.clone(),
        )
        .map_err(|_| ContractError::InvalidInput)?;
        validate_backup_read_request(&request, observed_at)?;
        self.validate_binding(request.object)?;
        Ok(request)
    }

    pub(super) fn prepare_verify(
        &self,
        peer: AuthenticatedPeer,
        value: &WireVerifyBackupRequest,
        observed_at: UnixMicros,
    ) -> Result<BackupVerifyRequest, ContractError> {
        let header = value.header.as_ref().ok_or(ContractError::InvalidInput)?;
        self.validate_sender(header, peer)?;
        let request = verify_request_parts(
            request_context(header, Revision::new(value.authority_revision))
                .map_err(|_| ContractError::InvalidInput)?,
            required_object(value.object.as_ref())?,
            value.object_reference.clone(),
        )
        .map_err(|_| ContractError::InvalidInput)?;
        validate_backup_verify_request(&request, observed_at)?;
        self.validate_binding(request.object)?;
        Ok(request)
    }

    pub(super) fn prepare_delete(
        &self,
        peer: AuthenticatedPeer,
        value: &DeleteBackupRequest,
        observed_at: UnixMicros,
    ) -> Result<BackupDeleteRequest, ContractError> {
        let header = value.header.as_ref().ok_or(ContractError::InvalidInput)?;
        self.validate_sender(header, peer)?;
        let retirement_revision = Revision::new(value.retirement_revision);
        let request = BackupDeleteRequest {
            context: request_context(header, retirement_revision)
                .map_err(|_| ContractError::InvalidInput)?,
            object: required_object(value.object.as_ref())?,
            object_reference: meshspan_contracts::BackupObjectReference::new(
                value.object_reference.clone(),
            )
            .map_err(|_| ContractError::InvalidInput)?,
            retirement_revision,
        };
        validate_backup_delete_request(&request, observed_at)?;
        self.validate_binding(request.object)?;
        Ok(request)
    }

    fn validate_sender(
        &self,
        header: &RequestHeader,
        peer: AuthenticatedPeer,
    ) -> Result<(), ContractError> {
        if header.mesh_id.as_slice() == self.mesh_id.as_bytes()
            && header.sender_node_id.as_slice() == peer.node_id().as_bytes()
            && header.sender_incarnation == peer.incarnation()
        {
            Ok(())
        } else {
            Err(ContractError::Unauthorized)
        }
    }

    fn validate_binding(&self, object: BackupObjectIdentity) -> Result<(), ContractError> {
        if object.destination_id == self.destination_id
            && object.provider_generation == self.provider_generation
        {
            Ok(())
        } else {
            Err(ContractError::Stale)
        }
    }
}

fn required_object(
    value: Option<&meshspan_protocol::v1::BackupObjectIdentity>,
) -> Result<BackupObjectIdentity, ContractError> {
    object(value.ok_or(ContractError::InvalidInput)?).map_err(|_| ContractError::InvalidInput)
}
