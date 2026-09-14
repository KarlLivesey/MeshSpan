// SPDX-License-Identifier: GPL-2.0-only

//! Connection-owned renewal scheduling and conservative fencing of uncertain outcomes.

use meshspan_domain::{OperationId, UnixMicros};
use meshspan_filesystem::{
    AdapterCloseFileRequest, AdapterLeaseRequest, FilesystemAccessContext, FilesystemFileAdapter,
    HandleLeaseReceipt,
};
use sha2::{Digest, Sha256};

use super::{OpenFile, SmbFileId, SmbFilesystemAdapter, SmbFilesystemAdapterError, deadline};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OpenLeaseState {
    Active,
    // Keep the exact operation identity. Native SMB admission samples its executed instant
    // under runtime ownership; this connector must never resubmit with a different instant.
    // The durable stage remains owned by the common authority and is never aborted here.
    Fenced {
        renewal_operation: Option<OperationId>,
    },
}

impl<F: FilesystemFileAdapter> SmbFilesystemAdapter<F> {
    pub(crate) fn next_renewal_at(&self) -> Option<UnixMicros> {
        let (expires_at, _) = self.renewals.first()?;
        // Half of a u64 is representable as i64, including the largest configured duration.
        let margin = i64::try_from(self.limits.handle_lease.get() / 2).unwrap_or(i64::MAX);
        Some(UnixMicros::new(expires_at.get().saturating_sub(margin)))
    }

    /// Performs at most one due authority operation. A failed open leaves the schedule so it
    /// cannot monopolize maintenance or acquire fresh authority after an uncertain result.
    pub(crate) fn maintain_lease(
        &mut self,
        context: FilesystemAccessContext,
    ) -> Result<bool, SmbFilesystemAdapterError<F::Error>> {
        if self.next_renewal_at().is_none_or(|due| due > context.now) {
            return Ok(false);
        }
        let (expires_at, file_id) = self
            .renewals
            .pop_first()
            .ok_or(SmbFilesystemAdapterError::UnknownFile)?;
        let open = self
            .handles
            .get_mut(&file_id)
            .ok_or(SmbFilesystemAdapterError::UnknownFile)?;
        open.lease_state = OpenLeaseState::Fenced {
            renewal_operation: None,
        };
        if expires_at <= context.now {
            return Err(SmbFilesystemAdapterError::InvalidTime);
        }
        let request = AdapterLeaseRequest {
            operation_id: lease_operation(open, context.now, b"renew")?,
            handle_id: open.handle_id,
            expected_fence: open.fence,
            takeover: false,
            lease_expires_at: deadline(context.now, self.limits.handle_lease)?,
            observed_at: context.now,
        };
        open.lease_state = OpenLeaseState::Fenced {
            renewal_operation: Some(request.operation_id),
        };
        let receipt = self
            .filesystem
            .renew_lease(context, request)
            .map_err(SmbFilesystemAdapterError::Filesystem)?;
        validate_receipt(receipt, request, context)?;
        open.lease_expires_at = receipt.lease_expires_at;
        open.lease_state = OpenLeaseState::Active;
        self.renewals.insert((receipt.lease_expires_at, file_id));
        Ok(true)
    }

    pub(crate) fn fence_next_lease(&mut self) {
        if let Some((_, file_id)) = self.renewals.pop_first()
            && let Some(open) = self.handles.get_mut(&file_id)
        {
            open.lease_state = OpenLeaseState::Fenced {
                renewal_operation: None,
            };
        }
    }

    pub(crate) fn has_open_files(&self) -> bool {
        !self.handles.is_empty()
    }

    /// Release one clean open through the common authority. Dirty or uncertain opens stop
    /// renewing and expire durably; closing them here would publish without a client request.
    pub(crate) fn detach_one(
        &mut self,
        context: FilesystemAccessContext,
    ) -> Result<bool, SmbFilesystemAdapterError<F::Error>> {
        let Some(open) = self.take_next_open() else {
            return Ok(false);
        };
        if open.dirty
            || open.lease_state != OpenLeaseState::Active
            || open.lease_expires_at <= context.now
        {
            return Ok(true);
        }
        let operation_id = lease_operation(&open, context.now, b"disconnect-close")?;
        let receipt = self
            .filesystem
            .close_file(
                context,
                AdapterCloseFileRequest {
                    operation_id,
                    delete_operation_id: lease_operation(&open, context.now, b"disconnect-delete")?,
                    handle_id: open.handle_id,
                    handle_fence: open.fence,
                    flush: None,
                    observed_at: context.now,
                },
            )
            .map_err(SmbFilesystemAdapterError::Filesystem)?;
        if receipt.close.operation_id != operation_id
            || receipt.close.handle_id != open.handle_id
            || receipt.close.handle_fence != open.fence
        {
            return Err(SmbFilesystemAdapterError::InvalidResponse);
        }
        Ok(true)
    }

    pub(crate) fn forget_next_open(&mut self) {
        drop(self.take_next_open());
    }

    pub(super) fn forget_fenced_open(&mut self, file_id: SmbFileId) -> bool {
        if self
            .handles
            .get(&file_id)
            .is_some_and(|open| open.lease_state != OpenLeaseState::Active)
        {
            self.handles.remove(&file_id);
            self.locks.retain(|(owner, _, _), _| *owner != file_id);
            true
        } else {
            false
        }
    }

    fn take_next_open(&mut self) -> Option<OpenFile> {
        let (file_id, open) = self.handles.pop_first()?;
        self.renewals.remove(&(open.lease_expires_at, file_id));
        self.locks.retain(|(owner, _, _), _| *owner != file_id);
        Some(open)
    }
}

fn lease_operation<E>(
    open: &OpenFile,
    now: UnixMicros,
    phase: &[u8],
) -> Result<OperationId, SmbFilesystemAdapterError<E>> {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.smb.handle-lease.v1\0");
    digest.update(phase);
    digest.update(open.handle_id.as_bytes());
    digest.update(open.fence.to_be_bytes());
    digest.update(open.lease_expires_at.get().to_be_bytes());
    digest.update(now.get().to_be_bytes());
    let digest: [u8; 32] = digest.finalize().into();
    OperationId::from_bytes(
        digest[..16]
            .try_into()
            .map_err(|_| SmbFilesystemAdapterError::InvalidIdentity)?,
    )
    .map_err(|_| SmbFilesystemAdapterError::InvalidIdentity)
}

fn validate_receipt<E>(
    receipt: HandleLeaseReceipt,
    request: AdapterLeaseRequest,
    context: FilesystemAccessContext,
) -> Result<(), SmbFilesystemAdapterError<E>> {
    if receipt.operation_id != request.operation_id
        || receipt.handle_id != request.handle_id
        || receipt.handle_fence != request.expected_fence
        || receipt.gateway_node_id != context.gateway_node_id
        || receipt.lease_expires_at != request.lease_expires_at
    {
        return Err(SmbFilesystemAdapterError::InvalidResponse);
    }
    Ok(())
}
