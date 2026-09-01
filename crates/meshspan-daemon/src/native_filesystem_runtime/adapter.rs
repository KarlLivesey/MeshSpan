// SPDX-License-Identifier: GPL-2.0-only

//! Forwarding of connector-neutral operations into the one shared production runtime.

use meshspan_filesystem::{
    AdapterCloseFileRequest, AdapterCreateDirectoryRequest, AdapterCreateFileRequest,
    AdapterFlushFileRequest, AdapterLeaseRequest, AdapterListRequest, AdapterLockRequest,
    AdapterOpenFileRequest, AdapterReadFileRequest, AdapterRenameRequest, AdapterStatRequest,
    AdapterUnlinkRequest, AdapterUnlockRequest, AdapterUploadAbortRequest,
    AdapterUploadBeginRequest, AdapterUploadCommitRequest, AdapterUploadRangePageRequest,
    AdapterUploadStatusRequest, AdapterUploadWriteRequest, AdapterWriteFileRequest,
    DirectoryPublicationReceipt, FilesystemFileAdapter, FilesystemHandleCloseReceipt,
    FilesystemHandleCreateReceipt, FilesystemHandleReadReceipt, FilesystemHandleWriteReceipt,
    FilesystemUploadAdapter, HandleLeaseReceipt, LockRangeReceipt, NamespaceListPage,
    NamespaceObjectStat, NamespacePublicationReceipt, NamespaceRenameReceipt,
    NamespaceUnlinkReceipt, UnlockRangeReceipt, UploadCommitReceipt, UploadRangePageReceipt,
    UploadSession, UploadStatusReceipt, UploadWriteReceipt,
};

use super::{NativeFilesystemRuntime, NativeFilesystemRuntimeError};

impl FilesystemFileAdapter for NativeFilesystemRuntime {
    type Error = NativeFilesystemRuntimeError;

    fn open_existing_file(
        &mut self,
        context: meshspan_filesystem::FilesystemAccessContext,
        request: &AdapterOpenFileRequest,
    ) -> Result<meshspan_filesystem::OpenHandleReceipt, Self::Error> {
        self.with_mut(|filesystem| filesystem.open_existing_file(context, request))
    }

    fn read_file(
        &mut self,
        context: meshspan_filesystem::FilesystemAccessContext,
        request: AdapterReadFileRequest,
    ) -> Result<FilesystemHandleReadReceipt, Self::Error> {
        self.with_mut(|filesystem| filesystem.read_file(context, request))
    }

    fn write_file(
        &mut self,
        context: meshspan_filesystem::FilesystemAccessContext,
        request: &AdapterWriteFileRequest,
    ) -> Result<FilesystemHandleWriteReceipt, Self::Error> {
        self.with_mut(|filesystem| filesystem.write_file(context, request))
    }

    fn flush_file(
        &mut self,
        context: meshspan_filesystem::FilesystemAccessContext,
        request: AdapterFlushFileRequest,
    ) -> Result<NamespacePublicationReceipt, Self::Error> {
        self.with_mut(|filesystem| filesystem.flush_file(context, request))
    }

    fn stat(
        &self,
        context: meshspan_filesystem::FilesystemAccessContext,
        request: &AdapterStatRequest,
    ) -> Result<NamespaceObjectStat, Self::Error> {
        self.with_ref(|filesystem| filesystem.stat(context, request))
    }

    fn list(
        &self,
        context: meshspan_filesystem::FilesystemAccessContext,
        request: &AdapterListRequest,
    ) -> Result<NamespaceListPage, Self::Error> {
        self.with_ref(|filesystem| filesystem.list(context, request))
    }

    fn create_directory(
        &mut self,
        context: meshspan_filesystem::FilesystemAccessContext,
        request: &AdapterCreateDirectoryRequest,
    ) -> Result<DirectoryPublicationReceipt, Self::Error> {
        self.with_mut(|filesystem| filesystem.create_directory(context, request))
    }

    fn create_file(
        &mut self,
        context: meshspan_filesystem::FilesystemAccessContext,
        request: &AdapterCreateFileRequest,
    ) -> Result<FilesystemHandleCreateReceipt, Self::Error> {
        self.with_mut(|filesystem| filesystem.create_file(context, request))
    }

    fn unlink(
        &mut self,
        context: meshspan_filesystem::FilesystemAccessContext,
        request: &AdapterUnlinkRequest,
    ) -> Result<NamespaceUnlinkReceipt, Self::Error> {
        self.with_mut(|filesystem| filesystem.unlink(context, request))
    }

    fn rename(
        &mut self,
        context: meshspan_filesystem::FilesystemAccessContext,
        request: &AdapterRenameRequest,
    ) -> Result<NamespaceRenameReceipt, Self::Error> {
        self.with_mut(|filesystem| filesystem.rename(context, request))
    }

    fn close_file(
        &mut self,
        context: meshspan_filesystem::FilesystemAccessContext,
        request: AdapterCloseFileRequest,
    ) -> Result<FilesystemHandleCloseReceipt, Self::Error> {
        self.with_mut(|filesystem| filesystem.close_file(context, request))
    }

    fn renew_lease(
        &mut self,
        context: meshspan_filesystem::FilesystemAccessContext,
        request: AdapterLeaseRequest,
    ) -> Result<HandleLeaseReceipt, Self::Error> {
        self.with_mut(|filesystem| filesystem.renew_lease(context, request))
    }

    fn lock_range(
        &mut self,
        context: meshspan_filesystem::FilesystemAccessContext,
        request: AdapterLockRequest,
    ) -> Result<LockRangeReceipt, Self::Error> {
        self.with_mut(|filesystem| filesystem.lock_range(context, request))
    }

    fn unlock_range(
        &mut self,
        context: meshspan_filesystem::FilesystemAccessContext,
        request: AdapterUnlockRequest,
    ) -> Result<UnlockRangeReceipt, Self::Error> {
        self.with_mut(|filesystem| filesystem.unlock_range(context, request))
    }
}

impl FilesystemUploadAdapter for NativeFilesystemRuntime {
    type Error = NativeFilesystemRuntimeError;

    fn begin_upload(
        &mut self,
        context: meshspan_filesystem::FilesystemAccessContext,
        request: &AdapterUploadBeginRequest,
    ) -> Result<UploadStatusReceipt, Self::Error> {
        self.with_mut(|filesystem| filesystem.begin_upload(context, request))
    }

    fn upload_status(
        &self,
        context: meshspan_filesystem::FilesystemAccessContext,
        request: AdapterUploadStatusRequest,
    ) -> Result<UploadStatusReceipt, Self::Error> {
        self.with_ref(|filesystem| filesystem.upload_status(context, request))
    }

    fn write_upload(
        &mut self,
        context: meshspan_filesystem::FilesystemAccessContext,
        request: &AdapterUploadWriteRequest,
    ) -> Result<UploadWriteReceipt, Self::Error> {
        self.with_mut(|filesystem| filesystem.write_upload(context, request))
    }

    fn upload_range_page(
        &self,
        context: meshspan_filesystem::FilesystemAccessContext,
        request: AdapterUploadRangePageRequest,
    ) -> Result<UploadRangePageReceipt, Self::Error> {
        self.with_ref(|filesystem| filesystem.upload_range_page(context, request))
    }

    fn abort_upload(
        &mut self,
        context: meshspan_filesystem::FilesystemAccessContext,
        request: AdapterUploadAbortRequest,
    ) -> Result<UploadSession, Self::Error> {
        self.with_mut(|filesystem| filesystem.abort_upload(context, request))
    }

    fn commit_upload(
        &mut self,
        context: meshspan_filesystem::FilesystemAccessContext,
        request: AdapterUploadCommitRequest,
    ) -> Result<UploadCommitReceipt, Self::Error> {
        self.with_mut(|filesystem| filesystem.commit_upload(context, request))
    }
}
