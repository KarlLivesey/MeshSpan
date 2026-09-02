// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::BoundedBytes;
use meshspan_domain::{
    AssuranceLevel, AuthenticationService, FileVersionId, NamespaceCommitId, NodeId, ObjectId,
    ObjectRevisionId, OperationId, UnixMicros, VolumeId,
};
use meshspan_filesystem::{
    AdapterCloseFileRequest, AdapterCreateDirectoryRequest, AdapterCreateFileRequest,
    AdapterFlushFileRequest, AdapterLeaseRequest, AdapterListRequest, AdapterLockRequest,
    AdapterOpenFileRequest, AdapterReadFileRequest, AdapterRenameRequest, AdapterStatRequest,
    AdapterUnlinkRequest, AdapterUnlockRequest, AdapterWriteFileRequest, ByteRange,
    CloseHandleOutcome, CloseHandleReceipt, DirectoryPublicationReceipt, FilesystemAccessContext,
    FilesystemFileAdapter, FilesystemHandleCloseReceipt, FilesystemHandleCreateReceipt,
    FilesystemHandleReadReceipt, FilesystemHandleWriteReceipt, HandleLeaseReceipt,
    HandleWriteAdmissionReceipt, LockRangeReceipt, NamespaceListPage, NamespaceObjectStat,
    NamespacePublicationReceipt, NamespaceRenameReceipt, NamespaceUnlinkReceipt, OpenHandleReceipt,
    PublicationDisposition, StageWriteOutcome, UnlockRangeReceipt,
};

use super::{
    FILE_ATTRIBUTE_NORMAL, SmbFilesystemAdapter, SmbFilesystemAdapterError, SmbFilesystemLimits,
    SmbTreeBinding,
};
use crate::{
    CloseRequest, CreateDisposition, CreateOptions, CreateRequest, CreateTargetKind, FlushRequest,
    ReadRequest, Smb2Command, Smb2Header, SmbRequestedAccess, SmbShareAccess, WriteRequest,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("test filesystem rejected an operation")]
struct TestError;

#[derive(Clone, Debug, Eq, PartialEq)]
enum Call {
    Create {
        components: Vec<String>,
        maximum_stage_bytes: Option<u64>,
    },
    Write {
        offset: u64,
        bytes: Vec<u8>,
    },
    Read {
        offset: u64,
        length: u64,
    },
    Flush {
        sequence: u64,
        final_length: u64,
    },
    Close {
        has_flush: bool,
    },
}

#[derive(Default)]
struct TestFilesystem {
    calls: Vec<Call>,
}

impl FilesystemFileAdapter for TestFilesystem {
    type Error = TestError;

    fn open_existing_file(
        &mut self,
        _context: FilesystemAccessContext,
        _request: &AdapterOpenFileRequest,
    ) -> Result<OpenHandleReceipt, Self::Error> {
        Err(TestError)
    }

    fn read_file(
        &mut self,
        _context: FilesystemAccessContext,
        request: AdapterReadFileRequest,
    ) -> Result<FilesystemHandleReadReceipt, Self::Error> {
        self.calls.push(Call::Read {
            offset: request.offset,
            length: request.length,
        });
        Ok(FilesystemHandleReadReceipt {
            opened_version_id: file_version()?,
            checkpoint_sequence: 1,
            bytes: BoundedBytes::copy_from(b"safe", 4).map_err(|_| TestError)?,
        })
    }

    fn write_file(
        &mut self,
        _context: FilesystemAccessContext,
        request: &AdapterWriteFileRequest,
    ) -> Result<FilesystemHandleWriteReceipt, Self::Error> {
        let length = u64::try_from(request.bytes.len()).map_err(|_| TestError)?;
        let range = ByteRange::new(request.offset, length).map_err(|_| TestError)?;
        self.calls.push(Call::Write {
            offset: request.offset,
            bytes: request.bytes.as_slice().to_vec(),
        });
        Ok(FilesystemHandleWriteReceipt {
            admission: HandleWriteAdmissionReceipt {
                disposition: PublicationDisposition::Applied,
                operation_id: request.operation_id,
                handle_id: request.handle_id,
                request_digest: [2; 32],
                handle_fence: request.handle_fence,
                range,
                content_digest: [3; 32],
                admitted_at: request.observed_at,
                result_digest: [4; 32],
            },
            stage_outcome: StageWriteOutcome::Applied,
            checkpoint: meshspan_filesystem::Checkpoint {
                sequence: 1,
                logical_extent: request.offset + length,
                initialised_ranges: std::iter::once(request.offset..request.offset + length)
                    .collect(),
            },
        })
    }

    fn flush_file(
        &mut self,
        _context: FilesystemAccessContext,
        request: AdapterFlushFileRequest,
    ) -> Result<NamespacePublicationReceipt, Self::Error> {
        self.calls.push(Call::Flush {
            sequence: request.expected_stage_sequence,
            final_length: request.final_length,
        });
        publication(request.operation_id)
    }

    fn stat(
        &self,
        _context: FilesystemAccessContext,
        _request: &AdapterStatRequest,
    ) -> Result<NamespaceObjectStat, Self::Error> {
        Err(TestError)
    }

    fn list(
        &self,
        _context: FilesystemAccessContext,
        _request: &AdapterListRequest,
    ) -> Result<NamespaceListPage, Self::Error> {
        Err(TestError)
    }

    fn create_directory(
        &mut self,
        _context: FilesystemAccessContext,
        _request: &AdapterCreateDirectoryRequest,
    ) -> Result<DirectoryPublicationReceipt, Self::Error> {
        Err(TestError)
    }

    fn create_file(
        &mut self,
        _context: FilesystemAccessContext,
        request: &AdapterCreateFileRequest,
    ) -> Result<FilesystemHandleCreateReceipt, Self::Error> {
        self.calls.push(Call::Create {
            components: request
                .path
                .components()
                .iter()
                .map(|component| component.display().to_owned())
                .collect(),
            maximum_stage_bytes: request.maximum_stage_bytes,
        });
        Ok(FilesystemHandleCreateReceipt {
            handle: OpenHandleReceipt {
                disposition: PublicationDisposition::Applied,
                operation_id: request.operation_id,
                handle_id: request.handle_id,
                request_digest: [5; 32],
                namespace_commit_id: namespace_commit()?,
                object_id: object()?,
                object_revision_id: object_revision()?,
                opened_version_id: file_version()?,
                opened_logical_length: 12,
                handle_fence: 1,
                truncate_on_first_write: false,
                result_digest: [6; 32],
            },
            creation: None,
        })
    }

    fn unlink(
        &mut self,
        _context: FilesystemAccessContext,
        _request: &AdapterUnlinkRequest,
    ) -> Result<NamespaceUnlinkReceipt, Self::Error> {
        Err(TestError)
    }

    fn rename(
        &mut self,
        _context: FilesystemAccessContext,
        _request: &AdapterRenameRequest,
    ) -> Result<NamespaceRenameReceipt, Self::Error> {
        Err(TestError)
    }

    fn close_file(
        &mut self,
        _context: FilesystemAccessContext,
        request: AdapterCloseFileRequest,
    ) -> Result<FilesystemHandleCloseReceipt, Self::Error> {
        self.calls.push(Call::Close {
            has_flush: request.flush.is_some(),
        });
        Ok(FilesystemHandleCloseReceipt {
            flush: request
                .flush
                .map(|flush| publication(flush.operation_id))
                .transpose()?,
            close: CloseHandleReceipt {
                disposition: PublicationDisposition::Applied,
                operation_id: request.operation_id,
                handle_id: request.handle_id,
                request_digest: [7; 32],
                handle_fence: request.handle_fence,
                outcome: CloseHandleOutcome::Closed,
                closed_at: request.observed_at,
                result_digest: [8; 32],
            },
        })
    }

    fn renew_lease(
        &mut self,
        _context: FilesystemAccessContext,
        _request: AdapterLeaseRequest,
    ) -> Result<HandleLeaseReceipt, Self::Error> {
        Err(TestError)
    }

    fn lock_range(
        &mut self,
        _context: FilesystemAccessContext,
        _request: AdapterLockRequest,
    ) -> Result<LockRangeReceipt, Self::Error> {
        Err(TestError)
    }

    fn unlock_range(
        &mut self,
        _context: FilesystemAccessContext,
        _request: AdapterUnlockRequest,
    ) -> Result<UnlockRangeReceipt, Self::Error> {
        Err(TestError)
    }
}

#[test]
fn file_commands_use_one_authorised_copy_on_write_lifecycle()
-> Result<(), Box<dyn std::error::Error>> {
    let mut adapter = adapter(64)?;
    let create = create_request(11, vec!["report.txt".to_owned()]);
    let opened = adapter.create_file(context()?, &create)?;
    assert_eq!(&opened.response.packet[112..120], &12_u64.to_le_bytes());

    let write = WriteRequest {
        header: header(Smb2Command::Write, 12),
        file_id: opened.file_id,
        offset: 4,
        bytes: b"new".to_vec(),
        write_through: false,
        unbuffered: false,
    };
    let response = adapter.write_file(context()?, &write)?;
    assert_eq!(&response.packet[68..72], &3_u32.to_le_bytes());

    let read = adapter.read_file(
        context()?,
        ReadRequest {
            header: header(Smb2Command::Read, 13),
            file_id: opened.file_id,
            offset: 2,
            length: 4,
            minimum_count: 0,
        },
    )?;
    assert_eq!(&read.packet[80..], b"safe");

    let flush = adapter.flush_file(
        context()?,
        FlushRequest {
            header: header(Smb2Command::Flush, 14),
            file_id: opened.file_id,
        },
    )?;
    assert_eq!(&flush[64..66], &4_u16.to_le_bytes());
    let close = adapter.close_file(
        context()?,
        CloseRequest {
            header: header(Smb2Command::Close, 15),
            file_id: opened.file_id,
            postquery_attributes: true,
        },
    )?;
    assert_eq!(&close.packet[112..120], &12_u64.to_le_bytes());

    assert_eq!(
        adapter.into_inner().calls,
        vec![
            Call::Create {
                components: vec!["shared".to_owned(), "report.txt".to_owned()],
                maximum_stage_bytes: Some(64),
            },
            Call::Write {
                offset: 4,
                bytes: b"new".to_vec(),
            },
            Call::Read {
                offset: 2,
                length: 4,
            },
            Call::Flush {
                sequence: 1,
                final_length: 12,
            },
            Call::Close { has_flush: false },
        ]
    );
    Ok(())
}

#[test]
fn identity_and_size_fail_before_common_filesystem_dispatch()
-> Result<(), Box<dyn std::error::Error>> {
    let mut adapter = adapter(6)?;
    let mut create = create_request(21, vec!["small.txt".to_owned()]);
    create.header.tree_id = 99;
    assert!(matches!(
        adapter.create_file(context()?, &create),
        Err(SmbFilesystemAdapterError::InvalidIdentity)
    ));

    create.header.tree_id = 23;
    let opened = adapter.create_file(context()?, &create)?;
    let oversized = WriteRequest {
        header: header(Smb2Command::Write, 22),
        file_id: opened.file_id,
        offset: 5,
        bytes: vec![1, 2],
        write_through: false,
        unbuffered: false,
    };
    assert!(matches!(
        adapter.write_file(context()?, &oversized),
        Err(SmbFilesystemAdapterError::LimitExceeded)
    ));
    assert_eq!(adapter.into_inner().calls.len(), 1);
    Ok(())
}

fn adapter(
    maximum_bytes: u64,
) -> Result<SmbFilesystemAdapter<TestFilesystem>, Box<dyn std::error::Error>> {
    let tree = SmbTreeBinding::new(
        29,
        23,
        volume()?,
        vec!["shared".to_owned()],
        meshspan_filesystem::NamespaceLimits::PORTABLE,
    )?;
    let limits = SmbFilesystemLimits::new(
        maximum_bytes,
        meshspan_domain::DurationMicros::new(60_000_000),
        meshspan_domain::DurationMicros::new(10_000_000),
    )?;
    Ok(SmbFilesystemAdapter::new(
        TestFilesystem::default(),
        tree,
        limits,
    ))
}

fn create_request(message_id: u64, path_components: Vec<String>) -> CreateRequest {
    CreateRequest {
        header: header(Smb2Command::Create, message_id),
        path_components,
        disposition: CreateDisposition::OpenOrCreate,
        desired_access: SmbRequestedAccess {
            wire_mask: 3,
            read_data: true,
            write_data: true,
            delete: false,
        },
        share_access: SmbShareAccess {
            read: true,
            write: true,
            delete: false,
        },
        file_attributes: FILE_ATTRIBUTE_NORMAL,
        options: CreateOptions {
            target_kind: CreateTargetKind::File,
            delete_on_close: false,
            write_through: false,
        },
    }
}

fn header(command: Smb2Command, message_id: u64) -> Smb2Header {
    Smb2Header {
        credit_charge: 1,
        command,
        credits_requested: 1,
        flags: 0,
        next_command: 0,
        message_id,
        process_id: 19,
        tree_id: 23,
        session_id: 29,
        signature: [0; 16],
    }
}

fn context() -> Result<FilesystemAccessContext, TestError> {
    Ok(FilesystemAccessContext {
        authentication_service: AuthenticationService::Smb,
        credential_digest: [9; 32],
        required_assurance: AssuranceLevel::SingleFactor,
        gateway_node_id: NodeId::from_bytes([8; 16]).map_err(|_| TestError)?,
        gateway_incarnation: 1,
        now: UnixMicros::new(1_000_000),
    })
}

fn publication(operation_id: OperationId) -> Result<NamespacePublicationReceipt, TestError> {
    Ok(NamespacePublicationReceipt {
        disposition: PublicationDisposition::Applied,
        operation_id,
        request_digest: [10; 32],
        file_version_id: file_version()?,
        namespace_commit_id: namespace_commit()?,
        head_sequence: 1,
        result_digest: [11; 32],
    })
}

fn volume() -> Result<VolumeId, TestError> {
    VolumeId::from_bytes([1; 16]).map_err(|_| TestError)
}

fn object() -> Result<ObjectId, TestError> {
    ObjectId::from_bytes([2; 16]).map_err(|_| TestError)
}

fn object_revision() -> Result<ObjectRevisionId, TestError> {
    ObjectRevisionId::from_bytes([3; 16]).map_err(|_| TestError)
}

fn file_version() -> Result<FileVersionId, TestError> {
    FileVersionId::from_bytes([4; 16]).map_err(|_| TestError)
}

fn namespace_commit() -> Result<NamespaceCommitId, TestError> {
    NamespaceCommitId::from_bytes([5; 16]).map_err(|_| TestError)
}
