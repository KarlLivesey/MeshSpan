// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::BoundedBytes;
use meshspan_domain::{
    AssuranceLevel, AuthenticationService, FileVersionId, LockId, NamespaceCommitId, NodeId,
    ObjectId, ObjectRevisionId, OperationId, StageId, UnixMicros, VolumeId,
};
use meshspan_filesystem::{
    AdapterCloseFileRequest, AdapterCreateDirectoryRequest, AdapterCreateFileRequest,
    AdapterFlushFileRequest, AdapterLeaseRequest, AdapterListRequest, AdapterLockRequest,
    AdapterOpenFileRequest, AdapterReadFileRequest, AdapterRenameRequest,
    AdapterSetDispositionRequest, AdapterSetLengthRequest, AdapterStatRequest,
    AdapterUnlinkRequest, AdapterUnlockRequest, AdapterWriteFileRequest, ByteRange,
    CloseHandleOutcome, CloseHandleReceipt, DirectoryPublicationReceipt, FilesystemAccessContext,
    FilesystemFileAdapter, FilesystemHandleCloseReceipt, FilesystemHandleCreateReceipt,
    FilesystemHandleLengthReceipt, FilesystemHandleReadReceipt, FilesystemHandleWriteReceipt,
    HandleInformationReceipt, HandleLeaseReceipt, HandleWriteAdmissionReceipt, LockRangeReceipt,
    NamespaceComponent, NamespaceListEntry, NamespaceListPage, NamespaceObjectStat,
    NamespacePublicationReceipt, NamespaceRenameReceipt, NamespaceUnlinkReceipt, OpenHandleReceipt,
    PublicationDisposition, RangeLockKind, StageLengthReceipt, StageWriteOutcome,
    UnlockRangeReceipt,
};

use super::{
    FILE_ATTRIBUTE_NORMAL, SmbFilesystemAdapter, SmbFilesystemAdapterError, SmbFilesystemLimits,
    SmbTreeBinding,
};
use crate::{
    CloseRequest, CreateDisposition, CreateOptions, CreateRequest, CreateTargetKind,
    DirectoryInformationClass, FlushRequest, LockElement, LockKind, LockRequest,
    QueryDirectoryRequest, QueryInfoRequest, ReadRequest, SetFileInformation, SetInfoRequest,
    Smb2Command, Smb2Header, SmbRequestedAccess, SmbShareAccess, WriteRequest,
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
    CreateDirectory {
        components: Vec<String>,
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
        sparse: bool,
    },
    Close {
        has_flush: bool,
    },
    Lock {
        offset: u64,
        length: u64,
        kind: RangeLockKind,
    },
    Unlock {
        lock_id: LockId,
    },
    Rename {
        source: Vec<String>,
        target: Vec<String>,
    },
    SetLength {
        logical_length: u64,
    },
    SetDisposition {
        delete_pending: bool,
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
            sparse: request.sparse,
        });
        publication(request.operation_id)
    }

    fn stat(
        &self,
        _context: FilesystemAccessContext,
        request: &AdapterStatRequest,
    ) -> Result<NamespaceObjectStat, Self::Error> {
        let name = request.path.components().last().ok_or(TestError)?.clone();
        let is_directory = name.display() == "shared";
        Ok(NamespaceObjectStat {
            namespace_commit_id: namespace_commit()?,
            object_id: ObjectId::from_bytes([21; 16]).map_err(|_| TestError)?,
            object_revision_id: ObjectRevisionId::from_bytes([22; 16]).map_err(|_| TestError)?,
            name,
            entry_generation: 1,
            kind: if is_directory {
                meshspan_filesystem::DirectoryEntryKind::Directory
            } else {
                meshspan_filesystem::DirectoryEntryKind::File
            },
            file_version_id: (!is_directory).then(file_version).transpose()?,
            logical_length: (!is_directory).then_some(16),
        })
    }

    fn list(
        &self,
        _context: FilesystemAccessContext,
        _request: &AdapterListRequest,
    ) -> Result<NamespaceListPage, Self::Error> {
        Ok(NamespaceListPage {
            namespace_commit_id: namespace_commit()?,
            directory_object_id: object()?,
            directory_object_revision_id: object_revision()?,
            entries: vec![NamespaceListEntry {
                name: NamespaceComponent::new(
                    "listed.txt",
                    meshspan_filesystem::NamespaceLimits::PORTABLE,
                )
                .map_err(|_| TestError)?,
                object_id: ObjectId::from_bytes([21; 16]).map_err(|_| TestError)?,
                object_revision_id: ObjectRevisionId::from_bytes([22; 16])
                    .map_err(|_| TestError)?,
                entry_generation: 1,
                kind: meshspan_filesystem::DirectoryEntryKind::File,
                file_version_id: Some(file_version()?),
                logical_length: Some(17),
            }],
            next_cursor: None,
        })
    }

    fn create_directory(
        &mut self,
        _context: FilesystemAccessContext,
        request: &AdapterCreateDirectoryRequest,
    ) -> Result<DirectoryPublicationReceipt, Self::Error> {
        self.calls.push(Call::CreateDirectory {
            components: request
                .path
                .components()
                .iter()
                .map(|component| component.display().to_owned())
                .collect(),
        });
        Ok(DirectoryPublicationReceipt {
            disposition: PublicationDisposition::Applied,
            operation_id: request.operation_id,
            request_digest: [16; 32],
            directory_object_id: object()?,
            directory_object_revision_id: object_revision()?,
            namespace_commit_id: namespace_commit()?,
            head_sequence: 1,
            result_digest: [17; 32],
        })
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
        request: &AdapterRenameRequest,
    ) -> Result<NamespaceRenameReceipt, Self::Error> {
        self.calls.push(Call::Rename {
            source: request
                .source
                .components()
                .iter()
                .map(|component| component.display().to_owned())
                .collect(),
            target: request
                .target
                .components()
                .iter()
                .map(|component| component.display().to_owned())
                .collect(),
        });
        Ok(NamespaceRenameReceipt {
            disposition: PublicationDisposition::Applied,
            operation_id: request.operation_id,
            request_digest: [23; 32],
            object_id: object()?,
            object_revision_id: object_revision()?,
            namespace_commit_id: namespace_commit()?,
            head_sequence: 2,
            result_digest: [24; 32],
        })
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
            delete: None,
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
        request: AdapterLockRequest,
    ) -> Result<LockRangeReceipt, Self::Error> {
        self.calls.push(Call::Lock {
            offset: request.range.start(),
            length: request.range.length(),
            kind: request.kind,
        });
        Ok(LockRangeReceipt {
            disposition: PublicationDisposition::Applied,
            operation_id: request.operation_id,
            lock_id: request.lock_id,
            handle_id: request.handle_id,
            request_digest: [12; 32],
            handle_fence: request.handle_fence,
            range: request.range,
            kind: request.kind,
            lease_expires_at: request.lease_expires_at,
            result_digest: [13; 32],
        })
    }

    fn unlock_range(
        &mut self,
        _context: FilesystemAccessContext,
        request: AdapterUnlockRequest,
    ) -> Result<UnlockRangeReceipt, Self::Error> {
        self.calls.push(Call::Unlock {
            lock_id: request.lock_id,
        });
        Ok(UnlockRangeReceipt {
            disposition: PublicationDisposition::Applied,
            operation_id: request.operation_id,
            lock_id: request.lock_id,
            handle_id: request.handle_id,
            request_digest: [14; 32],
            handle_fence: request.handle_fence,
            released_at: request.observed_at,
            result_digest: [15; 32],
        })
    }

    fn set_length(
        &mut self,
        _context: FilesystemAccessContext,
        request: AdapterSetLengthRequest,
    ) -> Result<FilesystemHandleLengthReceipt, Self::Error> {
        self.calls.push(Call::SetLength {
            logical_length: request.logical_length,
        });
        let stage_id = StageId::from_bytes(request.handle_id.as_bytes()).map_err(|_| TestError)?;
        Ok(FilesystemHandleLengthReceipt {
            authority: HandleInformationReceipt {
                disposition: PublicationDisposition::Applied,
                operation_id: request.operation_id,
                handle_id: request.handle_id,
                request_digest: [16; 32],
                handle_fence: request.handle_fence,
                working_logical_length: request.logical_length,
                delete_on_close: false,
                changed_at: request.observed_at,
                result_digest: [17; 32],
            },
            stage: StageLengthReceipt {
                outcome: StageWriteOutcome::Applied,
                operation_id: request.operation_id,
                stage_id,
                request_digest: [18; 32],
                stage_fence: request.handle_fence,
                mutation_sequence: 2,
                logical_length: request.logical_length,
                applied_at: request.observed_at,
                result_digest: [19; 32],
            },
            checkpoint: meshspan_filesystem::Checkpoint {
                sequence: 2,
                logical_extent: request.logical_length,
                initialised_ranges: Vec::new(),
            },
        })
    }

    fn set_disposition(
        &mut self,
        _context: FilesystemAccessContext,
        request: AdapterSetDispositionRequest,
    ) -> Result<HandleInformationReceipt, Self::Error> {
        self.calls.push(Call::SetDisposition {
            delete_pending: request.delete_on_close,
        });
        Ok(HandleInformationReceipt {
            disposition: PublicationDisposition::Applied,
            operation_id: request.operation_id,
            handle_id: request.handle_id,
            request_digest: [20; 32],
            handle_fence: request.handle_fence,
            working_logical_length: 12,
            delete_on_close: request.delete_on_close,
            changed_at: request.observed_at,
            result_digest: [21; 32],
        })
    }
}

#[test]
fn file_commands_use_one_authorised_copy_on_write_lifecycle()
-> Result<(), Box<dyn std::error::Error>> {
    let mut adapter = adapter(64)?;
    let create = create_request(11, vec!["report.txt".to_owned()]);
    let opened = adapter.create(context()?, &create)?;
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
                sparse: true,
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
        adapter.create(context()?, &create),
        Err(SmbFilesystemAdapterError::InvalidIdentity)
    ));

    create.header.tree_id = 23;
    let opened = adapter.create(context()?, &create)?;
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

#[test]
fn exact_range_lock_is_retained_for_a_later_unlock() -> Result<(), Box<dyn std::error::Error>> {
    let mut adapter = adapter(64)?;
    let opened = adapter.create(
        context()?,
        &create_request(30, vec!["locked.txt".to_owned()]),
    )?;
    adapter.lock_ranges(
        context()?,
        &LockRequest {
            header: header(Smb2Command::Lock, 31),
            file_id: opened.file_id,
            elements: vec![LockElement {
                offset: 5,
                length: 7,
                kind: LockKind::Exclusive {
                    fail_immediately: true,
                },
            }],
        },
    )?;
    adapter.lock_ranges(
        context()?,
        &LockRequest {
            header: header(Smb2Command::Lock, 32),
            file_id: opened.file_id,
            elements: vec![LockElement {
                offset: 5,
                length: 7,
                kind: LockKind::Unlock,
            }],
        },
    )?;

    let calls = adapter.into_inner().calls;
    assert!(matches!(
        calls.get(1),
        Some(Call::Lock {
            offset: 5,
            length: 7,
            kind: RangeLockKind::Exclusive
        })
    ));
    let Some(Call::Unlock { lock_id }) = calls.get(2) else {
        return Err(Box::new(TestError));
    };
    assert_ne!(*lock_id, LockId::from_bytes([16; 16])?);
    Ok(())
}

#[test]
fn directory_create_enumerate_and_close_use_the_logical_namespace()
-> Result<(), Box<dyn std::error::Error>> {
    let mut adapter = adapter(64)?;
    let mut create = create_request(40, vec!["documents".to_owned()]);
    create.disposition = CreateDisposition::CreateNew;
    create.desired_access.write_data = false;
    create.file_attributes = 0x0000_0010;
    create.options.target_kind = CreateTargetKind::Directory;
    let opened = adapter.create(context()?, &create)?;

    let response = adapter.query_directory(
        context()?,
        &QueryDirectoryRequest {
            header: header(Smb2Command::QueryDirectory, 41),
            information_class: DirectoryInformationClass::Names,
            restart_scan: true,
            return_single_entry: false,
            reopen: false,
            file_id: opened.file_id,
            search_pattern: Some("*".to_owned()),
            output_buffer_length: 4_096,
        },
    )?;
    let expected_name = "listed.txt"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    assert_eq!(&response.packet[84..], expected_name);
    adapter.close_file(
        context()?,
        CloseRequest {
            header: header(Smb2Command::Close, 42),
            file_id: opened.file_id,
            postquery_attributes: true,
        },
    )?;
    assert_eq!(
        adapter.into_inner().calls,
        vec![Call::CreateDirectory {
            components: vec!["shared".to_owned(), "documents".to_owned()]
        }]
    );
    Ok(())
}

#[test]
fn exact_directory_search_resolves_one_case_preserved_logical_name()
-> Result<(), Box<dyn std::error::Error>> {
    let mut adapter = adapter(64)?;
    let mut directory = create_request(43, Vec::new());
    directory.disposition = CreateDisposition::OpenExisting;
    directory.desired_access.write_data = false;
    directory.file_attributes = 0x0000_0010;
    directory.options.target_kind = CreateTargetKind::Directory;
    let root = adapter.create(context()?, &directory)?;
    let response = adapter.query_directory(
        context()?,
        &QueryDirectoryRequest {
            header: header(Smb2Command::QueryDirectory, 44),
            information_class: DirectoryInformationClass::Names,
            restart_scan: true,
            return_single_entry: true,
            reopen: false,
            file_id: root.file_id,
            search_pattern: Some("Exact.txt".to_owned()),
            output_buffer_length: 4_096,
        },
    )?;
    let expected_name = "Exact.txt"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    assert_eq!(&response.packet[84..], expected_name);
    Ok(())
}

#[test]
fn query_and_rename_use_current_logical_open_state() -> Result<(), Box<dyn std::error::Error>> {
    let mut adapter = adapter(64)?;
    let mut create = create_request(50, vec!["old.txt".to_owned()]);
    create.desired_access.delete = true;
    create.desired_access.wire_mask = 0x0013_0089;
    create.share_access.delete = true;
    let opened = adapter.create(context()?, &create)?;

    let before = adapter.query_info(
        context()?,
        QueryInfoRequest {
            header: header(Smb2Command::QueryInfo, 51),
            information_class: crate::FileInformationClass::All,
            output_buffer_length: 4_096,
            file_id: opened.file_id,
        },
    )?;
    assert_eq!(&before.packet[168..172], &16_u32.to_le_bytes());

    let rename = SetInfoRequest {
        header: header(Smb2Command::SetInfo, 52),
        file_id: opened.file_id,
        information: SetFileInformation::Rename {
            replace_if_exists: false,
            target_components: vec!["archive".to_owned(), "new.txt".to_owned()],
        },
    };
    assert_eq!(
        &adapter.set_info(context()?, &rename)?[64..],
        &2_u16.to_le_bytes()
    );

    let after = adapter.query_info(
        context()?,
        QueryInfoRequest {
            header: header(Smb2Command::QueryInfo, 53),
            information_class: crate::FileInformationClass::NormalizedName,
            output_buffer_length: 4_096,
            file_id: opened.file_id,
        },
    )?;
    let expected = "\\archive\\new.txt"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    assert_eq!(&after.packet[76..], expected);
    assert_eq!(
        adapter.into_inner().calls.get(1),
        Some(&Call::Rename {
            source: vec!["shared".to_owned(), "old.txt".to_owned()],
            target: vec![
                "shared".to_owned(),
                "archive".to_owned(),
                "new.txt".to_owned(),
            ],
        })
    );
    Ok(())
}

#[test]
fn length_and_disposition_mutate_the_common_handle_before_success()
-> Result<(), Box<dyn std::error::Error>> {
    let mut adapter = adapter(64)?;
    let mut create = create_request(60, vec!["mutable.txt".to_owned()]);
    create.desired_access.delete = true;
    create.share_access.delete = true;
    let opened = adapter.create(context()?, &create)?;

    adapter.set_info(
        context()?,
        &SetInfoRequest {
            header: header(Smb2Command::SetInfo, 61),
            file_id: opened.file_id,
            information: SetFileInformation::EndOfFile { length: 27 },
        },
    )?;
    adapter.set_info(
        context()?,
        &SetInfoRequest {
            header: header(Smb2Command::SetInfo, 62),
            file_id: opened.file_id,
            information: SetFileInformation::Disposition {
                delete_pending: true,
            },
        },
    )?;
    adapter.flush_file(
        context()?,
        FlushRequest {
            header: header(Smb2Command::Flush, 63),
            file_id: opened.file_id,
        },
    )?;

    assert_eq!(
        adapter.into_inner().calls,
        vec![
            Call::Create {
                components: vec!["shared".to_owned(), "mutable.txt".to_owned()],
                maximum_stage_bytes: Some(64),
            },
            Call::SetLength { logical_length: 27 },
            Call::SetDisposition {
                delete_pending: true,
            },
            Call::Flush {
                sequence: 2,
                final_length: 27,
                sparse: true,
            },
        ]
    );
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
