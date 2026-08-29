// SPDX-License-Identifier: GPL-2.0-only

//! Durable authority-owned file handles and cross-gateway share-mode admission.

#[path = "handles/flush.rs"]
mod flush;
#[path = "handles/lease.rs"]
mod lease;
#[path = "handles/locks.rs"]
mod locks;
#[path = "handles/path.rs"]
mod path;
#[path = "handles/read.rs"]
mod read;
#[path = "handles/rename.rs"]
mod rename;
#[path = "handles/state.rs"]
mod state;
#[cfg(test)]
#[path = "handles_tests.rs"]
mod tests;
#[path = "handles/write.rs"]
mod write;

pub(crate) use flush::{
    advance_progress as advance_flush_progress, base_content as handle_base_content,
    committed_stage_sequence, prepare as prepare_flush,
};
pub use lease::{
    CloseHandleOutcome, CloseHandleReceipt, CloseHandleRequest, HandleLeaseReceipt,
    HandleLeaseRequest,
};
pub(crate) use lease::{close, renew, resolve_close_request};
pub use locks::{
    ByteRange, LockRangeReceipt, LockRangeRequest, RangeLockKind, UnlockRangeReceipt,
    UnlockRangeRequest,
};
pub(crate) use locks::{lock_range, unlock_range};
pub(crate) use read::{HandleReadPlan, prepare_read};
pub use rename::{ReadyNamespaceDelete, ReadyNamespaceDeletePage};
pub(crate) use rename::{
    consume_unlink_authority, load_ready_deletes, prepare as prepare_rename, prepare_unlink,
    relocate_paths as relocate_handle_paths,
};
pub(crate) use write::admit_write;
pub use write::{HandleWriteAdmissionReceipt, HandleWriteAdmissionRequest};

use meshspan_domain::{
    BranchId, FileVersionId, HandleId, NamespaceCommitId, NodeId, ObjectId, ObjectRevisionId,
    OperationId, PrincipalId, Revision, UnixMicros, VolumeId,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use thiserror::Error;

use crate::publication::{PublicationDisposition, PublicationError, load_directory_node};
use crate::{
    DirectoryEntry, DirectoryEntryKind, DirectoryNodeDigest, DirectoryTrie, NamespacePath,
};

#[cfg(test)]
pub(crate) use path::load as load_handle_path;
pub(crate) use state::uses_private_stage;

const READ_ACCESS: u8 = 1;
const WRITE_ACCESS: u8 = 2;
const DELETE_ACCESS: u8 = 4;
const ACCESS_MASK: u8 = READ_ACCESS | WRITE_ACCESS | DELETE_ACCESS;

/// Desired operations held by one open file handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandleAccess(u8);

impl HandleAccess {
    /// Builds a non-empty closed access set.
    ///
    /// # Errors
    ///
    /// Rejects a handle that requests no data or deletion operation.
    pub const fn new(read: bool, write: bool, delete: bool) -> Result<Self, HandleError> {
        let mut bits = 0;
        if read {
            bits |= READ_ACCESS;
        }
        if write {
            bits |= WRITE_ACCESS;
        }
        if delete {
            bits |= DELETE_ACCESS;
        }
        if bits == 0 {
            Err(HandleError::InvalidInput)
        } else {
            Ok(Self(bits))
        }
    }

    /// Whether this handle requested read access.
    #[must_use]
    pub const fn reads(self) -> bool {
        self.0 & READ_ACCESS != 0
    }

    /// Whether this handle requested write access.
    #[must_use]
    pub const fn writes(self) -> bool {
        self.0 & WRITE_ACCESS != 0
    }

    /// Whether this handle requested deletion access.
    #[must_use]
    pub const fn deletes(self) -> bool {
        self.0 & DELETE_ACCESS != 0
    }

    const fn bits(self) -> u8 {
        self.0
    }

    fn from_bits(bits: u8) -> Result<Self, HandleError> {
        if bits == 0 || bits & !ACCESS_MASK != 0 {
            Err(HandleError::Corrupt)
        } else {
            Ok(Self(bits))
        }
    }
}

/// Existing operations another handle is permitted to keep sharing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandleShare(u8);

impl HandleShare {
    /// Builds a closed share set; sharing nothing is valid and exclusive.
    #[must_use]
    pub const fn new(read: bool, write: bool, delete: bool) -> Self {
        let mut bits = 0;
        if read {
            bits |= READ_ACCESS;
        }
        if write {
            bits |= WRITE_ACCESS;
        }
        if delete {
            bits |= DELETE_ACCESS;
        }
        Self(bits)
    }

    /// Whether other handles may read concurrently.
    #[must_use]
    pub const fn permits_read(self) -> bool {
        self.0 & READ_ACCESS != 0
    }

    /// Whether other handles may write concurrently.
    #[must_use]
    pub const fn permits_write(self) -> bool {
        self.0 & WRITE_ACCESS != 0
    }

    /// Whether other handles may request deletion concurrently.
    #[must_use]
    pub const fn permits_delete(self) -> bool {
        self.0 & DELETE_ACCESS != 0
    }

    const fn bits(self) -> u8 {
        self.0
    }

    fn from_bits(bits: u8) -> Result<Self, HandleError> {
        if bits & !ACCESS_MASK == 0 {
            Ok(Self(bits))
        } else {
            Err(HandleError::Corrupt)
        }
    }
}

/// Protocol-neutral create/open choice supplied by an access adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateDisposition {
    /// Fail if the path does not exist.
    OpenExisting,
    /// Fail if the path already exists.
    CreateNew,
    /// Open the path or reserve creation when absent.
    OpenOrCreate,
    /// Open an existing file and begin with empty staged content.
    OverwriteExisting,
    /// Overwrite an existing file or reserve creation when absent.
    OverwriteOrCreate,
}

impl CreateDisposition {
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::OpenExisting => 1,
            Self::CreateNew => 2,
            Self::OpenOrCreate => 3,
            Self::OverwriteExisting => 4,
            Self::OverwriteOrCreate => 5,
        }
    }

    pub(crate) fn from_code(code: u8) -> Result<Self, HandleError> {
        match code {
            1 => Ok(Self::OpenExisting),
            2 => Ok(Self::CreateNew),
            3 => Ok(Self::OpenOrCreate),
            4 => Ok(Self::OverwriteExisting),
            5 => Ok(Self::OverwriteOrCreate),
            _ => Err(HandleError::Corrupt),
        }
    }

    pub(crate) const fn truncates_existing(self) -> bool {
        matches!(self, Self::OverwriteExisting | Self::OverwriteOrCreate)
    }
}

/// Complete hostile-input boundary for atomically opening one existing file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenHandleRequest {
    /// Stable idempotency identity for the open attempt.
    pub operation_id: OperationId,
    /// Stable handle identity reserved by the caller's entropy source.
    pub handle_id: HandleId,
    /// Reachable local/cell branch authority.
    pub branch_id: BranchId,
    /// Volume containing the requested path.
    pub volume_id: VolumeId,
    /// Already bounded canonical path resolved inside the `MeshSpan` namespace.
    pub path: NamespacePath,
    /// Authenticated principal using the handle.
    pub principal_id: PrincipalId,
    /// Exact committed authorisation revision evaluated before open.
    pub authorization_revision: Revision,
    /// Gateway currently responsible for lease renewal.
    pub gateway_node_id: NodeId,
    /// Desired read/write/delete operations.
    pub desired_access: HandleAccess,
    /// Operations allowed on concurrent handles.
    pub share_access: HandleShare,
    /// Existing/creation behaviour requested by the adapter.
    pub create_disposition: CreateDisposition,
    /// Whether the final close should remove the namespace entry.
    pub delete_on_close: bool,
    /// Exclusive authoritative lease deadline.
    pub lease_expires_at: UnixMicros,
    /// Authoritative open instant.
    pub opened_at: UnixMicros,
}

/// Durable result of one atomic existing-file open.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenHandleReceipt {
    /// Whether this call applied or replayed the exact open operation.
    pub disposition: PublicationDisposition,
    /// Idempotency identity of the open.
    pub operation_id: OperationId,
    /// Fenced handle identity.
    pub handle_id: HandleId,
    /// Exact request digest retained for conflict detection.
    pub request_digest: [u8; 32],
    /// Namespace head under which the path was resolved.
    pub namespace_commit_id: NamespaceCommitId,
    /// Stable opened file object.
    pub object_id: ObjectId,
    /// Exact immutable object revision selected by the path.
    pub object_revision_id: ObjectRevisionId,
    /// Exact immutable file version pinned at open.
    pub opened_version_id: FileVersionId,
    /// First fencing generation issued for the handle.
    pub handle_fence: u64,
    /// Whether the adapter must initialise an empty private write stage.
    pub truncate_on_first_write: bool,
    /// Digest binding the complete durable result.
    pub result_digest: [u8; 32],
}

/// Exact live handle target exposed to the connector-neutral authority boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandleAuthorityTarget {
    /// Volume containing the opened object.
    pub volume_id: VolumeId,
    /// Stable opened object identity.
    pub object_id: ObjectId,
    /// Principal that owns the handle.
    pub principal_id: PrincipalId,
    /// Gateway currently holding the handle fence.
    pub gateway_node_id: NodeId,
    /// Authority revision recorded when the handle was opened or renewed.
    pub authorization_revision: Revision,
    /// Operations originally admitted for the handle.
    pub desired_access: HandleAccess,
    /// Exclusive handle lease deadline.
    pub lease_expires_at: UnixMicros,
}

/// Stable failures from handle admission and durable state.
#[derive(Debug, Error)]
pub enum HandleError {
    /// Request fields or relationships are invalid.
    #[error("filesystem handle input is invalid")]
    InvalidInput,
    /// The requested path does not identify a current regular file.
    #[error("filesystem handle target was not found")]
    NotFound,
    /// `create_new` selected a path that already exists.
    #[error("filesystem handle target already exists")]
    AlreadyExists,
    /// Creation-capable disposition selected an absent path; creation reservation is separate.
    #[error("filesystem handle target requires atomic creation")]
    CreationRequired,
    /// Another live handle's desired/share sets are incompatible.
    #[error("filesystem handle sharing violation")]
    SharingViolation,
    /// The target is waiting for its final live handle before namespace deletion.
    #[error("filesystem handle target is pending deletion")]
    DeletePending,
    /// The handle is absent, closed, expired or no longer owned by the supplied fence.
    #[error("filesystem handle fence is stale")]
    StaleHandle,
    /// A different gateway owns the live lease and takeover was not requested.
    #[error("filesystem handle lease belongs to another gateway")]
    GatewayMismatch,
    /// A live incompatible byte-range lock overlaps the requested range.
    #[error("filesystem byte-range lock conflicts with a live lock")]
    LockConflict,
    /// A prepared handle flush must reach a durable terminal state before namespace relocation.
    #[error("filesystem handle flush is still in progress")]
    FlushInProgress,
    /// A selected directory still contains at least one logical child.
    #[error("filesystem directory is not empty")]
    DirectoryNotEmpty,
    /// The selected lock is absent, released, expired or owned by another fence.
    #[error("filesystem byte-range lock is stale")]
    StaleLock,
    /// An idempotency or handle identity was reused for different input.
    #[error("filesystem handle operation conflicts with durable state")]
    OperationConflict,
    /// Durable namespace or handle state violates an invariant.
    #[error("filesystem handle state is corrupt")]
    Corrupt,
    /// Namespace loading or verification failed.
    #[error("filesystem handle namespace verification failed")]
    Namespace(#[from] PublicationError),
    /// SQLite persistence failed.
    #[error("filesystem handle database operation failed")]
    Sqlite(#[from] rusqlite::Error),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedFile {
    namespace_commit: NamespaceCommitId,
    object: ObjectId,
    object_revision: ObjectRevisionId,
    version: FileVersionId,
}

impl ResolvedFile {
    pub(crate) const fn created(
        namespace_commit: NamespaceCommitId,
        object: ObjectId,
        object_revision: ObjectRevisionId,
        version: FileVersionId,
    ) -> Self {
        Self {
            namespace_commit,
            object,
            object_revision,
            version,
        }
    }
}

struct StoredOpenReceipt {
    request_digest: Vec<u8>,
    handle: Vec<u8>,
    branch: Vec<u8>,
    volume: Vec<u8>,
    namespace_commit: Vec<u8>,
    object: Vec<u8>,
    object_revision: Vec<u8>,
    opened_version: Vec<u8>,
    opened_fence: i64,
    desired_access: i64,
    share_access: i64,
    create_disposition: i64,
    receipt_digest: Vec<u8>,
}

pub(crate) fn open_existing(
    connection: &mut Connection,
    request: &OpenHandleRequest,
) -> Result<OpenHandleReceipt, HandleError> {
    open_existing_at(connection, request, None)
}

pub(crate) fn open_existing_at(
    connection: &mut Connection,
    request: &OpenHandleRequest,
    expected_object_id: Option<ObjectId>,
) -> Result<OpenHandleReceipt, HandleError> {
    validate_open(request)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(receipt) = resolve_open_request(&transaction, request)? {
        return Ok(receipt);
    }
    let request_digest = open_request_digest(request);
    reject_operation_collision(&transaction, request.operation_id)?;
    expire_stale_handles(&transaction, request.opened_at)?;
    let Some(resolved) = resolve_file(&transaction, request)? else {
        return absent_disposition(request.create_disposition);
    };
    if expected_object_id.is_some_and(|expected| expected != resolved.object) {
        return Err(HandleError::StaleHandle);
    }
    if request.create_disposition == CreateDisposition::CreateNew {
        return Err(HandleError::AlreadyExists);
    }
    reject_handle_collision(&transaction, request.handle_id)?;
    reject_pending_delete(&transaction, request, resolved.object)?;
    enforce_share_modes(&transaction, request, resolved.object)?;
    let receipt = persist_open(&transaction, request, request_digest, resolved)?;
    transaction.commit()?;
    Ok(receipt)
}

pub(crate) fn resolve_open_object(
    connection: &Connection,
    request: &OpenHandleRequest,
) -> Result<Option<ObjectId>, HandleError> {
    validate_open(request)?;
    resolve_file(connection, request).map(|resolved| resolved.map(|file| file.object))
}

pub(crate) fn resolve_path_object(
    connection: &Connection,
    branch_id: BranchId,
    volume_id: VolumeId,
    path: &NamespacePath,
) -> Result<Option<ObjectId>, HandleError> {
    resolve_file_path(connection, branch_id, volume_id, path)
        .map(|resolved| resolved.map(|file| file.object))
}

pub(crate) fn authority_target(
    connection: &Connection,
    handle: HandleId,
    observed_at: UnixMicros,
) -> Result<HandleAuthorityTarget, HandleError> {
    state::authority_target(connection, handle, observed_at)
}

pub(crate) fn resolve_open_request(
    connection: &Connection,
    request: &OpenHandleRequest,
) -> Result<Option<OpenHandleReceipt>, HandleError> {
    validate_open(request)?;
    let request_digest = open_request_digest(request);
    let receipt = load_open_receipt(
        connection,
        request.operation_id,
        PublicationDisposition::Replayed,
    )?;
    receipt
        .map(|receipt| {
            if receipt.request_digest == request_digest && receipt.handle_id == request.handle_id {
                Ok(receipt)
            } else {
                Err(HandleError::OperationConflict)
            }
        })
        .transpose()
}

pub(crate) fn open_created(
    transaction: &Transaction<'_>,
    request: &OpenHandleRequest,
    expected: ResolvedFile,
) -> Result<OpenHandleReceipt, HandleError> {
    validate_open(request)?;
    if !matches!(
        request.create_disposition,
        CreateDisposition::CreateNew
            | CreateDisposition::OpenOrCreate
            | CreateDisposition::OverwriteOrCreate
    ) {
        return Err(HandleError::InvalidInput);
    }
    let request_digest = open_request_digest(request);
    if let Some(receipt) = load_open_receipt(
        transaction,
        request.operation_id,
        PublicationDisposition::Replayed,
    )? {
        return if receipt.request_digest == request_digest
            && receipt.handle_id == request.handle_id
            && receipt.namespace_commit_id == expected.namespace_commit
            && receipt.object_id == expected.object
            && receipt.object_revision_id == expected.object_revision
            && receipt.opened_version_id == expected.version
        {
            Ok(receipt)
        } else {
            Err(HandleError::OperationConflict)
        };
    }
    reject_operation_collision(transaction, request.operation_id)?;
    expire_stale_handles(transaction, request.opened_at)?;
    let resolved = resolve_file(transaction, request)?.ok_or(HandleError::Corrupt)?;
    if resolved != expected {
        return Err(HandleError::Corrupt);
    }
    reject_handle_collision(transaction, request.handle_id)?;
    reject_pending_delete(transaction, request, resolved.object)?;
    enforce_share_modes(transaction, request, resolved.object)?;
    persist_open(transaction, request, request_digest, resolved)
}

pub(crate) fn preflight_open(
    connection: &Connection,
    request: &OpenHandleRequest,
) -> Result<(), HandleError> {
    validate_open(request)?;
    let Some(resolved) = resolve_file(connection, request)? else {
        return match request.create_disposition {
            CreateDisposition::OpenExisting | CreateDisposition::OverwriteExisting => {
                Err(HandleError::NotFound)
            }
            CreateDisposition::CreateNew
            | CreateDisposition::OpenOrCreate
            | CreateDisposition::OverwriteOrCreate => Err(HandleError::CreationRequired),
        };
    };
    if request.create_disposition == CreateDisposition::CreateNew {
        return Err(HandleError::AlreadyExists);
    }
    reject_pending_delete(connection, request, resolved.object)?;
    enforce_share_modes(connection, request, resolved.object)
}

fn validate_open(request: &OpenHandleRequest) -> Result<(), HandleError> {
    if request.authorization_revision == Revision::ZERO
        || request.lease_expires_at <= request.opened_at
        || request.delete_on_close && !request.desired_access.deletes()
        || request.create_disposition.truncates_existing() && !request.desired_access.writes()
    {
        Err(HandleError::InvalidInput)
    } else {
        Ok(())
    }
}

fn absent_disposition(disposition: CreateDisposition) -> Result<OpenHandleReceipt, HandleError> {
    match disposition {
        CreateDisposition::OpenExisting | CreateDisposition::OverwriteExisting => {
            Err(HandleError::NotFound)
        }
        CreateDisposition::CreateNew
        | CreateDisposition::OpenOrCreate
        | CreateDisposition::OverwriteOrCreate => Err(HandleError::CreationRequired),
    }
}

fn resolve_file(
    connection: &Connection,
    request: &OpenHandleRequest,
) -> Result<Option<ResolvedFile>, HandleError> {
    resolve_file_path(
        connection,
        request.branch_id,
        request.volume_id,
        &request.path,
    )
}

fn resolve_file_path(
    connection: &Connection,
    branch_id: BranchId,
    volume_id: VolumeId,
    path: &NamespacePath,
) -> Result<Option<ResolvedFile>, HandleError> {
    type StoredHead = (Vec<u8>, Vec<u8>, Vec<u8>);
    let head: Option<StoredHead> = connection
        .query_row(
            "SELECT h.namespace_commit_id, c.root_object_id, c.root_object_revision_id
             FROM branch_namespace_heads h
             JOIN namespace_commits c USING(namespace_commit_id)
             WHERE h.branch_id = ?1 AND h.volume_id = ?2",
            params![
                branch_id.as_bytes().as_slice(),
                volume_id.as_bytes().as_slice()
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((commit, root_object, root_revision)) = head else {
        return Ok(None);
    };
    let namespace_commit_id = identifier(&commit, NamespaceCommitId::from_bytes)?;
    let mut object_id = identifier(&root_object, ObjectId::from_bytes)?;
    let mut revision_id = identifier(&root_revision, ObjectRevisionId::from_bytes)?;
    for (index, component) in path.components().iter().enumerate() {
        let revision = load_revision(connection, revision_id)?;
        if revision.volume_id != volume_id
            || revision.object_id != object_id
            || revision.kind != DirectoryEntryKind::Directory
        {
            return Err(HandleError::Corrupt);
        }
        let entry = lookup_entry(
            connection,
            revision.directory_root.ok_or(HandleError::Corrupt)?,
            component,
        )?;
        let Some(entry) = entry else {
            return Ok(None);
        };
        if index + 1 == path.components().len() {
            return resolve_leaf(
                connection,
                branch_id,
                volume_id,
                namespace_commit_id,
                &entry,
            );
        }
        if entry.kind() != DirectoryEntryKind::Directory {
            return Ok(None);
        }
        object_id = entry.object_id();
        revision_id = entry.object_revision_id();
    }
    Ok(None)
}

fn resolve_leaf(
    connection: &Connection,
    branch_id: BranchId,
    volume_id: VolumeId,
    namespace_commit_id: NamespaceCommitId,
    entry: &DirectoryEntry,
) -> Result<Option<ResolvedFile>, HandleError> {
    if entry.kind() != DirectoryEntryKind::File {
        return Ok(None);
    }
    let revision = load_revision(connection, entry.object_revision_id())?;
    let version_id = revision.file_version_id.ok_or(HandleError::Corrupt)?;
    if revision.volume_id != volume_id
        || revision.object_id != entry.object_id()
        || revision.kind != DirectoryEntryKind::File
    {
        return Err(HandleError::Corrupt);
    }
    let stored_head: Option<(Vec<u8>, Option<Vec<u8>>)> = connection
        .query_row(
            "SELECT volume_id, current_version_id FROM branch_files
             WHERE branch_id = ?1 AND object_id = ?2",
            params![
                branch_id.as_bytes().as_slice(),
                entry.object_id().as_bytes().as_slice()
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((volume, current)) = stored_head else {
        return Err(HandleError::Corrupt);
    };
    if volume.as_slice() != volume_id.as_bytes()
        || current.as_deref() != Some(version_id.as_bytes().as_slice())
    {
        return Err(HandleError::Corrupt);
    }
    Ok(Some(ResolvedFile {
        namespace_commit: namespace_commit_id,
        object: entry.object_id(),
        object_revision: entry.object_revision_id(),
        version: version_id,
    }))
}

#[derive(Clone, Copy)]
pub(crate) struct StoredRevision {
    pub(crate) volume_id: VolumeId,
    pub(crate) object_id: ObjectId,
    pub(crate) kind: DirectoryEntryKind,
    pub(crate) directory_root: Option<DirectoryNodeDigest>,
    pub(crate) file_version_id: Option<FileVersionId>,
}

pub(crate) fn load_revision(
    connection: &Connection,
    revision_id: ObjectRevisionId,
) -> Result<StoredRevision, HandleError> {
    type Stored = (Vec<u8>, Vec<u8>, i64, Option<Vec<u8>>, Option<Vec<u8>>);
    let stored: Stored = connection.query_row(
        "SELECT volume_id, object_id, object_kind, directory_root_digest, file_version_id
         FROM object_revisions WHERE object_revision_id = ?1",
        [revision_id.as_bytes().as_slice()],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )?;
    let kind = match stored.2 {
        1 => DirectoryEntryKind::Directory,
        2 => DirectoryEntryKind::File,
        _ => return Err(HandleError::Corrupt),
    };
    let directory_root = stored
        .3
        .as_deref()
        .map(|bytes| array(bytes).map(DirectoryNodeDigest::from_bytes))
        .transpose()?;
    let file_version_id = stored
        .4
        .as_deref()
        .map(|bytes| identifier(bytes, FileVersionId::from_bytes))
        .transpose()?;
    if (kind == DirectoryEntryKind::Directory) != directory_root.is_some()
        || (kind == DirectoryEntryKind::File) != file_version_id.is_some()
    {
        return Err(HandleError::Corrupt);
    }
    Ok(StoredRevision {
        volume_id: identifier(&stored.0, VolumeId::from_bytes)?,
        object_id: identifier(&stored.1, ObjectId::from_bytes)?,
        kind,
        directory_root,
        file_version_id,
    })
}

pub(crate) fn lookup_entry(
    connection: &Connection,
    root: DirectoryNodeDigest,
    name: &crate::NamespaceComponent,
) -> Result<Option<DirectoryEntry>, HandleError> {
    let mut selected = root;
    let mut records = Vec::new();
    for depth in 0..=64 {
        let record = load_directory_node(connection, selected)?.ok_or(HandleError::Corrupt)?;
        let child = record
            .selected_child(name, depth)
            .map_err(PublicationError::from)?;
        records.push(record);
        let Some(child) = child else {
            break;
        };
        selected = child;
    }
    let trie = DirectoryTrie::from_selected_records(root, records, name)
        .map_err(PublicationError::from)?;
    trie.lookup(name)
        .map_err(PublicationError::from)
        .map_err(Into::into)
}

fn enforce_share_modes(
    transaction: &Connection,
    request: &OpenHandleRequest,
    object_id: ObjectId,
) -> Result<(), HandleError> {
    let conflicts: i64 = transaction.query_row(
        "SELECT count(*) FROM open_handles
         WHERE branch_id = ?1 AND volume_id = ?2 AND object_id = ?3
           AND state = 1 AND lease_expires_at > ?4
           AND (((?5 & ((~share_access) & 7)) != 0)
             OR ((desired_access & ((~?6) & 7)) != 0))",
        params![
            request.branch_id.as_bytes().as_slice(),
            request.volume_id.as_bytes().as_slice(),
            object_id.as_bytes().as_slice(),
            request.opened_at.get(),
            request.desired_access.bits(),
            request.share_access.bits(),
        ],
        |row| row.get(0),
    )?;
    if conflicts == 0 {
        Ok(())
    } else {
        Err(HandleError::SharingViolation)
    }
}

fn persist_open(
    transaction: &Transaction<'_>,
    request: &OpenHandleRequest,
    request_digest: [u8; 32],
    resolved: ResolvedFile,
) -> Result<OpenHandleReceipt, HandleError> {
    let actual_path = resolve_actual_path(transaction, request, resolved)?;
    let result_digest = open_result_digest(request, request_digest, resolved);
    transaction.execute(
        "INSERT INTO open_handles(
            handle_id, open_operation_id, request_digest, branch_id, volume_id,
            opened_namespace_commit_id, object_id, object_revision_id, opened_version_id, principal_id,
            authorization_revision, gateway_node_id, opened_fence, handle_fence,
            desired_access, share_access, create_disposition, delete_on_close,
            lease_expires_at, state, opened_at, closed_at, receipt_digest
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 1, 1,
            ?13, ?14, ?15, ?16, ?17, 1, ?18, NULL, ?19
         )",
        params![
            request.handle_id.as_bytes().as_slice(),
            request.operation_id.as_bytes().as_slice(),
            request_digest.as_slice(),
            request.branch_id.as_bytes().as_slice(),
            request.volume_id.as_bytes().as_slice(),
            resolved.namespace_commit.as_bytes().as_slice(),
            resolved.object.as_bytes().as_slice(),
            resolved.object_revision.as_bytes().as_slice(),
            resolved.version.as_bytes().as_slice(),
            request.principal_id.as_bytes().as_slice(),
            to_i64(request.authorization_revision.get())?,
            request.gateway_node_id.as_bytes().as_slice(),
            request.desired_access.bits(),
            request.share_access.bits(),
            request.create_disposition.code(),
            request.delete_on_close,
            request.lease_expires_at.get(),
            request.opened_at.get(),
            result_digest.as_slice(),
        ],
    )?;
    path::persist(transaction, request.handle_id, &actual_path)?;
    Ok(OpenHandleReceipt {
        disposition: PublicationDisposition::Applied,
        operation_id: request.operation_id,
        handle_id: request.handle_id,
        request_digest,
        namespace_commit_id: resolved.namespace_commit,
        object_id: resolved.object,
        object_revision_id: resolved.object_revision,
        opened_version_id: resolved.version,
        handle_fence: 1,
        truncate_on_first_write: request.create_disposition.truncates_existing(),
        result_digest,
    })
}

fn resolve_actual_path(
    connection: &Connection,
    request: &OpenHandleRequest,
    resolved: ResolvedFile,
) -> Result<NamespacePath, HandleError> {
    type StoredHead = (Vec<u8>, Vec<u8>);
    let (root_object, root_revision): StoredHead = connection.query_row(
        "SELECT c.root_object_id, c.root_object_revision_id
         FROM branch_namespace_heads h
         JOIN namespace_commits c USING(namespace_commit_id)
         WHERE h.branch_id = ?1 AND h.volume_id = ?2",
        params![
            request.branch_id.as_bytes().as_slice(),
            request.volume_id.as_bytes().as_slice()
        ],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let mut object_id = identifier(&root_object, ObjectId::from_bytes)?;
    let mut revision_id = identifier(&root_revision, ObjectRevisionId::from_bytes)?;
    let mut components = Vec::with_capacity(request.path.components().len());
    for (index, requested) in request.path.components().iter().enumerate() {
        let revision = load_revision(connection, revision_id)?;
        if revision.volume_id != request.volume_id
            || revision.object_id != object_id
            || revision.kind != DirectoryEntryKind::Directory
        {
            return Err(HandleError::Corrupt);
        }
        let entry = lookup_entry(
            connection,
            revision.directory_root.ok_or(HandleError::Corrupt)?,
            requested,
        )?
        .ok_or(HandleError::Corrupt)?;
        components.push(entry.name().clone());
        if index + 1 == request.path.components().len() {
            if entry.object_id() != resolved.object
                || entry.object_revision_id() != resolved.object_revision
            {
                return Err(HandleError::Corrupt);
            }
        } else {
            object_id = entry.object_id();
            revision_id = entry.object_revision_id();
        }
    }
    NamespacePath::from_stored_components(components).map_err(|_| HandleError::Corrupt)
}

pub(crate) fn load_open_receipt(
    connection: &Connection,
    operation_id: OperationId,
    disposition: PublicationDisposition,
) -> Result<Option<OpenHandleReceipt>, HandleError> {
    let stored: Option<StoredOpenReceipt> = connection
        .query_row(
            "SELECT request_digest, handle_id, branch_id, volume_id,
                    opened_namespace_commit_id, object_id, object_revision_id,
                    opened_version_id, opened_fence, desired_access, share_access,
                    create_disposition, receipt_digest
             FROM open_handles WHERE open_operation_id = ?1",
            [operation_id.as_bytes().as_slice()],
            |row| {
                Ok(StoredOpenReceipt {
                    request_digest: row.get(0)?,
                    handle: row.get(1)?,
                    branch: row.get(2)?,
                    volume: row.get(3)?,
                    namespace_commit: row.get(4)?,
                    object: row.get(5)?,
                    object_revision: row.get(6)?,
                    opened_version: row.get(7)?,
                    opened_fence: row.get(8)?,
                    desired_access: row.get(9)?,
                    share_access: row.get(10)?,
                    create_disposition: row.get(11)?,
                    receipt_digest: row.get(12)?,
                })
            },
        )
        .optional()?;
    stored
        .as_ref()
        .map(|stored| decode_open_receipt(connection, operation_id, disposition, stored))
        .transpose()
}

fn decode_open_receipt(
    connection: &Connection,
    operation_id: OperationId,
    disposition: PublicationDisposition,
    stored: &StoredOpenReceipt,
) -> Result<OpenHandleReceipt, HandleError> {
    let request_digest = array(&stored.request_digest)?;
    let handle_id = identifier(&stored.handle, HandleId::from_bytes)?;
    let branch_id = identifier(&stored.branch, BranchId::from_bytes)?;
    let volume_id = identifier(&stored.volume, VolumeId::from_bytes)?;
    let namespace_commit_id = identifier(&stored.namespace_commit, NamespaceCommitId::from_bytes)?;
    let object_id = identifier(&stored.object, ObjectId::from_bytes)?;
    let object_revision_id = identifier(&stored.object_revision, ObjectRevisionId::from_bytes)?;
    let opened_version_id = identifier(&stored.opened_version, FileVersionId::from_bytes)?;
    let fence = u64::try_from(stored.opened_fence).map_err(|_| HandleError::Corrupt)?;
    let desired = u8::try_from(stored.desired_access).map_err(|_| HandleError::Corrupt)?;
    let shared = u8::try_from(stored.share_access).map_err(|_| HandleError::Corrupt)?;
    HandleAccess::from_bits(desired)?;
    HandleShare::from_bits(shared)?;
    let create_disposition = CreateDisposition::from_code(
        u8::try_from(stored.create_disposition).map_err(|_| HandleError::Corrupt)?,
    )?;
    let result_digest = array(&stored.receipt_digest)?;
    validate_open_lineage(
        connection,
        branch_id,
        volume_id,
        namespace_commit_id,
        object_id,
        object_revision_id,
        opened_version_id,
    )?;
    let resolved = ResolvedFile {
        namespace_commit: namespace_commit_id,
        object: object_id,
        object_revision: object_revision_id,
        version: opened_version_id,
    };
    let expected = open_result_digest_fields(
        operation_id,
        handle_id,
        request_digest,
        resolved,
        fence,
        create_disposition.truncates_existing(),
    );
    if fence != 1 || result_digest != expected {
        return Err(HandleError::Corrupt);
    }
    Ok(OpenHandleReceipt {
        disposition,
        operation_id,
        handle_id,
        request_digest,
        namespace_commit_id,
        object_id,
        object_revision_id,
        opened_version_id,
        handle_fence: fence,
        truncate_on_first_write: create_disposition.truncates_existing(),
        result_digest,
    })
}

fn validate_open_lineage(
    connection: &Connection,
    branch_id: BranchId,
    volume_id: VolumeId,
    namespace_commit_id: NamespaceCommitId,
    object_id: ObjectId,
    object_revision_id: ObjectRevisionId,
    version_id: FileVersionId,
) -> Result<(), HandleError> {
    let valid: i64 = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM namespace_commits c
            JOIN object_revisions r ON r.object_revision_id = ?4
            JOIN file_versions v ON v.version_id = ?5
            WHERE c.namespace_commit_id = ?1 AND c.branch_id = ?2 AND c.volume_id = ?3
              AND r.volume_id = ?3 AND r.object_id = ?6 AND r.object_kind = 2
              AND r.file_version_id = ?5 AND v.volume_id = ?3 AND v.object_id = ?6
         )",
        params![
            namespace_commit_id.as_bytes().as_slice(),
            branch_id.as_bytes().as_slice(),
            volume_id.as_bytes().as_slice(),
            object_revision_id.as_bytes().as_slice(),
            version_id.as_bytes().as_slice(),
            object_id.as_bytes().as_slice(),
        ],
        |row| row.get(0),
    )?;
    if valid == 1 {
        Ok(())
    } else {
        Err(HandleError::Corrupt)
    }
}

fn expire_stale_handles(transaction: &Transaction<'_>, now: UnixMicros) -> Result<(), HandleError> {
    transaction.execute(
        "UPDATE range_locks SET state = 3, released_at = ?1
         WHERE state = 1 AND (
             lease_expires_at <= ?1 OR EXISTS(
                 SELECT 1 FROM open_handles h
                 WHERE h.handle_id = range_locks.handle_id
                   AND h.state = 1 AND h.lease_expires_at <= ?1
             )
         )",
        [now.get()],
    )?;
    transaction.execute(
        "INSERT INTO pending_object_deletes(
            branch_id, volume_id, object_id, requesting_handle_id,
            object_revision_id, version_id, state, requested_at, ready_at
         )
         SELECT handles.branch_id, handles.volume_id, handles.object_id, handles.handle_id,
                COALESCE(progress.object_revision_id, handles.object_revision_id),
                COALESCE(progress.version_id, handles.opened_version_id), 1, ?1, NULL
         FROM open_handles handles
         LEFT JOIN handle_flush_progress progress ON progress.handle_id = handles.handle_id
         WHERE handles.state = 1 AND handles.lease_expires_at <= ?1
           AND handles.delete_on_close = 1
         ON CONFLICT(branch_id, object_id) DO NOTHING",
        [now.get()],
    )?;
    transaction.execute(
        "UPDATE open_handles SET state = 3, closed_at = ?1
         WHERE state = 1 AND lease_expires_at <= ?1",
        [now.get()],
    )?;
    transaction.execute(
        "UPDATE pending_object_deletes AS pending SET state = 2, ready_at = ?1
         WHERE pending.state = 1 AND NOT EXISTS(
             SELECT 1 FROM open_handles h
             WHERE h.branch_id = pending.branch_id AND h.volume_id = pending.volume_id
               AND h.object_id = pending.object_id AND h.state = 1
               AND h.lease_expires_at > ?1
         )",
        [now.get()],
    )?;
    Ok(())
}

fn reject_operation_collision(
    transaction: &Transaction<'_>,
    operation_id: OperationId,
) -> Result<(), HandleError> {
    let collision: i64 = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM namespace_publication_operations WHERE operation_id = ?1)
             OR EXISTS(SELECT 1 FROM directory_publication_operations WHERE operation_id = ?1)
             OR EXISTS(SELECT 1 FROM namespace_reconciliation_operations WHERE operation_id = ?1)
             OR EXISTS(SELECT 1 FROM namespace_snapshot_restore_operations WHERE operation_id = ?1)
             OR EXISTS(SELECT 1 FROM namespace_rename_operations WHERE operation_id = ?1)
             OR EXISTS(SELECT 1 FROM namespace_unlink_operations WHERE operation_id = ?1)
             OR EXISTS(SELECT 1 FROM range_locks WHERE operation_id = ?1)
             OR EXISTS(SELECT 1 FROM handle_mutation_operations WHERE operation_id = ?1)
             OR EXISTS(SELECT 1 FROM handle_write_admissions WHERE operation_id = ?1)
             OR EXISTS(SELECT 1 FROM handle_flush_plans WHERE operation_id = ?1)",
        [operation_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if collision == 0 {
        Ok(())
    } else {
        Err(HandleError::OperationConflict)
    }
}

fn reject_handle_collision(
    transaction: &Transaction<'_>,
    handle_id: HandleId,
) -> Result<(), HandleError> {
    let collision: i64 = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM open_handles WHERE handle_id = ?1)",
        [handle_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if collision == 0 {
        Ok(())
    } else {
        Err(HandleError::OperationConflict)
    }
}

fn reject_pending_delete(
    transaction: &Connection,
    request: &OpenHandleRequest,
    object_id: ObjectId,
) -> Result<(), HandleError> {
    let pending: i64 = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM pending_object_deletes
            WHERE branch_id = ?1 AND volume_id = ?2 AND object_id = ?3
         )",
        params![
            request.branch_id.as_bytes().as_slice(),
            request.volume_id.as_bytes().as_slice(),
            object_id.as_bytes().as_slice(),
        ],
        |row| row.get(0),
    )?;
    if pending == 0 {
        Ok(())
    } else {
        Err(HandleError::DeletePending)
    }
}

fn open_request_digest(request: &OpenHandleRequest) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.open-handle-request.v1\0");
    digest.update(&request.operation_id.as_bytes());
    digest.update(&request.handle_id.as_bytes());
    digest.update(&request.branch_id.as_bytes());
    digest.update(&request.volume_id.as_bytes());
    digest.update(&(request.path.components().len() as u64).to_be_bytes());
    for component in request.path.components() {
        update_text(&mut digest, component.display());
        update_text(&mut digest, component.canonical());
    }
    digest.update(&request.principal_id.as_bytes());
    digest.update(&request.authorization_revision.get().to_be_bytes());
    digest.update(&request.gateway_node_id.as_bytes());
    digest.update(&[request.desired_access.bits()]);
    digest.update(&[request.share_access.bits()]);
    digest.update(&[request.create_disposition.code()]);
    digest.update(&[u8::from(request.delete_on_close)]);
    digest.update(&request.lease_expires_at.get().to_be_bytes());
    digest.update(&request.opened_at.get().to_be_bytes());
    digest.finalize().into()
}

fn open_result_digest(
    request: &OpenHandleRequest,
    request_digest: [u8; 32],
    resolved: ResolvedFile,
) -> [u8; 32] {
    open_result_digest_fields(
        request.operation_id,
        request.handle_id,
        request_digest,
        resolved,
        1,
        request.create_disposition.truncates_existing(),
    )
}

fn open_result_digest_fields(
    operation_id: OperationId,
    handle_id: HandleId,
    request_digest: [u8; 32],
    resolved: ResolvedFile,
    fence: u64,
    truncate: bool,
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.open-handle-result.v1\0");
    digest.update(&operation_id.as_bytes());
    digest.update(&handle_id.as_bytes());
    digest.update(&request_digest);
    digest.update(&resolved.namespace_commit.as_bytes());
    digest.update(&resolved.object.as_bytes());
    digest.update(&resolved.object_revision.as_bytes());
    digest.update(&resolved.version.as_bytes());
    digest.update(&fence.to_be_bytes());
    digest.update(&[u8::from(truncate)]);
    digest.finalize().into()
}

fn update_text(digest: &mut blake3::Hasher, value: &str) {
    digest.update(&(value.len() as u64).to_be_bytes());
    digest.update(value.as_bytes());
}

fn identifier<T>(
    bytes: &[u8],
    constructor: fn([u8; 16]) -> Result<T, meshspan_domain::IdentifierError>,
) -> Result<T, HandleError> {
    constructor(bytes.try_into().map_err(|_| HandleError::Corrupt)?)
        .map_err(|_| HandleError::Corrupt)
}

fn array(bytes: &[u8]) -> Result<[u8; 32], HandleError> {
    bytes.try_into().map_err(|_| HandleError::Corrupt)
}

fn to_i64(value: u64) -> Result<i64, HandleError> {
    i64::try_from(value).map_err(|_| HandleError::InvalidInput)
}
