// SPDX-License-Identifier: GPL-2.0-only

//! Immutable manifest/version publication with one atomic branch-file head transition.

use std::fs;
use std::path::Path;

use meshspan_domain::{
    BranchId, ContentManifestId, FileVersionId, ObjectId, OperationId, PrincipalId, UnixMicros,
    VolumeId,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use thiserror::Error;

use crate::{DirectoryNodeDigest, DirectoryNodeRecord, DirectoryTrieError};

const DATABASE_FILE: &str = "filesystem-branch.sqlite3";
const MAXIMUM_SQLITE_INTEGER: u64 = 9_223_372_036_854_775_807;
const MAXIMUM_NODES_PER_DIRECTORY_MUTATION: usize = 65;
const MIGRATIONS: [Migration; 2] = [
    Migration {
        version: 1,
        sql: include_str!("../schema/branch/001_initial.sql"),
    },
    Migration {
        version: 2,
        sql: include_str!("../schema/branch/002_directory_nodes.sql"),
    },
];
const SCHEMA_VERSION: u32 = 2;

#[derive(Clone, Copy)]
struct Migration {
    version: u32,
    sql: &'static str,
}

/// One complete, independently verified immutable content-manifest root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManifestPublication {
    /// Stable identity of the manifest root.
    pub manifest_id: ContentManifestId,
    /// On-disk manifest encoding version.
    pub format_version: u16,
    /// Exact logical file length represented by the manifest.
    pub logical_length: u64,
    /// Digest of the reconstructed plaintext file content.
    pub content_digest: [u8; 32],
    /// Digest of the complete immutable manifest graph.
    pub root_digest: [u8; 32],
}

/// Exact immutable version and expected branch-file head transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilePublication {
    /// Idempotency identity for the whole publication transaction.
    pub operation_id: OperationId,
    /// Writable local/cell branch receiving the version.
    pub branch_id: BranchId,
    /// Volume containing the stable file object.
    pub volume_id: VolumeId,
    /// Stable file identity, independent of names and versions.
    pub object_id: ObjectId,
    /// Exact current version required before publication, or no version for a new file.
    pub expected_current_version_id: Option<FileVersionId>,
    /// New globally stable immutable version identity.
    pub version_id: FileVersionId,
    /// Causal prior file version; must equal the expected current version.
    pub parent_version_id: Option<FileVersionId>,
    /// Complete verified content manifest selected by the version.
    pub manifest: ManifestPublication,
    /// Principal responsible for publication.
    pub created_by: PrincipalId,
    /// Authoritative publication instant.
    pub created_at: UnixMicros,
}

/// Current branch-local version pointer for one stable file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BranchFileHead {
    /// Branch containing this head.
    pub branch_id: BranchId,
    /// Stable file identity.
    pub object_id: ObjectId,
    /// Volume containing the file.
    pub volume_id: VolumeId,
    /// Current immutable version, if any.
    pub current_version_id: Option<FileVersionId>,
    /// Monotonic successful head-transition sequence.
    pub sequence: u64,
}

/// Whether a publication created state or resolved an exact durable retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationDisposition {
    /// The new immutable records and file head were committed.
    Applied,
    /// The exact operation had already committed and returned its original receipt.
    Replayed,
}

/// Durable evidence for one atomic immutable version publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationReceipt {
    /// Whether this call applied or replayed the transaction.
    pub disposition: PublicationDisposition,
    /// Stable operation identity.
    pub operation_id: OperationId,
    /// Exact committed request digest.
    pub request_digest: [u8; 32],
    /// Published immutable version.
    pub version_id: FileVersionId,
    /// Resulting file-head sequence.
    pub head_sequence: u64,
    /// Digest binding the durable result fields.
    pub result_digest: [u8; 32],
}

/// SQLite-compatible branch store for immutable versions and atomic file heads.
pub struct VersionPublicationStore {
    connection: Connection,
}

impl VersionPublicationStore {
    /// Opens, migrates and verifies one daemon-local branch publication database.
    ///
    /// # Errors
    ///
    /// Rejects migration drift/newer schemas, integrity failure and IO/SQLite errors.
    pub fn open(state_directory: &Path, opened_at: UnixMicros) -> Result<Self, PublicationError> {
        fs::create_dir_all(state_directory)?;
        let mut connection = Connection::open(state_directory.join(DATABASE_FILE))?;
        configure(&connection)?;
        migrate(&mut connection, opened_at)?;
        verify_database(&connection)?;
        Ok(Self { connection })
    }

    /// Atomically persists one immutable manifest/version and advances its exact file head.
    ///
    /// # Errors
    ///
    /// Rejects malformed input, stale bases, identity reuse, corrupt durable state and IO/SQLite
    /// failure. A failed call publishes neither the version nor the file-head transition.
    pub fn publish(
        &mut self,
        publication: FilePublication,
    ) -> Result<PublicationReceipt, PublicationError> {
        self.publish_inner(publication, None)
    }

    /// Resolves the immutable durable receipt for one operation, if committed.
    ///
    /// # Errors
    ///
    /// Rejects malformed or digest-inconsistent durable records and SQLite failure.
    pub fn resolve(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<PublicationReceipt>, PublicationError> {
        load_operation(
            &self.connection,
            operation_id,
            PublicationDisposition::Replayed,
        )
    }

    /// Loads the exact current version pointer for one branch file.
    ///
    /// # Errors
    ///
    /// Rejects malformed durable identities/counters and SQLite failure.
    pub fn file_head(
        &self,
        branch_id: BranchId,
        object_id: ObjectId,
    ) -> Result<Option<BranchFileHead>, PublicationError> {
        load_file_head(&self.connection, branch_id, object_id)
    }

    /// Persists one bounded path-copy node set before a later namespace-head transaction.
    ///
    /// Immutable nodes may safely exist without a reachable head. Exact retries coalesce by
    /// content identity; different bytes under one digest fail closed.
    ///
    /// # Errors
    ///
    /// Rejects empty/excessive batches, malformed node encodings, digest collisions and SQLite
    /// failure. The whole node batch commits or rolls back together.
    pub fn persist_directory_nodes(
        &mut self,
        records: &[DirectoryNodeRecord],
        recorded_at: UnixMicros,
    ) -> Result<(), PublicationError> {
        if records.is_empty() || records.len() > MAXIMUM_NODES_PER_DIRECTORY_MUTATION {
            return Err(PublicationError::InvalidInput);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for record in records {
            persist_directory_node(&transaction, record, recorded_at)?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Loads and revalidates one immutable directory node by content identity.
    ///
    /// # Errors
    ///
    /// Rejects unsupported format, excessive/truncated encoding, digest mismatch and SQLite
    /// failure.
    pub fn directory_node(
        &self,
        digest: DirectoryNodeDigest,
    ) -> Result<Option<DirectoryNodeRecord>, PublicationError> {
        load_directory_node(&self.connection, digest)
    }

    fn publish_inner(
        &mut self,
        publication: FilePublication,
        fault: Option<PublicationFaultPoint>,
    ) -> Result<PublicationReceipt, PublicationError> {
        validate_publication(publication)?;
        let request_digest = publication_request_digest(publication);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(receipt) = load_operation(
            &transaction,
            publication.operation_id,
            PublicationDisposition::Replayed,
        )? {
            return if receipt.request_digest == request_digest {
                Ok(receipt)
            } else {
                Err(PublicationError::OperationConflict)
            };
        }
        let head = prepare_file(&transaction, publication)?;
        persist_manifest(&transaction, publication.manifest)?;
        inject_fault(fault, PublicationFaultPoint::Manifest)?;
        persist_version(&transaction, publication)?;
        inject_fault(fault, PublicationFaultPoint::Version)?;
        let head_sequence = advance_file_head(&transaction, publication, head.sequence)?;
        inject_fault(fault, PublicationFaultPoint::Head)?;
        let receipt = persist_operation(&transaction, publication, request_digest, head_sequence)?;
        inject_fault(fault, PublicationFaultPoint::Operation)?;
        transaction.commit()?;
        Ok(receipt)
    }
}

/// Stable publication failure categories.
#[derive(Debug, Error)]
pub enum PublicationError {
    /// A field, relationship, size or digest is invalid.
    #[error("file publication input is invalid")]
    InvalidInput,
    /// The presented current version no longer matches the branch file.
    #[error("file publication base is stale")]
    StaleHead,
    /// An immutable or idempotency identity already belongs to different content.
    #[error("file publication identity conflicts with durable state")]
    OperationConflict,
    /// Durable state violates an identity, digest or transition invariant.
    #[error("file publication state is corrupt")]
    Corrupt,
    /// Deterministic test-only transaction interruption.
    #[error("file publication transaction fault injected")]
    InjectedFault,
    /// Immutable directory-node encoding or graph validation failed.
    #[error("file publication directory node is invalid")]
    Directory(#[from] DirectoryTrieError),
    /// State-directory IO failed.
    #[error("file publication filesystem operation failed")]
    Io(#[from] std::io::Error),
    /// SQLite persistence failed.
    #[error("file publication database operation failed")]
    Sqlite(#[from] rusqlite::Error),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublicationFaultPoint {
    Manifest,
    Version,
    Head,
    Operation,
}

type StoredReceiptColumns = (Vec<u8>, Vec<u8>, Vec<u8>, i64);

fn validate_publication(publication: FilePublication) -> Result<(), PublicationError> {
    if publication.parent_version_id != publication.expected_current_version_id
        || publication.manifest.format_version == 0
        || publication.manifest.logical_length > MAXIMUM_SQLITE_INTEGER
    {
        return Err(PublicationError::InvalidInput);
    }
    Ok(())
}

fn prepare_file(
    transaction: &Transaction<'_>,
    publication: FilePublication,
) -> Result<BranchFileHead, PublicationError> {
    let existing = load_file_head(transaction, publication.branch_id, publication.object_id)?;
    if let Some(head) = existing {
        if head.volume_id != publication.volume_id
            || head.current_version_id != publication.expected_current_version_id
        {
            return Err(PublicationError::StaleHead);
        }
        return Ok(head);
    }
    if publication.expected_current_version_id.is_some() {
        return Err(PublicationError::StaleHead);
    }
    transaction.execute(
        "INSERT INTO branch_files(
            branch_id, object_id, volume_id, current_version_id, head_sequence
         ) VALUES (?1, ?2, ?3, NULL, 0)",
        params![
            publication.branch_id.as_bytes().as_slice(),
            publication.object_id.as_bytes().as_slice(),
            publication.volume_id.as_bytes().as_slice()
        ],
    )?;
    Ok(BranchFileHead {
        branch_id: publication.branch_id,
        object_id: publication.object_id,
        volume_id: publication.volume_id,
        current_version_id: None,
        sequence: 0,
    })
}

fn persist_manifest(
    transaction: &Transaction<'_>,
    manifest: ManifestPublication,
) -> Result<(), PublicationError> {
    let identifier = manifest.manifest_id.as_bytes();
    let existing: Option<(i64, i64, Vec<u8>, Vec<u8>)> = transaction
        .query_row(
            "SELECT format_version, logical_length, content_digest, root_digest
             FROM content_manifests WHERE manifest_id = ?1 AND state = 1",
            [identifier.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let expected = (
        i64::from(manifest.format_version),
        to_i64(manifest.logical_length)?,
        manifest.content_digest,
        manifest.root_digest,
    );
    if let Some(existing) = existing {
        return if existing.0 == expected.0
            && existing.1 == expected.1
            && existing.2.as_slice() == expected.2
            && existing.3.as_slice() == expected.3
        {
            Ok(())
        } else {
            Err(PublicationError::OperationConflict)
        };
    }
    transaction.execute(
        "INSERT INTO content_manifests(
            manifest_id, format_version, logical_length, content_digest, root_digest, state
         ) VALUES (?1, ?2, ?3, ?4, ?5, 1)",
        params![
            identifier.as_slice(),
            expected.0,
            expected.1,
            expected.2.as_slice(),
            expected.3.as_slice()
        ],
    )?;
    Ok(())
}

fn persist_version(
    transaction: &Transaction<'_>,
    publication: FilePublication,
) -> Result<(), PublicationError> {
    let version = publication.version_id.as_bytes();
    let collision: i64 = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM file_versions WHERE version_id = ?1)",
        [version.as_slice()],
        |row| row.get(0),
    )?;
    if collision != 0 {
        return Err(PublicationError::OperationConflict);
    }
    let parent = publication.parent_version_id.map(FileVersionId::as_bytes);
    transaction.execute(
        "INSERT INTO file_versions(
            version_id, branch_id, volume_id, object_id, parent_version_id, manifest_id,
            logical_length, content_digest, created_by, created_at, publication_operation_id
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            version.as_slice(),
            publication.branch_id.as_bytes().as_slice(),
            publication.volume_id.as_bytes().as_slice(),
            publication.object_id.as_bytes().as_slice(),
            parent.as_ref().map(<[u8; 16]>::as_slice),
            publication.manifest.manifest_id.as_bytes().as_slice(),
            to_i64(publication.manifest.logical_length)?,
            publication.manifest.content_digest.as_slice(),
            publication.created_by.as_bytes().as_slice(),
            publication.created_at.get(),
            publication.operation_id.as_bytes().as_slice()
        ],
    )?;
    Ok(())
}

fn advance_file_head(
    transaction: &Transaction<'_>,
    publication: FilePublication,
    previous_sequence: u64,
) -> Result<u64, PublicationError> {
    let sequence = previous_sequence
        .checked_add(1)
        .ok_or(PublicationError::InvalidInput)?;
    let updated = transaction.execute(
        "UPDATE branch_files
         SET current_version_id = ?1, head_sequence = ?2
         WHERE branch_id = ?3 AND object_id = ?4 AND head_sequence = ?5",
        params![
            publication.version_id.as_bytes().as_slice(),
            to_i64(sequence)?,
            publication.branch_id.as_bytes().as_slice(),
            publication.object_id.as_bytes().as_slice(),
            to_i64(previous_sequence)?
        ],
    )?;
    if updated == 1 {
        Ok(sequence)
    } else {
        Err(PublicationError::StaleHead)
    }
}

fn persist_operation(
    transaction: &Transaction<'_>,
    publication: FilePublication,
    request_digest: [u8; 32],
    head_sequence: u64,
) -> Result<PublicationReceipt, PublicationError> {
    let result_digest = publication_result_digest(
        publication.operation_id,
        request_digest,
        publication.version_id,
        head_sequence,
    );
    transaction.execute(
        "INSERT INTO publication_operations(
            operation_id, request_digest, version_id, head_sequence, result_digest, committed_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            publication.operation_id.as_bytes().as_slice(),
            request_digest.as_slice(),
            publication.version_id.as_bytes().as_slice(),
            to_i64(head_sequence)?,
            result_digest.as_slice(),
            publication.created_at.get()
        ],
    )?;
    Ok(PublicationReceipt {
        disposition: PublicationDisposition::Applied,
        operation_id: publication.operation_id,
        request_digest,
        version_id: publication.version_id,
        head_sequence,
        result_digest,
    })
}

fn persist_directory_node(
    transaction: &Transaction<'_>,
    record: &DirectoryNodeRecord,
    recorded_at: UnixMicros,
) -> Result<(), PublicationError> {
    let encoded = record.encode();
    let verified = DirectoryNodeRecord::decode(record.digest(), &encoded)?;
    if &verified != record {
        return Err(PublicationError::Corrupt);
    }
    let digest = record.digest().as_bytes();
    let existing: Option<(i64, Vec<u8>)> = transaction
        .query_row(
            "SELECT format_version, encoded_node FROM directory_nodes WHERE node_digest = ?1",
            [digest.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((format, existing)) = existing {
        let stored = DirectoryNodeRecord::decode(record.digest(), &existing)?;
        return if format == 1 && &stored == record {
            Ok(())
        } else {
            Err(PublicationError::Corrupt)
        };
    }
    transaction.execute(
        "INSERT INTO directory_nodes(node_digest, format_version, encoded_node, recorded_at)
         VALUES (?1, 1, ?2, ?3)",
        params![digest.as_slice(), encoded, recorded_at.get()],
    )?;
    Ok(())
}

fn load_directory_node(
    connection: &Connection,
    digest: DirectoryNodeDigest,
) -> Result<Option<DirectoryNodeRecord>, PublicationError> {
    let identifier = digest.as_bytes();
    let stored: Option<(i64, Vec<u8>)> = connection
        .query_row(
            "SELECT format_version, encoded_node FROM directory_nodes WHERE node_digest = ?1",
            [identifier.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    stored
        .map(|(format, encoded)| {
            if format != 1 {
                return Err(PublicationError::Corrupt);
            }
            DirectoryNodeRecord::decode(digest, &encoded).map_err(Into::into)
        })
        .transpose()
}

fn load_operation(
    connection: &Connection,
    operation_id: OperationId,
    disposition: PublicationDisposition,
) -> Result<Option<PublicationReceipt>, PublicationError> {
    let operation = operation_id.as_bytes();
    let stored: Option<StoredReceiptColumns> = connection
        .query_row(
            "SELECT o.request_digest, o.version_id, o.result_digest, o.head_sequence
             FROM publication_operations o
             WHERE o.operation_id = ?1",
            [operation.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    stored
        .map(|values| decode_receipt(operation_id, disposition, &values))
        .transpose()
}

fn decode_receipt(
    operation_id: OperationId,
    disposition: PublicationDisposition,
    values: &StoredReceiptColumns,
) -> Result<PublicationReceipt, PublicationError> {
    let request_digest = copy_array(&values.0)?;
    let version_id = decode_identifier(&values.1, FileVersionId::from_bytes)?;
    let result_digest = copy_array(&values.2)?;
    let head_sequence = from_i64(values.3)?;
    let expected =
        publication_result_digest(operation_id, request_digest, version_id, head_sequence);
    if result_digest != expected {
        return Err(PublicationError::Corrupt);
    }
    Ok(PublicationReceipt {
        disposition,
        operation_id,
        request_digest,
        version_id,
        head_sequence,
        result_digest,
    })
}

fn load_file_head(
    connection: &Connection,
    branch_id: BranchId,
    object_id: ObjectId,
) -> Result<Option<BranchFileHead>, PublicationError> {
    let branch = branch_id.as_bytes();
    let object = object_id.as_bytes();
    let stored: Option<(Vec<u8>, Option<Vec<u8>>, i64)> = connection
        .query_row(
            "SELECT volume_id, current_version_id, head_sequence
             FROM branch_files WHERE branch_id = ?1 AND object_id = ?2",
            params![branch.as_slice(), object.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    stored
        .map(|values| {
            Ok(BranchFileHead {
                branch_id,
                object_id,
                volume_id: decode_identifier(&values.0, VolumeId::from_bytes)?,
                current_version_id: values
                    .1
                    .as_deref()
                    .map(|bytes| decode_identifier(bytes, FileVersionId::from_bytes))
                    .transpose()?,
                sequence: from_i64(values.2)?,
            })
        })
        .transpose()
}

fn publication_request_digest(publication: FilePublication) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.file-publication.v1\0");
    digest.update(&publication.operation_id.as_bytes());
    digest.update(&publication.branch_id.as_bytes());
    digest.update(&publication.volume_id.as_bytes());
    digest.update(&publication.object_id.as_bytes());
    update_optional_identifier(&mut digest, publication.expected_current_version_id);
    digest.update(&publication.version_id.as_bytes());
    update_optional_identifier(&mut digest, publication.parent_version_id);
    digest.update(&publication.manifest.manifest_id.as_bytes());
    digest.update(&publication.manifest.format_version.to_be_bytes());
    digest.update(&publication.manifest.logical_length.to_be_bytes());
    digest.update(&publication.manifest.content_digest);
    digest.update(&publication.manifest.root_digest);
    digest.update(&publication.created_by.as_bytes());
    digest.update(&publication.created_at.get().to_be_bytes());
    digest.finalize().into()
}

fn publication_result_digest(
    operation_id: OperationId,
    request_digest: [u8; 32],
    version_id: FileVersionId,
    sequence: u64,
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.file-publication-result.v1\0");
    digest.update(&operation_id.as_bytes());
    digest.update(&request_digest);
    digest.update(&version_id.as_bytes());
    digest.update(&sequence.to_be_bytes());
    digest.finalize().into()
}

fn update_optional_identifier(digest: &mut blake3::Hasher, value: Option<FileVersionId>) {
    if let Some(value) = value {
        digest.update(&[1]);
        digest.update(&value.as_bytes());
    } else {
        digest.update(&[0]);
    }
}

fn inject_fault(
    selected: Option<PublicationFaultPoint>,
    current: PublicationFaultPoint,
) -> Result<(), PublicationError> {
    if selected == Some(current) {
        Err(PublicationError::InjectedFault)
    } else {
        Ok(())
    }
}

fn configure(connection: &Connection) -> Result<(), PublicationError> {
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA trusted_schema = OFF;
         PRAGMA recursive_triggers = OFF;
         PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;",
    )?;
    Ok(())
}

fn migrate(connection: &mut Connection, applied_at: UnixMicros) -> Result<(), PublicationError> {
    let migration_table_exists = connection
        .query_row(
            "SELECT 1 FROM sqlite_schema
             WHERE type = 'table' AND name = 'schema_migrations' LIMIT 1",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    let current: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if current > SCHEMA_VERSION || (current == 0 && migration_table_exists) {
        return Err(PublicationError::Corrupt);
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    for migration in MIGRATIONS {
        let digest: [u8; 32] = blake3::hash(migration.sql.as_bytes()).into();
        if migration.version <= current {
            let stored: Vec<u8> = transaction.query_row(
                "SELECT migration_digest FROM schema_migrations WHERE version = ?1",
                [migration.version],
                |row| row.get(0),
            )?;
            if stored.as_slice() != digest {
                return Err(PublicationError::Corrupt);
            }
            continue;
        }
        transaction.execute_batch(migration.sql)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, migration_digest, applied_at)
             VALUES (?1, ?2, ?3)",
            params![migration.version, digest.as_slice(), applied_at.get()],
        )?;
        transaction.pragma_update(None, "user_version", migration.version)?;
    }
    transaction.commit()?;
    Ok(())
}

fn verify_database(connection: &Connection) -> Result<(), PublicationError> {
    let quick: String = connection.pragma_query_value(None, "quick_check", |row| row.get(0))?;
    let foreign_key_violation = connection
        .prepare("PRAGMA foreign_key_check")?
        .query([])?
        .next()?
        .is_some();
    if quick == "ok" && !foreign_key_violation {
        Ok(())
    } else {
        Err(PublicationError::Corrupt)
    }
}

fn decode_identifier<T, E>(
    bytes: &[u8],
    constructor: impl FnOnce([u8; 16]) -> Result<T, E>,
) -> Result<T, PublicationError> {
    constructor(bytes.try_into().map_err(|_| PublicationError::Corrupt)?)
        .map_err(|_| PublicationError::Corrupt)
}

fn copy_array(bytes: &[u8]) -> Result<[u8; 32], PublicationError> {
    bytes.try_into().map_err(|_| PublicationError::Corrupt)
}

fn to_i64(value: u64) -> Result<i64, PublicationError> {
    i64::try_from(value).map_err(|_| PublicationError::InvalidInput)
}

fn from_i64(value: i64) -> Result<u64, PublicationError> {
    u64::try_from(value).map_err(|_| PublicationError::Corrupt)
}

#[cfg(test)]
#[path = "publication_tests.rs"]
mod tests;
