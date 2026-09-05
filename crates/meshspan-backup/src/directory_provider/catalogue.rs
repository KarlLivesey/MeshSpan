// SPDX-License-Identifier: GPL-2.0-only

//! Durable relational state for one directory backup provider.

mod bootstrap;

use std::path::Path;

use meshspan_contracts::{
    BackupDeleteRequest, BackupObjectIdentity, BackupObjectReference, BackupStoreRequest,
};
use meshspan_domain::{BackupDestinationId, BackupId, OperationId, UnixMicros};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use super::DirectoryBackupProviderError;

const ACTIVE_OBJECT: i64 = 1;
const RETIRED_OBJECT: i64 = 2;

#[derive(Clone, Copy)]
pub(super) enum OperationKind {
    Store = 1,
    Delete = 2,
}

pub(super) struct Catalogue {
    connection: Connection,
    maximum_bytes: u64,
}

impl Catalogue {
    pub(super) fn live_objects(
        &self,
        after: Option<BackupId>,
    ) -> Result<Vec<BackupObjectIdentity>, DirectoryBackupProviderError> {
        let mut statement = self.connection.prepare(
            "SELECT backup_id, destination_id, provider_generation, byte_length, digest
             FROM backup_objects WHERE state = 1 AND backup_id > ?1 ORDER BY backup_id LIMIT 64",
        )?;
        let lower = after.map_or([0; 16], BackupId::as_bytes);
        let rows = statement.query_map([lower.as_slice()], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Vec<u8>>(4)?,
            ))
        })?;
        let mut objects = Vec::new();
        for row in rows {
            let (backup, destination, generation, bytes, digest) = row?;
            objects.push(BackupObjectIdentity {
                backup_id: BackupId::from_bytes(
                    backup
                        .try_into()
                        .map_err(|_| DirectoryBackupProviderError::Corrupt)?,
                )
                .map_err(|_| DirectoryBackupProviderError::Corrupt)?,
                destination_id: BackupDestinationId::from_bytes(
                    destination
                        .try_into()
                        .map_err(|_| DirectoryBackupProviderError::Corrupt)?,
                )
                .map_err(|_| DirectoryBackupProviderError::Corrupt)?,
                provider_generation: to_u64(generation)?,
                byte_length: to_u64(bytes)?,
                digest: digest
                    .try_into()
                    .map_err(|_| DirectoryBackupProviderError::Corrupt)?,
            });
        }
        Ok(objects)
    }

    pub(super) fn open(
        file_path: &Path,
        destination_id: BackupDestinationId,
        provider_generation: u64,
        maximum_bytes: u64,
        opened_at: UnixMicros,
    ) -> Result<Self, DirectoryBackupProviderError> {
        let connection = bootstrap::open(
            file_path,
            destination_id,
            provider_generation,
            maximum_bytes,
            opened_at,
        )?;
        Ok(Self {
            connection,
            maximum_bytes,
        })
    }

    pub(super) fn operation_completed(
        &self,
        operation_id: OperationId,
        kind: OperationKind,
        request_digest: [u8; 32],
    ) -> Result<bool, DirectoryBackupProviderError> {
        let Some(existing) = load_operation(&self.connection, operation_id)? else {
            return Ok(false);
        };
        validate_existing_operation(&existing, kind, request_digest)?;
        Ok(true)
    }

    pub(super) fn admit_capacity(
        &self,
        requested: BackupObjectIdentity,
    ) -> Result<(), DirectoryBackupProviderError> {
        let used = self.connection.query_row(
            "SELECT COALESCE(sum(byte_length), 0) FROM backup_objects
             WHERE state = 1 AND NOT (
                backup_id = ?1 AND destination_id = ?2 AND provider_generation = ?3
             )",
            params![
                requested.backup_id.as_bytes().as_slice(),
                requested.destination_id.as_bytes().as_slice(),
                to_i64(requested.provider_generation)?,
            ],
            |row| row.get::<_, i64>(0),
        )?;
        if to_u64(used)?
            .checked_add(requested.byte_length)
            .is_none_or(|total| total > self.maximum_bytes)
        {
            Err(DirectoryBackupProviderError::ResourceExhausted)
        } else {
            Ok(())
        }
    }

    pub(super) fn record_store(
        &mut self,
        request: BackupStoreRequest,
        object_reference: &str,
        request_digest: [u8; 32],
        observed_at: UnixMicros,
    ) -> Result<(), DirectoryBackupProviderError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = load_operation(&transaction, request.context.operation_id)? {
            validate_existing_operation(&existing, OperationKind::Store, request_digest)?;
            return Ok(());
        }
        let existing = load_object(&transaction, request.object)?;
        match existing {
            Some(existing)
                if existing.reference == object_reference
                    && existing.length == request.object.byte_length
                    && existing.digest == request.object.digest
                    && existing.state == ACTIVE_OBJECT => {}
            None => insert_object(&transaction, request, object_reference, observed_at)?,
            _ => return Err(DirectoryBackupProviderError::Conflict),
        }
        insert_operation(
            &transaction,
            NewOperation {
                operation_id: request.context.operation_id,
                kind: OperationKind::Store,
                request_digest,
                object: request.object,
                object_reference,
                observed_at,
                retirement_revision: None,
            },
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub(super) fn record_delete(
        &mut self,
        request: &BackupDeleteRequest,
        request_digest: [u8; 32],
        observed_at: UnixMicros,
    ) -> Result<(), DirectoryBackupProviderError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = load_operation(&transaction, request.context.operation_id)? {
            validate_existing_operation(&existing, OperationKind::Delete, request_digest)?;
            return Ok(());
        }
        retire_object(&transaction, request, observed_at)?;
        insert_operation(
            &transaction,
            NewOperation {
                operation_id: request.context.operation_id,
                kind: OperationKind::Delete,
                request_digest,
                object: request.object,
                object_reference: request.object_reference.as_str(),
                observed_at,
                retirement_revision: Some(request.retirement_revision.get()),
            },
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub(super) fn validate_live_object(
        &self,
        expected: BackupObjectIdentity,
        object_reference: &BackupObjectReference,
    ) -> Result<(), DirectoryBackupProviderError> {
        let Some(existing) = load_object(&self.connection, expected)? else {
            return Err(DirectoryBackupProviderError::NotFound);
        };
        if existing.matches(expected, object_reference) && existing.state == ACTIVE_OBJECT {
            Ok(())
        } else if existing.state == RETIRED_OBJECT {
            Err(DirectoryBackupProviderError::NotFound)
        } else {
            Err(DirectoryBackupProviderError::Conflict)
        }
    }

    pub(super) fn validate_known_object(
        &self,
        expected: BackupObjectIdentity,
        object_reference: &BackupObjectReference,
    ) -> Result<(), DirectoryBackupProviderError> {
        let Some(existing) = load_object(&self.connection, expected)? else {
            return Err(DirectoryBackupProviderError::NotFound);
        };
        if existing.matches(expected, object_reference) {
            Ok(())
        } else {
            Err(DirectoryBackupProviderError::Conflict)
        }
    }
}

pub(super) fn operation_digest(
    kind: OperationKind,
    request: BackupStoreRequest,
    object_reference: &str,
    retirement_revision: Option<u64>,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.directory-backup.operation.v1");
    digest.update((kind as i64).to_be_bytes());
    digest.update(request.context.operation_id.as_bytes());
    digest.update(request.context.contract_version.major.to_be_bytes());
    digest.update(request.context.contract_version.minor.to_be_bytes());
    // Retirement permanently identifies deletion authority. Its network deadline
    // belongs to one attempt, not to the durable idempotency key: a restarted
    // worker must be able to renew that deadline and recover the same receipt.
    if !matches!(kind, OperationKind::Delete) {
        digest.update(request.context.deadline.get().to_be_bytes());
    }
    digest.update(
        request
            .context
            .expected_revision
            .map_or(0, meshspan_domain::Revision::get)
            .to_be_bytes(),
    );
    digest.update(request.object.backup_id.as_bytes());
    digest.update(request.object.destination_id.as_bytes());
    digest.update(request.object.provider_generation.to_be_bytes());
    digest.update(request.object.byte_length.to_be_bytes());
    digest.update(request.object.digest);
    digest.update((object_reference.len() as u64).to_be_bytes());
    digest.update(object_reference.as_bytes());
    digest.update(retirement_revision.unwrap_or(0).to_be_bytes());
    digest.finalize().into()
}

#[derive(Debug)]
struct StoredOperation {
    kind: i64,
    request_digest: [u8; 32],
}

struct StoredObject {
    reference: String,
    length: u64,
    digest: [u8; 32],
    state: i64,
}

impl StoredObject {
    fn matches(
        &self,
        expected: BackupObjectIdentity,
        object_reference: &BackupObjectReference,
    ) -> bool {
        self.reference == object_reference.as_str()
            && self.length == expected.byte_length
            && self.digest == expected.digest
    }
}

#[derive(Clone, Copy)]
struct NewOperation<'a> {
    operation_id: OperationId,
    kind: OperationKind,
    request_digest: [u8; 32],
    object: BackupObjectIdentity,
    object_reference: &'a str,
    observed_at: UnixMicros,
    retirement_revision: Option<u64>,
}

fn insert_object(
    transaction: &Transaction<'_>,
    request: BackupStoreRequest,
    object_reference: &str,
    observed_at: UnixMicros,
) -> Result<(), DirectoryBackupProviderError> {
    transaction.execute(
        "INSERT INTO backup_objects(
            backup_id, destination_id, provider_generation, object_reference,
            byte_length, digest, state, stored_at, retired_at, retirement_revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, NULL, NULL)",
        params![
            request.object.backup_id.as_bytes().as_slice(),
            request.object.destination_id.as_bytes().as_slice(),
            to_i64(request.object.provider_generation)?,
            object_reference,
            to_i64(request.object.byte_length)?,
            request.object.digest.as_slice(),
            observed_at.get(),
        ],
    )?;
    Ok(())
}

fn retire_object(
    transaction: &Transaction<'_>,
    request: &BackupDeleteRequest,
    observed_at: UnixMicros,
) -> Result<(), DirectoryBackupProviderError> {
    let changed = transaction.execute(
        "UPDATE backup_objects
         SET state = 2, retired_at = ?1, retirement_revision = ?2
         WHERE backup_id = ?3 AND destination_id = ?4 AND provider_generation = ?5
           AND object_reference = ?6 AND byte_length = ?7 AND digest = ?8 AND state = 1",
        params![
            observed_at.get(),
            to_i64(request.retirement_revision.get())?,
            request.object.backup_id.as_bytes().as_slice(),
            request.object.destination_id.as_bytes().as_slice(),
            to_i64(request.object.provider_generation)?,
            request.object_reference.as_str(),
            to_i64(request.object.byte_length)?,
            request.object.digest.as_slice(),
        ],
    )?;
    if changed != 0 {
        return Ok(());
    }
    let Some(existing) = load_object(transaction, request.object)? else {
        return Err(DirectoryBackupProviderError::NotFound);
    };
    if existing.reference == request.object_reference.as_str()
        && existing.length == request.object.byte_length
        && existing.digest == request.object.digest
        && existing.state == RETIRED_OBJECT
    {
        Ok(())
    } else {
        Err(DirectoryBackupProviderError::Conflict)
    }
}

fn insert_operation(
    transaction: &Transaction<'_>,
    operation: NewOperation<'_>,
) -> Result<(), DirectoryBackupProviderError> {
    transaction.execute(
        "INSERT INTO backup_operations(
            operation_id, operation_kind, request_digest, backup_id, object_reference,
            completed_at, retirement_revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            operation.operation_id.as_bytes().as_slice(),
            operation.kind as i64,
            operation.request_digest.as_slice(),
            operation.object.backup_id.as_bytes().as_slice(),
            operation.object_reference,
            operation.observed_at.get(),
            operation.retirement_revision.map(to_i64).transpose()?,
        ],
    )?;
    Ok(())
}

fn load_operation(
    connection: &Connection,
    operation_id: OperationId,
) -> Result<Option<StoredOperation>, DirectoryBackupProviderError> {
    connection
        .query_row(
            "SELECT operation_kind, request_digest FROM backup_operations WHERE operation_id = ?1",
            [operation_id.as_bytes().as_slice()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?
        .map(|(kind, digest)| {
            Ok(StoredOperation {
                kind,
                request_digest: digest
                    .as_slice()
                    .try_into()
                    .map_err(|_| DirectoryBackupProviderError::Corrupt)?,
            })
        })
        .transpose()
}

fn validate_existing_operation(
    existing: &StoredOperation,
    expected_kind: OperationKind,
    expected_digest: [u8; 32],
) -> Result<(), DirectoryBackupProviderError> {
    if existing.kind == expected_kind as i64 && existing.request_digest == expected_digest {
        Ok(())
    } else {
        Err(DirectoryBackupProviderError::Conflict)
    }
}

fn load_object(
    connection: &Connection,
    object: BackupObjectIdentity,
) -> Result<Option<StoredObject>, DirectoryBackupProviderError> {
    connection
        .query_row(
            "SELECT object_reference, byte_length, digest, state FROM backup_objects
             WHERE backup_id = ?1 AND destination_id = ?2 AND provider_generation = ?3",
            params![
                object.backup_id.as_bytes().as_slice(),
                object.destination_id.as_bytes().as_slice(),
                to_i64(object.provider_generation)?,
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?
        .map(|(reference, length, digest, state)| {
            Ok(StoredObject {
                reference,
                length: to_u64(length)?,
                digest: digest
                    .as_slice()
                    .try_into()
                    .map_err(|_| DirectoryBackupProviderError::Corrupt)?,
                state,
            })
        })
        .transpose()
}

fn to_i64(value: u64) -> Result<i64, DirectoryBackupProviderError> {
    i64::try_from(value).map_err(|_| DirectoryBackupProviderError::InvalidInput)
}

fn to_u64(value: i64) -> Result<u64, DirectoryBackupProviderError> {
    u64::try_from(value).map_err(|_| DirectoryBackupProviderError::Corrupt)
}
