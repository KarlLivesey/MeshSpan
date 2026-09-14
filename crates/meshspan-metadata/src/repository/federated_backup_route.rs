// SPDX-License-Identifier: GPL-2.0-only

//! Atomic selection of a consumer backup route before uncertain remote IO.

use super::{AuthoritativeRepository, EntityKind, EntityReference, RepositoryError, apply::to_i64};
use crate::{
    BackupDestinationBinding, BackupDestinationState, BindFederatedBackupRoute, CommandContext,
    FederatedBackupRouteRecord,
};
use meshspan_domain::{BackupDestinationId, BackupId, PartitionId, Revision};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

impl AuthoritativeRepository {
    /// Loads the original route even after failed IO, worker replacement or grant withdrawal.
    ///
    /// This is routing evidence only. Callers must obtain current signed remote authority.
    /// # Errors
    /// Rejects unavailable SQL, malformed encodings or contradictory indexed identities.
    pub fn federated_backup_route(
        &self,
        backup: BackupId,
        destination: BackupDestinationId,
    ) -> Result<Option<FederatedBackupRouteRecord>, RepositoryError> {
        load(self.database.connection(), backup, destination)
    }
}

pub(super) fn bind(
    transaction: &Transaction<'_>,
    partition: PartitionId,
    context: CommandContext,
    value: &BindFederatedBackupRoute,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let bytes = crate::command_codec::backup_route::record(value)
        .map_err(|_| RepositoryError::InvalidCommand)?;
    super::backup_run::validate_route_claim(
        transaction,
        partition,
        context,
        value.object.backup_id,
        value.claim,
    )?;
    let destination =
        super::backup_catalogue::destination(transaction, value.object.destination_id)?
            .ok_or(RepositoryError::InvalidCommand)?;
    if destination.revision != value.expected_destination_revision {
        return Err(RepositoryError::StaleRevision);
    }
    if destination.state != BackupDestinationState::Active
        || destination.binding
            != (BackupDestinationBinding::FederatedMesh {
                remote_mesh_id: value.scope.provider_mesh_id,
                provider_generation: value.object.provider_generation,
            })
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let valid: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM federation_relationships r JOIN meshes m ON m.mesh_id = r.local_mesh_id
         WHERE r.relationship_id = ?1 AND r.local_mesh_id = ?2 AND r.remote_mesh_id = ?3 AND r.state IN (2, 3))",
        params![value.scope.relationship_id.as_bytes().as_slice(), value.scope.remote_mesh_id.as_bytes().as_slice(), value.scope.provider_mesh_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if !valid {
        return Err(RepositoryError::InvalidCommand);
    }
    if let Some(backup) = super::backup_catalogue::backup(transaction, value.object.backup_id)?
        && (backup.encrypted_byte_length != value.object.byte_length
            || backup.encrypted_digest != value.object.digest)
    {
        return Err(RepositoryError::InvalidCommand);
    }
    if let Some(existing) = load(
        transaction,
        value.object.backup_id,
        value.object.destination_id,
    )? {
        if existing.binding.object != value.object || existing.binding.scope != value.scope {
            return Err(RepositoryError::InvalidCommand);
        }
    } else {
        transaction.execute("INSERT INTO federated_backup_routes(backup_id, destination_id, relationship_id, canonical_record, revision)
            VALUES (?1, ?2, ?3, ?4, ?5)", params![value.object.backup_id.as_bytes().as_slice(),
            value.object.destination_id.as_bytes().as_slice(), value.scope.relationship_id.as_bytes().as_slice(), bytes, to_i64(revision.get())?])?;
    }
    Ok(EntityReference {
        kind: EntityKind::FederatedBackupRoute,
        id: value.object.backup_id.as_bytes(),
    })
}

pub(super) fn validate_recorded_object(
    connection: &Connection,
    object: meshspan_contracts::BackupObjectIdentity,
) -> Result<(), RepositoryError> {
    if let Some(route) = load(connection, object.backup_id, object.destination_id)?
        && route.binding.object != object
    {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(())
}

fn load(
    connection: &Connection,
    backup: BackupId,
    destination: BackupDestinationId,
) -> Result<Option<FederatedBackupRouteRecord>, RepositoryError> {
    let row = connection
        .query_row(
            "SELECT canonical_record, relationship_id, revision FROM federated_backup_routes
        WHERE backup_id = ?1 AND destination_id = ?2",
            params![
                backup.as_bytes().as_slice(),
                destination.as_bytes().as_slice()
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?;
    row.map(|(bytes, relationship, revision)| {
        let binding = crate::command_codec::backup_route::parse(&bytes)
            .map_err(|_| RepositoryError::CorruptState)?;
        if binding.object.backup_id != backup
            || binding.object.destination_id != destination
            || binding.scope.relationship_id.as_bytes().as_slice() != relationship
            || revision <= 0
        {
            return Err(RepositoryError::CorruptState);
        }
        Ok(FederatedBackupRouteRecord {
            binding,
            revision: Revision::new(
                u64::try_from(revision).map_err(|_| RepositoryError::CorruptState)?,
            ),
        })
    })
    .transpose()
}
