// SPDX-License-Identifier: GPL-2.0-only

//! Bounded provider-local scans and public attestation identity for quota maintenance.

use super::{AuthoritativeRepository, Page, RepositoryError, federation_storage_lease};
use crate::{FederationStorageAllocationAuthority, FederationStorageAuthorityRequest};
use meshspan_domain::{FederationStorageAllocationId, NodeId, Revision, TargetId, UnixMicros};
use rusqlite::{OptionalExtension, params};

/// Index order of immutable allocations on one provider node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationStorageMaintenanceCursor {
    /// Exact registered folder.
    pub target_id: TargetId,
    /// Immutable target incarnation.
    pub target_generation: u64,
    /// Original interval end, used for ordering only; renewal is checked separately.
    pub original_valid_until: UnixMicros,
    /// Tie-breaking immutable allocation identity.
    pub allocation_id: FederationStorageAllocationId,
}

/// One currently authorised allocation and its accepted permanent fence, if any.
pub struct FederationStorageMaintenanceItem {
    /// Current permission, not a claim about physical free capacity.
    pub authority: FederationStorageAllocationAuthority,
    /// Accepted retained byte ceiling and local sequence.
    pub accepted_seal: Option<(u64, u64)>,
}

/// Current node incarnation and its latest registered public attestation key.
pub struct NodeAttestationContext {
    /// Revision fencing registration and new signed statements.
    pub revision: Revision,
    /// Current active process incarnation.
    pub incarnation: u64,
    /// Active key generation and public Ed25519 bytes; absent only before registration.
    pub key: Option<(u64, [u8; 32])>,
}

pub(super) const ALLOCATIONS_SQL: &str =
    "SELECT target_id,target_generation,valid_until,allocation_id
    FROM federation_storage_allocations WHERE provider_node_id=?1 AND state=1
    AND (target_id,target_generation,valid_until,allocation_id) > (?2,?3,?4,?5)
    ORDER BY target_id,target_generation,valid_until,allocation_id LIMIT 2";

impl AuthoritativeRepository {
    /// Visits one allocation on this provider using the active-provider keyset index.
    /// Empty pages may have a continuation when permission has expired or been revoked.
    ///
    /// # Errors
    /// Rejects invalid records, failed reads and concurrent authoritative changes.
    pub fn federation_storage_maintenance_page(
        &self,
        node: NodeId,
        after: Option<FederationStorageMaintenanceCursor>,
        now: UnixMicros,
    ) -> Result<
        Page<FederationStorageMaintenanceItem, FederationStorageMaintenanceCursor>,
        RepositoryError,
    > {
        let revision = self.current_revision()?;
        let mut query = self.database.connection().prepare(ALLOCATIONS_SQL)?;
        let (target, generation, end, allocation) =
            after.map_or(([0; 16], 0, 0, [0; 16]), |cursor| {
                (
                    cursor.target_id.as_bytes(),
                    cursor.target_generation,
                    cursor.original_valid_until.get(),
                    cursor.allocation_id.as_bytes(),
                )
            });
        let mut rows = query.query(params![
            node.as_bytes().as_slice(),
            target.as_slice(),
            super::apply::to_i64(generation)?,
            end,
            allocation.as_slice()
        ])?;
        let cursor = rows
            .next()?
            .map(|row| -> Result<_, RepositoryError> {
                let target: Vec<u8> = row.get(0)?;
                let allocation: Vec<u8> = row.get(3)?;
                let generation = positive(row.get(1)?)?;
                let end: i64 = row.get(2)?;
                if end <= 0 {
                    return Err(RepositoryError::CorruptState);
                }
                Ok(FederationStorageMaintenanceCursor {
                    target_id: TargetId::from_bytes(
                        target
                            .try_into()
                            .map_err(|_| RepositoryError::CorruptState)?,
                    )
                    .map_err(|_| RepositoryError::CorruptState)?,
                    target_generation: generation,
                    original_valid_until: UnixMicros::new(end),
                    allocation_id: FederationStorageAllocationId::from_bytes(
                        allocation
                            .try_into()
                            .map_err(|_| RepositoryError::CorruptState)?,
                    )
                    .map_err(|_| RepositoryError::CorruptState)?,
                })
            })
            .transpose()?;
        let has_next = rows.next()?.is_some();
        let item = cursor
            .map(|cursor| self.storage_maintenance_item(node, cursor, now))
            .transpose()?
            .flatten();
        if self.current_revision()? != revision {
            return Err(RepositoryError::StaleRevision);
        }
        Ok(Page {
            items: item.into_iter().collect(),
            next: cursor.filter(|_| has_next),
        })
    }

    /// Resolves only active node identity and public key material; never returns a secret.
    ///
    /// # Errors
    /// Rejects inactive nodes, malformed keys, retired latest keys and inconsistent reads.
    pub fn node_attestation_context(
        &self,
        node: NodeId,
    ) -> Result<NodeAttestationContext, RepositoryError> {
        let revision = self.current_revision()?;
        let connection = self.database.connection();
        let incarnation = connection
            .query_row(
                "SELECT current_incarnation FROM nodes WHERE node_id=?1 AND state=2",
                [node.as_bytes().as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .ok_or(RepositoryError::InvalidCommand)?;
        let key = connection
            .query_row(
                "SELECT generation,verifying_key,state FROM cleanup_attestation_keys
            WHERE node_id=?1 ORDER BY generation DESC LIMIT 1",
                [node.as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?
            .map(|(generation, key, state)| {
                if state != 1 {
                    return Err(RepositoryError::CorruptState);
                }
                let key: [u8; 32] = key.try_into().map_err(|_| RepositoryError::CorruptState)?;
                ed25519_dalek::VerifyingKey::from_bytes(&key)
                    .map_err(|_| RepositoryError::CorruptState)?;
                Ok((positive(generation)?, key))
            })
            .transpose()?;
        if self.current_revision()? != revision {
            return Err(RepositoryError::StaleRevision);
        }
        Ok(NodeAttestationContext {
            revision,
            incarnation: positive(incarnation)?,
            key,
        })
    }

    fn storage_maintenance_item(
        &self,
        node: NodeId,
        cursor: FederationStorageMaintenanceCursor,
        now: UnixMicros,
    ) -> Result<Option<FederationStorageMaintenanceItem>, RepositoryError> {
        let connection = self.database.connection();
        let lease = federation_storage_lease::load(connection, cursor.allocation_id)?;
        let Some(grant) = self.active_federation_grant(lease.grant_id)? else {
            return Ok(None);
        };
        let Some(authority) = self.active_federation_storage_allocation_authority(
            FederationStorageAuthorityRequest {
                relationship_id: grant.grant.relationship_id(),
                remote_mesh_id: grant.grant.recipient_mesh_id(),
                provider_node_id: node,
                allocation_id: cursor.allocation_id,
                grant_id: lease.grant_id,
                target_id: cursor.target_id,
                target_generation: cursor.target_generation,
                requested_bytes: 1,
                observed_at: now,
            },
        )?
        else {
            return Ok(None);
        };
        let accepted_seal = connection.query_row("SELECT ceiling_bytes,sequence FROM federation_storage_seals WHERE allocation_id=?1",
            [cursor.allocation_id.as_bytes().as_slice()], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))).optional()?
            .map(|(ceiling, sequence)| Ok::<_, RepositoryError>((u64::try_from(ceiling).map_err(|_| RepositoryError::CorruptState)?, positive(sequence)?))).transpose()?;
        Ok(Some(FederationStorageMaintenanceItem {
            authority,
            accepted_seal,
        }))
    }
}

fn positive(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(RepositoryError::CorruptState)
}
