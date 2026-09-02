// SPDX-License-Identifier: GPL-2.0-only

//! Immutable desired-locality policies and volume-wide policy selection.

use std::collections::BTreeSet;

use meshspan_domain::{
    AvailabilityCellId, DurationMicros, LocalityPolicyId, LocalityRequirementId,
    ProtectionPolicyId, Revision, VolumeId, uuid_v8,
};
use rusqlite::{OptionalExtension, Transaction, params};

use super::apply::to_i64;
use super::{EntityKind, EntityReference, Page, PageLimit, RepositoryError};
use crate::{AssignVolumeLocalityPolicy, CommandContext, CreateLocalityPolicy, PartitionDatabase};

const ACTIVE_STATE: i64 = 1;
const COMPLETE_LOCAL_REQUIREMENT: i64 = 1;
const INHERIT_DESCENDANTS: i64 = 2;
const MAXIMUM_REQUIREMENTS: usize = 64;

/// Stable seek position in the locality-policy inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalityPolicyCursor {
    canonical_name: String,
    policy_id: LocalityPolicyId,
}

impl LocalityPolicyCursor {
    /// Reconstructs one validated public continuation cursor.
    #[must_use]
    pub fn new(canonical_name: String, policy_id: LocalityPolicyId) -> Self {
        Self {
            canonical_name,
            policy_id,
        }
    }

    /// Returns the exact canonical seek name.
    #[must_use]
    pub fn canonical_name(&self) -> &str {
        &self.canonical_name
    }

    /// Returns the exact seek identity.
    #[must_use]
    pub const fn policy_id(&self) -> LocalityPolicyId {
        self.policy_id
    }
}

/// One complete-local requirement in an immutable locality policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalityRequirementRecord {
    /// Stable requirement identity.
    pub requirement_id: LocalityRequirementId,
    /// Cell which must independently reconstruct the selected version.
    pub cell_id: AvailabilityCellId,
    /// Optional survival promise evaluated within this cell.
    pub local_protection_policy_id: Option<ProtectionPolicyId>,
}

/// One named immutable desired-locality policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalityPolicyRecord {
    /// Stable policy identity.
    pub policy_id: LocalityPolicyId,
    /// User-visible policy name.
    pub display_name: String,
    /// Canonical stable seek name.
    pub canonical_name: String,
    /// Optional lag limit used to prioritise repair debt.
    pub maximum_lag: Option<DurationMicros>,
    /// Ordered cells which each require a complete local copy.
    pub requirements: Vec<LocalityRequirementRecord>,
    /// Immutable policy revision.
    pub revision: Revision,
}

/// Exact active desired-locality policy selected by a volume.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VolumeLocalityPolicy {
    /// Stable immutable policy identity.
    pub policy_id: LocalityPolicyId,
    /// Policy revision used by placement evidence.
    pub revision: Revision,
    /// Optional lag limit used to prioritise repair debt.
    pub maximum_lag: Option<DurationMicros>,
    /// Cells which must each receive a complete decodable placement.
    pub requirements: Vec<LocalityRequirementRecord>,
}

pub(super) fn create(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &CreateLocalityPolicy,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_new_policy(transaction, command)?;
    transaction.execute(
        "INSERT INTO locality_policies(
            locality_policy_id, display_name, canonical_name, maximum_lag_micros,
            state, created_by, created_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            command.policy_id.as_bytes().as_slice(),
            command.name.display(),
            command.name.canonical(),
            command
                .maximum_lag
                .map(DurationMicros::get)
                .map(to_i64)
                .transpose()?,
            ACTIVE_STATE,
            context.actor_principal_id.as_bytes().as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    for (order, requirement) in command.requirements.as_slice().iter().enumerate() {
        transaction.execute(
            "INSERT INTO locality_requirements(
                requirement_id, locality_policy_id, cell_id, requirement_kind,
                local_protection_policy_id, requirement_order, revision
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                requirement.requirement_id.as_bytes().as_slice(),
                command.policy_id.as_bytes().as_slice(),
                requirement.cell_id.as_bytes().as_slice(),
                COMPLETE_LOCAL_REQUIREMENT,
                requirement
                    .local_protection_policy_id
                    .map(ProtectionPolicyId::as_bytes),
                i64::try_from(order).map_err(|_| RepositoryError::CapacityExceeded)?,
                to_i64(revision.get())?,
            ],
        )?;
    }
    update_configuration_revision(transaction, revision)?;
    Ok(EntityReference {
        kind: EntityKind::LocalityPolicy,
        id: command.policy_id.as_bytes(),
    })
}

fn validate_new_policy(
    transaction: &Transaction<'_>,
    command: &CreateLocalityPolicy,
) -> Result<(), RepositoryError> {
    if command.requirements.is_empty()
        || command.requirements.len() > MAXIMUM_REQUIREMENTS
        || command.maximum_lag.is_some_and(|lag| lag.get() == 0)
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let mut requirement_ids = BTreeSet::new();
    let mut cell_ids = BTreeSet::new();
    for requirement in command.requirements.as_slice() {
        if !requirement_ids.insert(requirement.requirement_id)
            || !cell_ids.insert(requirement.cell_id)
            || !active_cell_exists(transaction, requirement.cell_id)?
            || !optional_protection_policy_exists(
                transaction,
                requirement.local_protection_policy_id,
            )?
        {
            return Err(RepositoryError::InvalidCommand);
        }
    }
    Ok(())
}

pub(super) fn assign_volume(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: AssignVolumeLocalityPolicy,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let valid: bool = transaction.query_row(
        "SELECT EXISTS(
           SELECT 1 FROM volumes v, locality_policies p
           WHERE v.volume_id = ?1 AND v.state = 1
             AND p.locality_policy_id = ?2 AND p.state = 1
         )",
        params![
            command.volume_id.as_bytes().as_slice(),
            command.policy_id.as_bytes().as_slice(),
        ],
        |row| row.get(0),
    )?;
    if !valid {
        return Err(RepositoryError::InvalidCommand);
    }
    transaction.execute(
        "UPDATE object_locality_bindings SET state = 2, revision = ?1
         WHERE volume_id = ?2 AND object_id IS NULL AND state = 1",
        params![
            to_i64(revision.get())?,
            command.volume_id.as_bytes().as_slice()
        ],
    )?;
    let binding_id = volume_binding_id(command.volume_id, revision);
    transaction.execute(
        "INSERT INTO object_locality_bindings(
            binding_id, volume_id, object_id, locality_policy_id, inheritance_mode,
            state, assigned_by, revision
         ) VALUES (?1, ?2, NULL, ?3, ?4, ?5, ?6, ?7)",
        params![
            binding_id.as_slice(),
            command.volume_id.as_bytes().as_slice(),
            command.policy_id.as_bytes().as_slice(),
            INHERIT_DESCENDANTS,
            ACTIVE_STATE,
            context.actor_principal_id.as_bytes().as_slice(),
            to_i64(revision.get())?,
        ],
    )?;
    transaction.execute(
        "UPDATE volumes SET default_locality_policy_id = ?1, revision = ?2
         WHERE volume_id = ?3",
        params![
            command.policy_id.as_bytes().as_slice(),
            to_i64(revision.get())?,
            command.volume_id.as_bytes().as_slice(),
        ],
    )?;
    update_configuration_revision(transaction, revision)?;
    Ok(EntityReference {
        kind: EntityKind::Volume,
        id: command.volume_id.as_bytes(),
    })
}

pub(super) fn for_volume(
    database: &PartitionDatabase,
    volume_id: VolumeId,
) -> Result<Option<VolumeLocalityPolicy>, RepositoryError> {
    let record = database
        .connection()
        .query_row(
            "SELECT p.locality_policy_id, p.maximum_lag_micros, p.revision
             FROM volumes v JOIN locality_policies p
               ON p.locality_policy_id = v.default_locality_policy_id
             WHERE v.volume_id = ?1 AND v.state = 1 AND p.state = 1",
            [volume_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((policy_id, maximum_lag, revision)) = record else {
        return Ok(None);
    };
    let policy_id = parse_policy_id(policy_id)?;
    let revision = positive_revision(revision)?;
    Ok(Some(VolumeLocalityPolicy {
        policy_id,
        revision,
        maximum_lag: optional_duration(maximum_lag)?,
        requirements: load_requirements(database, policy_id, revision)?,
    }))
}

pub(super) fn policies(
    database: &PartitionDatabase,
    after: Option<&LocalityPolicyCursor>,
    limit: PageLimit,
) -> Result<Page<LocalityPolicyRecord, LocalityPolicyCursor>, RepositoryError> {
    let after_name = after.map_or("", |cursor| cursor.canonical_name.as_str());
    let after_id = after.map_or([0; 16], |cursor| cursor.policy_id.as_bytes());
    let mut statement = database.connection().prepare(
        "SELECT locality_policy_id, display_name, canonical_name, maximum_lag_micros, revision
         FROM locality_policies
         WHERE state = ?1 AND (
           canonical_name > ?2 OR (canonical_name = ?2 AND locality_policy_id > ?3)
         ) ORDER BY canonical_name, locality_policy_id LIMIT ?4",
    )?;
    let rows = statement.query_map(
        params![
            ACTIVE_STATE,
            after_name,
            after_id.as_slice(),
            i64::try_from(limit.get().saturating_add(1))
                .map_err(|_| RepositoryError::CapacityExceeded)?,
        ],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, i64>(4)?,
            ))
        },
    )?;
    let stored = rows.collect::<Result<Vec<_>, _>>()?;
    let mut records = stored
        .into_iter()
        .map(
            |(policy_id, display_name, canonical_name, maximum_lag, revision)| {
                let policy_id = parse_policy_id(policy_id)?;
                let revision = positive_revision(revision)?;
                Ok(LocalityPolicyRecord {
                    policy_id,
                    display_name,
                    canonical_name,
                    maximum_lag: optional_duration(maximum_lag)?,
                    requirements: load_requirements(database, policy_id, revision)?,
                    revision,
                })
            },
        )
        .collect::<Result<Vec<_>, RepositoryError>>()?;
    let has_more = records.len() > limit.get();
    if has_more {
        records.pop();
    }
    let next = if has_more {
        records.last().map(|record| {
            LocalityPolicyCursor::new(record.canonical_name.clone(), record.policy_id)
        })
    } else {
        None
    };
    Ok(Page {
        items: records,
        next,
    })
}

pub(super) fn policy(
    database: &PartitionDatabase,
    policy_id: LocalityPolicyId,
) -> Result<Option<LocalityPolicyRecord>, RepositoryError> {
    let stored = database
        .connection()
        .query_row(
            "SELECT display_name, canonical_name, maximum_lag_micros, revision
             FROM locality_policies WHERE locality_policy_id = ?1 AND state = ?2",
            params![policy_id.as_bytes().as_slice(), ACTIVE_STATE],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?;
    stored
        .map(|(display_name, canonical_name, maximum_lag, revision)| {
            let revision = positive_revision(revision)?;
            Ok(LocalityPolicyRecord {
                policy_id,
                display_name,
                canonical_name,
                maximum_lag: optional_duration(maximum_lag)?,
                requirements: load_requirements(database, policy_id, revision)?,
                revision,
            })
        })
        .transpose()
}

fn load_requirements(
    database: &PartitionDatabase,
    policy_id: LocalityPolicyId,
    policy_revision: Revision,
) -> Result<Vec<LocalityRequirementRecord>, RepositoryError> {
    let mut statement = database.connection().prepare(
        "SELECT requirement_id, cell_id, local_protection_policy_id, requirement_kind, revision
         FROM locality_requirements WHERE locality_policy_id = ?1
         ORDER BY requirement_order, requirement_id LIMIT ?2",
    )?;
    let rows = statement.query_map(
        params![
            policy_id.as_bytes().as_slice(),
            i64::try_from(MAXIMUM_REQUIREMENTS + 1)
                .map_err(|_| RepositoryError::CapacityExceeded)?,
        ],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
            ))
        },
    )?;
    let stored = rows.collect::<Result<Vec<_>, _>>()?;
    if stored.is_empty() || stored.len() > MAXIMUM_REQUIREMENTS {
        return Err(RepositoryError::CorruptState);
    }
    stored
        .into_iter()
        .map(
            |(requirement_id, cell_id, local_policy_id, kind, revision)| {
                if kind != COMPLETE_LOCAL_REQUIREMENT
                    || u64::try_from(revision).ok() != Some(policy_revision.get())
                {
                    return Err(RepositoryError::CorruptState);
                }
                Ok(LocalityRequirementRecord {
                    requirement_id: LocalityRequirementId::from_bytes(exact_identifier(
                        requirement_id,
                    )?)
                    .map_err(|_| RepositoryError::CorruptState)?,
                    cell_id: AvailabilityCellId::from_bytes(exact_identifier(cell_id)?)
                        .map_err(|_| RepositoryError::CorruptState)?,
                    local_protection_policy_id: local_policy_id
                        .map(exact_identifier)
                        .transpose()?
                        .map(ProtectionPolicyId::from_bytes)
                        .transpose()
                        .map_err(|_| RepositoryError::CorruptState)?,
                })
            },
        )
        .collect()
}

fn active_cell_exists(
    transaction: &Transaction<'_>,
    cell_id: AvailabilityCellId,
) -> Result<bool, RepositoryError> {
    transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM availability_cells WHERE cell_id = ?1 AND state = 1)",
            [cell_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(RepositoryError::from)
}

fn optional_protection_policy_exists(
    transaction: &Transaction<'_>,
    policy_id: Option<ProtectionPolicyId>,
) -> Result<bool, RepositoryError> {
    let Some(policy_id) = policy_id else {
        return Ok(true);
    };
    transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM protection_policies WHERE policy_id = ?1 AND state = 1)",
            [policy_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(RepositoryError::from)
}

fn volume_binding_id(volume_id: VolumeId, revision: Revision) -> [u8; 16] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.volume-locality-binding.v1\0");
    digest.update(&volume_id.as_bytes());
    digest.update(&revision.get().to_be_bytes());
    let mut identifier = [0; 16];
    identifier.copy_from_slice(&digest.finalize().as_bytes()[..16]);
    uuid_v8(identifier)
}

fn parse_policy_id(value: Vec<u8>) -> Result<LocalityPolicyId, RepositoryError> {
    LocalityPolicyId::from_bytes(exact_identifier(value)?)
        .map_err(|_| RepositoryError::CorruptState)
}

fn positive_revision(value: i64) -> Result<Revision, RepositoryError> {
    let revision = Revision::new(u64::try_from(value).map_err(|_| RepositoryError::CorruptState)?);
    if revision == Revision::ZERO {
        Err(RepositoryError::CorruptState)
    } else {
        Ok(revision)
    }
}

fn optional_duration(value: Option<i64>) -> Result<Option<DurationMicros>, RepositoryError> {
    value
        .map(|value| {
            u64::try_from(value)
                .ok()
                .filter(|value| *value != 0)
                .map(DurationMicros::new)
                .ok_or(RepositoryError::CorruptState)
        })
        .transpose()
}

fn exact_identifier(value: Vec<u8>) -> Result<[u8; 16], RepositoryError> {
    value.try_into().map_err(|_| RepositoryError::CorruptState)
}

fn update_configuration_revision(
    transaction: &Transaction<'_>,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let updated = transaction.execute(
        "UPDATE meshes SET configuration_revision = ?1, revision = ?1",
        [to_i64(revision.get())?],
    )?;
    if updated == 1 {
        Ok(())
    } else {
        Err(RepositoryError::CorruptState)
    }
}
