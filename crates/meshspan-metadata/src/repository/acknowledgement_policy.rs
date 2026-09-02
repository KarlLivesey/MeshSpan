// SPDX-License-Identifier: GPL-2.0-only

//! Immutable write-acknowledgement policies and volume-wide policy selection.

use std::collections::BTreeSet;

use meshspan_domain::{
    AcknowledgementPolicyId, AvailabilityCellId, DurationMicros, ProtectionPolicyId,
    ProtectionScenarioId, Revision, VolumeId, uuid_v8,
};
use rusqlite::{OptionalExtension, Transaction, params};

use super::apply::to_i64;
use super::{EntityKind, EntityReference, Page, PageLimit, RepositoryError};
use crate::{
    AcknowledgementCellRequirement, AcknowledgementCellRole, AcknowledgementConsistencyClass,
    AssignVolumeAcknowledgementPolicy, CommandContext, CreateAcknowledgementPolicy,
    PartitionDatabase, StrongFallbackMode,
};

const ACTIVE_STATE: i64 = 1;
const INHERIT_DESCENDANTS: i64 = 2;
const MAXIMUM_SCENARIOS: usize = 64;
const MAXIMUM_CELLS: usize = 256;

/// Stable seek position in the acknowledgement-policy inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcknowledgementPolicyCursor {
    canonical_name: String,
    policy_id: AcknowledgementPolicyId,
}

impl AcknowledgementPolicyCursor {
    /// Reconstructs one validated public continuation cursor.
    #[must_use]
    pub fn new(canonical_name: String, policy_id: AcknowledgementPolicyId) -> Self {
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
    pub const fn policy_id(&self) -> AcknowledgementPolicyId {
        self.policy_id
    }
}

/// One named immutable write-acknowledgement policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcknowledgementPolicyRecord {
    /// Stable policy identity.
    pub policy_id: AcknowledgementPolicyId,
    /// User-visible policy name.
    pub display_name: String,
    /// Canonical stable seek name.
    pub canonical_name: String,
    /// Availability-first or strong publication semantics.
    pub consistency: AcknowledgementConsistencyClass,
    /// Minimum durable target count.
    pub minimum_durable_targets: u16,
    /// Minimum distinct machine count.
    pub minimum_distinct_nodes: u16,
    /// Optional strong acknowledgement deadline.
    pub strong_wait: Option<DurationMicros>,
    /// Explicit deadline result.
    pub fallback: StrongFallbackMode,
    /// Protection scenarios required before acknowledgement.
    pub required_scenarios: Vec<ProtectionScenarioId>,
    /// Cell-specific placement roles and predicates.
    pub cells: Vec<AcknowledgementCellRequirement>,
    /// Immutable policy revision.
    pub revision: Revision,
}

/// Exact active write-acknowledgement policy selected by a volume.
pub type VolumeAcknowledgementPolicy = AcknowledgementPolicyRecord;

pub(super) fn create(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &CreateAcknowledgementPolicy,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_new_policy(transaction, command)?;
    transaction.execute(
        "INSERT INTO acknowledgement_policies(
            acknowledgement_policy_id, display_name, canonical_name, consistency_class,
            minimum_durable_targets, minimum_distinct_nodes, strong_wait_micros, fallback_mode,
            state, created_by, created_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            command.policy_id.as_bytes().as_slice(),
            command.name.display(),
            command.name.canonical(),
            command.consistency as u8,
            command.minimum_durable_targets,
            command.minimum_distinct_nodes,
            command
                .strong_wait
                .map(DurationMicros::get)
                .map(to_i64)
                .transpose()?,
            command.fallback as u8,
            ACTIVE_STATE,
            context.actor_principal_id.as_bytes().as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    for scenario_id in command.required_scenarios.as_slice() {
        transaction.execute(
            "INSERT INTO acknowledgement_policy_scenarios(
                acknowledgement_policy_id, scenario_id, revision
             ) VALUES (?1, ?2, ?3)",
            params![
                command.policy_id.as_bytes().as_slice(),
                scenario_id.as_bytes().as_slice(),
                to_i64(revision.get())?,
            ],
        )?;
    }
    for cell in command.cells.as_slice() {
        transaction.execute(
            "INSERT INTO acknowledgement_zone_requirements(
                acknowledgement_policy_id, cell_id, requirement_kind,
                minimum_durable_targets, minimum_distinct_nodes,
                local_protection_policy_id, revision
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                command.policy_id.as_bytes().as_slice(),
                cell.cell_id.as_bytes().as_slice(),
                cell.role as u8,
                cell.minimum_durable_targets,
                cell.minimum_distinct_nodes,
                cell.local_protection_policy_id
                    .map(ProtectionPolicyId::as_bytes),
                to_i64(revision.get())?,
            ],
        )?;
    }
    update_configuration_revision(transaction, revision)?;
    Ok(EntityReference {
        kind: EntityKind::AcknowledgementPolicy,
        id: command.policy_id.as_bytes(),
    })
}

fn validate_new_policy(
    transaction: &Transaction<'_>,
    command: &CreateAcknowledgementPolicy,
) -> Result<(), RepositoryError> {
    if command.minimum_durable_targets == 0
        || command.minimum_distinct_nodes == 0
        || command.minimum_distinct_nodes > command.minimum_durable_targets
        || command.required_scenarios.len() > MAXIMUM_SCENARIOS
        || command.cells.len() > MAXIMUM_CELLS
        || command.strong_wait.is_some_and(|wait| wait.get() == 0)
        || (command.consistency == AcknowledgementConsistencyClass::Eventual
            && (command.strong_wait.is_some()
                || command.fallback != StrongFallbackMode::RemainPending))
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let mut scenario_ids = BTreeSet::new();
    for scenario_id in command.required_scenarios.as_slice() {
        if !scenario_ids.insert(*scenario_id) || !scenario_exists(transaction, *scenario_id)? {
            return Err(RepositoryError::InvalidCommand);
        }
    }
    let mut cells = BTreeSet::new();
    for cell in command.cells.as_slice() {
        if !cells.insert(cell.cell_id)
            || !valid_cell_requirement(cell)
            || !cell_exists(transaction, cell.cell_id)?
            || !optional_protection_policy_exists(transaction, cell.local_protection_policy_id)?
        {
            return Err(RepositoryError::InvalidCommand);
        }
    }
    Ok(())
}

fn valid_cell_requirement(value: &AcknowledgementCellRequirement) -> bool {
    let counts_are_valid = value.minimum_durable_targets.is_none_or(|count| count != 0)
        && value.minimum_distinct_nodes.is_none_or(|count| count != 0)
        && match (value.minimum_durable_targets, value.minimum_distinct_nodes) {
            (Some(targets), Some(nodes)) => nodes <= targets,
            _ => true,
        };
    let excluded_has_no_predicates = value.role != AcknowledgementCellRole::Excluded
        || (value.minimum_durable_targets.is_none()
            && value.minimum_distinct_nodes.is_none()
            && value.local_protection_policy_id.is_none());
    counts_are_valid && excluded_has_no_predicates
}

pub(super) fn assign_volume(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: AssignVolumeAcknowledgementPolicy,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let valid: bool = transaction.query_row(
        "SELECT EXISTS(
           SELECT 1 FROM volumes v, acknowledgement_policies p
           WHERE v.volume_id = ?1 AND v.state = 1
             AND p.acknowledgement_policy_id = ?2 AND p.state = 1
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
        "UPDATE object_acknowledgement_bindings SET state = 2, revision = ?1
         WHERE volume_id = ?2 AND object_id IS NULL AND state = 1",
        params![
            to_i64(revision.get())?,
            command.volume_id.as_bytes().as_slice()
        ],
    )?;
    transaction.execute(
        "INSERT INTO object_acknowledgement_bindings(
            binding_id, volume_id, object_id, acknowledgement_policy_id,
            inheritance_mode, state, assigned_by, revision
         ) VALUES (?1, ?2, NULL, ?3, ?4, ?5, ?6, ?7)",
        params![
            volume_binding_id(command.volume_id, revision).as_slice(),
            command.volume_id.as_bytes().as_slice(),
            command.policy_id.as_bytes().as_slice(),
            INHERIT_DESCENDANTS,
            ACTIVE_STATE,
            context.actor_principal_id.as_bytes().as_slice(),
            to_i64(revision.get())?,
        ],
    )?;
    transaction.execute(
        "UPDATE volumes SET default_acknowledgement_policy_id = ?1, revision = ?2
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
) -> Result<Option<VolumeAcknowledgementPolicy>, RepositoryError> {
    let policy_id = database
        .connection()
        .query_row(
            "SELECT default_acknowledgement_policy_id FROM volumes
             WHERE volume_id = ?1 AND state = 1",
            [volume_id.as_bytes().as_slice()],
            |row| row.get::<_, Option<Vec<u8>>>(0),
        )
        .optional()?
        .flatten();
    policy_id
        .map(|value| policy(database, parse_policy_id(value)?))
        .transpose()
        .map(Option::flatten)
}

pub(super) fn policies(
    database: &PartitionDatabase,
    after: Option<&AcknowledgementPolicyCursor>,
    limit: PageLimit,
) -> Result<Page<AcknowledgementPolicyRecord, AcknowledgementPolicyCursor>, RepositoryError> {
    let after_name = after.map_or("", |cursor| cursor.canonical_name.as_str());
    let after_id = after.map_or([0; 16], |cursor| cursor.policy_id.as_bytes());
    let mut statement = database.connection().prepare(
        "SELECT acknowledgement_policy_id FROM acknowledgement_policies
         WHERE state = ?1 AND (
           canonical_name > ?2 OR (canonical_name = ?2 AND acknowledgement_policy_id > ?3)
         ) ORDER BY canonical_name, acknowledgement_policy_id LIMIT ?4",
    )?;
    let rows = statement.query_map(
        params![
            ACTIVE_STATE,
            after_name,
            after_id.as_slice(),
            i64::try_from(limit.get().saturating_add(1))
                .map_err(|_| RepositoryError::CapacityExceeded)?,
        ],
        |row| row.get::<_, Vec<u8>>(0),
    )?;
    let identifiers = rows.collect::<Result<Vec<_>, _>>()?;
    let mut records = identifiers
        .into_iter()
        .map(|value| {
            policy(database, parse_policy_id(value)?)?.ok_or(RepositoryError::CorruptState)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let has_more = records.len() > limit.get();
    if has_more {
        records.pop();
    }
    let next = if has_more {
        records.last().map(|record| {
            AcknowledgementPolicyCursor::new(record.canonical_name.clone(), record.policy_id)
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
    policy_id: AcknowledgementPolicyId,
) -> Result<Option<AcknowledgementPolicyRecord>, RepositoryError> {
    let stored = database
        .connection()
        .query_row(
            "SELECT display_name, canonical_name, consistency_class, minimum_durable_targets,
                minimum_distinct_nodes, strong_wait_micros, fallback_mode, revision
         FROM acknowledgement_policies
         WHERE acknowledgement_policy_id = ?1 AND state = ?2",
            params![policy_id.as_bytes().as_slice(), ACTIVE_STATE],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            },
        )
        .optional()?;
    stored
        .map(
            |(
                display_name,
                canonical_name,
                consistency,
                targets,
                nodes,
                wait,
                fallback,
                revision,
            )| {
                let revision = positive_revision(revision)?;
                Ok(AcknowledgementPolicyRecord {
                    policy_id,
                    display_name,
                    canonical_name,
                    consistency: parse_consistency(consistency)?,
                    minimum_durable_targets: positive_u16(targets)?,
                    minimum_distinct_nodes: positive_u16(nodes)?,
                    strong_wait: optional_duration(wait)?,
                    fallback: parse_fallback(fallback)?,
                    required_scenarios: load_scenarios(database, policy_id, revision)?,
                    cells: load_cells(database, policy_id, revision)?,
                    revision,
                })
            },
        )
        .transpose()
}

fn load_scenarios(
    database: &PartitionDatabase,
    policy_id: AcknowledgementPolicyId,
    revision: Revision,
) -> Result<Vec<ProtectionScenarioId>, RepositoryError> {
    let mut statement = database.connection().prepare(
        "SELECT scenario_id, revision FROM acknowledgement_policy_scenarios
         WHERE acknowledgement_policy_id = ?1 ORDER BY scenario_id LIMIT ?2",
    )?;
    let rows = statement.query_map(
        params![
            policy_id.as_bytes().as_slice(),
            i64::try_from(MAXIMUM_SCENARIOS + 1).map_err(|_| RepositoryError::CapacityExceeded)?
        ],
        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
    )?;
    let stored = rows.collect::<Result<Vec<_>, _>>()?;
    if stored.len() > MAXIMUM_SCENARIOS {
        return Err(RepositoryError::CorruptState);
    }
    stored
        .into_iter()
        .map(|(value, stored_revision)| {
            require_same_revision(stored_revision, revision)?;
            ProtectionScenarioId::from_bytes(exact_identifier(value)?)
                .map_err(|_| RepositoryError::CorruptState)
        })
        .collect()
}

fn load_cells(
    database: &PartitionDatabase,
    policy_id: AcknowledgementPolicyId,
    revision: Revision,
) -> Result<Vec<AcknowledgementCellRequirement>, RepositoryError> {
    let mut statement = database.connection().prepare(
        "SELECT cell_id, requirement_kind, minimum_durable_targets, minimum_distinct_nodes,
                local_protection_policy_id, revision
         FROM acknowledgement_zone_requirements
         WHERE acknowledgement_policy_id = ?1 ORDER BY cell_id LIMIT ?2",
    )?;
    let rows = statement.query_map(
        params![
            policy_id.as_bytes().as_slice(),
            i64::try_from(MAXIMUM_CELLS + 1).map_err(|_| RepositoryError::CapacityExceeded)?
        ],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<i64>>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, Option<Vec<u8>>>(4)?,
                row.get::<_, i64>(5)?,
            ))
        },
    )?;
    let stored = rows.collect::<Result<Vec<_>, _>>()?;
    if stored.len() > MAXIMUM_CELLS {
        return Err(RepositoryError::CorruptState);
    }
    stored
        .into_iter()
        .map(
            |(cell, role, targets, nodes, local_policy, stored_revision)| {
                require_same_revision(stored_revision, revision)?;
                Ok(AcknowledgementCellRequirement {
                    cell_id: AvailabilityCellId::from_bytes(exact_identifier(cell)?)
                        .map_err(|_| RepositoryError::CorruptState)?,
                    role: parse_cell_role(role)?,
                    minimum_durable_targets: optional_positive_u16(targets)?,
                    minimum_distinct_nodes: optional_positive_u16(nodes)?,
                    local_protection_policy_id: local_policy
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

fn scenario_exists(
    transaction: &Transaction<'_>,
    id: ProtectionScenarioId,
) -> Result<bool, RepositoryError> {
    exists(
        transaction,
        "SELECT EXISTS(SELECT 1 FROM protection_scenarios WHERE scenario_id = ?1)",
        id.as_bytes(),
    )
}

fn cell_exists(
    transaction: &Transaction<'_>,
    id: AvailabilityCellId,
) -> Result<bool, RepositoryError> {
    exists(
        transaction,
        "SELECT EXISTS(SELECT 1 FROM availability_cells WHERE cell_id = ?1 AND state = 1)",
        id.as_bytes(),
    )
}

fn optional_protection_policy_exists(
    transaction: &Transaction<'_>,
    id: Option<ProtectionPolicyId>,
) -> Result<bool, RepositoryError> {
    let Some(id) = id else {
        return Ok(true);
    };
    exists(
        transaction,
        "SELECT EXISTS(SELECT 1 FROM protection_policies WHERE policy_id = ?1 AND state = 1)",
        id.as_bytes(),
    )
}

fn exists(
    transaction: &Transaction<'_>,
    query: &str,
    id: [u8; 16],
) -> Result<bool, RepositoryError> {
    transaction
        .query_row(query, [id.as_slice()], |row| row.get(0))
        .map_err(RepositoryError::from)
}

fn volume_binding_id(volume_id: VolumeId, revision: Revision) -> [u8; 16] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.volume-acknowledgement-binding.v1\0");
    digest.update(&volume_id.as_bytes());
    digest.update(&revision.get().to_be_bytes());
    let mut identifier = [0; 16];
    identifier.copy_from_slice(&digest.finalize().as_bytes()[..16]);
    uuid_v8(identifier)
}

fn parse_policy_id(value: Vec<u8>) -> Result<AcknowledgementPolicyId, RepositoryError> {
    AcknowledgementPolicyId::from_bytes(exact_identifier(value)?)
        .map_err(|_| RepositoryError::CorruptState)
}

fn parse_consistency(value: i64) -> Result<AcknowledgementConsistencyClass, RepositoryError> {
    match value {
        1 => Ok(AcknowledgementConsistencyClass::Eventual),
        2 => Ok(AcknowledgementConsistencyClass::Strong),
        _ => Err(RepositoryError::CorruptState),
    }
}

fn parse_fallback(value: i64) -> Result<StrongFallbackMode, RepositoryError> {
    match value {
        1 => Ok(StrongFallbackMode::RemainPending),
        2 => Ok(StrongFallbackMode::FailAtDeadline),
        3 => Ok(StrongFallbackMode::Eventual),
        _ => Err(RepositoryError::CorruptState),
    }
}

fn parse_cell_role(value: i64) -> Result<AcknowledgementCellRole, RepositoryError> {
    match value {
        1 => Ok(AcknowledgementCellRole::RequiredBeforeCommit),
        2 => Ok(AcknowledgementCellRole::Eventual),
        3 => Ok(AcknowledgementCellRole::Excluded),
        _ => Err(RepositoryError::CorruptState),
    }
}

fn positive_revision(value: i64) -> Result<Revision, RepositoryError> {
    let revision = Revision::new(u64::try_from(value).map_err(|_| RepositoryError::CorruptState)?);
    (revision != Revision::ZERO)
        .then_some(revision)
        .ok_or(RepositoryError::CorruptState)
}

fn positive_u16(value: i64) -> Result<u16, RepositoryError> {
    u16::try_from(value)
        .ok()
        .filter(|value| *value != 0)
        .ok_or(RepositoryError::CorruptState)
}

fn optional_positive_u16(value: Option<i64>) -> Result<Option<u16>, RepositoryError> {
    value.map(positive_u16).transpose()
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

fn require_same_revision(stored: i64, expected: Revision) -> Result<(), RepositoryError> {
    if u64::try_from(stored).ok() == Some(expected.get()) {
        Ok(())
    } else {
        Err(RepositoryError::CorruptState)
    }
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
