// SPDX-License-Identifier: GPL-2.0-only

//! Immutable survival policies and volume policy selection.

use std::collections::BTreeSet;

use meshspan_domain::{
    FailureScenario, FailureTerm, FaultGroupClassId, ProtectionPolicyId, ProtectionScenarioId,
    Revision, VolumeId, uuid_v8,
};
use rusqlite::{OptionalExtension, Transaction, params};

use super::apply::to_i64;
use super::{EntityKind, EntityReference, RepositoryError};
use crate::{
    AssignVolumeProtectionPolicy, CommandContext, CreateProtectionPolicy, PartitionDatabase,
};

const ACTIVE_STATE: i64 = 1;
const MAXIMUM_SCENARIOS: usize = 16;
const MAXIMUM_TERMS_PER_SCENARIO: usize = 16;

/// Exact active data-survival policy selected by a volume.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VolumeProtectionPolicy {
    /// Stable immutable policy identity.
    pub policy_id: ProtectionPolicyId,
    /// Policy revision used by placement evidence.
    pub revision: Revision,
    /// Ordered alternative failure promises which must each remain decodable.
    pub scenarios: Vec<FailureScenario>,
}

pub(super) fn create(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &CreateProtectionPolicy,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_new_policy(transaction, command)?;
    transaction.execute(
        "INSERT INTO protection_policies(
            policy_id, display_name, canonical_name, state, created_by, created_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            command.policy_id.as_bytes().as_slice(),
            command.name.display(),
            command.name.canonical(),
            ACTIVE_STATE,
            context.actor_principal_id.as_bytes().as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    for (scenario_order, scenario) in command.scenarios.as_slice().iter().enumerate() {
        transaction.execute(
            "INSERT INTO protection_scenarios(
                scenario_id, policy_id, display_name, scenario_order, revision
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                scenario.scenario_id.as_bytes().as_slice(),
                command.policy_id.as_bytes().as_slice(),
                scenario.name.display(),
                i64::try_from(scenario_order).map_err(|_| RepositoryError::CapacityExceeded)?,
                to_i64(revision.get())?,
            ],
        )?;
        for term in scenario.scenario.terms() {
            transaction.execute(
                "INSERT INTO protection_scenario_terms(
                    term_id, scenario_id, class_id, failure_count, revision
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    term_id(scenario.scenario_id, term.class_id).as_slice(),
                    scenario.scenario_id.as_bytes().as_slice(),
                    term.class_id.as_bytes().as_slice(),
                    i64::from(term.failure_count),
                    to_i64(revision.get())?,
                ],
            )?;
        }
    }
    update_configuration_revision(transaction, revision)?;
    Ok(EntityReference {
        kind: EntityKind::ProtectionPolicy,
        id: command.policy_id.as_bytes(),
    })
}

fn validate_new_policy(
    transaction: &Transaction<'_>,
    command: &CreateProtectionPolicy,
) -> Result<(), RepositoryError> {
    if command.scenarios.is_empty() || command.scenarios.len() > MAXIMUM_SCENARIOS {
        return Err(RepositoryError::InvalidCommand);
    }
    let mut scenario_ids = BTreeSet::new();
    for scenario in command.scenarios.as_slice() {
        if !scenario_ids.insert(scenario.scenario_id)
            || scenario.scenario.terms().is_empty()
            || scenario.scenario.terms().len() > MAXIMUM_TERMS_PER_SCENARIO
        {
            return Err(RepositoryError::InvalidCommand);
        }
        for term in scenario.scenario.terms() {
            require_failure_class(transaction, term.class_id)?;
        }
    }
    Ok(())
}

fn require_failure_class(
    transaction: &Transaction<'_>,
    class_id: FaultGroupClassId,
) -> Result<(), RepositoryError> {
    let exists: bool = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM fault_group_classes
            WHERE class_id = ?1 AND display_name IS NOT NULL
              AND class_kind IS NOT NULL AND system_managed IS NOT NULL
         )",
        [class_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if exists {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

pub(super) fn assign_volume(
    transaction: &Transaction<'_>,
    command: AssignVolumeProtectionPolicy,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let updated = transaction.execute(
        "UPDATE volumes SET protection_policy_id = ?1, revision = ?2
         WHERE volume_id = ?3 AND state = 1
           AND EXISTS(
             SELECT 1 FROM protection_policies
             WHERE policy_id = ?1 AND state = 1
           )",
        params![
            command.policy_id.as_bytes().as_slice(),
            to_i64(revision.get())?,
            command.volume_id.as_bytes().as_slice(),
        ],
    )?;
    if updated != 1 {
        return Err(RepositoryError::InvalidCommand);
    }
    update_configuration_revision(transaction, revision)?;
    Ok(EntityReference {
        kind: EntityKind::Volume,
        id: command.volume_id.as_bytes(),
    })
}

pub(super) fn for_volume(
    database: &PartitionDatabase,
    volume_id: VolumeId,
) -> Result<Option<VolumeProtectionPolicy>, RepositoryError> {
    let policy = database
        .connection()
        .query_row(
            "SELECT p.policy_id, p.revision
             FROM volumes v
             JOIN protection_policies p ON p.policy_id = v.protection_policy_id
             WHERE v.volume_id = ?1 AND v.state = 1 AND p.state = 1",
            [volume_id.as_bytes().as_slice()],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?;
    let Some((policy_id, revision)) = policy else {
        return Ok(None);
    };
    let policy_id = ProtectionPolicyId::from_bytes(exact_identifier(policy_id)?)
        .map_err(|_| RepositoryError::CorruptState)?;
    let revision =
        Revision::new(u64::try_from(revision).map_err(|_| RepositoryError::CorruptState)?);
    if revision == Revision::ZERO {
        return Err(RepositoryError::CorruptState);
    }
    let scenarios = load_scenarios(database, policy_id, revision)?;
    Ok(Some(VolumeProtectionPolicy {
        policy_id,
        revision,
        scenarios,
    }))
}

fn load_scenarios(
    database: &PartitionDatabase,
    policy_id: ProtectionPolicyId,
    policy_revision: Revision,
) -> Result<Vec<FailureScenario>, RepositoryError> {
    let mut statement = database.connection().prepare(
        "SELECT scenario_id, revision FROM protection_scenarios
         WHERE policy_id = ?1 ORDER BY scenario_order, scenario_id LIMIT ?2",
    )?;
    let rows = statement.query_map(
        params![
            policy_id.as_bytes().as_slice(),
            i64::try_from(MAXIMUM_SCENARIOS + 1).map_err(|_| RepositoryError::CapacityExceeded)?,
        ],
        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
    )?;
    let stored = rows.collect::<Result<Vec<_>, _>>()?;
    if stored.is_empty() || stored.len() > MAXIMUM_SCENARIOS {
        return Err(RepositoryError::CorruptState);
    }
    stored
        .into_iter()
        .map(|(scenario_id, revision)| {
            let scenario_id = ProtectionScenarioId::from_bytes(exact_identifier(scenario_id)?)
                .map_err(|_| RepositoryError::CorruptState)?;
            require_same_revision(revision, policy_revision)?;
            load_terms(database, scenario_id, policy_revision)
        })
        .collect()
}

fn load_terms(
    database: &PartitionDatabase,
    scenario_id: ProtectionScenarioId,
    policy_revision: Revision,
) -> Result<FailureScenario, RepositoryError> {
    let mut statement = database.connection().prepare(
        "SELECT class_id, failure_count, revision FROM protection_scenario_terms
         WHERE scenario_id = ?1 ORDER BY class_id LIMIT ?2",
    )?;
    let rows = statement.query_map(
        params![
            scenario_id.as_bytes().as_slice(),
            i64::try_from(MAXIMUM_TERMS_PER_SCENARIO + 1)
                .map_err(|_| RepositoryError::CapacityExceeded)?,
        ],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        },
    )?;
    let stored = rows.collect::<Result<Vec<_>, _>>()?;
    if stored.is_empty() || stored.len() > MAXIMUM_TERMS_PER_SCENARIO {
        return Err(RepositoryError::CorruptState);
    }
    let terms = stored
        .into_iter()
        .map(|(class_id, failure_count, revision)| {
            require_same_revision(revision, policy_revision)?;
            Ok(FailureTerm {
                class_id: FaultGroupClassId::from_bytes(exact_identifier(class_id)?)
                    .map_err(|_| RepositoryError::CorruptState)?,
                failure_count: u16::try_from(failure_count)
                    .map_err(|_| RepositoryError::CorruptState)?,
            })
        })
        .collect::<Result<Vec<_>, RepositoryError>>()?;
    FailureScenario::new(terms).map_err(|_| RepositoryError::CorruptState)
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

fn term_id(scenario_id: ProtectionScenarioId, class_id: FaultGroupClassId) -> [u8; 16] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.protection-term.v1\0");
    digest.update(&scenario_id.as_bytes());
    digest.update(&class_id.as_bytes());
    let mut identifier = [0; 16];
    identifier.copy_from_slice(&digest.finalize().as_bytes()[..16]);
    uuid_v8(identifier)
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
