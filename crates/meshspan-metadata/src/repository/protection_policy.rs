// SPDX-License-Identifier: GPL-2.0-only

//! Immutable survival policies and volume policy selection.

use std::collections::BTreeSet;

use meshspan_domain::{
    FailureScenario, FailureTerm, FaultGroupClassId, ProtectionPolicyId, ProtectionScenarioId,
    Revision, VolumeId, uuid_v8,
};
use rusqlite::{OptionalExtension, Transaction, params};

use super::apply::to_i64;
use super::{EntityKind, EntityReference, Page, PageLimit, RepositoryError};
use crate::{
    AssignVolumeProtectionPolicy, CommandContext, CreateProtectionPolicy, PartitionDatabase,
};

const ACTIVE_STATE: i64 = 1;
const MAXIMUM_SCENARIOS: usize = 16;
const MAXIMUM_TERMS_PER_SCENARIO: usize = 16;

/// Stable seek position in the protection-policy inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectionPolicyCursor {
    canonical_name: String,
    policy_id: ProtectionPolicyId,
}

impl ProtectionPolicyCursor {
    /// Reconstructs one validated public continuation cursor.
    #[must_use]
    pub fn new(canonical_name: String, policy_id: ProtectionPolicyId) -> Self {
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
    pub const fn policy_id(&self) -> ProtectionPolicyId {
        self.policy_id
    }
}

/// One named immutable data-survival policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectionPolicyRecord {
    /// Stable policy identity.
    pub policy_id: ProtectionPolicyId,
    /// User-visible policy name.
    pub display_name: String,
    /// Canonical stable seek name.
    pub canonical_name: String,
    /// Ordered alternative failure scenarios which must each remain decodable.
    pub scenarios: Vec<ProtectionScenarioRecord>,
    /// Immutable policy revision.
    pub revision: Revision,
}

/// One named scenario within an immutable protection policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectionScenarioRecord {
    /// Stable scenario identity.
    pub scenario_id: ProtectionScenarioId,
    /// User-visible scenario name.
    pub display_name: String,
    /// Failure terms which occur together in this scenario.
    pub terms: Vec<ProtectionTermRecord>,
}

impl ProtectionScenarioRecord {
    fn failure_scenario(&self) -> Result<FailureScenario, RepositoryError> {
        FailureScenario::new(self.terms.iter().map(|record| record.term).collect())
            .map_err(|_| RepositoryError::CorruptState)
    }
}

/// One failure-class count in a named protection scenario.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectionTermRecord {
    /// Stable failure-class identity.
    pub class_id: FaultGroupClassId,
    /// User-visible failure-class name.
    pub class_display_name: String,
    /// Number of simultaneous failures to survive.
    pub failure_count: u16,
    term: FailureTerm,
}

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
    let scenarios = load_scenarios(database, policy_id, revision)?
        .into_iter()
        .map(|record| record.failure_scenario())
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Some(VolumeProtectionPolicy {
        policy_id,
        revision,
        scenarios,
    }))
}

pub(super) fn policies(
    database: &PartitionDatabase,
    after: Option<&ProtectionPolicyCursor>,
    limit: PageLimit,
) -> Result<Page<ProtectionPolicyRecord, ProtectionPolicyCursor>, RepositoryError> {
    let after_name = after.map_or("", |cursor| cursor.canonical_name.as_str());
    let after_id = after.map_or([0; 16], |cursor| cursor.policy_id.as_bytes());
    let mut statement = database.connection().prepare(
        "SELECT policy_id, display_name, canonical_name, revision
         FROM protection_policies
         WHERE state = ?1 AND (
           canonical_name > ?2 OR (canonical_name = ?2 AND policy_id > ?3)
         )
         ORDER BY canonical_name, policy_id LIMIT ?4",
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
                row.get::<_, i64>(3)?,
            ))
        },
    )?;
    let stored = rows.collect::<Result<Vec<_>, _>>()?;
    let mut records = stored
        .into_iter()
        .map(|(policy_id, display_name, canonical_name, revision)| {
            let policy_id = ProtectionPolicyId::from_bytes(exact_identifier(policy_id)?)
                .map_err(|_| RepositoryError::CorruptState)?;
            let revision = positive_revision(revision)?;
            Ok(ProtectionPolicyRecord {
                policy_id,
                display_name,
                canonical_name,
                scenarios: load_scenarios(database, policy_id, revision)?,
                revision,
            })
        })
        .collect::<Result<Vec<_>, RepositoryError>>()?;
    let has_more = records.len() > limit.get();
    if has_more {
        records.pop();
    }
    let next = if has_more {
        records.last().map(|record| {
            ProtectionPolicyCursor::new(record.canonical_name.clone(), record.policy_id)
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
    policy_id: ProtectionPolicyId,
) -> Result<Option<ProtectionPolicyRecord>, RepositoryError> {
    let stored = database
        .connection()
        .query_row(
            "SELECT display_name, canonical_name, revision
             FROM protection_policies WHERE policy_id = ?1 AND state = ?2",
            params![policy_id.as_bytes().as_slice(), ACTIVE_STATE],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?;
    stored
        .map(|(display_name, canonical_name, revision)| {
            let revision = positive_revision(revision)?;
            Ok(ProtectionPolicyRecord {
                policy_id,
                display_name,
                canonical_name,
                scenarios: load_scenarios(database, policy_id, revision)?,
                revision,
            })
        })
        .transpose()
}

fn load_scenarios(
    database: &PartitionDatabase,
    policy_id: ProtectionPolicyId,
    policy_revision: Revision,
) -> Result<Vec<ProtectionScenarioRecord>, RepositoryError> {
    let mut statement = database.connection().prepare(
        "SELECT scenario_id, display_name, revision FROM protection_scenarios
         WHERE policy_id = ?1 ORDER BY scenario_order, scenario_id LIMIT ?2",
    )?;
    let rows = statement.query_map(
        params![
            policy_id.as_bytes().as_slice(),
            i64::try_from(MAXIMUM_SCENARIOS + 1).map_err(|_| RepositoryError::CapacityExceeded)?,
        ],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        },
    )?;
    let stored = rows.collect::<Result<Vec<_>, _>>()?;
    if stored.is_empty() || stored.len() > MAXIMUM_SCENARIOS {
        return Err(RepositoryError::CorruptState);
    }
    stored
        .into_iter()
        .map(|(scenario_id, display_name, revision)| {
            let scenario_id = ProtectionScenarioId::from_bytes(exact_identifier(scenario_id)?)
                .map_err(|_| RepositoryError::CorruptState)?;
            require_same_revision(revision, policy_revision)?;
            Ok(ProtectionScenarioRecord {
                scenario_id,
                display_name,
                terms: load_terms(database, scenario_id, policy_revision)?,
            })
        })
        .collect()
}

fn load_terms(
    database: &PartitionDatabase,
    scenario_id: ProtectionScenarioId,
    policy_revision: Revision,
) -> Result<Vec<ProtectionTermRecord>, RepositoryError> {
    let mut statement = database.connection().prepare(
        "SELECT t.class_id, c.display_name, t.failure_count, t.revision
         FROM protection_scenario_terms t
         JOIN fault_group_classes c ON c.class_id = t.class_id
         WHERE t.scenario_id = ?1 AND c.display_name IS NOT NULL
         ORDER BY t.class_id LIMIT ?2",
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
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        },
    )?;
    let stored = rows.collect::<Result<Vec<_>, _>>()?;
    if stored.is_empty() || stored.len() > MAXIMUM_TERMS_PER_SCENARIO {
        return Err(RepositoryError::CorruptState);
    }
    stored
        .into_iter()
        .map(|(class_id, class_display_name, failure_count, revision)| {
            require_same_revision(revision, policy_revision)?;
            let class_id = FaultGroupClassId::from_bytes(exact_identifier(class_id)?)
                .map_err(|_| RepositoryError::CorruptState)?;
            let failure_count =
                u16::try_from(failure_count).map_err(|_| RepositoryError::CorruptState)?;
            Ok(ProtectionTermRecord {
                class_id,
                class_display_name,
                failure_count,
                term: FailureTerm {
                    class_id,
                    failure_count,
                },
            })
        })
        .collect()
}

fn require_same_revision(stored: i64, expected: Revision) -> Result<(), RepositoryError> {
    if u64::try_from(stored).ok() == Some(expected.get()) {
        Ok(())
    } else {
        Err(RepositoryError::CorruptState)
    }
}

fn positive_revision(value: i64) -> Result<Revision, RepositoryError> {
    let revision = Revision::new(u64::try_from(value).map_err(|_| RepositoryError::CorruptState)?);
    if revision == Revision::ZERO {
        Err(RepositoryError::CorruptState)
    } else {
        Ok(revision)
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
