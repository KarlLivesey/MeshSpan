// SPDX-License-Identifier: GPL-2.0-only

//! Current declared topology, never a cached destination label, decides local overlap.

use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};

use super::BackupDestinationRecord;
use crate::repository::RepositoryError;
use crate::{BackupDestinationBinding, BackupFailureRelationship};

pub(super) fn assess(
    connection: &Connection,
    mut record: BackupDestinationRecord,
) -> Result<BackupDestinationRecord, RepositoryError> {
    let BackupDestinationBinding::RegisteredTarget {
        target_id,
        target_generation,
    } = record.binding
    else {
        // Remote/provider declarations have their own evidence contract. A mesh
        // identity or endpoint is never inferred to be a physical boundary here.
        return Ok(record);
    };
    let facts = connection.query_row(
        ASSESSMENT_SQL,
        params![
            target_id.as_bytes().as_slice(),
            super::super::apply::to_i64(target_generation)?
        ],
        |row| {
            Ok(Facts {
                partition: row.get(0)?,
                topology: row.get(1)?,
                membership: row.get(2)?,
                usable: row.get(3)?,
                source_count: row.get(4)?,
                overlap: row.get(5)?,
                complete: row.get(6)?,
            })
        },
    )?;
    if facts.partition.len() != 16
        || facts.topology <= 0
        || facts.membership <= 0
        || facts.source_count < 0
    {
        return Err(RepositoryError::CorruptState);
    }
    record.failure_relationship = facts.relationship();
    let mut digest = Sha256::new();
    digest.update(b"meshspan.backup-failure-topology.v1\0");
    digest.update(facts.partition);
    digest.update(facts.topology.to_be_bytes());
    digest.update(facts.membership.to_be_bytes());
    digest.update(target_id.as_bytes());
    digest.update(target_generation.to_be_bytes());
    digest.update(facts.source_count.to_be_bytes());
    digest.update([
        u8::from(facts.usable),
        u8::from(facts.overlap),
        u8::from(facts.complete),
    ]);
    record.failure_evidence_digest = digest.finalize().into();
    Ok(record)
}

struct Facts {
    partition: Vec<u8>,
    topology: i64,
    membership: i64,
    usable: bool,
    source_count: i64,
    overlap: bool,
    complete: bool,
}

impl Facts {
    fn relationship(&self) -> BackupFailureRelationship {
        if !self.usable || self.source_count == 0 {
            BackupFailureRelationship::Unknown
        } else if self.overlap {
            BackupFailureRelationship::Overlapping
        } else if self.complete {
            BackupFailureRelationship::Independent
        } else {
            BackupFailureRelationship::Unknown
        }
    }
}

// All replica members, including learners and retiring members, contribute
// source failure boundaries. Transient reachability never removes a boundary.
// Empty/missing group assignments cannot prove independence. Parent-group
// topology is not currently configurable; if present, require a future explicit
// hierarchy proof instead of inferring independence from unequal leaf IDs.
// EXISTS keeps inventories out of memory and uses indexed identity memberships.
const ASSESSMENT_SQL: &str = "WITH
 source_hosts AS MATERIALIZED (
   SELECT DISTINCT n.host_id FROM partition_voters pv JOIN nodes n USING(node_id)
   WHERE pv.partition_id = (SELECT partition_id FROM applied_state WHERE singleton = 1)),
 target AS (
   SELECT st.host_id FROM storage_targets st JOIN target_generations tg USING(target_id)
   JOIN hosts h ON h.host_id = st.host_id
   WHERE st.target_id = ?1 AND st.current_generation = ?2 AND tg.generation = ?2
     AND st.retired_at IS NULL AND tg.retired_at IS NULL AND h.retired_at IS NULL),
 involved_hosts AS (SELECT host_id FROM source_hosts UNION SELECT host_id FROM target)
 SELECT a.partition_id, m.configuration_revision, p.current_membership_revision,
   EXISTS(SELECT 1 FROM target), (SELECT count(*) FROM source_hosts),
   EXISTS(SELECT 1 FROM source_hosts s JOIN target t
     ON s.host_id = t.host_id OR EXISTS(
       SELECT 1 FROM host_fault_group_memberships x
       JOIN host_fault_group_memberships y USING(group_id)
       WHERE x.host_id = s.host_id AND y.host_id = t.host_id)),
   EXISTS(SELECT 1 FROM fault_group_classes WHERE system_managed = 0)
     AND NOT EXISTS(SELECT 1 FROM fault_groups WHERE parent_group_id IS NOT NULL)
     AND NOT EXISTS(SELECT 1 FROM involved_hosts h CROSS JOIN fault_group_classes c
       WHERE c.system_managed = 0 AND NOT EXISTS(SELECT 1 FROM host_fault_group_memberships f
         JOIN fault_groups g USING(group_id) WHERE f.host_id = h.host_id AND g.class_id = c.class_id))
 FROM applied_state a JOIN metadata_partitions p USING(partition_id) CROSS JOIN meshes m
 WHERE a.singleton = 1";

#[test]
fn assessment_uses_indexed_target_and_membership_lookups() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempfile::tempdir()?;
    let database = crate::PartitionDatabase::open(
        &directory.path().join("assessment.sqlite3"),
        meshspan_domain::PartitionId::from_bytes([1; 16])?,
        meshspan_domain::UnixMicros::new(1),
    )?;
    let mut statement = database
        .connection()
        .prepare(&format!("EXPLAIN QUERY PLAN {ASSESSMENT_SQL}"))?;
    let plan = statement
        .query_map(params![[1_u8; 16].as_slice(), 1], |row| {
            row.get::<_, String>(3)
        })?
        .collect::<Result<Vec<_>, _>>()?
        .join("\n");
    for expected in [
        "SEARCH pv",
        "SEARCH st",
        "SEARCH tg",
        "SEARCH x",
        "SEARCH y",
        "SEARCH f",
        "SEARCH g",
    ] {
        assert!(plan.contains(expected), "missing {expected}: {plan}");
    }
    Ok(())
}
