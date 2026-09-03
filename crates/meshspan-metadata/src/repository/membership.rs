// SPDX-License-Identifier: GPL-2.0-only

//! Fail-closed projection of authoritative partition voter and learner membership.

use std::collections::BTreeMap;

use meshspan_domain::{NodeId, Revision};
use rusqlite::{OptionalExtension, params};

use super::RepositoryError;
use crate::PartitionDatabase;

const ACTIVE_VOTER_ROLE: i64 = 1;
const STAGED_LEARNER_ROLE: i64 = 2;
const ACTIVE_MEMBER_STATE: i64 = 1;
const STAGED_MEMBER_STATE: i64 = 2;
const RETIRING_MEMBER_STATE: i64 = 3;
const ADMITTED_NODE_STATE: i64 = 1;
const ACTIVE_NODE_STATE: i64 = 2;
const DRAINING_NODE_STATE: i64 = 3;

/// Exact current-incarnation membership accepted by one authoritative metadata partition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthoritativeMembership {
    revision: Revision,
    active_voters: BTreeMap<NodeId, u64>,
    admitted_learners: BTreeMap<NodeId, u64>,
    retiring_members: BTreeMap<NodeId, u64>,
}

impl AuthoritativeMembership {
    /// Returns the authoritative membership revision represented by this projection.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    /// Returns active voter identities and their exact accepted process incarnations.
    #[must_use]
    pub const fn active_voters(&self) -> &BTreeMap<NodeId, u64> {
        &self.active_voters
    }

    /// Returns admitted metadata-eligible learners awaiting safe promotion.
    #[must_use]
    pub const fn admitted_learners(&self) -> &BTreeMap<NodeId, u64> {
        &self.admitted_learners
    }

    /// Returns members authoritatively fenced from new work and awaiting joint removal.
    #[must_use]
    pub const fn retiring_members(&self) -> &BTreeMap<NodeId, u64> {
        &self.retiring_members
    }
}

pub(super) fn load(
    database: &PartitionDatabase,
) -> Result<Option<AuthoritativeMembership>, RepositoryError> {
    let partition_id = database.partition_id().as_bytes();
    let revision = database
        .connection()
        .query_row(
            "SELECT current_membership_revision
             FROM metadata_partitions
             WHERE partition_id = ?1 AND state = 1",
            [partition_id.as_slice()],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    let Some(revision) = revision else {
        return Ok(None);
    };
    let revision = positive_u64(revision)?;
    let mut statement = database.connection().prepare(
        "SELECT pv.node_id, n.current_incarnation, pv.member_role, pv.state, n.state
         FROM partition_voters pv
         JOIN nodes n ON n.node_id = pv.node_id
         WHERE pv.partition_id = ?1
         ORDER BY pv.node_id",
    )?;
    let mut rows = statement.query(params![partition_id.as_slice()])?;
    let mut active_voters = BTreeMap::new();
    let mut admitted_learners = BTreeMap::new();
    let mut retiring_members = BTreeMap::new();
    while let Some(row) = rows.next()? {
        let node_id = node_id(&row.get::<_, Vec<u8>>(0)?)?;
        let incarnation = positive_u64(row.get(1)?)?;
        let role = row.get::<_, i64>(2)?;
        let member_state = row.get::<_, i64>(3)?;
        let node_state = row.get::<_, i64>(4)?;
        let inserted = match (role, member_state, node_state) {
            (ACTIVE_VOTER_ROLE, ACTIVE_MEMBER_STATE, ACTIVE_NODE_STATE) => {
                active_voters.insert(node_id, incarnation)
            }
            (STAGED_LEARNER_ROLE, STAGED_MEMBER_STATE, ADMITTED_NODE_STATE | ACTIVE_NODE_STATE) => {
                admitted_learners.insert(node_id, incarnation)
            }
            (
                ACTIVE_VOTER_ROLE | STAGED_LEARNER_ROLE,
                RETIRING_MEMBER_STATE,
                DRAINING_NODE_STATE,
            ) => retiring_members.insert(node_id, incarnation),
            _ => return Err(RepositoryError::CorruptState),
        };
        if inserted.is_some() {
            return Err(RepositoryError::CorruptState);
        }
    }
    if active_voters.is_empty()
        || active_voters
            .keys()
            .any(|node| admitted_learners.contains_key(node) || retiring_members.contains_key(node))
        || admitted_learners
            .keys()
            .any(|node| retiring_members.contains_key(node))
    {
        return Err(RepositoryError::CorruptState);
    }
    Ok(Some(AuthoritativeMembership {
        revision: Revision::new(revision),
        active_voters,
        admitted_learners,
        retiring_members,
    }))
}

fn node_id(bytes: &[u8]) -> Result<NodeId, RepositoryError> {
    let exact: [u8; 16] = bytes
        .try_into()
        .map_err(|_| RepositoryError::CorruptState)?;
    NodeId::from_bytes(exact).map_err(|_| RepositoryError::CorruptState)
}

fn positive_u64(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(RepositoryError::CorruptState)
}
