// SPDX-License-Identifier: GPL-2.0-only

//! Authoritative machine, storage-target and overlapping shared-failure topology.

use meshspan_domain::{FaultGroupClassId, FaultGroupId, HostId, NodeId, Revision, TargetId};
use rusqlite::{OptionalExtension, Transaction, params};

use super::apply::to_i64;
use super::{EntityKind, EntityReference, Page, PageLimit, RepositoryError};
use crate::{CreateFaultGroup, PartitionDatabase, SetHostFaultGroupMembership, StorageUsageLimit};

const ACTIVE_HOST_STATE: i64 = 1;
const ACTIVE_FAULT_GROUP_STATE: i64 = 1;
const USER_DEFINED_CLASS_KIND: i64 = 5;

/// Stable seek position in the machine inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TopologyNodeCursor {
    canonical_name: String,
    node_id: NodeId,
}

impl TopologyNodeCursor {
    /// Reconstructs one validated public continuation cursor.
    #[must_use]
    pub fn new(canonical_name: String, node_id: NodeId) -> Self {
        Self {
            canonical_name,
            node_id,
        }
    }

    /// Returns the exact canonical seek name.
    #[must_use]
    pub fn canonical_name(&self) -> &str {
        &self.canonical_name
    }

    /// Returns the exact seek identity.
    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.node_id
    }
}

/// One current daemon node and its machine boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TopologyNodeRecord {
    /// Stable daemon identity.
    pub node_id: NodeId,
    /// Stable machine identity shared by daemons on the same machine.
    pub host_id: HostId,
    /// User-visible daemon name.
    pub display_name: String,
    /// Canonical stable seek name.
    pub canonical_name: String,
    /// Node lifecycle state.
    pub state: u8,
    /// Current restart incarnation.
    pub incarnation: u64,
    /// Storage, gateway and metadata-eligible role bits.
    pub roles: u8,
    /// Private mesh endpoint once activated.
    pub private_endpoint: Option<String>,
    /// Last authoritative record revision.
    pub revision: Revision,
}

/// Stable seek position in the storage-target inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TopologyTargetCursor {
    canonical_name: String,
    target_id: TargetId,
}

impl TopologyTargetCursor {
    /// Reconstructs one validated public continuation cursor.
    #[must_use]
    pub fn new(canonical_name: String, target_id: TargetId) -> Self {
        Self {
            canonical_name,
            target_id,
        }
    }

    /// Returns the exact canonical seek name.
    #[must_use]
    pub fn canonical_name(&self) -> &str {
        &self.canonical_name
    }

    /// Returns the exact seek identity.
    #[must_use]
    pub const fn target_id(&self) -> TargetId {
        self.target_id
    }
}

/// One current registered target without its node-local filesystem path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TopologyTargetRecord {
    /// Stable storage-target identity.
    pub target_id: TargetId,
    /// Owning daemon.
    pub node_id: NodeId,
    /// Owning machine.
    pub host_id: HostId,
    /// User-visible target name.
    pub display_name: String,
    /// Canonical stable seek name.
    pub canonical_name: String,
    /// Target lifecycle state.
    pub state: u8,
    /// Current authority-fenced generation.
    pub generation: u64,
    /// Current MeshSpan-owned capacity ceiling.
    pub usage_limit: StorageUsageLimit,
    /// Last authoritative record revision.
    pub revision: Revision,
}

/// Stable seek position in the shared-failure-group inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FaultGroupCursor {
    class_name: String,
    group_name: String,
    group_id: FaultGroupId,
}

impl FaultGroupCursor {
    /// Reconstructs one validated public continuation cursor.
    #[must_use]
    pub fn new(class_name: String, group_name: String, group_id: FaultGroupId) -> Self {
        Self {
            class_name,
            group_name,
            group_id,
        }
    }

    /// Returns the exact canonical class seek name.
    #[must_use]
    pub fn class_name(&self) -> &str {
        &self.class_name
    }

    /// Returns the exact canonical group seek name.
    #[must_use]
    pub fn group_name(&self) -> &str {
        &self.group_name
    }

    /// Returns the exact seek identity.
    #[must_use]
    pub const fn group_id(&self) -> FaultGroupId {
        self.group_id
    }
}

/// One administrator-defined shared machine-failure boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FaultGroupRecord {
    /// Stable failure-class identity.
    pub class_id: FaultGroupClassId,
    /// User-visible failure-class name.
    pub class_display_name: String,
    /// Canonical failure-class seek name.
    pub class_canonical_name: String,
    /// Stable concrete group identity.
    pub group_id: FaultGroupId,
    /// User-visible concrete group name.
    pub group_display_name: String,
    /// Canonical concrete group seek name.
    pub group_canonical_name: String,
    /// Last authoritative group revision.
    pub revision: Revision,
}

/// Stable seek position in the machine/group membership inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultGroupMembershipCursor {
    host_id: HostId,
    group_id: FaultGroupId,
}

impl FaultGroupMembershipCursor {
    /// Reconstructs one validated public continuation cursor.
    #[must_use]
    pub const fn new(host_id: HostId, group_id: FaultGroupId) -> Self {
        Self { host_id, group_id }
    }

    /// Returns the exact host seek identity.
    #[must_use]
    pub const fn host_id(self) -> HostId {
        self.host_id
    }

    /// Returns the exact group seek identity.
    #[must_use]
    pub const fn group_id(self) -> FaultGroupId {
        self.group_id
    }
}

/// One many-to-many machine/group membership edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultGroupMembershipRecord {
    /// Member machine.
    pub host_id: HostId,
    /// Shared-failure group containing it.
    pub group_id: FaultGroupId,
    /// Last authoritative edge revision.
    pub revision: Revision,
}

pub(super) fn create_fault_group(
    transaction: &Transaction<'_>,
    command: &CreateFaultGroup,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    if command.class_name.canonical().len() > 128 {
        return Err(RepositoryError::InvalidCommand);
    }
    let class = command.class_id.as_bytes();
    let existing = transaction
        .query_row(
            "SELECT display_name, canonical_name FROM fault_group_classes WHERE class_id = ?1",
            [class.as_slice()],
            |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    match existing {
        Some((Some(_), canonical)) if canonical == command.class_name.canonical() => {}
        Some(_) => return Err(RepositoryError::InvalidCommand),
        None => {
            transaction.execute(
                "INSERT INTO fault_group_classes(
                    class_id, canonical_name, revision, display_name, class_kind, system_managed
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 0)",
                params![
                    class.as_slice(),
                    command.class_name.canonical(),
                    to_i64(revision.get())?,
                    command.class_name.display(),
                    USER_DEFINED_CLASS_KIND,
                ],
            )?;
        }
    }
    let group = command.group_id.as_bytes();
    transaction.execute(
        "INSERT INTO fault_groups(
            group_id, class_id, parent_group_id, canonical_name, revision, display_name, state
         ) VALUES (?1, ?2, NULL, ?3, ?4, ?5, ?6)",
        params![
            group.as_slice(),
            class.as_slice(),
            command.group_name.canonical(),
            to_i64(revision.get())?,
            command.group_name.display(),
            ACTIVE_FAULT_GROUP_STATE,
        ],
    )?;
    update_configuration_revision(transaction, revision)?;
    Ok(EntityReference {
        kind: EntityKind::FaultGroup,
        id: group,
    })
}

pub(super) fn set_host_membership(
    transaction: &Transaction<'_>,
    command: SetHostFaultGroupMembership,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    require_active_host_and_group(transaction, command.host_id, command.group_id)?;
    let host = command.host_id.as_bytes();
    let group = command.group_id.as_bytes();
    if command.present {
        transaction.execute(
            "INSERT INTO host_fault_group_memberships(host_id, group_id, revision)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(host_id, group_id) DO UPDATE SET revision = excluded.revision",
            params![host.as_slice(), group.as_slice(), to_i64(revision.get())?],
        )?;
    } else {
        transaction.execute(
            "DELETE FROM host_fault_group_memberships WHERE host_id = ?1 AND group_id = ?2",
            params![host.as_slice(), group.as_slice()],
        )?;
    }
    update_configuration_revision(transaction, revision)?;
    Ok(EntityReference {
        kind: EntityKind::FaultGroupMembership,
        id: group,
    })
}

pub(super) fn nodes(
    database: &PartitionDatabase,
    after: Option<&TopologyNodeCursor>,
    limit: PageLimit,
) -> Result<Page<TopologyNodeRecord, TopologyNodeCursor>, RepositoryError> {
    let after_name = after.map_or("", |cursor| cursor.canonical_name.as_str());
    let after_id = after.map_or([0; 16], |cursor| cursor.node_id.as_bytes());
    let mut statement = database.connection().prepare(
        "SELECT n.node_id, n.host_id, n.display_name, n.canonical_name, n.state,
                n.current_incarnation, COALESCE(SUM(1 << (nr.role_code - 1)), 0),
                na.private_endpoint, n.revision
         FROM nodes n
         LEFT JOIN node_roles nr ON nr.node_id = n.node_id
         LEFT JOIN node_activations na ON na.node_id = n.node_id
         WHERE (n.canonical_name > ?1 OR (n.canonical_name = ?1 AND n.node_id > ?2))
         GROUP BY n.node_id
         ORDER BY n.canonical_name, n.node_id LIMIT ?3",
    )?;
    let rows = statement.query_map(
        params![after_name, after_id.as_slice(), row_limit(limit)?],
        decode_node,
    )?;
    Ok(page(
        rows.collect::<Result<Vec<_>, _>>()?,
        limit,
        |record| TopologyNodeCursor::new(record.canonical_name.clone(), record.node_id),
    ))
}

pub(super) fn targets(
    database: &PartitionDatabase,
    after: Option<&TopologyTargetCursor>,
    limit: PageLimit,
) -> Result<Page<TopologyTargetRecord, TopologyTargetCursor>, RepositoryError> {
    let after_name = after.map_or("", |cursor| cursor.canonical_name.as_str());
    let after_id = after.map_or([0; 16], |cursor| cursor.target_id.as_bytes());
    let mut statement = database.connection().prepare(
        "SELECT target_id, node_id, host_id, display_name, canonical_name, state,
                current_generation, usage_limit_kind, usage_limit_value, revision
         FROM storage_targets
         WHERE (canonical_name > ?1 OR (canonical_name = ?1 AND target_id > ?2))
         ORDER BY canonical_name, target_id LIMIT ?3",
    )?;
    let rows = statement.query_map(
        params![after_name, after_id.as_slice(), row_limit(limit)?],
        decode_target,
    )?;
    Ok(page(
        rows.collect::<Result<Vec<_>, _>>()?,
        limit,
        |record| TopologyTargetCursor::new(record.canonical_name.clone(), record.target_id),
    ))
}

pub(super) fn fault_groups(
    database: &PartitionDatabase,
    after: Option<&FaultGroupCursor>,
    limit: PageLimit,
) -> Result<Page<FaultGroupRecord, FaultGroupCursor>, RepositoryError> {
    let after_class = after.map_or("", |cursor| cursor.class_name.as_str());
    let after_group = after.map_or("", |cursor| cursor.group_name.as_str());
    let after_id = after.map_or([0; 16], |cursor| cursor.group_id.as_bytes());
    let mut statement = database.connection().prepare(
        "SELECT c.class_id, c.display_name, c.canonical_name,
                g.group_id, g.display_name, g.canonical_name, g.revision
         FROM fault_groups g JOIN fault_group_classes c USING(class_id)
         WHERE g.state = 1 AND c.display_name IS NOT NULL AND g.display_name IS NOT NULL
           AND (c.canonical_name > ?1
             OR (c.canonical_name = ?1 AND g.canonical_name > ?2)
             OR (c.canonical_name = ?1 AND g.canonical_name = ?2 AND g.group_id > ?3))
         ORDER BY c.canonical_name, g.canonical_name, g.group_id LIMIT ?4",
    )?;
    let rows = statement.query_map(
        params![
            after_class,
            after_group,
            after_id.as_slice(),
            row_limit(limit)?
        ],
        decode_fault_group,
    )?;
    Ok(page(
        rows.collect::<Result<Vec<_>, _>>()?,
        limit,
        |record| {
            FaultGroupCursor::new(
                record.class_canonical_name.clone(),
                record.group_canonical_name.clone(),
                record.group_id,
            )
        },
    ))
}

pub(super) fn fault_group(
    database: &PartitionDatabase,
    group_id: FaultGroupId,
) -> Result<Option<FaultGroupRecord>, RepositoryError> {
    let group = group_id.as_bytes();
    database
        .connection()
        .query_row(
            "SELECT c.class_id, c.display_name, c.canonical_name,
                    g.group_id, g.display_name, g.canonical_name, g.revision
             FROM fault_groups g JOIN fault_group_classes c USING(class_id)
             WHERE g.group_id = ?1 AND g.state = 1
               AND c.display_name IS NOT NULL AND g.display_name IS NOT NULL",
            [group.as_slice()],
            decode_fault_group,
        )
        .optional()
        .map_err(RepositoryError::from)
}

pub(super) fn fault_group_memberships(
    database: &PartitionDatabase,
    after: Option<FaultGroupMembershipCursor>,
    limit: PageLimit,
) -> Result<Page<FaultGroupMembershipRecord, FaultGroupMembershipCursor>, RepositoryError> {
    let after_host = after.map_or([0; 16], |cursor| cursor.host_id.as_bytes());
    let after_group = after.map_or([0; 16], |cursor| cursor.group_id.as_bytes());
    let mut statement = database.connection().prepare(
        "SELECT host_id, group_id, revision FROM host_fault_group_memberships
         WHERE host_id > ?1 OR (host_id = ?1 AND group_id > ?2)
         ORDER BY host_id, group_id LIMIT ?3",
    )?;
    let rows = statement.query_map(
        params![
            after_host.as_slice(),
            after_group.as_slice(),
            row_limit(limit)?
        ],
        |row| {
            Ok(FaultGroupMembershipRecord {
                host_id: HostId::from_bytes(exact_identifier(row.get(0)?)?)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
                group_id: FaultGroupId::from_bytes(exact_identifier(row.get(1)?)?)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
                revision: Revision::new(positive(row.get(2)?)?),
            })
        },
    )?;
    Ok(page(
        rows.collect::<Result<Vec<_>, _>>()?,
        limit,
        |record| FaultGroupMembershipCursor::new(record.host_id, record.group_id),
    ))
}

fn require_active_host_and_group(
    transaction: &Transaction<'_>,
    host_id: HostId,
    group_id: FaultGroupId,
) -> Result<(), RepositoryError> {
    let host = host_id.as_bytes();
    let group = group_id.as_bytes();
    let valid: i64 = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM hosts h CROSS JOIN fault_groups g
            WHERE h.host_id = ?1 AND h.state = ?2 AND h.retired_at IS NULL
              AND g.group_id = ?3 AND g.state = ?4
         )",
        params![
            host.as_slice(),
            ACTIVE_HOST_STATE,
            group.as_slice(),
            ACTIVE_FAULT_GROUP_STATE,
        ],
        |row| row.get(0),
    )?;
    if valid == 1 {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
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

fn decode_node(row: &rusqlite::Row<'_>) -> rusqlite::Result<TopologyNodeRecord> {
    Ok(TopologyNodeRecord {
        node_id: NodeId::from_bytes(exact_identifier(row.get(0)?)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        host_id: HostId::from_bytes(exact_identifier(row.get(1)?)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        display_name: row.get(2)?,
        canonical_name: row.get(3)?,
        state: u8::try_from(row.get::<_, i64>(4)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
        incarnation: positive(row.get(5)?)?,
        roles: u8::try_from(row.get::<_, i64>(6)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
        private_endpoint: row.get(7)?,
        revision: Revision::new(positive(row.get(8)?)?),
    })
}

fn decode_target(row: &rusqlite::Row<'_>) -> rusqlite::Result<TopologyTargetRecord> {
    let limit_kind = row.get::<_, i64>(7)?;
    let limit_value = positive(row.get(8)?)?;
    Ok(TopologyTargetRecord {
        target_id: TargetId::from_bytes(exact_identifier(row.get(0)?)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        node_id: NodeId::from_bytes(exact_identifier(row.get(1)?)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        host_id: HostId::from_bytes(exact_identifier(row.get(2)?)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        display_name: row.get(3)?,
        canonical_name: row.get(4)?,
        state: u8::try_from(row.get::<_, i64>(5)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
        generation: positive(row.get(6)?)?,
        usage_limit: match limit_kind {
            1 => StorageUsageLimit::Percent(
                u8::try_from(limit_value).map_err(|_| rusqlite::Error::InvalidQuery)?,
            ),
            2 => StorageUsageLimit::Bytes(limit_value),
            _ => return Err(rusqlite::Error::InvalidQuery),
        },
        revision: Revision::new(positive(row.get(9)?)?),
    })
}

fn decode_fault_group(row: &rusqlite::Row<'_>) -> rusqlite::Result<FaultGroupRecord> {
    Ok(FaultGroupRecord {
        class_id: FaultGroupClassId::from_bytes(exact_identifier(row.get(0)?)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        class_display_name: row.get(1)?,
        class_canonical_name: row.get(2)?,
        group_id: FaultGroupId::from_bytes(exact_identifier(row.get(3)?)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        group_display_name: row.get(4)?,
        group_canonical_name: row.get(5)?,
        revision: Revision::new(positive(row.get(6)?)?),
    })
}

fn page<T, C>(mut items: Vec<T>, limit: PageLimit, cursor: impl FnOnce(&T) -> C) -> Page<T, C> {
    let has_more = items.len() > limit.get();
    if has_more {
        items.pop();
    }
    let next = if has_more {
        items.last().map(cursor)
    } else {
        None
    };
    Page { items, next }
}

fn row_limit(limit: PageLimit) -> Result<i64, RepositoryError> {
    i64::try_from(limit.get().saturating_add(1)).map_err(|_| RepositoryError::CapacityExceeded)
}

fn exact_identifier(value: Vec<u8>) -> rusqlite::Result<[u8; 16]> {
    value.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}

fn positive(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value != 0)
        .ok_or(rusqlite::Error::InvalidQuery)
}
