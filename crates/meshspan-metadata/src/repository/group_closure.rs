// SPDX-License-Identifier: GPL-2.0-only

//! Bounded exact nested-group closure reconstruction.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use meshspan_domain::{GroupGraph, GroupId, PrincipalId, Revision};
use rusqlite::{Transaction, params};

use super::RepositoryError;

const MAXIMUM_GROUPS: usize = 4_096;
const MAXIMUM_MEMBERSHIPS: usize = 65_536;
const MAXIMUM_CLOSURE_ROWS: usize = 1_000_000;

type Closure = BTreeMap<PrincipalId, (u64, u64)>;
type DirectMemberships = BTreeMap<GroupId, BTreeSet<PrincipalId>>;

pub(super) fn rebuild(
    transaction: &Transaction<'_>,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let (groups, memberships) = load_graph(transaction)?;
    validate_graph(&groups, &memberships)?;
    let closures = calculate_closures(&groups, &memberships)?;
    let row_count = closures.values().try_fold(0_usize, |total, closure| {
        total
            .checked_add(closure.len())
            .ok_or(RepositoryError::CapacityExceeded)
    })?;
    if row_count > MAXIMUM_CLOSURE_ROWS {
        return Err(RepositoryError::CapacityExceeded);
    }
    transaction.execute("DELETE FROM group_closure", [])?;
    let revision = to_i64(revision.get())?;
    for (group, closure) in closures {
        let group_bytes = group.as_bytes();
        for (member, (path_count, minimum_depth)) in closure {
            let member_bytes = member.as_bytes();
            transaction.execute(
                "INSERT INTO group_closure(
                    containing_group_id, member_principal_id, path_count, minimum_depth, revision
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    group_bytes.as_slice(),
                    member_bytes.as_slice(),
                    to_i64(path_count)?,
                    to_i64(minimum_depth)?,
                    revision
                ],
            )?;
        }
    }
    Ok(())
}

fn load_graph(
    transaction: &Transaction<'_>,
) -> Result<(BTreeSet<GroupId>, DirectMemberships), RepositoryError> {
    let mut groups = BTreeSet::new();
    let mut group_statement =
        transaction.prepare("SELECT principal_id FROM groups ORDER BY principal_id LIMIT ?1")?;
    let limit =
        to_i64(u64::try_from(MAXIMUM_GROUPS + 1).map_err(|_| RepositoryError::CapacityExceeded)?)?;
    let group_rows = group_statement.query_map([limit], |row| row.get::<_, Vec<u8>>(0))?;
    for row in group_rows {
        groups.insert(parse_group(&row?)?);
        if groups.len() > MAXIMUM_GROUPS {
            return Err(RepositoryError::CapacityExceeded);
        }
    }

    let mut memberships = DirectMemberships::new();
    let mut count = 0_usize;
    let mut membership_statement = transaction.prepare(
        "SELECT containing_group_id, member_principal_id
         FROM group_memberships WHERE state = 1
         ORDER BY containing_group_id, member_principal_id LIMIT ?1",
    )?;
    let limit = to_i64(
        u64::try_from(MAXIMUM_MEMBERSHIPS + 1).map_err(|_| RepositoryError::CapacityExceeded)?,
    )?;
    let rows = membership_statement.query_map([limit], |row| {
        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;
    for row in rows {
        let (group, member) = row?;
        memberships
            .entry(parse_group(&group)?)
            .or_default()
            .insert(parse_principal(&member)?);
        count = count
            .checked_add(1)
            .ok_or(RepositoryError::CapacityExceeded)?;
        if count > MAXIMUM_MEMBERSHIPS {
            return Err(RepositoryError::CapacityExceeded);
        }
    }
    Ok((groups, memberships))
}

fn validate_graph(
    groups: &BTreeSet<GroupId>,
    memberships: &BTreeMap<GroupId, BTreeSet<PrincipalId>>,
) -> Result<(), RepositoryError> {
    let mut graph = GroupGraph::default();
    for group in groups {
        graph
            .register_group(*group)
            .map_err(|_| RepositoryError::CapacityExceeded)?;
    }
    for (group, members) in memberships {
        for member in members {
            graph
                .add_member(*group, *member)
                .map_err(|_| RepositoryError::InvalidCommand)?;
        }
    }
    Ok(())
}

fn calculate_closures(
    groups: &BTreeSet<GroupId>,
    memberships: &BTreeMap<GroupId, BTreeSet<PrincipalId>>,
) -> Result<BTreeMap<GroupId, Closure>, RepositoryError> {
    let principal_groups: BTreeMap<PrincipalId, GroupId> = groups
        .iter()
        .map(|group| (group.principal_id(), *group))
        .collect();
    let mut parents = BTreeMap::<GroupId, BTreeSet<GroupId>>::new();
    let mut remaining_children = BTreeMap::<GroupId, usize>::new();
    let mut closures = BTreeMap::<GroupId, Closure>::new();
    for group in groups {
        let members = memberships.get(group).cloned().unwrap_or_default();
        let child_groups: BTreeSet<GroupId> = members
            .iter()
            .filter_map(|member| principal_groups.get(member).copied())
            .collect();
        remaining_children.insert(*group, child_groups.len());
        for child in child_groups {
            parents.entry(child).or_default().insert(*group);
        }
        closures.insert(
            *group,
            members.into_iter().map(|member| (member, (1, 1))).collect(),
        );
    }
    let mut ready: VecDeque<GroupId> = remaining_children
        .iter()
        .filter_map(|(group, remaining)| (*remaining == 0).then_some(*group))
        .collect();
    let mut processed = 0_usize;
    while let Some(child) = ready.pop_front() {
        processed += 1;
        let child_closure = closures
            .get(&child)
            .cloned()
            .ok_or(RepositoryError::CorruptState)?;
        for parent in parents.get(&child).cloned().unwrap_or_default() {
            merge_child(
                closures
                    .get_mut(&parent)
                    .ok_or(RepositoryError::CorruptState)?,
                &child_closure,
            )?;
            let remaining = remaining_children
                .get_mut(&parent)
                .ok_or(RepositoryError::CorruptState)?;
            *remaining = remaining
                .checked_sub(1)
                .ok_or(RepositoryError::CorruptState)?;
            if *remaining == 0 {
                ready.push_back(parent);
            }
        }
    }
    if processed != groups.len() {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(closures)
}

fn merge_child(parent: &mut Closure, child: &Closure) -> Result<(), RepositoryError> {
    for (member, (paths, depth)) in child {
        let inherited_depth = depth
            .checked_add(1)
            .ok_or(RepositoryError::CapacityExceeded)?;
        let entry = parent.entry(*member).or_insert((0, inherited_depth));
        entry.0 = entry
            .0
            .checked_add(*paths)
            .filter(|value| i64::try_from(*value).is_ok())
            .ok_or(RepositoryError::CapacityExceeded)?;
        entry.1 = entry.1.min(inherited_depth);
    }
    Ok(())
}

fn parse_group(value: &[u8]) -> Result<GroupId, RepositoryError> {
    GroupId::from_bytes(parse_identifier(value)?).map_err(|_| RepositoryError::CorruptState)
}

fn parse_principal(value: &[u8]) -> Result<PrincipalId, RepositoryError> {
    PrincipalId::from_bytes(parse_identifier(value)?).map_err(|_| RepositoryError::CorruptState)
}

fn parse_identifier(value: &[u8]) -> Result<[u8; 16], RepositoryError> {
    value.try_into().map_err(|_| RepositoryError::CorruptState)
}

fn to_i64(value: u64) -> Result<i64, RepositoryError> {
    i64::try_from(value).map_err(|_| RepositoryError::CapacityExceeded)
}
