// SPDX-License-Identifier: GPL-2.0-only

//! Bounded active-plan decoder and independent proof reconstruction.

use std::collections::BTreeSet;

use meshspan_domain::{NodeId, QuorumPlanId};

use super::{
    ActiveQuorumPlan, MAXIMUM_RECORD_BYTES, QuorumPlanRecordError, RECORD_MAGIC, RECORD_VERSION,
};
use crate::{JointQuorumPlan, QuorumPlanSpec, QuorumPredicate, WeightedVoter, compile_plan};

const STABLE_PHASE: u8 = 1;
const JOINT_PHASE: u8 = 2;
const MAXIMUM_IDENTIFIERS: usize = 256;
const MAXIMUM_PREDICATE_NODES: usize = 256;
const MAXIMUM_PREDICATE_DEPTH: usize = 8;

pub(super) fn decode(bytes: &[u8]) -> Result<ActiveQuorumPlan, QuorumPlanRecordError> {
    if bytes.len() > MAXIMUM_RECORD_BYTES {
        return Err(QuorumPlanRecordError::Malformed);
    }
    let mut cursor = Cursor::new(bytes);
    if cursor.take(RECORD_MAGIC.len())? != RECORD_MAGIC || cursor.unsigned_16()? != RECORD_VERSION {
        return Err(QuorumPlanRecordError::Malformed);
    }
    let plan = match cursor.byte()? {
        STABLE_PHASE => ActiveQuorumPlan::Stable(Box::new(compiled_plan(&mut cursor)?)),
        JOINT_PHASE => {
            let old = compiled_plan(&mut cursor)?;
            let new = compiled_plan(&mut cursor)?;
            let joint =
                JointQuorumPlan::new(old, new).map_err(|_| QuorumPlanRecordError::Unsafe)?;
            ActiveQuorumPlan::Joint(Box::new(joint))
        }
        _ => return Err(QuorumPlanRecordError::Malformed),
    };
    if cursor.remaining() != 0 {
        return Err(QuorumPlanRecordError::Malformed);
    }
    Ok(plan)
}

fn compiled_plan(
    cursor: &mut Cursor<'_>,
) -> Result<crate::CompiledQuorumPlan, QuorumPlanRecordError> {
    let plan_id = QuorumPlanId::from_bytes(cursor.identifier_bytes()?)
        .map_err(|_| QuorumPlanRecordError::Malformed)?;
    let format_version = cursor.unsigned_16()?;
    let membership_epoch = cursor.unsigned_64()?;
    let voters = identifiers(cursor)?;
    let learners = identifiers(cursor)?;
    let eligible_leaders = identifiers(cursor)?;
    let mut node_count = 0_usize;
    let election = predicate(cursor, 1, &mut node_count)?;
    let commit = predicate(cursor, 1, &mut node_count)?;
    let read = predicate(cursor, 1, &mut node_count)?;
    compile_plan(QuorumPlanSpec {
        plan_id,
        format_version,
        membership_epoch,
        voters,
        learners,
        eligible_leaders,
        election,
        commit,
        read,
    })
    .map_err(|_| QuorumPlanRecordError::Unsafe)
}

fn identifiers(cursor: &mut Cursor<'_>) -> Result<BTreeSet<NodeId>, QuorumPlanRecordError> {
    let count = cursor.bounded_count(MAXIMUM_IDENTIFIERS)?;
    let mut values = BTreeSet::new();
    for _ in 0..count {
        let value = NodeId::from_bytes(cursor.identifier_bytes()?)
            .map_err(|_| QuorumPlanRecordError::Malformed)?;
        if !values.insert(value) {
            return Err(QuorumPlanRecordError::Malformed);
        }
    }
    Ok(values)
}

fn predicate(
    cursor: &mut Cursor<'_>,
    depth: usize,
    node_count: &mut usize,
) -> Result<QuorumPredicate, QuorumPlanRecordError> {
    *node_count = node_count
        .checked_add(1)
        .ok_or(QuorumPlanRecordError::Malformed)?;
    if depth > MAXIMUM_PREDICATE_DEPTH || *node_count > MAXIMUM_PREDICATE_NODES {
        return Err(QuorumPlanRecordError::Malformed);
    }
    match cursor.byte()? {
        1 => voter(cursor),
        2 => at_least(cursor, depth, node_count),
        3 => weighted(cursor),
        4 => Ok(QuorumPredicate::All {
            children: child_predicates(cursor, depth, node_count)?,
        }),
        _ => Err(QuorumPlanRecordError::Malformed),
    }
}

fn voter(cursor: &mut Cursor<'_>) -> Result<QuorumPredicate, QuorumPlanRecordError> {
    let node_id = NodeId::from_bytes(cursor.identifier_bytes()?)
        .map_err(|_| QuorumPlanRecordError::Malformed)?;
    Ok(QuorumPredicate::Voter(node_id))
}

fn at_least(
    cursor: &mut Cursor<'_>,
    depth: usize,
    node_count: &mut usize,
) -> Result<QuorumPredicate, QuorumPlanRecordError> {
    let threshold = cursor.byte()?;
    Ok(QuorumPredicate::AtLeast {
        threshold,
        children: child_predicates(cursor, depth, node_count)?,
    })
}

fn child_predicates(
    cursor: &mut Cursor<'_>,
    depth: usize,
    node_count: &mut usize,
) -> Result<Vec<QuorumPredicate>, QuorumPlanRecordError> {
    let count = cursor.bounded_count(MAXIMUM_PREDICATE_NODES)?;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(predicate(cursor, depth + 1, node_count)?);
    }
    Ok(values)
}

fn weighted(cursor: &mut Cursor<'_>) -> Result<QuorumPredicate, QuorumPlanRecordError> {
    let threshold = cursor.unsigned_32()?;
    let count = cursor.bounded_count(MAXIMUM_IDENTIFIERS)?;
    let mut voters = Vec::with_capacity(count);
    for _ in 0..count {
        let voter = NodeId::from_bytes(cursor.identifier_bytes()?)
            .map_err(|_| QuorumPlanRecordError::Malformed)?;
        voters.push(WeightedVoter {
            voter,
            weight: cursor.unsigned_16()?,
        });
    }
    Ok(QuorumPredicate::WeightedAtLeast { threshold, voters })
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], QuorumPlanRecordError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(QuorumPlanRecordError::Malformed)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(QuorumPlanRecordError::Malformed)?;
        self.position = end;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, QuorumPlanRecordError> {
        Ok(self.take(1)?[0])
    }

    fn unsigned_16(&mut self) -> Result<u16, QuorumPlanRecordError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| QuorumPlanRecordError::Malformed)?,
        ))
    }

    fn unsigned_32(&mut self) -> Result<u32, QuorumPlanRecordError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| QuorumPlanRecordError::Malformed)?,
        ))
    }

    fn unsigned_64(&mut self) -> Result<u64, QuorumPlanRecordError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| QuorumPlanRecordError::Malformed)?,
        ))
    }

    fn identifier_bytes(&mut self) -> Result<[u8; 16], QuorumPlanRecordError> {
        self.take(16)?
            .try_into()
            .map_err(|_| QuorumPlanRecordError::Malformed)
    }

    fn bounded_count(&mut self, maximum: usize) -> Result<usize, QuorumPlanRecordError> {
        let value = usize::from(self.unsigned_16()?);
        if value > maximum {
            Err(QuorumPlanRecordError::Malformed)
        } else {
            Ok(value)
        }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }
}
