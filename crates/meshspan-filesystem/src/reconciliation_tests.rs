// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    BranchId, NamespaceCommitId, ObjectId, ObjectRevisionId, OperationId, VolumeId,
};

use super::{
    ReconciliationCommit, ReconciliationCommitPayload, ReconciliationError, ReconciliationFrontier,
    ReconciliationLimits, plan_reconciliation,
};

#[test]
fn every_delivery_order_produces_one_causal_plan() -> Result<(), Box<dyn std::error::Error>> {
    let root = commit(1, 1, &[], 10, 10)?;
    let home = commit(2, 2, &[1], 30, 20)?;
    let office = commit(3, 3, &[1], 20, 30)?;
    let home_child = commit(4, 2, &[2], 5, 40)?;
    let expected = vec![office.commit_id, home.commit_id, home_child.commit_id];
    let expected_parents = [office.commit_id, home_child.commit_id];
    let inputs = [root, home, office, home_child];
    let permutations = [
        [0, 1, 2, 3],
        [3, 2, 1, 0],
        [1, 3, 0, 2],
        [2, 0, 3, 1],
        [0, 2, 1, 3],
        [3, 1, 2, 0],
    ];
    let mut expected_digest = None;
    for permutation in permutations {
        let commits = permutation.map(|index| inputs[index].clone());
        let plan = plan_reconciliation(
            &commits,
            &frontier(Some(1), &[4, 3])?,
            ReconciliationLimits::DEFAULT,
        )?;
        assert_eq!(plan.ordered_commits(), expected);
        assert_eq!(plan.merge_parents(), expected_parents);
        if let Some(digest) = expected_digest {
            assert_eq!(plan.digest(), digest);
        } else {
            expected_digest = Some(plan.digest());
        }
    }
    Ok(())
}

#[test]
fn included_and_branch_duplicate_operations_are_applied_at_most_once()
-> Result<(), Box<dyn std::error::Error>> {
    let root = commit(1, 1, &[], 10, 7)?;
    let exact_replay = commit(2, 2, &[1], 10, 7)?;
    let plan = plan_reconciliation(
        &[root, exact_replay.clone()],
        &frontier(Some(1), &[2])?,
        ReconciliationLimits::DEFAULT,
    )?;
    assert!(plan.ordered_commits().is_empty());
    assert_eq!(plan.merge_parents(), [exact_replay.commit_id]);

    let duplicate_a = commit(3, 3, &[1], 20, 8)?;
    let duplicate_b = commit(4, 4, &[1], 20, 8)?;
    let plan = plan_reconciliation(
        &[commit(1, 1, &[], 10, 7)?, duplicate_a.clone(), duplicate_b],
        &frontier(Some(1), &[4, 3])?,
        ReconciliationLimits::DEFAULT,
    )?;
    assert_eq!(plan.ordered_commits(), [duplicate_a.commit_id]);
    Ok(())
}

#[test]
fn digest_binds_the_complete_validated_causal_graph() -> Result<(), Box<dyn std::error::Error>> {
    let root = commit(1, 1, &[], 10, 7)?;
    let child = commit(2, 2, &[1], 20, 8)?;
    let original = plan_reconciliation(
        &[root.clone(), child.clone()],
        &frontier(Some(1), &[2])?,
        ReconciliationLimits::DEFAULT,
    )?;
    let mut changed = child;
    changed.root_object_revision_id = ObjectRevisionId::from_bytes([99; 16])?;
    let changed = plan_reconciliation(
        &[root, changed],
        &frontier(Some(1), &[2])?,
        ReconciliationLimits::DEFAULT,
    )?;
    assert_ne!(original.digest(), changed.digest());
    Ok(())
}

#[test]
fn hostile_graphs_and_limits_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let root = commit(1, 1, &[], 10, 1)?;
    let mut conflicting = commit(2, 2, &[1], 10, 2)?;
    assert_eq!(
        plan_reconciliation(
            &[root.clone(), conflicting.clone()],
            &frontier(Some(1), &[2])?,
            ReconciliationLimits::DEFAULT,
        ),
        Err(ReconciliationError::OperationConflict)
    );

    conflicting.operation_id = OperationId::from_bytes([11; 16])?;
    conflicting.parents = vec![NamespaceCommitId::from_bytes([9; 16])?];
    assert_eq!(
        plan_reconciliation(
            &[root.clone(), conflicting],
            &frontier(Some(1), &[2])?,
            ReconciliationLimits::DEFAULT,
        ),
        Err(ReconciliationError::MissingCommit)
    );

    let mut first = commit(1, 1, &[2], 10, 1)?;
    let second = commit(2, 2, &[1], 11, 2)?;
    assert_eq!(
        plan_reconciliation(
            &[first.clone(), second],
            &frontier(None, &[2])?,
            ReconciliationLimits::DEFAULT,
        ),
        Err(ReconciliationError::Cycle)
    );

    first.parents.clear();
    let unrelated = commit(3, 3, &[], 12, 3)?;
    assert_eq!(
        plan_reconciliation(
            &[first.clone(), commit(2, 2, &[1], 11, 2)?, unrelated],
            &frontier(Some(1), &[2])?,
            ReconciliationLimits::DEFAULT,
        ),
        Err(ReconciliationError::UnreachableCommit)
    );

    assert_eq!(
        plan_reconciliation(
            &[first, commit(2, 2, &[1], 11, 2)?],
            &frontier(Some(1), &[2])?,
            ReconciliationLimits::new(1, 1, 1)?,
        ),
        Err(ReconciliationError::BoundsExceeded)
    );
    Ok(())
}

fn commit(
    commit: u8,
    branch: u8,
    parents: &[u8],
    operation: u8,
    request: u8,
) -> Result<ReconciliationCommit, Box<dyn std::error::Error>> {
    Ok(ReconciliationCommit {
        commit_id: NamespaceCommitId::from_bytes([commit; 16])?,
        branch_id: BranchId::from_bytes([branch; 16])?,
        volume_id: VolumeId::from_bytes([50; 16])?,
        root_object_id: ObjectId::from_bytes([51; 16])?,
        root_object_revision_id: ObjectRevisionId::from_bytes([commit + 60; 16])?,
        parents: parents
            .iter()
            .map(|parent| NamespaceCommitId::from_bytes([*parent; 16]))
            .collect::<Result<_, _>>()?,
        operation_id: OperationId::from_bytes([operation; 16])?,
        request_digest: [request; 32],
        payload: ReconciliationCommitPayload::Mutation {
            intent_digest: [commit; 32],
        },
    })
}

fn frontier(
    converged: Option<u8>,
    eligible: &[u8],
) -> Result<ReconciliationFrontier, Box<dyn std::error::Error>> {
    Ok(ReconciliationFrontier {
        converged_head: converged
            .map(|value| NamespaceCommitId::from_bytes([value; 16]))
            .transpose()?,
        eligible_heads: eligible
            .iter()
            .map(|value| NamespaceCommitId::from_bytes([*value; 16]))
            .collect::<Result<_, _>>()?,
    })
}
