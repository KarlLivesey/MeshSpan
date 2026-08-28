// SPDX-License-Identifier: GPL-2.0-only

use std::collections::BTreeSet;

use meshspan_domain::{NodeId, QuorumPlanId};

use super::{
    QuorumFamily, QuorumPlanError, QuorumPlanSpec, QuorumPredicate, WeightedVoter, compile_plan,
    flat_plan, prove_joint_transition,
};

#[test]
fn flat_defaults_for_every_one_to_nine_voter_count_match_independent_oracle()
-> Result<(), Box<dyn std::error::Error>> {
    for count in 1..=9 {
        let voters = voters(1, count)?;
        let spec = flat_plan(
            QuorumPlanId::from_bytes([u8::try_from(100 + count)?; 16])?,
            u64::try_from(count)?,
            voters.clone(),
            BTreeSet::new(),
        )?;
        let compiled = compile_plan(spec)?;
        let election_threshold = count / 2 + 1;
        let write_threshold = count - election_threshold + 1;
        assert_eq!(
            compiled
                .family(QuorumFamily::Election)
                .minimal_quorums()
                .len(),
            choose(count, election_threshold)
        );
        assert_eq!(
            compiled
                .family(QuorumFamily::Commit)
                .minimal_quorums()
                .len(),
            choose(count, write_threshold)
        );
        assert_flat_truth_table(&compiled, &voters, election_threshold, write_threshold);
    }
    Ok(())
}

#[test]
fn four_voters_use_three_for_election_and_two_for_commit_and_read()
-> Result<(), Box<dyn std::error::Error>> {
    let voters = voters(1, 4)?;
    let compiled = compile_plan(flat_plan(
        QuorumPlanId::from_bytes([20; 16])?,
        1,
        voters.clone(),
        BTreeSet::new(),
    )?)?;
    let two: BTreeSet<NodeId> = voters.iter().take(2).copied().collect();
    let three: BTreeSet<NodeId> = voters.iter().take(3).copied().collect();
    assert!(!compiled.satisfies(QuorumFamily::Election, &two));
    assert!(compiled.satisfies(QuorumFamily::Election, &three));
    assert!(compiled.satisfies(QuorumFamily::Commit, &two));
    assert!(compiled.satisfies(QuorumFamily::Read, &two));
    Ok(())
}

#[test]
fn hierarchical_and_weighted_plans_compile_without_double_counting()
-> Result<(), Box<dyn std::error::Error>> {
    let hierarchy_voters = voters(1, 6)?;
    let ordered: Vec<NodeId> = hierarchy_voters.iter().copied().collect();
    let buildings: Vec<QuorumPredicate> = ordered
        .chunks(2)
        .map(|building| QuorumPredicate::AtLeast {
            threshold: 2,
            children: building
                .iter()
                .copied()
                .map(QuorumPredicate::Voter)
                .collect(),
        })
        .collect();
    let hierarchy = QuorumPredicate::AtLeast {
        threshold: 2,
        children: buildings,
    };
    let hierarchical = compile_plan(spec(
        30,
        1,
        hierarchy_voters,
        hierarchy.clone(),
        hierarchy.clone(),
        hierarchy,
    )?)?;
    assert_eq!(
        hierarchical
            .family(QuorumFamily::Election)
            .minimal_quorums()
            .len(),
        3
    );

    let weighted_voters = voters(20, 3)?;
    let weighted_order: Vec<NodeId> = weighted_voters.iter().copied().collect();
    let weighted = QuorumPredicate::WeightedAtLeast {
        threshold: 3,
        voters: vec![
            WeightedVoter {
                voter: weighted_order[0],
                weight: 2,
            },
            WeightedVoter {
                voter: weighted_order[1],
                weight: 1,
            },
            WeightedVoter {
                voter: weighted_order[2],
                weight: 1,
            },
        ],
    };
    let compiled = compile_plan(spec(
        31,
        1,
        weighted_voters,
        weighted.clone(),
        weighted.clone(),
        weighted,
    )?)?;
    assert_eq!(
        compiled
            .family(QuorumFamily::Election)
            .minimal_quorums()
            .len(),
        2
    );
    Ok(())
}

#[test]
fn unsafe_or_ambiguous_predicates_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let voters = voters(1, 3)?;
    let ordered: Vec<NodeId> = voters.iter().copied().collect();
    let election = QuorumPredicate::AtLeast {
        threshold: 2,
        children: ordered
            .iter()
            .copied()
            .map(QuorumPredicate::Voter)
            .collect(),
    };
    let unsafe_spec = spec(
        40,
        1,
        voters.clone(),
        election.clone(),
        QuorumPredicate::Voter(ordered[0]),
        election.clone(),
    )?;
    assert_eq!(
        compile_plan(unsafe_spec),
        Err(QuorumPlanError::UnsafeIntersection)
    );
    let duplicate = QuorumPredicate::AtLeast {
        threshold: 1,
        children: vec![
            QuorumPredicate::Voter(ordered[0]),
            QuorumPredicate::Voter(ordered[0]),
        ],
    };
    assert_eq!(
        compile_plan(spec(
            41,
            1,
            voters,
            duplicate.clone(),
            duplicate.clone(),
            duplicate,
        )?),
        Err(QuorumPlanError::InvalidPredicate)
    );
    Ok(())
}

#[test]
fn proof_digest_is_canonical_and_joint_transition_is_epoch_guarded()
-> Result<(), Box<dyn std::error::Error>> {
    let first_three = voters(1, 3)?;
    let plan = flat_plan(
        QuorumPlanId::from_bytes([50; 16])?,
        1,
        first_three.clone(),
        BTreeSet::new(),
    )?;
    let mut reversed = plan.clone();
    reverse_children(&mut reversed.election);
    reverse_children(&mut reversed.commit);
    reverse_children(&mut reversed.read);
    let old = compile_plan(plan)?;
    let reordered = compile_plan(reversed)?;
    assert_eq!(old.proof_digest(), reordered.proof_digest());

    let new = compile_plan(flat_plan(
        QuorumPlanId::from_bytes([51; 16])?,
        2,
        voters(1, 4)?,
        BTreeSet::new(),
    )?)?;
    let transition = prove_joint_transition(&old, &new)?;
    assert_eq!((transition.old_epoch, transition.new_epoch), (1, 2));
    assert_eq!(
        prove_joint_transition(&new, &old),
        Err(QuorumPlanError::UnsafeTransition)
    );
    Ok(())
}

fn assert_flat_truth_table(
    plan: &super::CompiledQuorumPlan,
    voters: &BTreeSet<NodeId>,
    election_threshold: usize,
    write_threshold: usize,
) {
    let ordered: Vec<NodeId> = voters.iter().copied().collect();
    let set_count = 1_u16 << ordered.len();
    for mask in 0..set_count {
        let acknowledged: BTreeSet<NodeId> = ordered
            .iter()
            .enumerate()
            .filter_map(|(index, voter)| ((mask & (1_u16 << index)) != 0).then_some(*voter))
            .collect();
        assert_eq!(
            plan.satisfies(QuorumFamily::Election, &acknowledged),
            acknowledged.len() >= election_threshold
        );
        assert_eq!(
            plan.satisfies(QuorumFamily::Commit, &acknowledged),
            acknowledged.len() >= write_threshold
        );
        assert_eq!(
            plan.satisfies(QuorumFamily::Read, &acknowledged),
            acknowledged.len() >= write_threshold
        );
    }
}

fn voters(start: u8, count: usize) -> Result<BTreeSet<NodeId>, Box<dyn std::error::Error>> {
    (0..count)
        .map(|offset| {
            let byte = start
                .checked_add(u8::try_from(offset)?)
                .ok_or("fixture voter overflow")?;
            NodeId::from_bytes([byte; 16]).map_err(Into::into)
        })
        .collect()
}

fn spec(
    plan_byte: u8,
    epoch: u64,
    voters: BTreeSet<NodeId>,
    election: QuorumPredicate,
    commit: QuorumPredicate,
    read: QuorumPredicate,
) -> Result<QuorumPlanSpec, Box<dyn std::error::Error>> {
    Ok(QuorumPlanSpec {
        plan_id: QuorumPlanId::from_bytes([plan_byte; 16])?,
        format_version: 1,
        membership_epoch: epoch,
        learners: BTreeSet::new(),
        eligible_leaders: voters.clone(),
        voters,
        election,
        commit,
        read,
    })
}

fn choose(total: usize, selected: usize) -> usize {
    let selected = selected.min(total - selected);
    (0..selected).fold(1_usize, |value, index| {
        value * (total - index) / (index + 1)
    })
}

fn reverse_children(predicate: &mut QuorumPredicate) {
    match predicate {
        QuorumPredicate::AtLeast { children, .. } | QuorumPredicate::All { children } => {
            children.reverse();
            children.iter_mut().for_each(reverse_children);
        }
        QuorumPredicate::WeightedAtLeast { voters, .. } => voters.reverse(),
        QuorumPredicate::Voter(_) => {}
    }
}
