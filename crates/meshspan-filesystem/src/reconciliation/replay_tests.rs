// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    BranchId, FileVersionId, NamespaceCommitId, ObjectId, ObjectRevisionId, OperationId, VolumeId,
};

use super::{
    NamespaceReplayBase, NamespaceReplayDisposition, NamespaceReplayEntry, plan_namespace_replay,
};
use crate::{
    BranchMutation, BranchMutationIntent, DirectoryEntryKind, DirectoryRevisionTransition,
    NamespaceLimits, NamespacePath, ReconciliationCommit, ReconciliationCommitPayload,
    ReconciliationFrontier, ReconciliationLimits, plan_reconciliation,
};

#[test]
fn distinct_and_conflicting_creates_are_delivery_order_independent()
-> Result<(), Box<dyn std::error::Error>> {
    let mut commits = vec![
        commit(1, 1, &[], 1, 10)?,
        commit(2, 2, &[1], 2, 20)?,
        commit(3, 3, &[1], 3, 30)?,
    ];
    let distinct = vec![
        file_intent(3, &["beta"], 31, None, 41)?,
        file_intent(2, &["alpha"], 30, None, 40)?,
    ];
    bind_intents(&mut commits, &distinct);
    let causal = plan_reconciliation(
        &commits,
        &frontier(1, &[3, 2])?,
        ReconciliationLimits::DEFAULT,
    )?;
    let base = NamespaceReplayBase {
        root_object_revision_id: Some(revision(10)?),
        entries: Vec::new(),
    };
    let first = plan_namespace_replay(&causal, &commits, &distinct, &base)?;
    let mut reversed_commits = commits.clone();
    reversed_commits.reverse();
    let mut reversed_intents = distinct.clone();
    reversed_intents.reverse();
    let second = plan_namespace_replay(&causal, &reversed_commits, &reversed_intents, &base)?;
    assert_eq!(first, second);
    assert!(
        first
            .actions()
            .iter()
            .all(|action| action.disposition == NamespaceReplayDisposition::Applied)
    );

    let conflicts = vec![
        file_intent(3, &["Report"], 31, None, 41)?,
        file_intent(2, &["report"], 30, None, 40)?,
    ];
    let mut conflict_commits = commits.clone();
    bind_intents(&mut conflict_commits, &conflicts);
    let conflict_causal = plan_reconciliation(
        &conflict_commits,
        &frontier(1, &[3, 2])?,
        ReconciliationLimits::DEFAULT,
    )?;
    let conflict = plan_namespace_replay(&conflict_causal, &conflict_commits, &conflicts, &base)?;
    assert_eq!(
        conflict.actions()[0].disposition,
        NamespaceReplayDisposition::Applied
    );
    assert_eq!(
        conflict.actions()[1].disposition,
        NamespaceReplayDisposition::Recovered
    );
    assert_eq!(
        conflict.actions()[0].target_path.components()[0].display(),
        "report"
    );
    assert!(
        conflict.actions()[1].target_path.components()[0]
            .display()
            .contains("recovered")
    );
    assert_ne!(
        conflict.actions()[0].target_path,
        conflict.actions()[1].target_path
    );
    Ok(())
}

#[test]
fn concurrent_file_loser_and_its_later_edit_follow_one_recovered_copy()
-> Result<(), Box<dyn std::error::Error>> {
    let mut commits = vec![
        commit(1, 1, &[], 1, 10)?,
        commit(2, 2, &[1], 2, 20)?,
        commit(3, 3, &[1], 3, 30)?,
        commit(4, 3, &[3], 4, 40)?,
    ];
    let intents = vec![
        file_intent(4, &["report"], 30, Some(32), 33)?,
        file_intent(2, &["report"], 30, Some(31), 34)?,
        file_intent(3, &["report"], 30, Some(31), 32)?,
    ];
    bind_intents(&mut commits, &intents);
    let causal = plan_reconciliation(
        &commits,
        &frontier(1, &[4, 2])?,
        ReconciliationLimits::DEFAULT,
    )?;
    let base = NamespaceReplayBase {
        root_object_revision_id: Some(revision(10)?),
        entries: vec![entry(&["report"], 30, 31, DirectoryEntryKind::File)?],
    };
    let replay = plan_namespace_replay(&causal, &commits, &intents, &base)?;
    assert_eq!(replay.actions().len(), 3);
    let winner = &replay.actions()[0];
    let recovered = &replay.actions()[1];
    let recovered_edit = &replay.actions()[2];
    assert_eq!(winner.disposition, NamespaceReplayDisposition::Applied);
    assert_eq!(recovered.disposition, NamespaceReplayDisposition::Recovered);
    assert_eq!(
        recovered_edit.disposition,
        NamespaceReplayDisposition::Recovered
    );
    assert_eq!(recovered.target_path, recovered_edit.target_path);
    assert_eq!(recovered.target_object_id, recovered_edit.target_object_id);
    assert_ne!(recovered.target_object_id, recovered.source_object_id);
    assert_ne!(
        recovered.target_file_version_id,
        match recovered.mutation {
            BranchMutation::File { version_id } => Some(version_id),
            BranchMutation::CreateDirectory => None,
        }
    );
    assert!(recovered.target_publication_operation_id.is_some());
    assert_eq!(
        recovered_edit.target_prior_object_revision_id,
        Some(recovered.target_object_revision_id)
    );
    assert_ne!(
        recovered.target_file_version_id,
        recovered_edit.target_file_version_id
    );
    assert_ne!(
        recovered.target_object_revision_id,
        recovered_edit.target_object_revision_id
    );
    Ok(())
}

#[test]
fn descendants_follow_a_conflicting_directory_to_its_recovered_path()
-> Result<(), Box<dyn std::error::Error>> {
    let mut commits = vec![
        commit(1, 1, &[], 1, 10)?,
        commit(2, 2, &[1], 2, 20)?,
        commit(3, 3, &[1], 3, 30)?,
        commit(4, 3, &[3], 4, 40)?,
    ];
    let winning_directory = directory_intent(2, &["docs"], 50, 60)?;
    let recovered_directory = directory_intent(3, &["DOCS"], 51, 61)?;
    let child = BranchMutationIntent {
        commit_id: commit_id(4)?,
        path: path(&["docs", "notes.txt"])?,
        ancestors: vec![DirectoryRevisionTransition::new(
            object(51)?,
            revision(61)?,
            revision(62)?,
        )?],
        object_id: object(52)?,
        object_revision_id: revision(63)?,
        prior_object_revision_id: None,
        entry_generation: 1,
        mutation: BranchMutation::File {
            version_id: version(70)?,
        },
    };
    bind_intents(
        &mut commits,
        &[
            child.clone(),
            recovered_directory.clone(),
            winning_directory.clone(),
        ],
    );
    let causal = plan_reconciliation(
        &commits,
        &frontier(1, &[2, 4])?,
        ReconciliationLimits::DEFAULT,
    )?;
    let replay = plan_namespace_replay(
        &causal,
        &commits,
        &[child, recovered_directory, winning_directory],
        &NamespaceReplayBase {
            root_object_revision_id: Some(revision(10)?),
            entries: Vec::new(),
        },
    )?;
    let recovered = &replay.actions()[1];
    let descendant = &replay.actions()[2];
    assert_eq!(recovered.disposition, NamespaceReplayDisposition::Recovered);
    assert_eq!(
        descendant.target_path.components()[0],
        recovered.target_path.components()[0]
    );
    assert_eq!(
        descendant.target_path.components()[1].display(),
        "notes.txt"
    );
    assert_eq!(descendant.target_ancestors.len(), 1);
    assert_eq!(descendant.target_ancestors[0].object_id(), object(51)?);
    assert_eq!(
        descendant.target_ancestors[0].expected_revision_id(),
        revision(61)?
    );
    assert_eq!(
        descendant.target_ancestors[0].new_revision_id(),
        revision(62)?
    );
    Ok(())
}

#[test]
fn nested_edits_rebase_over_a_newer_converged_directory_revision()
-> Result<(), Box<dyn std::error::Error>> {
    let mut commits = vec![
        commit(1, 1, &[], 1, 10)?,
        commit(2, 1, &[1], 2, 20)?,
        commit(3, 2, &[1], 3, 30)?,
    ];
    let intent = BranchMutationIntent {
        commit_id: commit_id(3)?,
        path: path(&["docs", "offline.txt"])?,
        ancestors: vec![DirectoryRevisionTransition::new(
            object(50)?,
            revision(60)?,
            revision(62)?,
        )?],
        object_id: object(51)?,
        object_revision_id: revision(63)?,
        prior_object_revision_id: None,
        entry_generation: 1,
        mutation: BranchMutation::File {
            version_id: version(70)?,
        },
    };
    bind_intents(&mut commits, std::slice::from_ref(&intent));
    let causal = plan_reconciliation(&commits, &frontier(2, &[3])?, ReconciliationLimits::DEFAULT)?;
    let replay = plan_namespace_replay(
        &causal,
        &commits,
        &[intent],
        &NamespaceReplayBase {
            root_object_revision_id: Some(revision(20)?),
            entries: vec![entry(&["docs"], 50, 61, DirectoryEntryKind::Directory)?],
        },
    )?;

    let action = &replay.actions()[0];
    assert_eq!(action.target_path, path(&["docs", "offline.txt"])?);
    assert_eq!(action.target_ancestors.len(), 1);
    assert_eq!(
        action.target_ancestors[0].expected_revision_id(),
        revision(61)?
    );
    assert_ne!(action.target_ancestors[0].new_revision_id(), revision(62)?);
    Ok(())
}

#[test]
fn merge_commits_are_causal_markers_not_namespace_mutations()
-> Result<(), Box<dyn std::error::Error>> {
    let mut commits = vec![
        commit(1, 1, &[], 1, 10)?,
        commit(2, 2, &[1], 2, 20)?,
        commit(3, 3, &[1], 3, 30)?,
        commit(4, 1, &[2, 3], 4, 40)?,
        commit(5, 1, &[4], 5, 50)?,
    ];
    commits[3].payload = ReconciliationCommitPayload::Merge {
        replay_digest: [44; 32],
    };
    let intents = vec![
        file_intent(2, &["home"], 40, None, 60)?,
        file_intent(3, &["office"], 41, None, 61)?,
        file_intent(5, &["after-merge"], 42, None, 62)?,
    ];
    bind_intents(&mut commits, &intents);
    let causal = plan_reconciliation(&commits, &frontier(1, &[5])?, ReconciliationLimits::DEFAULT)?;
    let replay = plan_namespace_replay(
        &causal,
        &commits,
        &intents,
        &NamespaceReplayBase {
            root_object_revision_id: Some(revision(10)?),
            entries: Vec::new(),
        },
    )?;

    assert_eq!(replay.actions().len(), 3);
    let merge_id = commit_id(4)?;
    assert!(
        replay
            .actions()
            .iter()
            .all(|action| action.commit_id != merge_id)
    );
    Ok(())
}

#[test]
fn malformed_intents_and_incomplete_nested_bases_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let mut commits = vec![commit(1, 1, &[], 1, 10)?, commit(2, 2, &[1], 2, 20)?];
    let file = file_intent(2, &["file"], 51, None, 62)?;
    bind_intents(&mut commits, std::slice::from_ref(&file));
    let causal = plan_reconciliation(&commits, &frontier(1, &[2])?, ReconciliationLimits::DEFAULT)?;
    assert!(matches!(
        plan_namespace_replay(
            &causal,
            &commits,
            &[],
            &NamespaceReplayBase {
                root_object_revision_id: Some(revision(10)?),
                entries: Vec::new(),
            },
        ),
        Err(crate::ReconciliationError::MissingIntent)
    ));
    let mut substituted = commits.clone();
    substituted[1].root_object_revision_id = revision(99)?;
    assert!(matches!(
        plan_namespace_replay(
            &causal,
            &substituted,
            std::slice::from_ref(&file),
            &NamespaceReplayBase {
                root_object_revision_id: Some(revision(10)?),
                entries: Vec::new(),
            },
        ),
        Err(crate::ReconciliationError::InvalidInput)
    ));
    let nested = BranchMutationIntent {
        commit_id: commit_id(2)?,
        path: path(&["missing", "file"])?,
        ancestors: vec![DirectoryRevisionTransition::new(
            object(50)?,
            revision(60)?,
            revision(61)?,
        )?],
        object_id: object(51)?,
        object_revision_id: revision(62)?,
        prior_object_revision_id: None,
        entry_generation: 1,
        mutation: BranchMutation::File {
            version_id: version(70)?,
        },
    };
    let mut substituted_intent = file.clone();
    substituted_intent.path = path(&["other"])?;
    assert!(matches!(
        plan_namespace_replay(
            &causal,
            &commits,
            &[substituted_intent],
            &NamespaceReplayBase {
                root_object_revision_id: Some(revision(10)?),
                entries: Vec::new(),
            },
        ),
        Err(crate::ReconciliationError::InvalidInput)
    ));
    let mut nested_commits = commits.clone();
    bind_intents(&mut nested_commits, std::slice::from_ref(&nested));
    let nested_causal = plan_reconciliation(
        &nested_commits,
        &frontier(1, &[2])?,
        ReconciliationLimits::DEFAULT,
    )?;
    assert!(matches!(
        plan_namespace_replay(
            &nested_causal,
            &nested_commits,
            &[nested],
            &NamespaceReplayBase {
                root_object_revision_id: Some(revision(10)?),
                entries: Vec::new(),
            },
        ),
        Err(crate::ReconciliationError::MissingBaseEntry)
    ));
    Ok(())
}

fn commit(
    id: u8,
    branch: u8,
    parents: &[u8],
    operation: u8,
    root_revision: u8,
) -> Result<ReconciliationCommit, Box<dyn std::error::Error>> {
    Ok(ReconciliationCommit {
        commit_id: commit_id(id)?,
        branch_id: BranchId::from_bytes([branch; 16])?,
        volume_id: VolumeId::from_bytes([90; 16])?,
        root_object_id: object(91)?,
        root_object_revision_id: revision(root_revision)?,
        parents: parents
            .iter()
            .map(|parent| commit_id(*parent))
            .collect::<Result<_, _>>()?,
        operation_id: OperationId::from_bytes([operation; 16])?,
        request_digest: [id; 32],
        payload: ReconciliationCommitPayload::Mutation {
            intent_digest: [id; 32],
        },
    })
}

fn bind_intents(commits: &mut [ReconciliationCommit], intents: &[BranchMutationIntent]) {
    for intent in intents {
        if let Some(commit) = commits
            .iter_mut()
            .find(|commit| commit.commit_id == intent.commit_id)
        {
            commit.payload = ReconciliationCommitPayload::Mutation {
                intent_digest: intent.digest(),
            };
        }
    }
}

fn file_intent(
    commit: u8,
    components: &[&str],
    object_id: u8,
    prior_revision: Option<u8>,
    new_revision: u8,
) -> Result<BranchMutationIntent, Box<dyn std::error::Error>> {
    Ok(BranchMutationIntent {
        commit_id: commit_id(commit)?,
        path: path(components)?,
        ancestors: Vec::new(),
        object_id: object(object_id)?,
        object_revision_id: revision(new_revision)?,
        prior_object_revision_id: prior_revision.map(revision).transpose()?,
        entry_generation: 1,
        mutation: BranchMutation::File {
            version_id: version(new_revision)?,
        },
    })
}

fn directory_intent(
    commit: u8,
    components: &[&str],
    object_id: u8,
    new_revision: u8,
) -> Result<BranchMutationIntent, Box<dyn std::error::Error>> {
    Ok(BranchMutationIntent {
        commit_id: commit_id(commit)?,
        path: path(components)?,
        ancestors: Vec::new(),
        object_id: object(object_id)?,
        object_revision_id: revision(new_revision)?,
        prior_object_revision_id: None,
        entry_generation: 1,
        mutation: BranchMutation::CreateDirectory,
    })
}

fn entry(
    components: &[&str],
    object_id: u8,
    object_revision: u8,
    kind: DirectoryEntryKind,
) -> Result<NamespaceReplayEntry, Box<dyn std::error::Error>> {
    Ok(NamespaceReplayEntry {
        path: path(components)?,
        object_id: object(object_id)?,
        object_revision_id: revision(object_revision)?,
        kind,
        entry_generation: 1,
    })
}

fn frontier(
    converged: u8,
    eligible: &[u8],
) -> Result<ReconciliationFrontier, Box<dyn std::error::Error>> {
    Ok(ReconciliationFrontier {
        converged_head: Some(commit_id(converged)?),
        eligible_heads: eligible
            .iter()
            .map(|head| commit_id(*head))
            .collect::<Result<_, _>>()?,
    })
}

fn path(components: &[&str]) -> Result<NamespacePath, Box<dyn std::error::Error>> {
    Ok(NamespacePath::from_components(
        components.iter().copied(),
        NamespaceLimits::PORTABLE,
    )?)
}

fn commit_id(value: u8) -> Result<NamespaceCommitId, meshspan_domain::IdentifierError> {
    NamespaceCommitId::from_bytes([value; 16])
}

fn object(value: u8) -> Result<ObjectId, meshspan_domain::IdentifierError> {
    ObjectId::from_bytes([value; 16])
}

fn revision(value: u8) -> Result<ObjectRevisionId, meshspan_domain::IdentifierError> {
    ObjectRevisionId::from_bytes([value; 16])
}

fn version(value: u8) -> Result<FileVersionId, meshspan_domain::IdentifierError> {
    FileVersionId::from_bytes([value; 16])
}
