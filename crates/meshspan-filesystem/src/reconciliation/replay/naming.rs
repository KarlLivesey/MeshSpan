// SPDX-License-Identifier: GPL-2.0-only

//! Deterministic recovered names, paths and derived immutable identities.

use meshspan_domain::{NamespaceCommitId, ObjectId, ObjectRevisionId};

use super::super::ReconciliationError;
use crate::{CompatibilityProfile, NamespaceComponent, NamespaceLimits, NamespacePath};

pub(super) fn recovered_path(
    source: &NamespacePath,
    commit_id: NamespaceCommitId,
    entry_count: usize,
    mut occupied: impl FnMut(&NamespacePath) -> bool,
) -> Result<NamespacePath, ReconciliationError> {
    for counter in 0..=entry_count {
        let component = recovered_component(
            source
                .components()
                .last()
                .ok_or(ReconciliationError::InvalidInput)?,
            commit_id,
            counter,
        )?;
        let mut sibling = source.components().to_vec();
        if let Some(leaf) = sibling.last_mut() {
            *leaf = component.clone();
        }
        if let Ok(path) = NamespacePath::from_stored_components(sibling)
            && !occupied(&path)
        {
            return Ok(path);
        }
        if source.components().len() == 1 {
            let fallback = NamespacePath::from_stored_components(vec![component])
                .map_err(|_| ReconciliationError::BoundsExceeded)?;
            if !occupied(&fallback) {
                return Ok(fallback);
            }
        }
    }
    Err(ReconciliationError::BoundsExceeded)
}

fn recovered_component(
    source: &NamespaceComponent,
    commit_id: NamespaceCommitId,
    counter: usize,
) -> Result<NamespaceComponent, ReconciliationError> {
    let suffix = if counter == 0 {
        format!(" (recovered {commit_id})")
    } else {
        format!(" (recovered {commit_id}-{counter})")
    };
    let limit = NamespaceLimits::INTERNAL.maximum_component_bytes();
    let available = limit.saturating_sub(suffix.len());
    let mut end = source.display().len().min(available);
    while !source.display().is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    let display = format!("{}{suffix}", &source.display()[..end]);
    NamespaceComponent::new(
        &display,
        NamespaceLimits::new(CompatibilityProfile::Extended, limit, 1_024, 1_048_576)
            .map_err(|_| ReconciliationError::BoundsExceeded)?,
    )
    .map_err(|_| ReconciliationError::BoundsExceeded)
}

pub(super) fn path_prefix(
    path: &NamespacePath,
    length: usize,
) -> Result<NamespacePath, ReconciliationError> {
    NamespacePath::from_stored_components(path.components()[..length].to_vec())
        .map_err(|_| ReconciliationError::BoundsExceeded)
}

pub(super) fn path_key(path: &NamespacePath) -> Vec<String> {
    path.components()
        .iter()
        .map(|component| component.canonical().to_owned())
        .collect()
}

pub(super) fn derived_object(
    plan_digest: [u8; 32],
    commit_id: NamespaceCommitId,
    source: ObjectId,
) -> Result<ObjectId, ReconciliationError> {
    let bytes = derived_identifier(
        b"meshspan.filesystem.recovered-object.v1\0",
        plan_digest,
        commit_id,
        source.as_bytes(),
        0,
    );
    ObjectId::from_bytes(bytes).map_err(|_| ReconciliationError::InvalidInput)
}

pub(super) fn derived_revision(
    plan_digest: [u8; 32],
    commit_id: NamespaceCommitId,
    source: ObjectRevisionId,
    ordinal: u32,
) -> Result<ObjectRevisionId, ReconciliationError> {
    let bytes = derived_identifier(
        b"meshspan.filesystem.recovered-revision.v1\0",
        plan_digest,
        commit_id,
        source.as_bytes(),
        ordinal,
    );
    ObjectRevisionId::from_bytes(bytes).map_err(|_| ReconciliationError::InvalidInput)
}

fn derived_identifier(
    domain: &[u8],
    plan_digest: [u8; 32],
    commit_id: NamespaceCommitId,
    source: [u8; 16],
    ordinal: u32,
) -> [u8; 16] {
    let mut digest = blake3::Hasher::new();
    digest.update(domain);
    digest.update(&plan_digest);
    digest.update(&commit_id.as_bytes());
    digest.update(&source);
    digest.update(&ordinal.to_be_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.finalize().as_bytes()[..16]);
    if bytes == [0; 16] {
        bytes[15] = 1;
    }
    bytes
}
