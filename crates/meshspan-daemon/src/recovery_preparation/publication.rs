// SPDX-License-Identifier: GPL-2.0-only

//! Deterministic exports from a published preparation; retry verifies rather than replaces bytes.

use super::{RecoveryPreparationError as Error, RecoverySource, workspace::Workspace};
use crate::protected_file::{self, ProtectedFileError, PublishMode};
use meshspan_metadata::{AuthoritativeRepository, RecoveryReplacementPlan};
use sha2::{Digest as _, Sha256};
use std::{
    io::{self, Read as _, Write},
    path::Path,
};

pub(super) fn export(
    repo: &AuthoritativeRepository,
    source: &RecoverySource<'_>,
    plan: &RecoveryReplacementPlan,
    root: &Path,
    workspace: &Workspace,
) -> Result<serde_json::Value, Error> {
    publish_exact(
        workspace,
        root,
        "root.der",
        source.authority.root_certificate_der(),
    )?;
    let mut bundles = Vec::new();
    for node in &plan.nodes {
        let node_id = crate::create_mesh_setup::format_uuid(node.node_id.as_bytes());
        let name = format!("{node_id}.bundle");
        workspace.clean_publication_temporary(&name)?;
        match protected_file::open_read(&root.join(&name)) {
            Ok(mut existing) => {
                let mut expected = DigestWriter(Sha256::new(), 0);
                repo.export_recovery_key_bundle(source.authority, node.node_id, &mut expected)
                    .map_err(|_| Error::Material)?;
                if existing.metadata().map_err(|_| Error::Workspace)?.len() != expected.1 {
                    return Err(Error::Conflict);
                }
                let mut actual = DigestWriter(Sha256::new(), 0);
                io::copy(
                    &mut (&mut existing).take(expected.1.saturating_add(1)),
                    &mut actual,
                )
                .map_err(|_| Error::Material)?;
                if actual.0.finalize() != expected.0.finalize() {
                    return Err(Error::Conflict);
                }
                existing.sync_all().map_err(|_| Error::Workspace)?;
                protected_file::sync_parent(&root.join(&name)).map_err(|_| Error::Workspace)?;
            }
            Err(ProtectedFileError::Missing) => {
                protected_file::publish_checked(&root.join(&name), PublishMode::Create, |output| {
                    repo.export_recovery_key_bundle(source.authority, node.node_id, output)
                        .map_err(|_| ProtectedFileError::Invalid)
                })
                .map_err(|_| Error::Material)?;
            }
            Err(_) => return Err(Error::Workspace),
        }
        bundles.push(serde_json::json!({"node_id": node_id, "file": name}));
    }
    let expected = source.manifest;
    let authorization = repo.recovery_preparation_authorization(source.authority)?;
    Ok(
        serde_json::json!({ "prepared": true, "service_started": false,
        "admission_ready": false, "target_inventory_verified": true,
        "target_inventory_sha256": crate::update_candidate::hex(&authorization.claims().target_inventory_digest),
        "recovery_id": crate::create_mesh_setup::format_uuid(plan.recovery_id.as_bytes()),
        "source_log_index": expected.partition.applied_position.index.to_string(),
        "source_log_term": expected.partition.applied_position.term.to_string(),
        "state_revision": expected.partition.state_revision.get().to_string(),
        "retained_secret_generations": plan.secrets.generation_count.to_string(), "bundles": bundles,
        "scope": "Signed isolated metadata, verified inventory/content and encrypted replacement keys and certificates; not restored protection or service admission" }),
    )
}

pub(super) fn publish_exact(
    workspace: &Workspace,
    root: &Path,
    name: &str,
    bytes: &[u8],
) -> Result<(), Error> {
    workspace.clean_publication_temporary(name)?;
    let destination = root.join(name);
    match protected_file::open_read(&destination) {
        Ok(mut file) => {
            let mut saved = vec![0; bytes.len()];
            file.read_exact(&mut saved).map_err(|_| Error::Conflict)?;
            let mut trailing = [0];
            if saved != bytes || file.read(&mut trailing).map_err(|_| Error::Workspace)? != 0 {
                return Err(Error::Conflict);
            }
            file.sync_all().map_err(|_| Error::Workspace)?;
            protected_file::sync_parent(&destination).map_err(|_| Error::Workspace)
        }
        Err(ProtectedFileError::Missing) => {
            protected_file::publish(&destination, bytes, PublishMode::Create)
                .map_err(|_| Error::Workspace)
        }
        Err(_) => Err(Error::Workspace),
    }
}

pub(super) struct DigestWriter(Sha256, u64);
impl DigestWriter {
    pub(super) fn new() -> Self {
        Self(Sha256::new(), 0)
    }
    pub(super) fn finish(self) -> ([u8; 32], u64) {
        (self.0.finalize().into(), self.1)
    }
}
impl Write for DigestWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.1 = self
            .1
            .checked_add(u64::try_from(bytes.len()).map_err(io::Error::other)?)
            .ok_or_else(|| io::Error::other("recovery export length overflow"))?;
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
