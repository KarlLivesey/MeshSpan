// SPDX-License-Identifier: GPL-2.0-only

//! Single-snapshot delivery: one recipient package or a common encrypted state for all nodes.

use super::{AUTHORIZATION, CONTENT, Error, KEYS, METADATA, NAMESPACE, STATE};
use crate::protected_file::{self, PublishMode};
use meshspan_domain::Clock as _;
use meshspan_metadata::{
    AuthoritativeRepository, RecoveryReplacementNode, RecoveryReplacementPlan,
};
use meshspan_recovery_bundle::{
    RecoveredAuthority, RecoveryAuthorization, RecoveryStateTransferClaims,
};
use std::{ffi::OsString, fs, path::Path};

pub(in super::super) fn export_command(arguments: &[OsString]) -> Result<(), Error> {
    let [prepared, bundle, code, backup, node, work] = arguments else {
        return Err(Error::StateExportArguments);
    };
    let authority = open_authority(bundle, code)?;
    let node_id = super::node_id(node)?;
    let work = Path::new(work);
    let snapshot = Snapshot::create(Path::new(prepared), &authority, Path::new(backup), work)?;
    let node = snapshot
        .plan
        .nodes
        .iter()
        .find(|node| node.node_id == node_id)
        .ok_or(Error::Authority)?
        .clone();
    export_keys(&snapshot.repository, &authority, &node, work)?;
    let authorization = snapshot.authorization.clone();
    let references = snapshot.restored_references;
    let encrypted = snapshot.encrypt(work, &[node.wrapping_public_key])?;
    authorize_package(&authority, &authorization, &node, encrypted, work)?;
    super::print_report(&serde_json::json!({
        "exported": true, "service_started": false, "admission_ready": false,
        "node_id": crate::create_mesh_setup::format_uuid(node_id.as_bytes()),
        "state_sha256": crate::update_candidate::hex(&encrypted.digest),
        "restored_route_references": references.to_string(),
        "scope": "Encrypted prepared metadata/history, candidate restored routes and recipient keys; not present protection or service admission"
    }))
}

pub(in super::super) fn export_set_command(arguments: &[OsString]) -> Result<(), Error> {
    let [prepared, bundle, code, backup, work] = arguments else {
        return Err(Error::StateSetExportArguments);
    };
    let authority = open_authority(bundle, code)?;
    let work = Path::new(work);
    let mut snapshot = Snapshot::create(Path::new(prepared), &authority, Path::new(backup), work)?;
    let nodes = snapshot.plan.nodes.clone();
    let authorization = snapshot.authorization.clone();
    let references = snapshot.restored_references;
    for node in &nodes {
        let package = work.join(crate::create_mesh_setup::format_uuid(
            node.node_id.as_bytes(),
        ));
        super::private_directory(&package)?;
        export_keys(&snapshot.repository, &authority, node, &package)?;
    }
    let reserved_revision = snapshot.materialise_node_keys(&authority, work)?;
    let recipients: Vec<_> = nodes.iter().map(|node| node.wrapping_public_key).collect();
    let encrypted = snapshot.encrypt(work, &recipients)?;
    // These are immutable encrypted bytes in newly created same-filesystem directories.
    // Hard links preserve ordinary standalone package layout without N copies of the archive.
    // Every installer still verifies its signed digest; link identity is not trust.
    for node in &nodes {
        let package = work.join(crate::create_mesh_setup::format_uuid(
            node.node_id.as_bytes(),
        ));
        fs::hard_link(work.join(STATE), package.join(STATE)).map_err(|_| Error::Workspace)?;
        protected_file::sync_parent(&package.join(STATE)).map_err(|_| Error::Workspace)?;
    }
    protected_file::remove(&work.join(STATE)).map_err(|_| Error::Cleanup)?;
    for node in &nodes {
        let package = work.join(crate::create_mesh_setup::format_uuid(
            node.node_id.as_bytes(),
        ));
        authorize_package(&authority, &authorization, node, encrypted, &package)?;
    }
    super::print_report(&serde_json::json!({
        "exported": true, "service_started": false, "admission_ready": false,
        "node_count": nodes.len(),
        "reserved_revision": reserved_revision.get().to_string(),
        "state_sha256": crate::update_candidate::hex(&encrypted.digest),
        "restored_route_references": references.to_string(),
        "scope": "Every selected node receives the same frozen metadata/history and routes; not live recovery admission"
    }))
}

struct Snapshot {
    repository: AuthoritativeRepository,
    source: meshspan_backup::BackupSourceManifest,
    authorization: RecoveryAuthorization,
    plan: RecoveryReplacementPlan,
    restored_references: u64,
    metadata_name: &'static str,
}

impl Snapshot {
    fn create(
        prepared: &Path,
        authority: &RecoveredAuthority,
        backup: &Path,
        work: &Path,
    ) -> Result<Self, Error> {
        let source = super::open_repository(prepared)?;
        let authorization = source.recovery_preparation_authorization(authority)?;
        super::private_directory(work)?;
        let staging = work.join("staging");
        super::private_directory(&staging)?;
        // This is the only read of mutable coordinator state. Keys and routes use the copy.
        let manifest = source.create_backup(
            authorization.claims().backup_id,
            &staging.join(METADATA),
            crate::OperatingSystemClock.now(),
        )?;
        drop(source);
        super::sync_private(&staging.join(METADATA))?;
        let repository = super::open_repository(&staging.join(METADATA))?;
        if repository.recovery_preparation_authorization(authority)? != authorization {
            return Err(Error::Conflict);
        }
        let plan = repository
            .staged_recovery_replacement_plan(authority)?
            .ok_or(Error::Material)?;
        let restored_references = super::routes::prepare(&repository, authority, backup, &staging)?;
        Ok(Self {
            repository,
            source: manifest.source_manifest(),
            authorization,
            plan,
            restored_references,
            metadata_name: METADATA,
        })
    }

    fn materialise_node_keys(
        &mut self,
        authority: &RecoveredAuthority,
        work: &Path,
    ) -> Result<meshspan_domain::Revision, Error> {
        let revision = self.repository.materialise_recovery_node_keys(authority)?;
        // The original coordinator is untouched. Re-snapshot after the atomic projection so
        // the signed encrypted archive describes its new exact bytes, not the old digest.
        let destination = work.join("staging/runtime.sqlite3");
        self.source = self
            .repository
            .create_backup(self.source.backup_id, &destination, self.source.created_at)?
            .source_manifest();
        super::sync_private(&destination)?;
        self.metadata_name = "runtime.sqlite3";
        Ok(revision)
    }

    fn encrypt(
        self,
        work: &Path,
        recipients: &[meshspan_secret_envelope::WrappingPublicKey],
    ) -> Result<meshspan_backup::BackupFileEvidence, Error> {
        drop(self.repository);
        let staging = work.join("staging");
        let encrypted = meshspan_backup::encrypt_backup_files(
            meshspan_backup::BackupFiles {
                metadata: &staging.join(self.metadata_name),
                history: Some(meshspan_backup::BackupHistoryFiles {
                    namespace: &staging.join(NAMESPACE),
                    content: &staging.join(CONTENT),
                }),
            },
            &work.join(STATE),
            self.source,
            recipients,
            &mut crate::OperatingSystemRandom,
        )
        .map_err(|_| Error::Material)?;
        super::sync_private(&work.join(STATE))?;
        // Only this invocation's fixed plaintext copies; never traverse an operator folder.
        for name in [METADATA, NAMESPACE, CONTENT] {
            remove_snapshot(&staging, name)?;
        }
        if self.metadata_name != METADATA {
            remove_snapshot(&staging, self.metadata_name)?;
        }
        fs::remove_dir(&staging).map_err(|_| Error::Cleanup)?;
        protected_file::sync_parent(&staging).map_err(|_| Error::Cleanup)?;
        Ok(encrypted)
    }
}

fn remove_snapshot(staging: &Path, name: &str) -> Result<(), Error> {
    fs::remove_file(staging.join(name)).map_err(|_| Error::Cleanup)?;
    // Read-only verification of a WAL-mode SQLite backup can create an empty WAL and
    // its shared-memory index. All connections are closed; these are owned copies only.
    for suffix in ["-wal", "-shm", "-journal"] {
        match fs::remove_file(staging.join(format!("{name}{suffix}"))) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(Error::Cleanup),
        }
    }
    Ok(())
}

fn open_authority(bundle: &OsString, code: &OsString) -> Result<RecoveredAuthority, Error> {
    let bundle = crate::offline_backup::read_bundle(Path::new(bundle)).map_err(|_| Error::Input)?;
    super::super::open_authority(&bundle, Path::new(code))
}

fn export_keys(
    repository: &AuthoritativeRepository,
    authority: &RecoveredAuthority,
    node: &RecoveryReplacementNode,
    work: &Path,
) -> Result<(), Error> {
    protected_file::publish_checked(&work.join(KEYS), PublishMode::Create, |output| {
        repository
            .export_recovery_key_bundle(authority, node.node_id, output)
            .map_err(|_| protected_file::ProtectedFileError::Invalid)
    })
    .map_err(|_| Error::Material)
}

fn authorize_package(
    authority: &RecoveredAuthority,
    authorization: &RecoveryAuthorization,
    node: &RecoveryReplacementNode,
    encrypted: meshspan_backup::BackupFileEvidence,
    work: &Path,
) -> Result<(), Error> {
    let (key_bundle_digest, key_bundle_length) = super::file_digest(&work.join(KEYS))?;
    let transfer = authority
        .authorize_state_transfer(RecoveryStateTransferClaims {
            authorization: authorization.clone(),
            node_id: node.node_id,
            incarnation: node.incarnation,
            state_digest: encrypted.digest,
            state_length: encrypted.byte_length,
            key_bundle_digest,
            key_bundle_length,
        })
        .map_err(|_| Error::Authority)?;
    let encoded = transfer.encode().map_err(|_| Error::Material)?;
    protected_file::publish(&work.join(AUTHORIZATION), &encoded, PublishMode::Create)
        .map_err(|_| Error::Workspace)
}
