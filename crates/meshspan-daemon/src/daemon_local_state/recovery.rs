// SPDX-License-Identifier: GPL-2.0-only

//! Resume a root-authorised recovery without inventing a claim or local setup transaction.

use super::{DaemonLocalState, DaemonLocalStateError as Error, StateDirectory};
use crate::protected_file::{self, PublishMode};
use crate::{LocalNodeIdentity, LocalWrappingKey};
use meshspan_domain::{NodeId, Revision, UnixMicros};
use meshspan_metadata::{
    AuthoritativeRepository, LocalDatabase, PartitionDatabase, RecoveryKeyRecipient,
    verify_recovery_key_bundle,
};
use meshspan_recovery_bundle::{RecoveryConsensusAdmission, RecoveryStateTransfer};
use std::{fs, path::Path};

const PERMISSION: &str = "consensus.permission";

pub(super) fn open(
    directory: StateDirectory,
    claim_output: Option<&Path>,
    now: UnixMicros,
) -> Result<DaemonLocalState, Error> {
    let permission = read_permission(directory.path())?;
    let material = Material::open(directory.path())?;
    let database = local_database(directory.path(), material.transfer.claims().node_id, now)?;
    activate(directory.path(), &material, &permission, now)?;
    let claim_output_path = claim_output.map_or_else(
        || directory.path().join(super::DEFAULT_CLAIM_FILE),
        Path::to_path_buf,
    );
    Ok(DaemonLocalState {
        directory,
        database,
        identity: material.identity,
        wrapping_key: material.wrapping,
        claim_output_path,
        claim_outcome: crate::ClaimEnsureOutcome {
            disposition: crate::ClaimEnsureDisposition::RecoveryAuthorized,
            claim_id: None,
        },
    })
}

pub(super) fn admit(directory: &Path, encoded: &[u8], now: UnixMicros) -> Result<Revision, Error> {
    if !fs::symlink_metadata(directory)?.is_dir() {
        return Err(Error::UnsafeStateDirectory);
    }
    let directory = StateDirectory::open(directory, &[])?;
    let material = Material::open(directory.path())?;
    let _local = local_database(directory.path(), material.transfer.claims().node_id, now)?;
    material.verify_permission(encoded)?;
    let destination = directory.path().join(PERMISSION);
    if super::regular_file_exists(&destination)? {
        if read_permission(directory.path())?.as_slice() != encoded {
            return Err(Error::InvalidRecoveryState);
        }
    } else {
        // A crash before the database transaction commits resumes from this exact signed intent.
        protected_file::publish(&destination, encoded, PublishMode::Create)
            .map_err(|_| Error::InvalidRecoveryState)?;
    }
    activate(directory.path(), &material, encoded, now)
}

// Update handoff needs an identity before opening or migrating metadata. Key verification is
// deliberately file-only here; normal daemon startup separately verifies applied admission.
pub(super) fn existing_node_id(directory: &Path) -> Result<NodeId, Error> {
    let permission = read_permission(directory)?;
    let material = Material::open(directory)?;
    material.verify_permission(&permission)?;
    material.verify_keys(directory)?;
    Ok(material.transfer.claims().node_id)
}

struct Material {
    root: Vec<u8>,
    transfer: RecoveryStateTransfer,
    identity: LocalNodeIdentity,
    wrapping: LocalWrappingKey,
}

impl Material {
    fn open(directory: &Path) -> Result<Self, Error> {
        let root = protected_file::read_bounded(&directory.join("recovery-root.der"), 1, 8192)
            .map_err(|_| Error::InvalidRecoveryState)?
            .to_vec();
        let encoded = protected_file::read_bounded(&directory.join("state.auth"), 1, 512)
            .map_err(|_| Error::InvalidRecoveryState)?;
        let transfer = RecoveryStateTransfer::decode(&root, &encoded)
            .map_err(|_| Error::InvalidRecoveryState)?;
        let secrets = directory.join(super::SECRET_DIRECTORY);
        let identity = LocalNodeIdentity::open(
            &secrets.join(super::IDENTITY_FILE),
            super::BOOTSTRAP_DNS_NAME,
        )?;
        let wrapping = LocalWrappingKey::open(&secrets.join(super::WRAPPING_KEY_FILE))?;
        crate::LocalTotpCeremonyKey::open(&secrets.join(super::TOTP_CEREMONY_KEY_FILE))?;
        crate::LocalPasskeyCeremonyKey::open(&secrets.join(super::PASSKEY_CEREMONY_KEY_FILE))?;
        Ok(Self {
            root,
            transfer,
            identity,
            wrapping,
        })
    }

    fn verify_permission(&self, encoded: &[u8]) -> Result<RecoveryConsensusAdmission, Error> {
        let permission = RecoveryConsensusAdmission::decode(&self.root, encoded)
            .map_err(|_| Error::InvalidRecoveryState)?;
        let selected = permission.claims();
        let installed = self.transfer.claims();
        if selected.authorization != installed.authorization
            || selected.state_digest != installed.state_digest
            || selected.state_length != installed.state_length
        {
            return Err(Error::InvalidRecoveryState);
        }
        Ok(permission)
    }

    fn verify_keys(&self, directory: &Path) -> Result<(), Error> {
        let mut keys = protected_file::open_read(&directory.join("keys.bundle"))
            .map_err(|_| Error::InvalidRecoveryState)?;
        if keys.metadata()?.len() != self.transfer.claims().key_bundle_length {
            return Err(Error::InvalidRecoveryState);
        }
        let verified = verify_recovery_key_bundle(
            &mut keys,
            &self.root,
            RecoveryKeyRecipient {
                node_id: self.transfer.claims().node_id,
                identity_public_key: self
                    .identity
                    .public_key_sec1()
                    .try_into()
                    .map_err(|_| Error::InvalidRecoveryState)?,
                wrapping_public_key: self.wrapping.public_key(),
            },
            |secret, envelope| self.wrapping.decrypt_secret(secret, envelope),
        )
        .map_err(|_| Error::InvalidRecoveryState)?;
        if !verified.matches_state_transfer(&self.transfer) {
            return Err(Error::InvalidRecoveryState);
        }
        Ok(())
    }
}

fn activate(
    directory: &Path,
    material: &Material,
    encoded: &[u8],
    now: UnixMicros,
) -> Result<Revision, Error> {
    let permission = material.verify_permission(encoded)?;
    let file = directory.join(super::ROOT_AUTHORITY_DATABASE);
    let _guard = protected_file::open_read(&file).map_err(|_| Error::InvalidRecoveryState)?;
    let mut repository =
        AuthoritativeRepository::new(PartitionDatabase::open_existing(&file, now)?);
    let node = repository
        .recovery_replacement_node(&material.root, &material.transfer)
        .map_err(|_| Error::InvalidRecoveryState)?;
    if node.identity_public_key.as_slice() != material.identity.public_key_sec1()
        || node.wrapping_public_key != material.wrapping.public_key()
    {
        return Err(Error::IdentityMismatch);
    }
    let previous = repository
        .recovery_consensus_admission(&material.root)
        .map_err(|_| Error::InvalidRecoveryState)?;
    if previous.is_none() {
        material.verify_keys(directory)?;
        let archive = directory.join("state.msb");
        let _archive_guard =
            protected_file::open_read(&archive).map_err(|_| Error::InvalidRecoveryState)?;
        let evidence = meshspan_backup::read_backup_evidence(
            &archive,
            material.transfer.claims().state_digest,
        )
        .map_err(|_| Error::InvalidRecoveryState)?;
        if evidence.byte_length != material.transfer.claims().state_length {
            return Err(Error::InvalidRecoveryState);
        }
        verify_history(&repository, directory, now)?;
        if node.roles.bits() & meshspan_metadata::JoinRoles::GATEWAY != 0 {
            initialise_gateway_heads(&repository, directory, node.node_id, now)?;
        }
    }
    repository
        .activate_recovery_consensus(&material.root, &permission, &material.transfer, now)
        .map_err(|_| Error::InvalidRecoveryState)
}

fn local_database(directory: &Path, node: NodeId, now: UnixMicros) -> Result<LocalDatabase, Error> {
    let database = LocalDatabase::open_existing(&directory.join(super::LOCAL_DATABASE_FILE), now)?;
    if database.node_id() != node
        || database
            .latest_local_claim()
            .map_err(|_| Error::InvalidRecoveryState)?
            .is_some()
        || database
            .local_setup()
            .map_err(|_| Error::InvalidRecoveryState)?
            .is_some()
        || super::regular_file_exists(&directory.join(super::DEFAULT_CLAIM_FILE))?
    {
        return Err(Error::InvalidRecoveryState);
    }
    Ok(database)
}

fn verify_history(
    repository: &AuthoritativeRepository,
    directory: &Path,
    now: UnixMicros,
) -> Result<(), Error> {
    let directory = directory.join("filesystem");
    for name in ["filesystem-branch.sqlite3", "filesystem-content.sqlite3"] {
        let _guard = protected_file::open_read(&directory.join(name))
            .map_err(|_| Error::InvalidRecoveryState)?;
    }
    let mut history = meshspan_filesystem::VersionPublicationStore::open(&directory, now)
        .map_err(|_| Error::InvalidRecoveryState)?;
    let catalog = meshspan_filesystem::DurableContentCatalog::open(&directory, now)
        .map_err(|_| Error::InvalidRecoveryState)?;
    crate::recovery_preparation::verify_backup_history(repository, &mut history, &catalog)
        .map_err(|_| Error::InvalidRecoveryState)
}

fn read_permission(directory: &Path) -> Result<zeroize::Zeroizing<Vec<u8>>, Error> {
    if !super::regular_file_exists(&directory.join(PERMISSION))? {
        return Err(Error::RecoveryAdmissionRequired);
    }
    protected_file::read_bounded(&directory.join(PERMISSION), 1, 512)
        .map_err(|_| Error::InvalidRecoveryState)
}

/// A replacement has its own connector branch, not the original gateway's branch identity.
/// Only absent local heads are initialised from the verified recovered converged heads. Each
/// adoption is durable/idempotent before metadata activation, so interruption cannot discard
/// an existing local branch or leave a successful admission ahead of this projection.
fn initialise_gateway_heads(
    repository: &AuthoritativeRepository,
    directory: &Path,
    node: NodeId,
    now: UnixMicros,
) -> Result<(), Error> {
    let branch = meshspan_domain::InitialBootstrapMaterial::local_branch_id(node)
        .map_err(|_| Error::InvalidRecoveryState)?;
    let mut history =
        meshspan_filesystem::VersionPublicationStore::open(&directory.join("filesystem"), now)
            .map_err(|_| Error::InvalidRecoveryState)?;
    let limit = meshspan_metadata::PageLimit::new(128).map_err(|_| Error::InvalidRecoveryState)?;
    let mut after = None;
    loop {
        let page = repository
            .volume_identity_page(after, limit)
            .map_err(|_| Error::InvalidRecoveryState)?;
        for volume in page.items {
            if history
                .namespace_head(branch, volume)
                .map_err(|_| Error::InvalidRecoveryState)?
                .is_some()
            {
                continue;
            }
            if let Some(head) = repository
                .converged_volume_head(volume)
                .map_err(|_| Error::InvalidRecoveryState)?
            {
                history
                    .adopt_imported_namespace_head(
                        branch,
                        volume,
                        head.namespace_commit_id,
                        head.root_object_revision_id,
                    )
                    .map_err(|_| Error::InvalidRecoveryState)?;
            }
        }
        match page.next {
            Some(next) => after = Some(next),
            None => return Ok(()),
        }
    }
}
