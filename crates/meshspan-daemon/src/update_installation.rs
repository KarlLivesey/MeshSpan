// SPDX-License-Identifier: GPL-2.0-only

//! Durable selection and self-exec mechanics. Consensus restart admission is a separate owner.

use crate::{
    HeadlessDaemonConfig,
    daemon_local_state::StateDirectory,
    protected_file::{self, ProtectedFileError, PublishMode},
    update_artifact_store::UpdateArtifactStore,
};
use meshspan_domain::{NodeId, WorkId};
use meshspan_metadata::{
    UpdateManifest, UpdateNodePhase, UpdateNodeRecord, UpdateRolloutRecord, UpdateSignerRecord,
};
use serde_json::{Value, json};
use std::{
    os::unix::process::CommandExt as _,
    path::{Path, PathBuf},
    process::Command,
};

const SELECTION_FILE: &str = "installed-update.json";
const MAXIMUM_SELECTION_BYTES: usize = 128 * 1024;

#[derive(Clone)]
pub(crate) struct InstallSelection {
    format: u32,
    pub(crate) rollout_id: [u8; 16],
    pub(crate) node_id: [u8; 16],
    pub(crate) incarnation: u64,
    pub(crate) restart_sequence: u64,
    restart_evidence_digest: [u8; 32],
    pub(crate) minimum_revision: u64,
    manifest: Vec<u8>,
    signature: Vec<u8>,
    trusted_key: Vec<u8>,
}

impl InstallSelection {
    pub(crate) fn new(
        record: &UpdateRolloutRecord,
        node: &UpdateNodeRecord,
        signer: &UpdateSignerRecord,
        minimum_revision: u64,
    ) -> Result<Self, InstallationError> {
        if node.phase != UpdateNodePhase::Restarting
            || !node.restart_pending
            || !signer.enabled
            || signer.signer_id != record.signer_id
        {
            return Err(InstallationError::State);
        }
        let selection = Self {
            format: 1,
            rollout_id: record.rollout_id.as_bytes(),
            node_id: node.node_id.as_bytes(),
            incarnation: node.incarnation,
            restart_sequence: node.sequence,
            restart_evidence_digest: node.evidence_digest.ok_or(InstallationError::State)?,
            minimum_revision,
            manifest: record.canonical_manifest.clone(),
            signature: record.signature.clone(),
            trusted_key: signer.public_key.to_vec(),
        };
        selection.validate()?;
        Ok(selection)
    }

    pub(crate) fn load(directory: &Path) -> Result<Option<Self>, InstallationError> {
        let bytes = match protected_file::read_bounded(
            &directory.join(SELECTION_FILE),
            1,
            MAXIMUM_SELECTION_BYTES,
        ) {
            Ok(bytes) => bytes,
            Err(ProtectedFileError::Missing) => return Ok(None),
            Err(_) => return Err(InstallationError::State),
        };
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| InstallationError::State)?;
        let selection = Self {
            format: serde_json::from_value(value["format"].clone())?,
            rollout_id: serde_json::from_value(value["rollout_id"].clone())?,
            node_id: serde_json::from_value(value["node_id"].clone())?,
            incarnation: serde_json::from_value(value["incarnation"].clone())?,
            restart_sequence: serde_json::from_value(value["restart_sequence"].clone())?,
            restart_evidence_digest: serde_json::from_value(
                value["restart_evidence_digest"].clone(),
            )?,
            minimum_revision: serde_json::from_value(value["minimum_revision"].clone())?,
            manifest: serde_json::from_value(value["manifest"].clone())?,
            signature: serde_json::from_value(value["signature"].clone())?,
            trusted_key: serde_json::from_value(value["trusted_key"].clone())?,
        };
        // Exact round-trip rejects unknown/duplicate fields and noncanonical encodings.
        if selection.encode()? != *bytes {
            return Err(InstallationError::State);
        }
        selection.validate()?;
        Ok(Some(selection))
    }

    pub(crate) fn save(&self, directory: &Path) -> Result<(), InstallationError> {
        self.validate()?;
        let bytes = self.encode()?;
        if bytes.len() > MAXIMUM_SELECTION_BYTES {
            return Err(InstallationError::State);
        }
        protected_file::publish(
            &directory.join(SELECTION_FILE),
            &bytes,
            PublishMode::Replace,
        )
        .map_err(|_| InstallationError::State)
    }

    pub(crate) fn matches(&self, record: &UpdateRolloutRecord, node: &UpdateNodeRecord) -> bool {
        self.rollout_id == record.rollout_id.as_bytes()
            && self.node_id == node.node_id.as_bytes()
            && self.incarnation == node.incarnation
            && node.restart_pending
            && self.restart_sequence <= node.sequence
            && self.manifest == record.canonical_manifest
            && self.signature == record.signature
    }

    fn encode(&self) -> Result<Vec<u8>, InstallationError> {
        Ok(serde_json::to_vec(&json!({
            "format":self.format, "rollout_id":self.rollout_id, "node_id":self.node_id,
            "incarnation":self.incarnation, "restart_sequence":self.restart_sequence,
            "restart_evidence_digest":self.restart_evidence_digest,
            "minimum_revision":self.minimum_revision, "manifest":self.manifest,
            "signature":self.signature, "trusted_key":self.trusted_key,
        }))?)
    }

    pub(crate) fn current_process(&self, directory: &Path) -> Result<bool, InstallationError> {
        let manifest = self.validate()?;
        let executable = executable(directory, &manifest)?;
        Ok(std::fs::canonicalize(std::env::current_exe()?)? == executable)
    }

    fn validate(&self) -> Result<UpdateManifest, InstallationError> {
        if self.format != 1
            || self.incarnation == 0
            || self.restart_sequence < 2
            || self.minimum_revision == 0
            || self.restart_evidence_digest == [0; 32]
            || self.manifest.len() > 16384
            || self.signature.len() > 72
            || self.trusted_key.len() != 65
        {
            return Err(InstallationError::State);
        }
        NodeId::from_bytes(self.node_id).map_err(|_| InstallationError::State)?;
        WorkId::from_bytes(self.rollout_id).map_err(|_| InstallationError::State)?;
        meshspan_metadata::authenticate_update_manifest(
            &self.manifest,
            &self.signature,
            &self.trusted_key,
        )
        .map_err(|_| InstallationError::State)
    }
}

/// Follow the retained installation before opening/migrating databases. Holding the
/// directory lock through exec prevents concurrent old/new writers; CLOEXEC releases it.
pub(crate) async fn follow_selected(
    config: &HeadlessDaemonConfig,
) -> Result<(), InstallationError> {
    let directory = config.storage().daemon_state_dir().to_path_buf();
    let storage = config.storage().storage_paths().to_vec();
    let arguments = config.restart_arguments();
    tokio::task::spawn_blocking(move || {
        let directory =
            StateDirectory::open(&directory, &storage).map_err(|_| InstallationError::State)?;
        let Some(selection) = InstallSelection::load(directory.path())? else {
            return Ok(());
        };
        if directory
            .existing_node_id()
            .map_err(|_| InstallationError::State)?
            .as_bytes()
            != selection.node_id
        {
            return Err(InstallationError::State);
        }
        let manifest = selection.validate()?;
        let executable = executable(directory.path(), &manifest)?;
        if std::fs::canonicalize(std::env::current_exe()?)? == executable {
            return Ok(());
        }
        // No shell, supervisor service, original join secret or arbitrary candidate path.
        Err(InstallationError::Exec(
            Command::new(executable).args(arguments).exec(),
        ))
    })
    .await
    .map_err(|_| InstallationError::Worker)?
}

fn executable(directory: &Path, manifest: &UpdateManifest) -> Result<PathBuf, InstallationError> {
    let target = crate::update_candidate::local_target().map_err(|_| InstallationError::State)?;
    let file = UpdateArtifactStore::open(directory)
        .map_err(|_| InstallationError::State)?
        .executable(manifest, target)
        .map_err(|_| InstallationError::State)?;
    Ok(std::fs::canonicalize(file)?)
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum InstallationError {
    #[error("retained update installation is invalid or unavailable")]
    State,
    #[error("retained update installation encoding is invalid")]
    Encoding(#[from] serde_json::Error),
    #[error("update installation IO failed")]
    Io(#[from] std::io::Error),
    #[error("selected update executable could not start")]
    Exec(#[source] std::io::Error),
    #[error("update installation worker failed")]
    Worker,
}
