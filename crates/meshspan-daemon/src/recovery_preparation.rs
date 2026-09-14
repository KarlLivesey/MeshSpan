// SPDX-License-Identifier: GPL-2.0-only

//! Offline operator preparation. No node is activated by this command.

mod collection;
mod content;
mod history;
pub(crate) use history::verify_backup_history;
mod materials;
mod publication;
mod restoration;
mod selection;
mod state_transfer;
mod targets;
mod workspace;

use crate::protected_file;
use materials::PreparedMaterials;
use meshspan_api_contract::{MAX_RECOVERY_SELECTION_BYTES, decode_recovery_preparation_selection};
use meshspan_domain::Clock as _;
use meshspan_metadata::{
    AuthoritativeRepository, EncryptedPartitionBackupManifest, EncryptedRestorePaths,
    PartitionDatabase, RecoveryReplacementPlan, prepare_authorized_partition_recovery,
    restore_partition_backup,
};
use meshspan_recovery_bundle::{
    RecoveredAuthority, RecoveryAuthorizationClaims, RecoveryBundle, RecoveryBundleCode,
};
use selection::Selection;
use sha2::{Digest as _, Sha256};
use std::{
    ffi::{OsStr, OsString},
    fs,
    io::Write as _,
    path::Path,
};
use workspace::Workspace;

/// Command name, six required operands and at most 1,024 three-operand target attachments.
pub(crate) const MAXIMUM_COMMAND_ARGUMENTS: usize = 7 + 3 * 1024;

/// Recovery command routing stays with the owner; the runtime only schedules blocking work.
pub(crate) fn recognises_command(name: &OsStr) -> bool {
    matches!(
        name.to_str(),
        Some(
            "prepare-recovery"
                | "stage-recovery-history"
                | "verify-recovery-content"
                | "collect-recovery-installation"
                | "export-recovery-state"
                | "export-recovery-state-set"
                | "install-recovery-state"
                | "prepare-recovery-target"
                | "collect-recovery-target"
                | "restore-recovery-target"
                | "collect-recovery-restoration"
                | "collect-recovery-state"
                | "authorize-recovery-consensus"
                | "admit-recovery-state"
        )
    )
}

pub(crate) fn run_command(arguments: &[OsString]) -> Result<(), RecoveryPreparationError> {
    let Some((name, values)) = arguments.split_first() else {
        return Err(RecoveryPreparationError::Arguments);
    };
    match name.to_str() {
        Some("prepare-recovery") => prepare_command(values),
        Some("stage-recovery-history") => history::stage_history_command(values),
        Some("verify-recovery-content") => content::verify_content_command(values),
        Some("collect-recovery-installation") => collection::collect_command(values),
        Some("export-recovery-state") => state_transfer::export_command(values),
        Some("export-recovery-state-set") => state_transfer::export_set_command(values),
        Some("install-recovery-state") => state_transfer::install_command(values),
        Some("prepare-recovery-target") => targets::prepare_command(values),
        Some("collect-recovery-target") => targets::collect_command(values),
        Some("restore-recovery-target") => restoration::run_command(values),
        Some("collect-recovery-restoration") => restoration::collect_command(values),
        Some("collect-recovery-state") => state_transfer::collect_command(values),
        Some("authorize-recovery-consensus") => state_transfer::authorize_command(values),
        Some("admit-recovery-state") => state_transfer::admit_command(values),
        _ => Err(RecoveryPreparationError::Arguments),
    }
}

/// Redacted preparation failure. Partial private work is never a completed recovery.
#[derive(Debug, thiserror::Error)]
pub enum RecoveryPreparationError {
    /// Recovery codes are read from owner-only files, never from process arguments.
    #[error(
        "usage: prepare-recovery BACKUP SHA256 RECOVERY_BUNDLE RECOVERY_CODE_FILE SELECTION_JSON WORK_DIRECTORY"
    )]
    Arguments,
    /// Collect one node's signed report into the isolated preparation, without service admission.
    #[error(
        "usage: collect-recovery-installation PREPARED_DATABASE RECOVERY_BUNDLE RECOVERY_CODE_FILE NODE_UUID INSTALLATION_REPORT"
    )]
    CollectionArguments,
    /// Export one node's encrypted prepared state without publishing service authority.
    #[error(
        "usage: export-recovery-state PREPARED_DATABASE RECOVERY_BUNDLE RECOVERY_CODE_FILE BACKUP NODE_UUID NEW_WORK_DIRECTORY"
    )]
    StateExportArguments,
    /// Export all selected nodes from one snapshot and one shared encrypted state archive.
    #[error(
        "usage: export-recovery-state-set PREPARED_DATABASE RECOVERY_BUNDLE RECOVERY_CODE_FILE BACKUP NEW_WORK_DIRECTORY"
    )]
    StateSetExportArguments,
    /// Install only into a new private isolated workspace, never over a running daemon.
    #[error(
        "usage: install-recovery-state PACKAGE_DIRECTORY ROOT_CERTIFICATE NODE_UUID IDENTITY_KEY_FILE WRAPPING_KEY_FILE NEW_WORK_DIRECTORY [--storage-target TARGET_WORK_DIRECTORY STORAGE_FOLDER]..."
    )]
    StateInstallArguments,
    /// Collect the node signature for an independently selected root-authorised state package.
    #[error(
        "usage: collect-recovery-state PREPARED_DATABASE RECOVERY_BUNDLE RECOVERY_CODE_FILE EXPECTED_STATE_AUTH INSTALLATION_REPORT"
    )]
    StateCollectionArguments,
    /// Sign one common installed state set; membership application and readiness remain separate.
    #[error(
        "usage: authorize-recovery-consensus PREPARED_DATABASE RECOVERY_BUNDLE RECOVERY_CODE_FILE STATE_SET_DIRECTORY PERMISSION_FILE"
    )]
    ConsensusPermissionArguments,
    /// Install the signed replacement epoch on an existing, exclusively locked recovered node.
    #[error("usage: admit-recovery-state DAEMON_STATE_DIRECTORY CONSENSUS_PERMISSION_FILE")]
    ConsensusAdmissionArguments,
    /// Select one existing replacement folder without marking it admitted or active.
    #[error(
        "usage: prepare-recovery-target PACKAGE_DIRECTORY ROOT_CERTIFICATE IDENTITY_KEY_FILE WRAPPING_KEY_FILE STORAGE_REQUEST_JSON WORK_DIRECTORY"
    )]
    TargetArguments,
    /// Retain the independently verified selected-node folder attestation.
    #[error(
        "usage: collect-recovery-target PREPARED_DATABASE RECOVERY_BUNDLE RECOVERY_CODE_FILE TARGET_REPORT"
    )]
    TargetCollectionArguments,
    /// Restore physical shards into a prepared target without admitting live service.
    #[error(
        "usage: restore-recovery-target PACKAGE_DIRECTORY ROOT_CERTIFICATE IDENTITY_KEY_FILE WRAPPING_KEY_FILE TARGET_WORK_DIRECTORY RESTORE_REQUEST_JSON"
    )]
    TargetRestoreArguments,
    /// Compare the entire node receipt stream with the authenticated archive before recording it.
    #[error(
        "usage: collect-recovery-restoration PREPARED_DATABASE RECOVERY_BUNDLE RECOVERY_CODE_FILE BACKUP RESTORATION_DIRECTORY WORK_DIRECTORY"
    )]
    RestorationCollectionArguments,
    /// Stage surviving history and layouts without admitting their local branches.
    #[error(
        "usage: stage-recovery-history PREPARED_DATABASE RECOVERY_BUNDLE RECOVERY_CODE_FILE BACKUP_OR_SURVIVING_FILESYSTEM_DIRECTORY NEW_WORK_DIRECTORY"
    )]
    HistoryArguments,
    /// Verify archived files against isolated copies of independently identified surviving targets.
    #[error(
        "usage: verify-recovery-content PREPARED_DATABASE RECOVERY_BUNDLE RECOVERY_CODE_FILE BACKUP STORAGE_SELECTION_JSON NEW_WORK_DIRECTORY"
    )]
    ContentArguments,
    /// Selected targets or required file bytes failed offline recovery verification.
    #[error("recovery storage identity, copy or complete file content could not be verified")]
    Content,
    /// Required history, layout or wrapped key is missing or does not match the selected backup.
    #[error("recovery history, content layout or referenced key could not be verified")]
    History,
    /// Malformed, excessive or unsafe public/private input.
    #[error("recovery preparation input is malformed, excessive or unsafe")]
    Input,
    /// Independent source, root or wrapping identity did not match.
    #[error("recovery preparation authority does not match the saved backup")]
    Authority,
    /// Source or replacement election/read/write predicates could not be established.
    #[error("recovery preparation quorum could not be validated")]
    Quorum,
    /// Failed encrypted key planning, complete-inventory proof or transfer export.
    #[error("recovery preparation material failed verification or storage")]
    Material,
    /// Work must be a private directory belonging to the same recovery intent.
    #[error("recovery preparation workspace is missing, unsafe or could not be persisted")]
    Workspace,
    /// Another process owns the same preparation; retry after that process exits.
    #[error("recovery preparation is already running in this workspace")]
    Busy,
    /// Changed intent or published bytes cannot overwrite the existing recovery.
    #[error("recovery preparation conflicts with existing intent or published material")]
    Conflict,
    /// Temporary plaintext could not be safely removed.
    #[error(
        "recovery preparation cleanup failed; private plaintext may remain in the requested workspace"
    )]
    Cleanup,
    /// Existing typed metadata boundary refused the operation.
    #[error("recovery preparation metadata validation or persistence failed")]
    Metadata(#[from] meshspan_metadata::RepositoryError),
    /// Worker or report output failed; no success is implied.
    #[error("recovery preparation worker or report failed")]
    Worker,
}

pub(crate) fn prepare_command(arguments: &[OsString]) -> Result<(), RecoveryPreparationError> {
    let [backup, digest, bundle, code, selection, work] = arguments else {
        return Err(RecoveryPreparationError::Arguments);
    };
    let inputs = [backup, bundle, code, selection].map(Path::new);
    let expected =
        crate::offline_backup::parse_digest(digest).map_err(|_| RecoveryPreparationError::Input)?;
    let bundle = crate::offline_backup::read_bundle(Path::new(bundle))
        .map_err(|_| RecoveryPreparationError::Input)?;
    let authority = open_authority(&bundle, Path::new(code))?;
    let selection =
        protected_file::read_bounded(Path::new(selection), 1, MAX_RECOVERY_SELECTION_BYTES)
            .map_err(|_| RecoveryPreparationError::Input)?;
    let selection = decode_recovery_preparation_selection(&selection)
        .map_err(|_| RecoveryPreparationError::Input)?;
    let evidence = meshspan_backup::read_backup_evidence(Path::new(backup), expected)
        .map_err(|_| RecoveryPreparationError::Authority)?;
    if evidence.source.mesh_id != bundle.mesh_id() {
        return Err(RecoveryPreparationError::Authority);
    }
    let work = std::env::current_dir()
        .map_err(|_| RecoveryPreparationError::Workspace)?
        .join(work);
    let work = content::isolated_destination(&selection.storage, &work)?;
    // Owned workspace cleanup must never become authority to remove an operator input.
    for input in inputs {
        let input = fs::canonicalize(input).map_err(|_| RecoveryPreparationError::Input)?;
        if input.starts_with(&work) {
            return Err(RecoveryPreparationError::Workspace);
        }
    }
    let mut intent = Sha256::new();
    intent.update(b"MeshSpan offline preparation workspace v1\0");
    intent.update(expected);
    intent.update(bundle.digest());
    intent.update(serde_json::to_vec(&selection).map_err(|_| RecoveryPreparationError::Input)?);
    let workspace = Workspace::open(&work, &intent.finalize().into())?;
    let source = RecoverySource {
        backup: Path::new(backup),
        bundle: &bundle,
        authority: &authority,
        manifest: crate::offline_backup::partition_manifest(evidence),
    };
    let repo = prepare_or_resume(&source, selection, &work, &workspace)?;
    let plan = repo
        .staged_recovery_replacement_plan(&authority)?
        .ok_or(RecoveryPreparationError::Material)?;
    let report = publication::export(&repo, &source, &plan, &work, &workspace)?;
    let bytes = serde_json::to_vec(&report).map_err(|_| RecoveryPreparationError::Worker)?;
    publication::publish_exact(&workspace, &work, "prepared.json", &bytes)?;
    let mut output = std::io::stdout().lock();
    output
        .write_all(&bytes)
        .and_then(|()| output.write_all(b"\n"))
        .map_err(|_| RecoveryPreparationError::Worker)
}

fn open_authority(
    bundle: &RecoveryBundle,
    code: &Path,
) -> Result<RecoveredAuthority, RecoveryPreparationError> {
    let code =
        protected_file::read_bounded(code, 1, 128).map_err(|_| RecoveryPreparationError::Input)?;
    let code = RecoveryBundleCode::parse(
        std::str::from_utf8(&code)
            .map_err(|_| RecoveryPreparationError::Input)?
            .trim_end_matches(['\r', '\n']),
    )
    .map_err(|_| RecoveryPreparationError::Authority)?;
    bundle
        .open(&code)
        .map_err(|_| RecoveryPreparationError::Authority)
}

struct RecoverySource<'a> {
    backup: &'a Path,
    bundle: &'a RecoveryBundle,
    authority: &'a RecoveredAuthority,
    manifest: EncryptedPartitionBackupManifest,
}

impl RecoverySource<'_> {
    fn restore(
        &self,
        temporary: &Path,
    ) -> Result<AuthoritativeRepository, RecoveryPreparationError> {
        let plaintext = temporary.join("plaintext.sqlite3");
        meshspan_backup::restore_backup_files(
            self.backup,
            meshspan_backup::BackupFiles {
                metadata: &plaintext,
                history: Some(meshspan_backup::BackupHistoryFiles {
                    namespace: &temporary.join("filesystem-branch.sqlite3"),
                    content: &temporary.join("filesystem-content.sqlite3"),
                }),
            },
            self.manifest.encrypted,
            self.authority.wrapping_key(),
        )
        .map_err(|_| RecoveryPreparationError::History)?;
        let source = AuthoritativeRepository::new(restore_partition_backup(
            &plaintext,
            &temporary.join("restored.sqlite3"),
            self.manifest.partition,
            crate::OperatingSystemClock.now(),
        )?);
        fs::remove_file(plaintext).map_err(|_| RecoveryPreparationError::Cleanup)?;
        let stored = source
            .mesh_recovery_authority(self.bundle.mesh_id())?
            .ok_or(RecoveryPreparationError::Authority)?;
        if stored.bundle_digest != self.bundle.digest()
            || stored.root_certificate_der != self.authority.root_certificate_der()
            || stored.public_wrapping_key != self.authority.public_wrapping_key()
        {
            return Err(RecoveryPreparationError::Authority);
        }
        Ok(source)
    }
}

fn build_preparation(
    input: &RecoverySource<'_>,
    selection: meshspan_api_contract::RecoveryPreparationSelection,
    work: &Path,
    inventory_root: &Path,
) -> Result<AuthoritativeRepository, RecoveryPreparationError> {
    // Both restores recheck against the independently saved digest, not a newly calculated hash.
    let expected = input.manifest;
    let backup = input.backup;
    let authority = input.authority;
    let source = input.restore(work)?;
    let inventory_digest =
        content::prepare_inventory(input, &source, &selection.storage, work, inventory_root)?;
    let selected = Selection::convert(selection, &source)?;
    let materials = PreparedMaterials::create(&source, authority, &selected, work)?;
    let plan = RecoveryReplacementPlan {
        mesh_id: expected.partition.mesh_id,
        partition_id: expected.partition.partition_id,
        recovery_id: selected.recovery_id,
        recovery_epoch: 1,
        secrets: materials.inventory,
        quorum: selected.quorum,
        nodes: selected.nodes,
    };
    let authorization = authority
        .authorize_recovery(recovery_claims(&expected, &plan, inventory_digest)?)
        .map_err(|_| RecoveryPreparationError::Authority)?;
    let restored = work.join("prepared.sqlite3");
    prepare_authorized_partition_recovery(
        EncryptedRestorePaths {
            encrypted_source: backup,
            plaintext_staging: &work.join("preparation.tmp"),
            restored_destination: &restored,
        },
        expected,
        authority,
        &authorization,
        crate::OperatingSystemClock.now(),
    )?;
    let mut repo = AuthoritativeRepository::new(
        PartitionDatabase::open_existing(&restored, crate::OperatingSystemClock.now())
            .map_err(|_| RecoveryPreparationError::Workspace)?,
    );
    materials.stage(&mut repo, authority, work)?;
    repo.stage_recovery_replacement_plan(authority, &plan, crate::OperatingSystemClock.now())?;
    repo.fence_recovery_credentials(authority, crate::OperatingSystemClock.now())?;
    Ok(repo)
}

fn recovery_claims(
    expected: &EncryptedPartitionBackupManifest,
    plan: &RecoveryReplacementPlan,
    inventory_digest: [u8; 32],
) -> Result<RecoveryAuthorizationClaims, RecoveryPreparationError> {
    Ok(RecoveryAuthorizationClaims {
        mesh_id: plan.mesh_id,
        partition_id: plan.partition_id,
        recovery_id: plan.recovery_id,
        backup_id: expected.partition.backup_id,
        backup_digest: expected.encrypted.digest,
        source_log_index: expected.partition.applied_position.index,
        source_log_term: expected.partition.applied_position.term,
        source_revision: expected.partition.state_revision,
        previous_epoch: 0,
        recovery_epoch: 1,
        replacement_manifest_digest: plan.digest().map_err(|_| RecoveryPreparationError::Input)?,
        target_inventory_digest: inventory_digest,
    })
}

fn prepare_or_resume(
    input: &RecoverySource<'_>,
    selection: meshspan_api_contract::RecoveryPreparationSelection,
    work: &Path,
    workspace: &Workspace,
) -> Result<AuthoritativeRepository, RecoveryPreparationError> {
    let published = work.join("prepared.sqlite3");
    match fs::symlink_metadata(&published) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let build = workspace.begin_build()?;
            let result = (|| {
                let repo =
                    build_preparation(input, selection.clone(), &build, &work.join("inventory"))?;
                let snapshot = build.join("snapshot.sqlite3");
                repo.create_backup(
                    input.manifest.partition.backup_id,
                    &snapshot,
                    crate::OperatingSystemClock.now(),
                )?;
                drop(repo);
                workspace.publish_database(&snapshot)
            })();
            workspace.cleanup_build()?;
            result?;
        }
        Err(_) => return Err(RecoveryPreparationError::Workspace),
        Ok(_) => {}
    }
    let _guard =
        protected_file::open_read(&published).map_err(|_| RecoveryPreparationError::Workspace)?;
    let repo = AuthoritativeRepository::new(
        PartitionDatabase::open_existing(&published, crate::OperatingSystemClock.now())
            .map_err(|_| RecoveryPreparationError::Workspace)?,
    );
    let inventory_digest = content::prepared_inventory_digest(
        &repo,
        &selection.storage,
        &work.join("inventory"),
        input.manifest.encrypted.digest,
    )?;
    let selected = Selection::convert(selection, &repo)?;
    let plan = repo
        .staged_recovery_replacement_plan(input.authority)?
        .ok_or(RecoveryPreparationError::Material)?;
    let requested = RecoveryReplacementPlan {
        mesh_id: input.manifest.partition.mesh_id,
        partition_id: input.manifest.partition.partition_id,
        recovery_epoch: 1,
        nodes: selected.nodes,
        quorum: selected.quorum,
        recovery_id: selected.recovery_id,
        ..plan.clone()
    };
    let authorization = repo.recovery_preparation_authorization(input.authority)?;
    if plan != requested
        || *authorization.claims()
            != recovery_claims(&input.manifest, &requested, inventory_digest)?
        || repo
            .mesh_recovery_authority(input.bundle.mesh_id())?
            .ok_or(RecoveryPreparationError::Authority)?
            .bundle_digest
            != input.bundle.digest()
    {
        return Err(RecoveryPreparationError::Conflict);
    }
    // Export revalidates the fence and never manufactures one for an incomplete copy.
    workspace.cleanup_build()?;
    Ok(repo)
}
