// SPDX-License-Identifier: GPL-2.0-only

//! Replacement folder preparation and coordinator collection, never live registration.

use super::{RecoveryPreparationError as Error, publication, workspace::Workspace};
use crate::protected_file;
use meshspan_api_contract::StorageFolderUsageLimit;
use meshspan_domain::{Clock as _, OperationId, TargetId};
use meshspan_metadata::{
    AuthoritativeRepository, JoinRoles, PartitionDatabase, PreparedRecoveryTarget,
    RecoveryKeyBundleVerification, RecoveryKeyRecipient, StorageUsageLimit,
    verify_recovery_key_bundle,
};
use meshspan_recovery_bundle::RecoveryStateTransfer;
use meshspan_storage::{FolderRegistration, RegisteredFolder, StorageFolderError, UsageLimit};
use sha2::{Digest as _, Sha256};
use std::{ffi::OsString, fs, io::Write as _, os::unix::ffi::OsStrExt as _, path::Path};

pub(super) fn prepare_command(arguments: &[OsString]) -> Result<(), Error> {
    let [package, root, identity, wrapping, request, work] = arguments else {
        return Err(Error::TargetArguments);
    };
    let identity = crate::LocalNodeIdentity::open(Path::new(identity), "meshspan-recovery.invalid")
        .map_err(|_| Error::Input)?;
    let wrapping = crate::LocalWrappingKey::open(Path::new(wrapping)).map_err(|_| Error::Input)?;
    let (transfer, verified) =
        verify_recipient(Path::new(package), Path::new(root), &identity, &wrapping)?;
    let bytes = protected_file::read_bounded(
        Path::new(request),
        1,
        meshspan_api_contract::MAX_REGISTER_STORAGE_FOLDER_BYTES,
    )
    .map_err(|_| Error::Input)?;
    let request = meshspan_api_contract::decode_register_storage_folder_request(&bytes)
        .map_err(|_| Error::Input)?;
    let folder_path = fs::canonicalize(request.path.as_str()).map_err(|_| Error::Input)?;
    let work = std::env::current_dir()
        .map_err(|_| Error::Workspace)?
        .join(work);
    let parent =
        fs::canonicalize(work.parent().ok_or(Error::Workspace)?).map_err(|_| Error::Workspace)?;
    let work = parent.join(work.file_name().ok_or(Error::Workspace)?);
    if work.starts_with(&folder_path) {
        return Err(Error::Workspace);
    }
    let operation_id = OperationId::from_bytes(
        crate::create_mesh_setup::parse_uuid(request.operation_id.as_str())
            .map_err(|_| Error::Input)?,
    )
    .map_err(|_| Error::Input)?;
    let usage_limit = usage_limit(&request.usage_limit)?;
    let node = verified.replacement_node();
    let mut intent = Sha256::new();
    intent.update(b"MeshSpan recovery folder intent v1\0");
    intent.update(transfer.encode().map_err(|_| Error::Authority)?);
    intent.update(serde_json::to_vec(&request).map_err(|_| Error::Input)?);
    intent.update(folder_path.as_os_str().as_bytes());
    let workspace = Workspace::open(&work, &intent.finalize().into())?;
    let target_id = target_id(&transfer, operation_id)?;
    let registration = FolderRegistration {
        mesh_id: transfer.claims().authorization.claims().mesh_id,
        target_id,
        generation: 1,
        usage_limit: match usage_limit {
            StorageUsageLimit::Percent(value) => UsageLimit::Percent(value),
            StorageUsageLimit::Bytes(value) => UsageLimit::Bytes(value),
        },
    };
    // The exact intent is durable before marker creation. Retry only reopens that target ID.
    let folder = match RegisteredFolder::register_new(
        &folder_path,
        registration,
        &mut crate::OperatingSystemRandom,
    ) {
        Ok(folder) => folder,
        Err(StorageFolderError::PrivateDirectoryNotEmpty) => {
            RegisteredFolder::reopen_pending(&folder_path, registration)
                .map_err(|_| Error::Content)?
        }
        Err(_) => return Err(Error::Content),
    };
    let target = PreparedRecoveryTarget {
        authorization: transfer.claims().authorization.clone(),
        node_id: node.node_id,
        incarnation: node.incarnation,
        operation_id,
        target_id,
        generation: 1,
        marker_fingerprint: folder.marker().fingerprint().as_bytes(),
        usage_limit,
    };
    let signature = identity
        .sign_enrolment_transcript(&target.installation_message()?)
        .map_err(|_| Error::Worker)?;
    publication::publish_exact(
        &workspace,
        &work,
        "target.report",
        &target.encode_report(&signature)?,
    )?;
    print_target(&target, "prepared")
}

pub(super) fn collect_command(arguments: &[OsString]) -> Result<(), Error> {
    let [prepared, bundle, code, report] = arguments else {
        return Err(Error::TargetCollectionArguments);
    };
    let bundle = crate::offline_backup::read_bundle(Path::new(bundle)).map_err(|_| Error::Input)?;
    let authority = super::open_authority(&bundle, Path::new(code))?;
    let bytes =
        protected_file::read_bounded(Path::new(report), 1, 512).map_err(|_| Error::Input)?;
    let _guard = protected_file::open_read(Path::new(prepared)).map_err(|_| Error::Input)?;
    let mut repository = AuthoritativeRepository::new(
        PartitionDatabase::open_existing(Path::new(prepared), crate::OperatingSystemClock.now())
            .map_err(|_| Error::Input)?,
    );
    let target =
        repository.record_recovery_target(&authority, &bytes, crate::OperatingSystemClock.now())?;
    print_target(&target, "recorded")
}

pub(super) fn verify_recipient(
    package: &Path,
    root: &Path,
    identity: &crate::LocalNodeIdentity,
    wrapping: &crate::LocalWrappingKey,
) -> Result<(RecoveryStateTransfer, RecoveryKeyBundleVerification), Error> {
    let root = protected_file::read_bounded(root, 1, 8192).map_err(|_| Error::Input)?;
    let encoded = protected_file::read_bounded(&package.join("state.auth"), 1, 512)
        .map_err(|_| Error::Input)?;
    let transfer = RecoveryStateTransfer::decode(&root, &encoded).map_err(|_| Error::Authority)?;
    let mut input =
        protected_file::open_read(&package.join("keys.bundle")).map_err(|_| Error::Input)?;
    if input.metadata().map_err(|_| Error::Input)?.len() != transfer.claims().key_bundle_length {
        return Err(Error::Authority);
    }
    let verified = verify_recovery_key_bundle(
        &mut input,
        &root,
        RecoveryKeyRecipient {
            node_id: transfer.claims().node_id,
            identity_public_key: identity
                .public_key_sec1()
                .try_into()
                .map_err(|_| Error::Input)?,
            wrapping_public_key: wrapping.public_key(),
        },
        |secret, envelope| wrapping.decrypt_secret(secret, envelope),
    )
    .map_err(|_| Error::Authority)?;
    if !verified.matches_state_transfer(&transfer)
        || verified.replacement_node().roles.bits() & JoinRoles::STORAGE == 0
    {
        return Err(Error::Authority);
    }
    Ok((transfer, verified))
}

fn target_id(transfer: &RecoveryStateTransfer, operation: OperationId) -> Result<TargetId, Error> {
    let mut digest = Sha256::new();
    digest.update(b"MeshSpan recovery target identity v1\0");
    digest.update(
        transfer
            .claims()
            .authorization
            .claims()
            .recovery_id
            .as_bytes(),
    );
    digest.update(transfer.claims().node_id.as_bytes());
    digest.update(operation.as_bytes());
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest.finalize()[..16]);
    TargetId::from_bytes(meshspan_domain::uuid_v8(bytes)).map_err(|_| Error::Input)
}

fn usage_limit(value: &StorageFolderUsageLimit) -> Result<StorageUsageLimit, Error> {
    let limit = match value {
        StorageFolderUsageLimit::Percent { percent } => StorageUsageLimit::Percent(*percent),
        StorageFolderUsageLimit::Bytes { bytes } => {
            StorageUsageLimit::Bytes(bytes.parse().map_err(|_| Error::Input)?)
        }
    };
    limit.validate().map_err(|_| Error::Input)
}

fn print_target(target: &PreparedRecoveryTarget, outcome: &str) -> Result<(), Error> {
    let report = serde_json::json!({ "outcome": outcome, "target_id": crate::create_mesh_setup::format_uuid(target.target_id.as_bytes()),
        "node_id": crate::create_mesh_setup::format_uuid(target.node_id.as_bytes()),
        "marker_fingerprint": crate::update_candidate::hex(&target.marker_fingerprint),
        "generation": target.generation.to_string(), "service_started": false, "admission_ready": false,
        "scope": "Probed replacement folder only; not active registration, stored shards or restored protection" });
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, &report).map_err(|_| Error::Worker)?;
    output.write_all(b"\n").map_err(|_| Error::Worker)
}
