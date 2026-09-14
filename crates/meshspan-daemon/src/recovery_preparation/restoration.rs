// SPDX-License-Identifier: GPL-2.0-only

//! Node-owned physical restoration from independently authenticated encrypted state.

mod collection;
mod receipt_reader;
mod writer;
pub(super) use collection::collect_command;

use super::{RecoveryPreparationError as Error, publication, workspace::Workspace};
use crate::protected_file;
use meshspan_domain::{Clock as _, RandomSource as _, TargetId};
use meshspan_metadata::{
    AuthoritativeRepository, PartitionDatabase, PreparedRecoveryTarget, StorageUsageLimit,
};
use meshspan_storage::{
    CapacityPolicy, FolderRegistration, FolderShardStore, MarkerFingerprint, RegisteredFolder,
    StoragePermitVerifier, UsageLimit,
};
use sha2::{Digest as _, Sha256};
use std::{
    ffi::OsString,
    fs,
    io::{self, Write as _},
    path::Path,
};

pub(super) fn run_command(arguments: &[OsString]) -> Result<(), Error> {
    let [
        package,
        root,
        identity_file,
        wrapping_file,
        target_work,
        request_file,
    ] = arguments
    else {
        return Err(Error::TargetRestoreArguments);
    };
    let identity =
        crate::LocalNodeIdentity::open(Path::new(identity_file), "meshspan-recovery.invalid")
            .map_err(|_| Error::Input)?;
    let wrapping =
        crate::LocalWrappingKey::open(Path::new(wrapping_file)).map_err(|_| Error::Input)?;
    let (transfer, _) = super::targets::verify_recipient(
        Path::new(package),
        Path::new(root),
        &identity,
        &wrapping,
    )?;
    let target_work = fs::canonicalize(target_work).map_err(|_| Error::Workspace)?;
    let target = load_target(&target_work, &transfer, &identity, Path::new(root))?;
    let request_bytes = protected_file::read_bounded(Path::new(request_file), 1, 32 * 1024)
        .map_err(|_| Error::Input)?;
    let request = meshspan_api_contract::decode_recovery_target_restore_request(&request_bytes)
        .map_err(|_| Error::Input)?;
    let source = (
        TargetId::from_bytes(
            crate::create_mesh_setup::parse_uuid(&request.source_target_id)
                .map_err(|_| Error::Input)?,
        )
        .map_err(|_| Error::Input)?,
        request
            .source_generation
            .parse::<u64>()
            .map_err(|_| Error::Input)?,
    );
    if source.1 == 0 || source.1 > i64::MAX.unsigned_abs() || source.0 == target.target_id {
        return Err(Error::Input);
    }
    let folder = fs::canonicalize(request.path.as_str()).map_err(|_| Error::Input)?;
    let inventory =
        fs::canonicalize(request.inventory_directory.as_str()).map_err(|_| Error::Input)?;
    if target_work.starts_with(&folder)
        || target_work.starts_with(&inventory)
        || folder.starts_with(&inventory)
        || inventory.starts_with(&folder)
    {
        return Err(Error::Workspace);
    }
    let destination =
        target_work.join(format!("restore-{}-{}", request.source_target_id, source.1));
    let mut intent = Sha256::new();
    intent.update(b"MeshSpan target restoration intent v1\0");
    intent.update(transfer.encode().map_err(|_| Error::Authority)?);
    intent.update(target.installation_message()?);
    intent.update(source.0.as_bytes());
    intent.update(source.1.to_be_bytes());
    let workspace = Workspace::open(&destination, &intent.finalize().into())?;
    workspace.cleanup_build()?;
    let build = workspace.build_directory();
    // Always restore fresh authenticated source files. A changed local SQLite row is not authority.
    super::state_transfer::install_into(&[
        package.clone(),
        root.clone(),
        crate::create_mesh_setup::format_uuid(target.node_id.as_bytes()).into(),
        identity_file.clone(),
        wrapping_file.clone(),
        build.clone().into_os_string(),
    ])?;
    let result = restore(&target, source, &folder, &inventory, (&build, &target_work))?;
    let report = publish_result(
        &workspace,
        &destination,
        &target,
        source,
        (&identity, result),
    )?;
    workspace.cleanup_build()?;
    let mut output = io::stdout().lock();
    output
        .write_all(&report)
        .and_then(|()| output.write_all(b"\n"))
        .map_err(|_| Error::Worker)
}

pub(super) fn load_target(
    work: &Path,
    transfer: &meshspan_recovery_bundle::RecoveryStateTransfer,
    identity: &crate::LocalNodeIdentity,
    root: &Path,
) -> Result<PreparedRecoveryTarget, Error> {
    let root = protected_file::read_bounded(root, 1, 8192).map_err(|_| Error::Input)?;
    let bytes = protected_file::read_bounded(&work.join("target.report"), 1, 512)
        .map_err(|_| Error::Input)?;
    let (target, signature) = PreparedRecoveryTarget::decode_report(&root, &bytes)?;
    if target.authorization != transfer.claims().authorization
        || target.node_id != transfer.claims().node_id
        || target.incarnation != transfer.claims().incarnation
    {
        return Err(Error::Authority);
    }
    meshspan_certificates::NodePublicIdentity::from_sec1(identity.public_key_sec1())
        .map_err(|_| Error::Authority)?
        .verify_enrolment_transcript(&target.installation_message()?, &signature)
        .map_err(|_| Error::Authority)?;
    Ok(target)
}

fn restore(
    target: &PreparedRecoveryTarget,
    source: (TargetId, u64),
    folder: &Path,
    inventory: &Path,
    directories: (&Path, &Path),
) -> Result<writer::RestorationResult, Error> {
    let (build, target_work) = directories;
    let now = crate::OperatingSystemClock.now();
    let database = PartitionDatabase::open_existing(&build.join("prepared.sqlite3"), now)
        .map_err(|_| Error::Material)?;
    database.check_integrity().map_err(|_| Error::Material)?;
    let repository = AuthoritativeRepository::new(database);
    if repository
        .recovery_storage_target_marker(source.0, source.1)?
        .is_none()
    {
        return Err(Error::Authority);
    }
    let mut provider = open_provider(target, folder, target_work, false)?;
    writer::restore_retained(
        &repository,
        target,
        source,
        &mut provider,
        (build, inventory),
    )
}

pub(super) fn open_provider(
    target: &PreparedRecoveryTarget,
    folder: &Path,
    work: &Path,
    require_existing: bool,
) -> Result<FolderShardStore, Error> {
    let claims = target.authorization.claims();
    let usage_limit = match target.usage_limit {
        StorageUsageLimit::Percent(value) => UsageLimit::Percent(value),
        StorageUsageLimit::Bytes(value) => UsageLimit::Bytes(value),
    };
    let folder = RegisteredFolder::reopen(
        folder,
        FolderRegistration {
            mesh_id: claims.mesh_id,
            target_id: target.target_id,
            generation: target.generation,
            usage_limit,
        },
        MarkerFingerprint::from_bytes(target.marker_fingerprint),
    )
    .map_err(|_| Error::Content)?;
    // This process exposes no provider endpoint. Its fresh, unpublished MAC key cannot authorise
    // live reads/removals; normal admission must reopen the provider under actual mesh authority.
    let mut bytes = [0; 32];
    crate::OperatingSystemRandom
        .fill_bytes(&mut bytes)
        .map_err(|_| Error::Worker)?;
    let key =
        meshspan_contracts::StoragePermitMacKey::from_bytes(bytes).map_err(|_| Error::Worker)?;
    let permits = StoragePermitVerifier::new(
        claims.mesh_id,
        claims.recovery_epoch,
        claims.source_revision,
        key,
    )
    .map_err(|_| Error::Content)?;
    let open = if require_existing {
        FolderShardStore::reopen
    } else {
        FolderShardStore::open
    };
    open(
        folder,
        work,
        CapacityPolicy {
            usage_limit,
            repair_reserve_bytes: 0,
            revision: claims.source_revision,
        },
        permits,
        crate::OperatingSystemClock.now(),
        &mut crate::OperatingSystemRandom,
    )
    .map_err(|_| Error::Content)
}

fn publish_result(
    workspace: &Workspace,
    destination: &Path,
    target: &PreparedRecoveryTarget,
    source: (TargetId, u64),
    result: (&crate::LocalNodeIdentity, writer::RestorationResult),
) -> Result<Vec<u8>, Error> {
    let (identity, result) = result;
    let message = meshspan_metadata::RecoveryShardRestoration {
        target: target.clone(),
        source_target_id: source.0,
        source_generation: source.1,
        receipts_digest: result.digest,
        receipt_count: result.receipts,
        encrypted_bytes: result.bytes,
    }
    .installation_message()?;
    let signature = identity
        .sign_enrolment_transcript(&message)
        .map_err(|_| Error::Worker)?;
    let saved = destination.join("receipts.bin");
    match protected_file::open_read(&saved) {
        Ok(mut file) => {
            let mut digest = publication::DigestWriter::new();
            io::copy(&mut file, &mut digest).map_err(|_| Error::Workspace)?;
            if digest.finish().0 != result.digest {
                return Err(Error::Conflict);
            }
        }
        Err(protected_file::ProtectedFileError::Missing) => {
            fs::hard_link(workspace.build_directory().join("receipts.bin"), &saved)
                .map_err(|_| Error::Workspace)?;
            protected_file::sync_parent(&saved).map_err(|_| Error::Workspace)?;
        }
        Err(_) => return Err(Error::Workspace),
    }
    let report = serde_json::json!({"restored": true, "service_started": false, "admission_ready": false,
        "receipt_count": result.receipts.to_string(), "encrypted_bytes": result.bytes.to_string(),
        "receipts_sha256": crate::update_candidate::hex(&result.digest),
        "installation_message": crate::update_candidate::hex(&message), "installation_signature": crate::update_candidate::hex(&signature),
        "scope": "Durable physical shard copies only; no active routes, membership or protection claim"});
    let bytes = serde_json::to_vec(&report).map_err(|_| Error::Worker)?;
    publication::publish_exact(workspace, destination, "restored.json", &bytes)?;
    Ok(bytes)
}

pub(super) fn replacement_operation(
    target: &PreparedRecoveryTarget,
    receipt: meshspan_contracts::ShardReceipt,
) -> Result<meshspan_domain::OperationId, Error> {
    let mut digest = Sha256::new();
    digest.update(b"MeshSpan recovery shard operation v1\0");
    digest.update(target.authorization.claims().recovery_id.as_bytes());
    digest.update(target.target_id.as_bytes());
    digest.update(target.generation.to_be_bytes());
    digest.update(meshspan_contracts::encode_shard_receipt_v1(receipt));
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest.finalize()[..16]);
    meshspan_domain::OperationId::from_bytes(meshspan_domain::uuid_v8(bytes))
        .map_err(|_| Error::Content)
}
