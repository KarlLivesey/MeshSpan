// SPDX-License-Identifier: GPL-2.0-only

//! Offline archive-to-file verification. No provider activation or plaintext file publication.

use super::RecoveryPreparationError as Error;
use crate::protected_file::{self, PublishMode};
use meshspan_api_contract::RecoveryStorageSelection;
use meshspan_contracts::{BoundedBytes, ContractVersion, RequestContext, ShardIdentity};
use meshspan_domain::{Clock as _, OperationId, TargetId, UnixMicros};
use meshspan_filesystem::{
    CommittedContentLayoutTransfer, ContentEncryptionKey, ContentReadError, DurableContentCatalog,
    RecoveryShardSource, VersionPublicationStore,
};
use meshspan_metadata::{AuthoritativeRepository, PartitionDatabase};
use meshspan_storage::{MarkerFingerprint, RecoveryFolder, RecoveryInventory};
use std::{
    collections::BTreeSet, ffi::OsString, fs, io::Write as _, os::unix::fs::DirBuilderExt as _,
    path::Path,
};

struct StorageSelection {
    maximum_copied_bytes: String,
    targets: Vec<SelectedTarget>,
}

struct SelectedTarget {
    target_id: String,
    generation: String,
    storage_path: String,
}

pub(crate) fn verify_content_command(arguments: &[OsString]) -> Result<(), Error> {
    let [prepared, bundle, code, source, selection, work] = arguments else {
        return Err(Error::ContentArguments);
    };
    let bundle = crate::offline_backup::read_bundle(Path::new(bundle)).map_err(|_| Error::Input)?;
    let authority = super::open_authority(&bundle, Path::new(code))?;
    let _guard = protected_file::open_read(Path::new(prepared)).map_err(|_| Error::Input)?;
    let repository = AuthoritativeRepository::new(
        PartitionDatabase::open_existing(Path::new(prepared), crate::OperatingSystemClock.now())
            .map_err(|_| Error::Input)?,
    );
    let authorization = repository.recovery_preparation_authorization(&authority)?;
    let bytes = protected_file::read_bounded(
        Path::new(selection),
        1,
        meshspan_api_contract::MAX_RECOVERY_SELECTION_BYTES,
    )
    .map_err(|_| Error::Input)?;
    let selected_input = meshspan_api_contract::decode_recovery_storage_selection(&bytes)
        .map_err(|_| Error::Input)?;
    let selected = StorageSelection::from_value(selected_input.clone())?;
    let work = std::env::current_dir()
        .map_err(|_| Error::Workspace)?
        .join(work);
    let work = isolated_destination(&selected_input, &work)?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&work)
        .map_err(|_| Error::Workspace)?;
    protected_file::sync_parent(&work).map_err(|_| Error::Workspace)?;
    // The prepared database supplies signed intent, never unsigned replacement source rows.
    drop(repository);
    let (repository, mut history, catalog) =
        restore_source(Path::new(source), &work, &authority, authorization.claims())?;
    let mut content = ContentCheck {
        inventory: selected.capture(
            &repository,
            authorization.claims().mesh_id,
            authorization.claims().backup_digest,
            &work.join("inventory"),
        )?,
        logical_bytes: 0,
        chunks: 0,
    };
    let (roots, manifests) = super::history::verify_content(
        &repository,
        &authority,
        &mut history,
        &catalog,
        &mut content,
    )?;
    let inventory = content.inventory.summary().map_err(|_| Error::Content)?;
    let inventory_digest = inventory_digest(
        &repository,
        &selected_input,
        &content.inventory,
        authorization.claims().backup_digest,
    )?;
    if inventory_digest != authorization.claims().target_inventory_digest {
        return Err(Error::Conflict);
    }
    let report = serde_json::json!({
        "content_verified": true,
        "recovery_id": crate::create_mesh_setup::format_uuid(authorization.claims().recovery_id.as_bytes()),
        "backup_sha256": crate::update_candidate::hex(&authorization.claims().backup_digest),
        "retained_roots_checked": roots.to_string(),
        "manifest_references_checked": manifests.to_string(),
        "logical_bytes_checked": content.logical_bytes.to_string(),
        "chunks_checked": content.chunks.to_string(),
        "pack_copies": inventory.packs.to_string(),
        "copied_source_bytes": inventory.copied_bytes.to_string(),
        "target_inventory_sha256": crate::update_candidate::hex(&inventory_digest),
        "target_inventory_verified": true, "admission_ready": false, "service_started": false,
        "scope": "Complete selected file-byte verification and signed inventory commitment; not restored protection or service admission"
    });
    let bytes = serde_json::to_vec(&report).map_err(|_| Error::Worker)?;
    protected_file::publish(&work.join("content.json"), &bytes, PublishMode::Create)
        .map_err(|_| Error::Workspace)?;
    let mut output = std::io::stdout().lock();
    output
        .write_all(&bytes)
        .and_then(|()| output.write_all(b"\n"))
        .map_err(|_| Error::Worker)
}

pub(super) fn restore_source(
    backup: &Path,
    work: &Path,
    authority: &meshspan_recovery_bundle::RecoveredAuthority,
    claims: &meshspan_recovery_bundle::RecoveryAuthorizationClaims,
) -> Result<
    (
        AuthoritativeRepository,
        VersionPublicationStore,
        DurableContentCatalog,
    ),
    Error,
> {
    let evidence = meshspan_backup::read_backup_evidence(backup, claims.backup_digest)
        .map_err(|_| Error::History)?;
    let source = evidence.source;
    if source.mesh_id != claims.mesh_id
        || source.partition_id != claims.partition_id
        || source.backup_id != claims.backup_id
        || source.last_log_index != claims.source_log_index
        || source.last_log_term != claims.source_log_term
        || source.state_revision != claims.source_revision.get()
    {
        return Err(Error::Authority);
    }
    let metadata = work.join("source.sqlite3");
    meshspan_backup::restore_backup_files(
        backup,
        meshspan_backup::BackupFiles {
            metadata: &metadata,
            history: Some(meshspan_backup::BackupHistoryFiles {
                namespace: &work.join("filesystem-branch.sqlite3"),
                content: &work.join("filesystem-content.sqlite3"),
            }),
        },
        evidence,
        authority.wrapping_key(),
    )
    .map_err(|_| Error::History)?;
    let now = crate::OperatingSystemClock.now();
    let repository = AuthoritativeRepository::new(meshspan_metadata::restore_partition_backup(
        &metadata,
        &work.join("verified.sqlite3"),
        crate::offline_backup::partition_manifest(evidence).partition,
        now,
    )?);
    fs::remove_file(metadata).map_err(|_| Error::Workspace)?;
    let stored = repository
        .mesh_recovery_authority(claims.mesh_id)?
        .ok_or(Error::Authority)?;
    if stored.root_certificate_der != authority.root_certificate_der()
        || stored.public_wrapping_key != authority.public_wrapping_key()
    {
        return Err(Error::Authority);
    }
    Ok((
        repository,
        VersionPublicationStore::open(work, now).map_err(|_| Error::History)?,
        DurableContentCatalog::open(work, now).map_err(|_| Error::History)?,
    ))
}

impl StorageSelection {
    fn from_value(decoded: RecoveryStorageSelection) -> Result<Self, Error> {
        let selected = Self {
            maximum_copied_bytes: decoded.maximum_copied_bytes,
            targets: decoded
                .targets
                .into_iter()
                .map(|target| SelectedTarget {
                    target_id: target.target_id,
                    generation: target.generation,
                    storage_path: target.storage_path,
                })
                .collect(),
        };
        positive(&selected.maximum_copied_bytes)?;
        if selected.targets.is_empty() || selected.targets.len() > 1024 {
            return Err(Error::Input);
        }
        let mut identities = BTreeSet::new();
        let mut paths = BTreeSet::new();
        for target in &selected.targets {
            let id = target.identity()?;
            let generation = positive(&target.generation)?;
            if target.storage_path.is_empty()
                || target.storage_path.len() > 16384
                || target.storage_path.contains('\0')
                || !identities.insert((id, generation))
                || !paths.insert(&target.storage_path)
            {
                return Err(Error::Input);
            }
        }
        Ok(selected)
    }

    fn capture(
        &self,
        repository: &AuthoritativeRepository,
        mesh: meshspan_domain::MeshId,
        scope: [u8; 32],
        directory: &Path,
    ) -> Result<RecoveryInventory, Error> {
        let mut inventory = match fs::symlink_metadata(directory) {
            Ok(_) => RecoveryInventory::open(directory, scope),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                RecoveryInventory::create(directory, scope, positive(&self.maximum_copied_bytes)?)
            }
            Err(_) => return Err(Error::Workspace),
        }
        .map_err(|_| Error::Content)?;
        let mut packs = 0_u64;
        for selected in &self.targets {
            let target = selected.identity()?;
            let generation = positive(&selected.generation)?;
            let marker = repository
                .recovery_storage_target_marker(target, generation)?
                .ok_or(Error::Content)?;
            let folder = RecoveryFolder::open(
                Path::new(&selected.storage_path),
                MarkerFingerprint::from_bytes(marker),
            )
            .map_err(|_| Error::Content)?;
            if folder.marker().mesh_id() != mesh
                || folder.marker().target_id() != target
                || folder.marker().generation() != generation
            {
                return Err(Error::Content);
            }
            for sequence in folder.pack_sequences().map_err(|_| Error::Content)? {
                inventory
                    .capture_pack(&folder, sequence.map_err(|_| Error::Content)?)
                    .map_err(|_| Error::Content)?;
                packs = packs.checked_add(1).ok_or(Error::Content)?;
            }
        }
        if inventory.summary().map_err(|_| Error::Content)?.packs != packs {
            return Err(Error::Content);
        }
        Ok(inventory)
    }
}

pub(super) fn isolated_destination(
    selected: &RecoveryStorageSelection,
    work: &Path,
) -> Result<std::path::PathBuf, Error> {
    StorageSelection::from_value(selected.clone())?;
    let parent =
        fs::canonicalize(work.parent().ok_or(Error::Workspace)?).map_err(|_| Error::Workspace)?;
    let work = parent.join(work.file_name().ok_or(Error::Workspace)?);
    for target in &selected.targets {
        match fs::canonicalize(&target.storage_path) {
            Ok(source) if work.starts_with(&source) => return Err(Error::Workspace),
            Ok(_) => {}
            // A published preparation can resume using retained copies after original media loss.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(Error::Input),
        }
    }
    Ok(work)
}

pub(super) fn prepare_inventory(
    source: &super::RecoverySource<'_>,
    repository: &AuthoritativeRepository,
    selected: &RecoveryStorageSelection,
    history_directory: &Path,
    inventory_directory: &Path,
) -> Result<[u8; 32], Error> {
    let selected_targets = StorageSelection::from_value(selected.clone())?;
    let mut content = ContentCheck {
        inventory: selected_targets.capture(
            repository,
            source.manifest.partition.mesh_id,
            source.manifest.encrypted.digest,
            inventory_directory,
        )?,
        logical_bytes: 0,
        chunks: 0,
    };
    let now = crate::OperatingSystemClock.now();
    let mut history =
        VersionPublicationStore::open(history_directory, now).map_err(|_| Error::History)?;
    let catalog =
        DurableContentCatalog::open(history_directory, now).map_err(|_| Error::History)?;
    super::history::verify_content(
        repository,
        source.authority,
        &mut history,
        &catalog,
        &mut content,
    )?;
    inventory_digest(
        repository,
        selected,
        &content.inventory,
        source.manifest.encrypted.digest,
    )
}

pub(super) fn prepared_inventory_digest(
    repository: &AuthoritativeRepository,
    selected: &RecoveryStorageSelection,
    directory: &Path,
    scope: [u8; 32],
) -> Result<[u8; 32], Error> {
    let inventory = RecoveryInventory::open(directory, scope).map_err(|_| Error::Content)?;
    inventory_digest(repository, selected, &inventory, scope)
}

fn inventory_digest(
    repository: &AuthoritativeRepository,
    selected: &RecoveryStorageSelection,
    inventory: &RecoveryInventory,
    scope: [u8; 32],
) -> Result<[u8; 32], Error> {
    let selected = StorageSelection::from_value(selected.clone())?;
    let mut targets = Vec::with_capacity(selected.targets.len());
    for target in &selected.targets {
        let id = target.identity()?;
        let generation = positive(&target.generation)?;
        let marker = repository
            .recovery_storage_target_marker(id, generation)?
            .ok_or(Error::Content)?;
        targets.push((id, generation, marker));
    }
    targets.sort_unstable();
    let mut digest = super::publication::DigestWriter::new();
    digest
        .write_all(b"MeshSpan recovery inventory v1\0")
        .map_err(|_| Error::Worker)?;
    digest.write_all(&scope).map_err(|_| Error::Worker)?;
    digest
        .write_all(
            &u64::try_from(targets.len())
                .map_err(|_| Error::Content)?
                .to_be_bytes(),
        )
        .map_err(|_| Error::Worker)?;
    for (id, generation, marker) in targets {
        digest
            .write_all(&id.as_bytes())
            .and_then(|()| digest.write_all(&generation.to_be_bytes()))
            .and_then(|()| digest.write_all(&marker))
            .map_err(|_| Error::Worker)?;
    }
    inventory
        .write_manifest(&mut digest)
        .map_err(|_| Error::Content)?;
    Ok(digest.finish().0)
}

impl SelectedTarget {
    fn identity(&self) -> Result<TargetId, Error> {
        let target = TargetId::parse(&self.target_id.replace('-', "")).map_err(|_| Error::Input)?;
        if crate::create_mesh_setup::format_uuid(target.as_bytes()) != self.target_id {
            return Err(Error::Input);
        }
        Ok(target)
    }
}

fn positive(value: &str) -> Result<u64, Error> {
    let parsed = value.parse::<u64>().map_err(|_| Error::Input)?;
    if parsed == 0 || i64::try_from(parsed).is_err() || parsed.to_string() != value {
        return Err(Error::Input);
    }
    Ok(parsed)
}

pub(super) struct ContentCheck {
    inventory: RecoveryInventory,
    logical_bytes: u64,
    chunks: u64,
}

impl ContentCheck {
    pub(super) fn verify(
        &mut self,
        layout: &CommittedContentLayoutTransfer<'_>,
        key: ContentEncryptionKey,
    ) -> Result<(), Error> {
        let context = RequestContext {
            contract_version: ContractVersion::V1_0,
            operation_id: OperationId::from_bytes(layout.header().manifest.manifest_id.as_bytes())
                .map_err(|_| Error::Content)?,
            deadline: UnixMicros::new(i64::MAX),
            expected_revision: None,
        };
        let verified = layout
            .recover_to(
                context,
                key,
                &meshspan_coding::ReedSolomonCoding::new(),
                self,
                &mut std::io::sink(),
            )
            .map_err(|_| Error::Content)?;
        self.logical_bytes = self
            .logical_bytes
            .checked_add(verified.logical_length)
            .ok_or(Error::Content)?;
        self.chunks = self
            .chunks
            .checked_add(verified.chunks)
            .ok_or(Error::Content)?;
        Ok(())
    }
}

impl RecoveryShardSource for ContentCheck {
    fn read_candidate(
        &mut self,
        shard: ShardIdentity,
        length: u64,
        digest: [u8; 32],
    ) -> Result<Option<BoundedBytes>, ContentReadError> {
        self.inventory
            .read_exact(shard, length, digest)
            .map_err(|_| ContentReadError::Unavailable)
    }
}

impl super::history::HistoryContentVisitor for ContentCheck {
    fn visit(
        &mut self,
        layout: &CommittedContentLayoutTransfer<'_>,
        key: Option<ContentEncryptionKey>,
    ) -> Result<(), Error> {
        self.verify(layout, key.ok_or(Error::History)?)
    }
}
