// SPDX-License-Identifier: GPL-2.0-only

//! Isolated donor-history staging. No source writes, shard availability or service admission.

use super::RecoveryPreparationError as Error;
use crate::protected_file::{self, PublishMode};
use meshspan_domain::{Clock as _, DurationMicros, VolumeId};
use meshspan_filesystem::{
    CommittedContentLayoutTransfer, ContentEncryptionKey, ContentKeyEnvelopeCipher,
    DurableContentCatalog, ManifestPublication, NamespaceHistoryObjectRequest,
    NamespaceHistoryPageRequest, VersionPublicationStore, VolumeKeyEncryptionKey,
};
use meshspan_metadata::{
    AuthoritativeRepository, PageLimit, PartitionDatabase, RetainedNamespaceRoot,
    RetainedNamespaceRootSource, VOLUME_CONTENT_KEY_SECRET_KIND,
};
use meshspan_recovery_bundle::RecoveredAuthority;
use std::{
    ffi::OsString,
    fs::{self, DirBuilder, File},
    io::Write as _,
    os::unix::fs::{DirBuilderExt as _, PermissionsExt as _},
    path::Path,
};

pub(crate) fn stage_history_command(arguments: &[OsString]) -> Result<(), Error> {
    let [prepared, bundle, code, source, work] = arguments else {
        return Err(Error::HistoryArguments);
    };
    let bundle = crate::offline_backup::read_bundle(Path::new(bundle)).map_err(|_| Error::Input)?;
    let authority = super::open_authority(&bundle, Path::new(code))?;
    let _guard = protected_file::open_read(Path::new(prepared)).map_err(|_| Error::Input)?;
    let repository = AuthoritativeRepository::new(
        PartitionDatabase::open_existing(Path::new(prepared), crate::OperatingSystemClock.now())
            .map_err(|_| Error::Input)?,
    );
    let authorization = repository.recovery_preparation_authorization(&authority)?;
    let work = std::env::current_dir()
        .map_err(|_| Error::Workspace)?
        .join(work);
    DirBuilder::new()
        .mode(0o700)
        .create(&work)
        .map_err(|_| Error::Workspace)?;
    protected_file::sync_parent(&work).map_err(|_| Error::Workspace)?;
    let now = crate::OperatingSystemClock.now();
    let from_backup = !fs::symlink_metadata(source)
        .map_err(|_| Error::Input)?
        .is_dir();
    let (mut history, catalog) = if from_backup {
        restore_archived_history(Path::new(source), &work, &authority, authorization.claims())?
    } else {
        meshspan_filesystem::snapshot_recovery_journals(Path::new(source), &work, now)
            .map_err(|_| Error::History)?
    };
    let mut checked = HistoryCheck {
        repository: &repository,
        authority: Some(&authority),
        history: &mut history,
        catalog: &catalog,
        roots: 0,
        manifests: 0,
        content: None,
    };
    checked.verify_roots()?;
    let report = serde_json::json!({"staged": true,
        "recovery_id": crate::create_mesh_setup::format_uuid(authorization.claims().recovery_id.as_bytes()),
        "source_log_index": authorization.claims().source_log_index.to_string(),
        "source_revision": authorization.claims().source_revision.get().to_string(),
        "retained_roots_checked": checked.roots.to_string(),
        "manifest_references_checked": checked.manifests.to_string(),
        "history_source": if from_backup { "authenticated_backup" } else { "surviving_journals" },
        "shards_verified": false, "admission_ready": false, "service_started": false,
        "scope": "Isolated surviving history and layout/key-reference checks; not file-byte recovery or authority to serve donor branches"});
    drop(catalog);
    drop(history);
    for name in ["filesystem-branch.sqlite3", "filesystem-content.sqlite3"] {
        let file = File::open(work.join(name)).map_err(|_| Error::Workspace)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .and_then(|()| file.sync_all())
            .map_err(|_| Error::Workspace)?;
    }
    let bytes = serde_json::to_vec(&report).map_err(|_| Error::Worker)?;
    protected_file::publish(&work.join("history.json"), &bytes, PublishMode::Create)
        .map_err(|_| Error::Workspace)?;
    let mut output = std::io::stdout().lock();
    output
        .write_all(&bytes)
        .and_then(|()| output.write_all(b"\n"))
        .map_err(|_| Error::Worker)
}

pub(super) fn restore_archived_history(
    backup: &Path,
    work: &Path,
    authority: &RecoveredAuthority,
    claims: &meshspan_recovery_bundle::RecoveryAuthorizationClaims,
) -> Result<(VersionPublicationStore, DurableContentCatalog), Error> {
    let evidence = meshspan_backup::read_backup_evidence(backup, claims.backup_digest)
        .map_err(|_| Error::History)?;
    if evidence.source.backup_id != claims.backup_id {
        return Err(Error::History);
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
    fs::remove_file(metadata).map_err(|_| Error::Workspace)?;
    let now = crate::OperatingSystemClock.now();
    Ok((
        VersionPublicationStore::open(work, now).map_err(|_| Error::History)?,
        DurableContentCatalog::open(work, now).map_err(|_| Error::History)?,
    ))
}

/// Producer-side structural closure check. Offline restoration additionally decrypts every key.
pub(crate) fn verify_backup_history(
    repository: &AuthoritativeRepository,
    history: &mut VersionPublicationStore,
    catalog: &DurableContentCatalog,
) -> Result<(), Error> {
    HistoryCheck {
        repository,
        authority: None,
        history,
        catalog,
        roots: 0,
        manifests: 0,
        content: None,
    }
    .verify_roots()
}

pub(super) fn verify_content(
    repository: &AuthoritativeRepository,
    authority: &RecoveredAuthority,
    history: &mut VersionPublicationStore,
    catalog: &DurableContentCatalog,
    content: &mut super::content::ContentCheck,
) -> Result<(u64, u64), Error> {
    let mut checked = HistoryCheck {
        repository,
        authority: Some(authority),
        history,
        catalog,
        roots: 0,
        manifests: 0,
        content: Some(content),
    };
    checked.verify_roots()?;
    Ok((checked.roots, checked.manifests))
}

struct HistoryCheck<'a> {
    repository: &'a AuthoritativeRepository,
    authority: Option<&'a RecoveredAuthority>,
    history: &'a mut VersionPublicationStore,
    catalog: &'a DurableContentCatalog,
    roots: u64,
    manifests: u64,
    content: Option<&'a mut dyn HistoryContentVisitor>,
}

/// Visits each authenticated retained manifest; storage-only restoration needs no plaintext key.
pub(super) trait HistoryContentVisitor {
    fn visit(
        &mut self,
        layout: &CommittedContentLayoutTransfer<'_>,
        key: Option<ContentEncryptionKey>,
    ) -> Result<(), Error>;
}

pub(super) fn visit_retained_content(
    repository: &AuthoritativeRepository,
    history: &mut VersionPublicationStore,
    catalog: &DurableContentCatalog,
    visitor: &mut impl HistoryContentVisitor,
) -> Result<(), Error> {
    HistoryCheck {
        repository,
        authority: None,
        history,
        catalog,
        roots: 0,
        manifests: 0,
        content: Some(visitor),
    }
    .verify_roots()
}

impl HistoryCheck<'_> {
    fn verify_roots(&mut self) -> Result<(), Error> {
        let limit = PageLimit::new(128).map_err(|_| Error::History)?;
        let revision = self.repository.current_revision()?;
        let mut after_volume = None;
        loop {
            let volumes = self.repository.volume_identity_page(after_volume, limit)?;
            for volume in volumes.items {
                let mut after_root = None;
                loop {
                    let page = self
                        .repository
                        .retained_namespace_roots(volume, revision, after_root, limit)?;
                    for root in page.roots {
                        self.verify_root(volume, root)?;
                    }
                    match page.next {
                        Some(next) => after_root = Some(next),
                        None => break,
                    }
                }
            }
            match volumes.next {
                Some(next) => after_volume = Some(next),
                None => return Ok(()),
            }
        }
    }

    fn verify_root(&mut self, volume: VolumeId, root: RetainedNamespaceRoot) -> Result<(), Error> {
        // Each archive captures current heads and user snapshots, not other archives'
        // retention. Inheriting those pins would keep retired backups' data forever.
        if matches!(root.source, RetainedNamespaceRootSource::Backup(_)) {
            return Ok(());
        }
        if self
            .history
            .namespace_commit_coordinates(root.namespace_commit_id)
            .map_err(|_| Error::History)?
            != (volume, root.root_object_revision_id)
        {
            return Err(Error::History);
        }
        let mut cursor = Vec::new();
        // Local copied-journal export only. No network grant or external authority is minted.
        let scope_binding = *blake3::hash(&root.namespace_commit_id.as_bytes()).as_bytes();
        loop {
            let now = crate::OperatingSystemClock.now();
            let page = self
                .history
                .namespace_retained_tree_page(NamespaceHistoryPageRequest {
                    scope_binding,
                    volume_id: volume,
                    requested_heads: vec![root.namespace_commit_id],
                    known_commits: Vec::new(),
                    cursor,
                    limit: 128,
                    now,
                    expires_at: now
                        .checked_add(DurationMicros::new(3_600_000_000))
                        .ok_or(Error::History)?,
                })
                .map_err(|_| Error::History)?;
            for object_digest in page.immutable_object_digests {
                let object = self
                    .history
                    .namespace_history_object(NamespaceHistoryObjectRequest {
                        scope_binding,
                        export_token: page.export_token,
                        object_digest,
                        now,
                    })
                    .map_err(|_| Error::History)?;
                if let Some(manifest) = object.as_manifest().map_err(|_| Error::History)? {
                    self.verify_manifest(volume, manifest)?;
                }
            }
            if page.next_cursor.is_empty() {
                break;
            }
            cursor = page.next_cursor;
        }
        self.roots = self.roots.checked_add(1).ok_or(Error::History)?;
        Ok(())
    }

    fn verify_manifest(
        &mut self,
        volume: VolumeId,
        manifest: ManifestPublication,
    ) -> Result<(), Error> {
        let publication = self
            .catalog
            .committed_content_by_manifest(manifest.manifest_id)
            .map_err(|_| Error::History)?
            .ok_or(Error::History)?;
        let transfer = self
            .catalog
            .committed_layout_transfer(publication)
            .map_err(|_| Error::History)?;
        let header = transfer.header();
        if transfer.volume_id() != volume || header.manifest != manifest {
            return Err(Error::History);
        }
        let context = meshspan_secret_envelope::SecretContext::new(
            VOLUME_CONTENT_KEY_SECRET_KIND,
            volume.as_bytes(),
            header.wrapped_key.key_generation,
        )
        .map_err(|_| Error::History)?;
        let record = self
            .repository
            .secret_generation(context)?
            .ok_or(Error::History)?;
        let key = if let Some(authority) = self.authority {
            let plaintext = authority
                .open_secret(&record.secret, &record.recipients)
                .map_err(|_| Error::History)?;
            if plaintext.expose().len() != 32 {
                return Err(Error::History);
            }
            let mut bytes = zeroize::Zeroizing::new([0; 32]);
            bytes.copy_from_slice(plaintext.expose());
            let cipher = ContentKeyEnvelopeCipher::new(
                VolumeKeyEncryptionKey::from_protected_bytes(context.generation(), bytes)
                    .map_err(|_| Error::History)?,
            );
            Some(
                cipher
                    .unwrap(manifest.manifest_id, header.wrapped_key)
                    .map_err(|_| Error::History)?,
            )
        } else {
            None
        };
        if let Some(content) = self.content.as_deref_mut() {
            content.visit(&transfer, key)?;
        }
        self.manifests = self.manifests.checked_add(1).ok_or(Error::History)?;
        Ok(())
    }
}
