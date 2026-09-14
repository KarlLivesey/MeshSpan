// SPDX-License-Identifier: GPL-2.0-only

//! Independent archive comparison precedes atomic coordinator receipt retention.

use super::{Error, receipt_reader::ReceiptReader};
use crate::protected_file;
use meshspan_domain::Clock as _;
use meshspan_filesystem::{CommittedContentLayoutTransfer, ContentEncryptionKey};
use meshspan_metadata::{AuthoritativeRepository, PartitionDatabase, RecoveryShardRestoration};
use sha2::{Digest as _, Sha256};
use std::{
    ffi::OsString,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
};

pub(in super::super) fn collect_command(arguments: &[OsString]) -> Result<(), Error> {
    let [prepared, bundle_file, code, backup, report_directory, work] = arguments else {
        return Err(Error::RestorationCollectionArguments);
    };
    let bundle =
        crate::offline_backup::read_bundle(Path::new(bundle_file)).map_err(|_| Error::Input)?;
    let authority = super::super::open_authority(&bundle, Path::new(code))?;
    let report_directory = Path::new(report_directory);
    let encoded =
        protected_file::read_bounded(&report_directory.join("restored.json"), 1, 16 * 1024)
            .map_err(|_| Error::Input)?;
    let report = meshspan_api_contract::decode_recovery_restoration_attestation(&encoded)
        .map_err(|_| Error::Input)?;
    let claim = RecoveryShardRestoration::decode_message(
        authority.root_certificate_der(),
        &report.message,
    )?;
    if report.receipt_count != claim.receipt_count
        || report.encrypted_bytes != claim.encrypted_bytes
        || report.receipts_digest != claim.receipts_digest
    {
        return Err(Error::Content);
    }
    let _guard = protected_file::open_read(Path::new(prepared)).map_err(|_| Error::Input)?;
    let mut repository = AuthoritativeRepository::new(
        PartitionDatabase::open_existing(Path::new(prepared), crate::OperatingSystemClock.now())
            .map_err(|_| Error::Input)?,
    );
    repository.verify_recovery_restoration(&authority, (&claim, &report.signature))?;
    let work = isolated_work(
        Path::new(work),
        [
            Path::new(prepared),
            Path::new(bundle_file),
            Path::new(code),
            Path::new(backup),
            report_directory,
        ],
    )?;
    let mut intent = Sha256::new();
    intent.update(b"MeshSpan restoration collection v1\0");
    intent.update(&report.message);
    intent.update(&report.signature);
    let workspace = super::super::workspace::Workspace::open(&work, &intent.finalize().into())?;
    let build = workspace.begin_build()?;
    let (source, mut history, catalog) = super::super::content::restore_source(
        Path::new(backup),
        &build,
        &authority,
        claim.target.authorization.claims(),
    )?;
    let snapshot = build.join("receipts.bin");
    let reader = ReceiptReader::open(
        &report_directory.join("receipts.bin"),
        &claim,
        Some(&snapshot),
    )?;
    let mut comparison = ArchiveComparison {
        reader,
        claim: &claim,
    };
    super::super::history::visit_retained_content(
        &source,
        &mut history,
        &catalog,
        &mut comparison,
    )?;
    comparison.reader.finish()?;
    let input = ReceiptReader::open(&snapshot, &claim, None)?;
    let result = repository.record_recovery_restoration(
        &authority,
        (&claim, &report.signature),
        input.map(|receipt| receipt.map_err(|_| meshspan_metadata::RepositoryError::CorruptState)),
        crate::OperatingSystemClock.now(),
    )?;
    drop(catalog);
    drop(history);
    drop(source);
    drop(repository);
    workspace.cleanup_build()?;
    let output = serde_json::json!({"recorded": true, "archive_matched": true, "service_started": false, "admission_ready": false,
        "target_id": crate::create_mesh_setup::format_uuid(claim.target.target_id.as_bytes()),
        "receipt_count": claim.receipt_count.to_string(), "recorded_at_unix_micros": result.recorded_at.get().to_string(),
        "scope": "Complete signed receipt stream matched to the authenticated archive; not live routes or service admission"});
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &output).map_err(|_| Error::Worker)?;
    stdout.write_all(b"\n").map_err(|_| Error::Worker)
}

struct ArchiveComparison<'a> {
    reader: ReceiptReader<'a>,
    claim: &'a RecoveryShardRestoration,
}

impl super::super::history::HistoryContentVisitor for ArchiveComparison<'_> {
    fn visit(
        &mut self,
        layout: &CommittedContentLayoutTransfer<'_>,
        _key: Option<ContentEncryptionKey>,
    ) -> Result<(), Error> {
        for index in 0..layout.header().chunk_count {
            let stripe = layout.recovery_stripe(index).map_err(|_| Error::History)?;
            for source in stripe.receipts.as_slice().iter().filter(|receipt| {
                receipt.target_id == self.claim.source_target_id
                    && receipt.target_generation == self.claim.source_generation
            }) {
                let mut expected = *source;
                expected.operation_id = super::replacement_operation(&self.claim.target, *source)?;
                expected.target_id = self.claim.target.target_id;
                expected.target_generation = self.claim.target.generation;
                if self.reader.next().ok_or(Error::Content)?? != expected {
                    return Err(Error::Content);
                }
            }
        }
        Ok(())
    }
}

fn isolated_work(work: &Path, inputs: [&Path; 5]) -> Result<PathBuf, Error> {
    let absolute = std::env::current_dir()
        .map_err(|_| Error::Workspace)?
        .join(work);
    let parent = fs::canonicalize(absolute.parent().ok_or(Error::Workspace)?)
        .map_err(|_| Error::Workspace)?;
    let work = parent.join(absolute.file_name().ok_or(Error::Workspace)?);
    for input in inputs {
        let input = fs::canonicalize(input).map_err(|_| Error::Input)?;
        if input.starts_with(&work) || work.starts_with(&input) {
            return Err(Error::Workspace);
        }
    }
    Ok(work)
}
