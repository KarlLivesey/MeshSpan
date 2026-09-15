// SPDX-License-Identifier: GPL-2.0-only

//! Retained-tree traversal, one-stripe reconstruction and streamed normal-provider receipts.

use super::Error;
use meshspan_contracts::{BoundedBytes, ShardIdentity, ShardReceipt};
use meshspan_domain::{Clock as _, TargetId, UnixMicros};
use meshspan_filesystem::{
    CommittedContentLayoutTransfer, ContentEncryptionKey, ContentReadError, DurableContentCatalog,
    RecoveryShardSource, ShardRepairRequest, VersionPublicationStore,
};
use meshspan_metadata::{AuthoritativeRepository, PreparedRecoveryTarget};
use meshspan_storage::{FolderShardStore, RecoveryInventory};
use sha2::{Digest as _, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::Write as _,
    os::unix::fs::OpenOptionsExt as _,
    path::Path,
};

pub(super) struct RestorationResult {
    pub digest: [u8; 32],
    pub receipts: u64,
    pub bytes: u64,
}

pub(super) fn restore_retained(
    repository: &AuthoritativeRepository,
    target: &PreparedRecoveryTarget,
    source: (TargetId, u64),
    provider: &mut FolderShardStore,
    directories: (&Path, &Path),
) -> Result<RestorationResult, Error> {
    let (build, inventory) = directories;
    let now = crate::OperatingSystemClock.now();
    let mut history = VersionPublicationStore::open(build, now).map_err(|_| Error::History)?;
    let catalog = DurableContentCatalog::open(build, now).map_err(|_| Error::History)?;
    let mut writer = RestorationWriter {
        target,
        source,
        provider,
        inventory: Inventory(
            RecoveryInventory::open(inventory, target.authorization.claims().backup_digest)
                .map_err(|_| Error::Content)?,
        ),
        output: OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(build.join("receipts.bin"))
            .map_err(|_| Error::Workspace)?,
        digest: Sha256::new(),
        receipts: 0,
        bytes: 0,
    };
    writer.write(b"MSRRCPT\x01")?;
    super::super::history::visit_retained_content(repository, &mut history, &catalog, &mut writer)?;
    writer.output.sync_all().map_err(|_| Error::Workspace)?;
    Ok(RestorationResult {
        digest: writer.digest.finalize().into(),
        receipts: writer.receipts,
        bytes: writer.bytes,
    })
}

struct RestorationWriter<'a> {
    target: &'a PreparedRecoveryTarget,
    source: (TargetId, u64),
    provider: &'a mut FolderShardStore,
    inventory: Inventory,
    output: File,
    digest: Sha256,
    receipts: u64,
    bytes: u64,
}

impl super::super::history::HistoryContentVisitor for RestorationWriter<'_> {
    fn visit(
        &mut self,
        layout: &CommittedContentLayoutTransfer<'_>,
        _key: Option<ContentEncryptionKey>,
    ) -> Result<(), Error> {
        for index in 0..layout.header().chunk_count {
            let stripe = layout.recovery_stripe(index).map_err(|_| Error::History)?;
            let now = crate::OperatingSystemClock.now();
            let requests = stripe
                .receipts
                .as_slice()
                .iter()
                .filter(|receipt| (receipt.target_id, receipt.target_generation) == self.source)
                .map(|receipt| self.request(*receipt, now))
                .collect::<Result<Vec<_>, _>>()?;
            if requests.is_empty() {
                continue;
            }
            let receipts = meshspan_filesystem::restore_recovery_stripe(
                &requests,
                &stripe,
                &meshspan_coding::ReedSolomonCoding::new(),
                &mut self.inventory,
                self.provider,
            )
            .map_err(|_| Error::Content)?;
            for receipt in receipts.as_slice() {
                self.record(*receipt)?;
            }
        }
        Ok(())
    }
}

impl RestorationWriter<'_> {
    fn request(&self, receipt: ShardReceipt, now: UnixMicros) -> Result<ShardRepairRequest, Error> {
        Ok(ShardRepairRequest {
            replacement_operation_id: super::replacement_operation(self.target, receipt)?,
            source_receipt: receipt,
            replacement_target_id: self.target.target_id,
            replacement_target_generation: self.target.generation,
            replacement_shard_generation: receipt.shard.generation,
            authorization_revision: self.target.authorization.claims().source_revision,
            // A local durable recovery intent, not a remotely usable expiring capability.
            deadline: UnixMicros::new(i64::MAX),
            observed_at: now,
        })
    }

    fn record(&mut self, receipt: ShardReceipt) -> Result<(), Error> {
        let bytes = meshspan_data_plane::encode_shard_receipt(receipt);
        self.write(
            &u16::try_from(bytes.len())
                .map_err(|_| Error::Content)?
                .to_be_bytes(),
        )?;
        self.write(&bytes)?;
        self.receipts = self.receipts.checked_add(1).ok_or(Error::Content)?;
        self.bytes = self
            .bytes
            .checked_add(receipt.length)
            .ok_or(Error::Content)?;
        Ok(())
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.output.write_all(bytes).map_err(|_| Error::Workspace)?;
        self.digest.update(bytes);
        Ok(())
    }
}

struct Inventory(RecoveryInventory);

impl RecoveryShardSource for Inventory {
    fn read_candidate(
        &mut self,
        shard: ShardIdentity,
        length: u64,
        digest: [u8; 32],
    ) -> Result<Option<BoundedBytes>, ContentReadError> {
        self.0
            .read_content_shard(shard, length, digest)
            .map_err(|_| ContentReadError::Corrupt)
    }
}
