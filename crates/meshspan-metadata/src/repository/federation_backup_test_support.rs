// SPDX-License-Identifier: GPL-2.0-only

//! Shared exact backup/restore harness for federation repository proofs.

use std::path::Path;

use meshspan_domain::{BackupId, UnixMicros};

use super::{AuthoritativeRepository, restore_partition_backup};

pub(super) fn backup_and_restore(
    repository: &AuthoritativeRepository,
    directory: &Path,
    identity_byte: u8,
) -> Result<AuthoritativeRepository, Box<dyn std::error::Error>> {
    let backup_path = directory.join(format!("federation-{identity_byte}.backup.sqlite3"));
    let restore_path = directory.join(format!("federation-{identity_byte}.restored.sqlite3"));
    let manifest = repository.create_backup(
        BackupId::from_bytes([identity_byte; 16])?,
        &backup_path,
        UnixMicros::new(1_000 + i64::from(identity_byte)),
    )?;
    let restored = restore_partition_backup(
        &backup_path,
        &restore_path,
        manifest,
        UnixMicros::new(2_000 + i64::from(identity_byte)),
    )?;
    Ok(AuthoritativeRepository::new(restored))
}
