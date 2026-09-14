// SPDX-License-Identifier: GPL-2.0-only

//! Canonical commitments to copied pack bytes, excluding disposable SQLite shared-memory files.

use super::{Error, RecoveryInventory, pack_directory, validate_copy};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
use std::{
    fs,
    io::{Read as _, Write},
    path::Path,
};

impl RecoveryInventory {
    /// Streams a version-one, path-independent manifest of every completed copied pack.
    /// Records are sorted by mesh/target/generation/sequence, never local allocation order.
    /// Main, WAL and rollback-journal bytes are length/digest bound; SHM is disposable.
    /// This proves identity of copied bytes, not healthy shards or complete file availability.
    /// The caller supplies its independent backup/target scope and hashes/signs only on success.
    /// # Errors
    /// Rejects pending work, missing/unsafe copies, excessive lengths, corruption or IO failure.
    /// The destination can contain a partial manifest on failure and must not be published.
    pub fn write_manifest(&self, output: &mut dyn Write) -> Result<(), Error> {
        let summary = self.summary()?;
        output.write_all(b"MSRECOVERYPACKS\x01")?;
        output.write_all(&summary.packs.to_be_bytes())?;
        let mut remaining = summary.copied_bytes;
        let mut packs = 0_u64;
        self.repository.visit_packs(|candidate| {
            let directory = pack_directory(&self.directory, candidate.id)?;
            validate_copy(&directory)?;
            output.write_all(&candidate.marker.encode())?;
            output.write_all(&candidate.sequence.to_be_bytes())?;
            for (role, name) in [
                (1, "pack.sqlite3"),
                (2, "pack.sqlite3-wal"),
                (3, "pack.sqlite3-journal"),
            ] {
                write_member(&directory.join(name), role, &mut remaining, output)?;
            }
            packs = packs.checked_add(1).ok_or(Error::Corrupt)?;
            Ok(())
        })?;
        if remaining != 0 || packs != summary.packs {
            return Err(Error::Corrupt);
        }
        Ok(())
    }
}

fn write_member(
    file: &Path,
    role: u8,
    remaining: &mut u64,
    output: &mut dyn Write,
) -> Result<(), Error> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits().cast_signed());
    let mut input = match options.open(file) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && role != 1 => {
            output.write_all(&[role, 0])?;
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    let metadata = input.metadata()?;
    let length = metadata.len();
    if !metadata.is_file() || length > *remaining {
        return Err(Error::Corrupt);
    }
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0; 64 * 1024];
    let mut left = length;
    while left > 0 {
        let limit = usize::try_from(left.min(buffer.len() as u64)).map_err(|_| Error::Corrupt)?;
        input.read_exact(&mut buffer[..limit])?;
        hasher.update(&buffer[..limit]);
        left -= u64::try_from(limit).map_err(|_| Error::Corrupt)?;
    }
    let mut trailing = [0];
    if input.read(&mut trailing)? != 0 {
        return Err(Error::Corrupt);
    }
    *remaining -= length;
    output.write_all(&[role, 1])?;
    output.write_all(&length.to_be_bytes())?;
    output.write_all(hasher.finalize().as_bytes())?;
    Ok(())
}
