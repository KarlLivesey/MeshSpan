// SPDX-License-Identifier: GPL-2.0-only

//! Complete-byte pack inspection for evidence-only bit-rot scrub.

use meshspan_contracts::ShardIdentity;
use rusqlite::{OptionalExtension, params};

use super::{PackStore, PackStoreError};
use crate::shard::encode_shard;

const SHARD_ACTIVE: i64 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PackScrubResult {
    Missing,
    Present {
        observed_length: u64,
        observed_digest: [u8; 32],
        healthy: bool,
    },
}

impl PackStore {
    pub fn scrub_exact(
        &self,
        shard: ShardIdentity,
        expected_length: u64,
        expected_digest: [u8; 32],
    ) -> Result<PackScrubResult, PackStoreError> {
        let key = encode_shard(shard);
        let stored: Option<(i64, Vec<u8>, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT stored_length, stored_digest, stored_bytes
                 FROM shards WHERE shard_identity = ?1 AND state = ?2",
                params![key.as_slice(), SHARD_ACTIVE],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((catalogued_length, catalogued_digest, bytes)) = stored else {
            return Ok(PackScrubResult::Missing);
        };
        let observed_length = u64::try_from(bytes.len()).map_err(|_| PackStoreError::Corrupt)?;
        let observed_digest: [u8; 32] = blake3::hash(&bytes).into();
        let healthy = u64::try_from(catalogued_length).ok() == Some(expected_length)
            && catalogued_digest.as_slice() == expected_digest
            && observed_length == expected_length
            && observed_digest == expected_digest;
        Ok(PackScrubResult::Present {
            observed_length,
            observed_digest,
            healthy,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use meshspan_contracts::{BoundedBytes, ShardIdentity};
    use meshspan_domain::{EntropyError, MeshId, OperationId, RandomSource, TargetId, UnixMicros};
    use rusqlite::params;
    use tempfile::tempdir;

    use super::PackScrubResult;
    use crate::pack::{PackPutRequest, PackStore};
    use crate::shard::encode_shard;
    use crate::{FolderRegistration, RegisteredFolder, UsageLimit};

    struct FixedRandom;

    impl RandomSource for FixedRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
            destination.fill(3);
            Ok(())
        }
    }

    #[test]
    fn scrub_recalculates_healthy_corrupt_and_missing_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let storage_path = directory.path().join("target");
        fs::create_dir(&storage_path)?;
        let mut random = FixedRandom;
        let folder = RegisteredFolder::register_new(
            &storage_path,
            FolderRegistration {
                mesh_id: MeshId::from_bytes([1; 16])?,
                target_id: TargetId::from_bytes([2; 16])?,
                generation: 3,
                usage_limit: UsageLimit::DEFAULT,
            },
            &mut random,
        )?;
        let shard = ShardIdentity {
            manifest_digest: [4; 32],
            stripe_index: 5,
            shard_index: 6,
            generation: 7,
        };
        let bytes = BoundedBytes::copy_from(b"complete encrypted shard", 1_024)?;
        let digest: [u8; 32] = blake3::hash(bytes.as_slice()).into();
        let mut pack = PackStore::open(&folder, 1, UnixMicros::new(1))?;
        pack.put_exact(PackPutRequest {
            operation_id: OperationId::from_bytes([8; 16])?,
            request_digest: [9; 32],
            shard,
            expected_digest: digest,
            bytes: &bytes,
            now: UnixMicros::new(10),
        })?;
        assert_eq!(
            pack.scrub_exact(shard, u64::try_from(bytes.len())?, digest)?,
            PackScrubResult::Present {
                observed_length: u64::try_from(bytes.len())?,
                observed_digest: digest,
                healthy: true,
            }
        );

        let key = encode_shard(shard);
        pack.connection.execute(
            "UPDATE shards SET stored_bytes = ?1 WHERE shard_identity = ?2",
            params![b"bit rot".as_slice(), key.as_slice()],
        )?;
        assert!(matches!(
            pack.scrub_exact(shard, u64::try_from(bytes.len())?, digest)?,
            PackScrubResult::Present { healthy: false, .. }
        ));
        pack.connection.execute("DELETE FROM pack_operations", [])?;
        pack.connection.execute(
            "DELETE FROM shards WHERE shard_identity = ?1",
            [key.as_slice()],
        )?;
        assert_eq!(
            pack.scrub_exact(shard, u64::try_from(bytes.len())?, digest)?,
            PackScrubResult::Missing
        );
        Ok(())
    }
}
