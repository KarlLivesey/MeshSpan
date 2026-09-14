// SPDX-License-Identifier: GPL-2.0-only

//! Normal folder-provider records derived from reverified, node-signed recovery targets.

use super::{Error, Projection};
use crate::repository::{apply::to_i64, recovery_preparation::targets, storage_target};
use crate::{CreateComponent, PreparedRecoveryTarget, RecordName, RegisterStorageTarget};
use meshspan_domain::{ComponentInstanceId, TargetId, uuid_v8};
use rusqlite::{Transaction, params};
use sha2::{Digest as _, Sha256};

// The current PreparedRecoveryTarget protocol is specifically folder-v1. Adding another
// provider requires its own declared preparation/probe contract, not interpreting these bytes.
const CONFIGURATION: &[u8] = b"{\"format\":\"meshspan-folder-v1\"}";

pub(super) fn install(
    transaction: &Transaction<'_>,
    root: &[u8],
    projection: &Projection,
) -> Result<(), Error> {
    // Keep original generation/marker history for archive verification, but never make a
    // stale source target authoritative merely because it later reappears on the network.
    transaction.execute(
        "UPDATE storage_targets SET state = 5, retired_at = ?1, revision = ?2 WHERE state != 5",
        params![
            projection.fence.fenced_at.get(),
            to_i64(projection.revision.get())?
        ],
    )?;
    let mut after: Option<TargetId> = None;
    loop {
        let mut statement = transaction.prepare(
            "SELECT target_id, operation_id, node_id, report FROM partition_recovery_targets
             WHERE (?1 IS NULL OR target_id > ?1) ORDER BY target_id LIMIT 128",
        )?;
        let records = statement
            .query_map([after.map(|id| id.as_bytes().to_vec())], |row| {
                Ok((
                    row.get::<_, [u8; 16]>(0)?,
                    row.get::<_, [u8; 16]>(1)?,
                    row.get::<_, [u8; 16]>(2)?,
                    super::super::key_journal::bounded_blob(row, 3, 512)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        if records.is_empty() {
            break;
        }
        for (target_id, operation_id, node_id, report) in records {
            let (target, signature) = PreparedRecoveryTarget::decode_report(root, &report)?;
            if target.target_id.as_bytes() != target_id
                || target.operation_id.as_bytes() != operation_id
                || target.node_id.as_bytes() != node_id
            {
                return Err(Error::CorruptState);
            }
            targets::verify_target(
                transaction,
                &projection.authorization,
                &projection.plan,
                &target,
                &signature,
            )?;
            let command = registration(&target, projection)?;
            storage_target::register_recovered(
                transaction,
                projection.fence.fenced_at,
                &command,
                projection.revision,
            )?;
            after = Some(target.target_id);
        }
    }
    Ok(())
}

fn registration(
    target: &PreparedRecoveryTarget,
    projection: &Projection,
) -> Result<RegisterStorageTarget, Error> {
    let node = projection
        .plan
        .nodes
        .iter()
        .find(|node| node.node_id == target.node_id)
        .ok_or(Error::InvalidCommand)?;
    let mut hash = Sha256::new();
    hash.update(b"MeshSpan recovery folder provider v1\0");
    hash.update(projection.plan.recovery_id.as_bytes());
    hash.update(target.target_id.as_bytes());
    let digest = hash.finalize();
    let mut identifier = [0_u8; 16];
    identifier.copy_from_slice(digest.get(..16).ok_or(Error::CorruptState)?);
    let label = format!("{:032x}", u128::from_be_bytes(target.target_id.as_bytes()));
    Ok(RegisterStorageTarget {
        target_id: target.target_id,
        node_id: target.node_id,
        host_id: node.host_id,
        provider: CreateComponent {
            instance_id: ComponentInstanceId::from_bytes(uuid_v8(identifier))
                .map_err(|_| Error::CorruptState)?,
            component_kind: 1,
            name: RecordName::new(&format!("Folder provider {label}"))
                .map_err(|_| Error::InvalidCommand)?,
            implementation_id: "meshspan-folder".to_owned(),
            contract_major: 1,
            contract_minor: 0,
            schema_version: 1,
            canonical_configuration: CONFIGURATION.to_vec(),
            configuration_digest: Sha256::digest(CONFIGURATION).into(),
        },
        name: RecordName::new(&format!("Storage folder {label}"))
            .map_err(|_| Error::InvalidCommand)?,
        generation: target.generation,
        marker_fingerprint: target.marker_fingerprint,
        backing_device_fingerprint: None,
        filesystem_fingerprint: None,
        usage_limit: target.usage_limit,
    })
}
