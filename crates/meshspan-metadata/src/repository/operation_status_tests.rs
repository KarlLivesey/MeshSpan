// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{OperationId, PartitionId, UnixMicros};
use rusqlite::params;
use sha2::{Digest, Sha256};

use super::{AuthoritativeRepository, LogPosition, PageLimit};
use crate::PartitionDatabase;

#[test]
fn operation_inventory_pages_newest_first_without_repeating_the_boundary()
-> Result<(), Box<dyn std::error::Error>> {
    let partition_id = PartitionId::from_bytes([61; 16])?;
    let database = PartitionDatabase::open(
        std::path::Path::new(":memory:"),
        partition_id,
        UnixMicros::new(1),
    )?;
    let mut repository = AuthoritativeRepository::new(database);
    let (context, command) = super::bootstrap_appliance_tests::fixture(partition_id)?;
    repository.apply_committed(LogPosition { index: 1, term: 1 }, context, &command)?;

    let newer_id = OperationId::from_bytes([62; 16])?;
    let mut result_payload: Vec<u8> = repository.database.connection().query_row(
        "SELECT result_payload FROM operations WHERE operation_id = ?1",
        [context.operation_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    result_payload[18..26].copy_from_slice(&2_u64.to_be_bytes());
    let result_digest: [u8; 32] = Sha256::digest(&result_payload).into();
    repository.database.connection().execute(
        "INSERT INTO operations(
            operation_id, partition_id, actor_principal_id, actor_node_id, operation_kind,
            request_version, request_digest, outcome, durability_scope, started_at, completed_at,
            committed_log_index, result_kind, result_version, result_payload, result_digest,
            error_kind, revision
         ) SELECT ?1, partition_id, actor_principal_id, actor_node_id, operation_kind,
                  request_version, request_digest, outcome, durability_scope, started_at + 1,
                  completed_at + 1, committed_log_index, result_kind, result_version,
                  ?3, ?4, error_kind, revision + 1
           FROM operations WHERE operation_id = ?2",
        params![
            newer_id.as_bytes().as_slice(),
            context.operation_id.as_bytes().as_slice(),
            result_payload,
            result_digest.as_slice()
        ],
    )?;

    let first = repository.operation_statuses(None, PageLimit::new(1)?)?;
    assert_eq!(first.items[0].operation_id, newer_id);
    let second = repository.operation_statuses(first.next, PageLimit::new(1)?)?;
    assert_eq!(second.items[0].operation_id, context.operation_id);
    assert!(second.next.is_none());
    Ok(())
}
