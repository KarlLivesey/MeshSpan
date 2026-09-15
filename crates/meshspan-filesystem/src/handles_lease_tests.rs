// SPDX-License-Identifier: GPL-2.0-only

use super::*;

#[test]
fn renewal_preserves_explicit_handle_locks_without_extending_independent_locks()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.publish_root_file(&publication()?)?;
    let owner = open_request(150, 151, CreateDisposition::OpenExisting, 100)?;
    let competitor = open_request(152, 153, CreateDisposition::OpenExisting, 200)?;
    store
        .open_handle(&owner)
        .map_err(|error| format!("open owner: {error}"))?;
    store
        .open_handle(&competitor)
        .map_err(|error| format!("open competitor: {error}"))?;
    let mut bound = exclusive_lock(154, &owner, 0, 100, 20)?;
    bound.lifetime = RangeLockLifetime::Handle;
    let acquired = store
        .lock_range(bound)
        .map_err(|error| format!("acquire bound lock: {error}"))?;
    store
        .lock_range(exclusive_lock(156, &owner, 20, 100, 20)?)
        .map_err(|error| format!("acquire independent lock: {error}"))?;
    store
        .lock_range(exclusive_lock(158, &owner, 40, 60, 20)?)
        .map_err(|error| format!("acquire independent lock: {error}"))?;
    let renewal = renew_request(&owner, 160, 200, 30)?;
    store
        .renew_handle_lease(renewal)
        .map_err(|error| format!("initial renewal: {error}"))?;
    let integrity: String =
        store
            .test_connection()
            .pragma_query_value(None, "quick_check", |row| row.get(0))?;
    assert_eq!(integrity, "ok");
    let mut foreign_keys = store
        .test_connection()
        .prepare("PRAGMA foreign_key_check")?;
    assert!(foreign_keys.query([])?.next()?.is_none());
    drop(foreign_keys);
    drop(store);
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(110))
        .map_err(|error| format!("reopen publication store: {error}"))?;
    assert_eq!(
        store
            .renew_handle_lease(renewal)
            .map_err(|error| format!("renewal replay: {error}"))?
            .disposition,
        PublicationDisposition::Replayed
    );
    let replayed = store
        .lock_range(bound)
        .map_err(|error| format!("lock replay: {error}"))?;
    assert_eq!(replayed.lease_expires_at, UnixMicros::new(100));
    assert_eq!(replayed.result_digest, acquired.result_digest);
    assert!(matches!(
        store.lock_range(exclusive_lock(161, &competitor, 0, 190, 110)?),
        Err(HandleError::LockConflict)
    ));
    for (operation, start) in [(163, 20), (165, 40)] {
        store.lock_range(exclusive_lock(operation, &competitor, start, 190, 110)?)?;
    }
    store.close_handle(close_request(167, &owner, 1, 120)?)?;
    store.lock_range(exclusive_lock(168, &competitor, 0, 190, 130)?)?;
    Ok(())
}

#[test]
fn legacy_lock_migration_preserves_independent_receipts_and_lifetimes()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.publish_root_file(&publication()?)?;
    let owner = open_request(170, 171, CreateDisposition::OpenExisting, 100)?;
    store.open_handle(&owner)?;
    let lock = exclusive_lock(172, &owner, 0, 100, 20)?;
    let acquired = store.lock_range(lock)?;
    store.test_connection().execute_batch(
        "DELETE FROM schema_migrations WHERE version = 46;
        ALTER TABLE range_locks DROP COLUMN acquired_lease_expires_at;
        ALTER TABLE range_locks DROP COLUMN lock_lifetime;
        PRAGMA user_version = 45;",
    )?;
    drop(store);
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(30))?;
    let replayed = store.lock_range(lock)?;
    assert_eq!(replayed.request_digest, acquired.request_digest);
    assert_eq!(replayed.result_digest, acquired.result_digest);
    assert_eq!(replayed.lifetime, RangeLockLifetime::Independent);
    store.renew_handle_lease(renew_request(&owner, 174, 200, 30)?)?;
    let expiry: i64 = store.test_connection().query_row(
        "SELECT lease_expires_at FROM range_locks WHERE lock_id = ?1",
        [lock.lock_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    assert_eq!(expiry, 100);
    let changed = LockRangeRequest {
        lifetime: RangeLockLifetime::Handle,
        ..lock
    };
    assert!(matches!(
        store.lock_range(changed),
        Err(HandleError::OperationConflict)
    ));
    store
        .test_connection()
        .execute_batch("PRAGMA foreign_key_check;")?;
    Ok(())
}

#[test]
fn forged_lock_lifetime_cannot_acquire_renewal_authority() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.publish_root_file(&publication()?)?;
    let owner = open_request(180, 181, CreateDisposition::OpenExisting, 100)?;
    store.open_handle(&owner)?;
    let lock = exclusive_lock(182, &owner, 0, 100, 20)?;
    store.lock_range(lock)?;
    store.test_connection().execute(
        "UPDATE range_locks SET lock_lifetime = 2 WHERE lock_id = ?1",
        [lock.lock_id.as_bytes().as_slice()],
    )?;
    assert!(matches!(
        store.renew_handle_lease(renew_request(&owner, 184, 200, 30)?),
        Err(HandleError::Corrupt)
    ));
    assert_eq!(
        store
            .handle_authority_target(owner.handle_id, UnixMicros::new(30))?
            .lease_expires_at,
        UnixMicros::new(100),
        "a rejected lock renewal must not extend its owning handle"
    );
    Ok(())
}

fn renew_request(
    owner: &OpenHandleRequest,
    operation: u8,
    expiry: i64,
    now: i64,
) -> Result<HandleLeaseRequest, Box<dyn std::error::Error>> {
    Ok(HandleLeaseRequest {
        operation_id: OperationId::from_bytes([operation; 16])?,
        handle_id: owner.handle_id,
        expected_fence: 1,
        principal_id: owner.principal_id,
        authorization_revision: Revision::new(2),
        gateway_node_id: owner.gateway_node_id,
        takeover: false,
        lease_expires_at: UnixMicros::new(expiry),
        observed_at: UnixMicros::new(now),
    })
}

// Every lifetime vector uses a ten-byte range and a distinct adjacent operation/lock ID pair.
fn exclusive_lock(
    operation: u8,
    owner: &OpenHandleRequest,
    start: u64,
    expiry: i64,
    now: i64,
) -> Result<LockRangeRequest, Box<dyn std::error::Error>> {
    lock_request(
        operation,
        operation.checked_add(1).ok_or("fixture ID overflow")?,
        owner,
        1,
        start,
        10,
        RangeLockKind::Exclusive,
        expiry,
        now,
    )
}
