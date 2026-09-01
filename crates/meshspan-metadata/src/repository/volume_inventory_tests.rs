// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{ObjectId, PartitionId, PrincipalId, UnixMicros, VolumeId};
use rusqlite::params;
use tempfile::tempdir;

use super::{AuthoritativeRepository, PageLimit, VolumeInventoryCursor};
use crate::PartitionDatabase;

#[test]
fn volume_candidates_page_by_name_without_permission_assumptions()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let database = PartitionDatabase::open(
        &directory.path().join("volume-inventory.sqlite3"),
        PartitionId::from_bytes([1; 16])?,
        UnixMicros::new(1),
    )?;
    insert_principal(&database)?;
    insert_volume(&database, 20, "Zulu", "zulu", 1)?;
    insert_volume(&database, 21, "Alpha", "alpha", 2)?;
    let repository = AuthoritativeRepository::new(database);

    let first = repository.volume_inventory_candidates(None, PageLimit::new(1)?)?;
    assert_eq!(first.items.len(), 1);
    assert_eq!(first.items[0].display_name, "Alpha");
    assert_eq!(first.items[0].state, 2);
    let second = repository.volume_inventory_candidates(first.next.as_ref(), PageLimit::new(1)?)?;
    assert_eq!(second.items[0].display_name, "Zulu");
    assert!(second.next.is_none());
    Ok(())
}

#[test]
fn volume_cursor_uses_both_canonical_name_and_identity() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let database = PartitionDatabase::open(
        &directory.path().join("volume-cursor.sqlite3"),
        PartitionId::from_bytes([1; 16])?,
        UnixMicros::new(1),
    )?;
    insert_principal(&database)?;
    insert_volume(&database, 30, "First", "shared", 1)?;
    database
        .connection()
        .execute("DROP INDEX volumes_autoindex_volumes_2", [])
        .ok();
    let repository = AuthoritativeRepository::new(database);
    let after =
        VolumeInventoryCursor::new("shared".to_owned(), VolumeId::from_bytes(versioned(29))?);
    let page = repository.volume_inventory_candidates(Some(&after), PageLimit::new(1)?)?;
    assert_eq!(page.items.len(), 1);
    assert_eq!(
        page.items[0].volume_id,
        VolumeId::from_bytes(versioned(30))?
    );
    Ok(())
}

fn insert_principal(database: &PartitionDatabase) -> Result<(), Box<dyn std::error::Error>> {
    let principal = PrincipalId::from_bytes(versioned(2))?;
    database.connection().execute(
        "INSERT INTO principals(
            principal_id, principal_kind, display_name, canonical_name, state, created_at, revision
         ) VALUES (?1, 1, 'Administrator', 'administrator', 1, 1, 1)",
        [principal.as_bytes().as_slice()],
    )?;
    Ok(())
}

fn insert_volume(
    database: &PartitionDatabase,
    seed: u8,
    display_name: &str,
    canonical_name: &str,
    state: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    let volume = VolumeId::from_bytes(versioned(seed))?;
    let root = ObjectId::from_bytes(versioned(seed.saturating_add(40)))?;
    let owner_set = versioned(seed.saturating_add(80));
    let principal = PrincipalId::from_bytes(versioned(2))?;
    database.connection().execute(
        "INSERT INTO owner_sets(owner_set_id, created_by, created_at, revision)
         VALUES (?1, ?2, 1, 1)",
        params![owner_set.as_slice(), principal.as_bytes().as_slice()],
    )?;
    database.connection().execute(
        "INSERT INTO volumes(
            volume_id, display_name, canonical_name, state, created_by, created_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, 1, 1)",
        params![
            volume.as_bytes().as_slice(),
            display_name,
            canonical_name,
            state,
            principal.as_bytes().as_slice()
        ],
    )?;
    database.connection().execute(
        "INSERT INTO namespace_objects(
            object_id, volume_id, parent_object_id, object_kind, display_name, canonical_name,
            owner_set_id, state, created_by, created_at, revision
         ) VALUES (?1, ?2, NULL, 1, '', '', ?3, 1, ?4, 1, 1)",
        params![
            root.as_bytes().as_slice(),
            volume.as_bytes().as_slice(),
            owner_set.as_slice(),
            principal.as_bytes().as_slice()
        ],
    )?;
    Ok(())
}

fn versioned(seed: u8) -> [u8; 16] {
    let mut value = [seed; 16];
    value[6] = 0x40;
    value[8] = 0x80;
    value
}
