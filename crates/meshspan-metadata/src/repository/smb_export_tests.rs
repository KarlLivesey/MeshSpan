// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    NodeId, ObjectId, PartitionId, PrincipalId, SmbExportId, UnixMicros, VolumeId,
};
use rusqlite::params;
use tempfile::tempdir;

use super::{AuthoritativeRepository, SmbExportGatewayPolicy};
use crate::PartitionDatabase;

#[test]
fn gateway_export_query_reconstructs_a_bounded_folder_root()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let database = PartitionDatabase::open(
        &directory.path().join("smb-exports.sqlite3"),
        PartitionId::from_bytes(versioned(1))?,
        UnixMicros::new(1),
    )?;
    let principal_id = PrincipalId::from_bytes(versioned(2))?;
    let volume_id = VolumeId::from_bytes(versioned(3))?;
    let root_id = ObjectId::from_bytes(versioned(4))?;
    let folder_id = ObjectId::from_bytes(versioned(5))?;
    insert_namespace(&database, principal_id, volume_id, root_id, folder_id)?;
    database.connection().execute(
        "INSERT INTO smb_exports(
            export_id, volume_id, root_object_id, display_name, canonical_name,
            gateway_policy, encryption_required, state, created_by, created_at, revision
         ) VALUES (?1, ?2, ?3, 'Finance', 'finance', 1, 1, 1, ?4, 10, 7)",
        params![
            SmbExportId::from_bytes(versioned(6))?.as_bytes().as_slice(),
            volume_id.as_bytes().as_slice(),
            folder_id.as_bytes().as_slice(),
            principal_id.as_bytes().as_slice(),
        ],
    )?;
    let exports = AuthoritativeRepository::new(database)
        .smb_exports_for_gateway(NodeId::from_bytes(versioned(7))?)?;
    assert_eq!(exports.len(), 1);
    assert_eq!(exports[0].display_name, "Finance");
    assert_eq!(exports[0].root_components, ["Departments"]);
    assert_eq!(
        exports[0].gateway_policy,
        SmbExportGatewayPolicy::AllEligible
    );
    assert!(exports[0].encryption_required);
    Ok(())
}

fn insert_namespace(
    database: &PartitionDatabase,
    principal_id: PrincipalId,
    volume_id: VolumeId,
    root_id: ObjectId,
    folder_id: ObjectId,
) -> Result<(), Box<dyn std::error::Error>> {
    database.connection().execute(
        "INSERT INTO principals(
            principal_id, principal_kind, display_name, canonical_name, state, created_at, revision
         ) VALUES (?1, 1, 'Administrator', 'administrator', 1, 1, 1)",
        [principal_id.as_bytes().as_slice()],
    )?;
    let owner_set = versioned(8);
    database.connection().execute(
        "INSERT INTO owner_sets(owner_set_id, created_by, created_at, revision)
         VALUES (?1, ?2, 1, 1)",
        params![owner_set.as_slice(), principal_id.as_bytes().as_slice()],
    )?;
    database.connection().execute(
        "INSERT INTO volumes(
            volume_id, display_name, canonical_name, state, created_by, created_at, revision
         ) VALUES (?1, 'Main', 'main', 1, ?2, 1, 1)",
        params![
            volume_id.as_bytes().as_slice(),
            principal_id.as_bytes().as_slice()
        ],
    )?;
    database.connection().execute(
        "INSERT INTO namespace_objects(
            object_id, volume_id, parent_object_id, object_kind, display_name, canonical_name,
            owner_set_id, state, created_by, created_at, revision
         ) VALUES (?1, ?2, NULL, 1, '', '', ?3, 1, ?4, 1, 1),
                  (?5, ?2, ?1, 1, 'Departments', 'departments', ?3, 1, ?4, 1, 1)",
        params![
            root_id.as_bytes().as_slice(),
            volume_id.as_bytes().as_slice(),
            owner_set.as_slice(),
            principal_id.as_bytes().as_slice(),
            folder_id.as_bytes().as_slice(),
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
