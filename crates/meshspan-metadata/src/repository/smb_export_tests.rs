// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    AuditEventId, HostId, NodeId, ObjectId, OperationId, PartitionId, PrincipalId, Revision,
    SmbExportId, UnixMicros, VolumeId,
};
use rusqlite::params;
use tempfile::tempdir;

use super::smb_export_configuration::{publish, withdraw};
use super::{AuthoritativeRepository, SmbExportGatewayPolicy};
use crate::{
    CommandContext, PartitionDatabase, PublishSmbExport, RecordName, SmbExportGatewaySelection,
    WithdrawSmbExport,
};

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
    let gateway_id = NodeId::from_bytes(versioned(7))?;
    insert_gateway(&database, gateway_id, 2)?;
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
    let exports = AuthoritativeRepository::new(database).smb_exports_for_gateway(gateway_id)?;
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

#[test]
fn publication_and_withdrawal_change_only_authorised_gateway_catalogues()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let mut database = PartitionDatabase::open(
        &directory.path().join("smb-publication.sqlite3"),
        PartitionId::from_bytes(versioned(21))?,
        UnixMicros::new(1),
    )?;
    let principal_id = PrincipalId::from_bytes(versioned(22))?;
    let volume_id = VolumeId::from_bytes(versioned(23))?;
    let root_id = ObjectId::from_bytes(versioned(24))?;
    let folder_id = ObjectId::from_bytes(versioned(25))?;
    let gateway_id = NodeId::from_bytes(versioned(26))?;
    let other_gateway_id = NodeId::from_bytes(versioned(27))?;
    let export_id = SmbExportId::from_bytes(versioned(28))?;
    insert_namespace(&database, principal_id, volume_id, root_id, folder_id)?;
    insert_gateway(&database, gateway_id, 2)?;
    insert_gateway(&database, other_gateway_id, 2)?;
    let context = command_context(principal_id, 29)?;
    {
        let transaction = database.connection_mut().transaction()?;
        publish(
            &transaction,
            context,
            &PublishSmbExport {
                export_id,
                volume_id,
                root_object_id: folder_id,
                share_name: RecordName::new("Finance")?,
                gateways: SmbExportGatewaySelection::Selected(BoundedItems::new(
                    vec![gateway_id],
                    1_024,
                )?),
                encryption_required: true,
            },
            Revision::new(2),
        )?;
        transaction.commit()?;
    }
    let repository = AuthoritativeRepository::new(database);
    assert_eq!(repository.smb_exports_for_gateway(gateway_id)?.len(), 1);
    assert!(
        repository
            .smb_exports_for_gateway(other_gateway_id)?
            .is_empty()
    );
    let mut database = repository.into_database();
    {
        let transaction = database.connection_mut().transaction()?;
        withdraw(
            &transaction,
            &WithdrawSmbExport {
                export_id,
                reason: "No longer published".to_owned(),
            },
            Revision::new(3),
        )?;
        transaction.commit()?;
    }
    assert!(
        AuthoritativeRepository::new(database)
            .smb_exports_for_gateway(gateway_id)?
            .is_empty()
    );
    Ok(())
}

#[test]
fn publication_rejects_duplicate_or_ineligible_selected_gateways()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let mut database = PartitionDatabase::open(
        &directory.path().join("invalid-smb-publication.sqlite3"),
        PartitionId::from_bytes(versioned(31))?,
        UnixMicros::new(1),
    )?;
    let principal_id = PrincipalId::from_bytes(versioned(32))?;
    let volume_id = VolumeId::from_bytes(versioned(33))?;
    let root_id = ObjectId::from_bytes(versioned(34))?;
    let folder_id = ObjectId::from_bytes(versioned(35))?;
    let gateway_id = NodeId::from_bytes(versioned(36))?;
    insert_namespace(&database, principal_id, volume_id, root_id, folder_id)?;
    insert_gateway(&database, gateway_id, 2)?;
    let transaction = database.connection_mut().transaction()?;
    let result = publish(
        &transaction,
        command_context(principal_id, 37)?,
        &PublishSmbExport {
            export_id: SmbExportId::from_bytes(versioned(38))?,
            volume_id,
            root_object_id: folder_id,
            share_name: RecordName::new("Finance")?,
            gateways: SmbExportGatewaySelection::Selected(BoundedItems::new(
                vec![gateway_id, gateway_id],
                1_024,
            )?),
            encryption_required: true,
        },
        Revision::new(2),
    );
    assert!(matches!(
        result,
        Err(super::RepositoryError::InvalidCommand)
    ));
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

fn insert_gateway(
    database: &PartitionDatabase,
    node_id: NodeId,
    role_code: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let host_id = HostId::from_bytes(node_id.as_bytes())?;
    let suffix = node_id.as_bytes()[0];
    database.connection().execute(
        "INSERT INTO hosts(
            host_id, display_name, canonical_name, state, created_at, retired_at, revision
         ) VALUES (?1, ?2, ?2, 1, 1, NULL, 1)",
        params![host_id.as_bytes().as_slice(), format!("host-{suffix}")],
    )?;
    database.connection().execute(
        "INSERT INTO nodes(
            node_id, host_id, display_name, canonical_name, state, current_incarnation,
            admitted_at, activated_at, retired_at, revision
         ) VALUES (?1, ?2, ?3, ?3, 2, 1, 1, 1, NULL, 1)",
        params![
            node_id.as_bytes().as_slice(),
            host_id.as_bytes().as_slice(),
            format!("node-{suffix}"),
        ],
    )?;
    database.connection().execute(
        "INSERT INTO node_roles(node_id, role_code, revision) VALUES (?1, ?2, 1)",
        params![node_id.as_bytes().as_slice(), role_code],
    )?;
    Ok(())
}

fn command_context(
    actor_principal_id: PrincipalId,
    seed: u8,
) -> Result<CommandContext, Box<dyn std::error::Error>> {
    Ok(CommandContext {
        operation_id: OperationId::from_bytes(versioned(seed))?,
        actor_principal_id,
        audit_event_id: AuditEventId::from_bytes(versioned(seed.wrapping_add(1)))?,
        occurred_at: UnixMicros::new(10),
        expected_revision: None,
    })
}

fn versioned(seed: u8) -> [u8; 16] {
    let mut value = [seed; 16];
    value[6] = 0x40;
    value[8] = 0x80;
    value
}
