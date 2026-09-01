// SPDX-License-Identifier: GPL-2.0-only

use std::collections::BTreeSet;

use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    AuditEventId, HostId, MeshId, NodeId, ObjectId, OperationId, OwnerSetId, PartitionId,
    PrincipalId, Revision, RoleId, UnixMicros, VolumeId,
};
use meshspan_secret_envelope::WrappingPrivateKey;

use super::tests::{initial_test_volume_key, mark_test_recovery_verified, protected_bootstrap};
use super::{AuthoritativeRepository, LogPosition, RepositoryError};
use crate::{
    AuthoritativeCommand, BootstrapMesh, CommandContext, CreateVolume, PartitionDatabase,
    RecordName, VOLUME_CONTENT_KEY_SECRET_KIND,
};

#[test]
fn volume_and_recoverable_key_commit_as_one_revision() -> Result<(), Box<dyn std::error::Error>> {
    let (mut repository, administrator) = fixture()?;
    let volume_id = VolumeId::from_bytes([30; 16])?;
    let receipt = repository.apply_committed(
        LogPosition { index: 2, term: 1 },
        context(31, administrator, 32, Some(1))?,
        &create_volume(volume_id, administrator, "Protected", 33)?,
    )?;

    let volume = repository
        .volume_inventory_record(volume_id)?
        .ok_or("volume was not committed")?;
    let secret = repository
        .secret_generation(meshspan_secret_envelope::SecretContext::new(
            VOLUME_CONTENT_KEY_SECRET_KIND,
            volume_id.as_bytes(),
            1,
        )?)?
        .ok_or("volume key was not committed")?;
    assert_eq!(receipt.committed_revision, Revision::new(2));
    assert_eq!(volume.revision, receipt.committed_revision);
    assert_eq!(secret.revision, receipt.committed_revision);
    assert_eq!(secret.secret.parts().ciphertext.len(), 48);
    assert_eq!(secret.recipients.len(), 2);
    assert_eq!(repository.latest_volume_key_generation(volume_id)?, Some(1));
    assert_eq!(
        repository.latest_volume_key_generation(VolumeId::from_bytes([34; 16])?)?,
        None
    );
    Ok(())
}

#[test]
fn wrong_key_context_rolls_back_every_volume_row() -> Result<(), Box<dyn std::error::Error>> {
    let (mut repository, administrator) = fixture()?;
    let volume_id = VolumeId::from_bytes([40; 16])?;
    let mut command = create_volume(volume_id, administrator, "Rejected", 41)?;
    let AuthoritativeCommand::CreateVolume(value) = &mut command else {
        return Err("wrong fixture command".into());
    };
    value.key_generation = initial_test_volume_key(VolumeId::from_bytes([42; 16])?)?;

    assert!(matches!(
        repository.apply_committed(
            LogPosition { index: 2, term: 1 },
            context(43, administrator, 44, Some(1))?,
            &command,
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    assert_eq!(repository.current_revision()?, Revision::new(1));
    assert!(repository.volume_inventory_record(volume_id)?.is_none());
    assert_table_counts(&repository, (0, 0, 2, 4))
}

#[test]
fn rejected_duplicate_name_cannot_leave_an_orphan_key() -> Result<(), Box<dyn std::error::Error>> {
    let (mut repository, administrator) = fixture()?;
    let first = VolumeId::from_bytes([50; 16])?;
    repository.apply_committed(
        LogPosition { index: 2, term: 1 },
        context(51, administrator, 52, Some(1))?,
        &create_volume(first, administrator, "Same name", 53)?,
    )?;
    let second = VolumeId::from_bytes([54; 16])?;
    assert!(matches!(
        repository.apply_committed(
            LogPosition { index: 3, term: 1 },
            context(55, administrator, 56, Some(2))?,
            &create_volume(second, administrator, "Same name", 57)?,
        ),
        Err(RepositoryError::Sqlite(_))
    ));
    assert_eq!(repository.current_revision()?, Revision::new(2));
    assert!(repository.volume_inventory_record(second)?.is_none());
    assert_table_counts(&repository, (1, 1, 3, 6))
}

#[test]
fn omitted_eligible_gateway_recipient_rolls_back_the_volume()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut repository, administrator) = fixture()?;
    let volume_id = VolumeId::from_bytes([58; 16])?;
    let mut command = create_volume(volume_id, administrator, "Incomplete recipients", 59)?;
    let AuthoritativeCommand::CreateVolume(value) = &mut command else {
        return Err("wrong fixture command".into());
    };
    let recovery_key = meshspan_secret_envelope::WrappingPublicKey::from_bytes([146; 32])?;
    value
        .key_generation
        .recipients
        .retain(|recipient| recipient.recipient_public_key == recovery_key.as_bytes());

    assert!(matches!(
        repository.apply_committed(
            LogPosition { index: 2, term: 1 },
            context(60, administrator, 61, Some(1))?,
            &command,
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    assert_eq!(repository.current_revision()?, Revision::new(1));
    assert!(repository.volume_inventory_record(volume_id)?.is_none());
    assert_table_counts(&repository, (0, 0, 2, 4))
}

#[test]
fn volume_key_recipient_resolution_fails_without_an_active_gateway()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut repository, _) = fixture()?;
    repository
        .database
        .connection_mut()
        .execute("UPDATE nodes SET state = 3 WHERE state = 2", [])?;

    assert!(matches!(
        repository.volume_key_recipients(),
        Err(RepositoryError::CorruptState)
    ));
    Ok(())
}

#[test]
fn volume_key_recipient_resolution_fails_when_an_active_gateway_has_no_key()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut repository, _) = fixture()?;
    insert_node(&mut repository, 63, 2, 2)?;

    assert!(matches!(
        repository.volume_key_recipients(),
        Err(RepositoryError::CorruptState)
    ));
    Ok(())
}

#[test]
fn volume_key_recipients_exclude_storage_only_and_inactive_gateways()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut repository, _) = fixture()?;
    let gateway = insert_recipient_node(&mut repository, 60, 2, 2)?;
    let storage_only = insert_recipient_node(&mut repository, 61, 1, 2)?;
    let inactive_gateway = insert_recipient_node(&mut repository, 62, 2, 3)?;

    let actual = repository
        .volume_key_recipients()?
        .iter()
        .map(|recipient| recipient.fingerprint())
        .collect::<BTreeSet<_>>();
    let recovery = meshspan_secret_envelope::WrappingPublicKey::from_bytes([146; 32])?;
    let bootstrap_gateway = crate::test_support::node_wrapping_private_key()?.public_key();
    assert_eq!(actual.len(), 3);
    assert!(actual.contains(&recovery.fingerprint()));
    assert!(actual.contains(&bootstrap_gateway.fingerprint()));
    assert!(actual.contains(&gateway.fingerprint()));
    assert!(!actual.contains(&storage_only.fingerprint()));
    assert!(!actual.contains(&inactive_gateway.fingerprint()));
    Ok(())
}

fn fixture() -> Result<(AuthoritativeRepository, PrincipalId), Box<dyn std::error::Error>> {
    let administrator = PrincipalId::from_bytes([2; 16])?;
    let mesh_id = MeshId::from_bytes([3; 16])?;
    let database = PartitionDatabase::open(
        std::path::Path::new(":memory:"),
        PartitionId::from_bytes([1; 16])?,
        UnixMicros::new(1),
    )?;
    let mut repository = AuthoritativeRepository::new(database);
    repository.apply_committed(
        LogPosition { index: 1, term: 1 },
        context(10, administrator, 11, Some(0))?,
        &protected_bootstrap(BootstrapMesh {
            mesh_id,
            mesh_name: RecordName::new("Volume protection proof")?,
            administrator_id: administrator,
            administrator_name: RecordName::new("Administrator")?,
            administrator_role_id: RoleId::from_bytes([4; 16])?,
            host_id: HostId::from_bytes([5; 16])?,
            host_name: RecordName::new("Host")?,
            node_id: NodeId::from_bytes([6; 16])?,
            node_name: RecordName::new("Gateway")?,
            partition_name: RecordName::new("Authority")?,
        })?,
    )?;
    mark_test_recovery_verified(&mut repository, mesh_id, administrator)?;
    Ok((repository, administrator))
}

fn create_volume(
    volume_id: VolumeId,
    owner: PrincipalId,
    name: &str,
    seed: u8,
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    Ok(AuthoritativeCommand::CreateVolume(CreateVolume {
        volume_id,
        name: RecordName::new(name)?,
        root_object_id: ObjectId::from_bytes([seed; 16])?,
        owner_set_id: OwnerSetId::from_bytes([seed.wrapping_add(1); 16])?,
        owners: BoundedItems::new(vec![owner], 1_024)?,
        key_generation: initial_test_volume_key(volume_id)?,
    }))
}

fn context(
    operation: u8,
    actor: PrincipalId,
    audit: u8,
    expected_revision: Option<u64>,
) -> Result<CommandContext, Box<dyn std::error::Error>> {
    Ok(CommandContext {
        operation_id: OperationId::from_bytes([operation; 16])?,
        actor_principal_id: actor,
        audit_event_id: AuditEventId::from_bytes([audit; 16])?,
        occurred_at: UnixMicros::new(100),
        expected_revision: expected_revision.map(Revision::new),
    })
}

fn assert_table_counts(
    repository: &AuthoritativeRepository,
    expected: (i64, i64, i64, i64),
) -> Result<(), Box<dyn std::error::Error>> {
    let actual = repository.database.connection().query_row(
        "SELECT
            (SELECT count(*) FROM volumes),
            (SELECT count(*) FROM namespace_objects),
            (SELECT count(*) FROM secret_generations),
            (SELECT count(*) FROM secret_recipient_envelopes)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    assert_eq!(actual, expected);
    Ok(())
}

fn insert_recipient_node(
    repository: &mut AuthoritativeRepository,
    seed: u8,
    role_code: i64,
    node_state: i64,
) -> Result<meshspan_secret_envelope::WrappingPublicKey, Box<dyn std::error::Error>> {
    let node_id = insert_node(repository, seed, role_code, 2)?;
    let key = WrappingPrivateKey::from_bytes([seed.wrapping_add(2); 32])?.public_key();
    repository.database.connection_mut().execute(
        "INSERT INTO secret_wrapping_recipients(
            key_fingerprint, recipient_kind, owner_id, generation, public_key, state,
            registered_at, retired_at, revision
         ) VALUES (?1, 1, ?2, 1, ?3, 1, 1, NULL, 1)",
        rusqlite::params![
            key.fingerprint().as_slice(),
            node_id.as_bytes().as_slice(),
            key.as_bytes().as_slice(),
        ],
    )?;
    repository.database.connection_mut().execute(
        "INSERT INTO node_wrapping_keys(
            node_id, generation, public_key, key_fingerprint, state, registered_at,
            retired_at, revision
         ) VALUES (?1, 1, ?2, ?3, 1, 1, NULL, 1)",
        rusqlite::params![
            node_id.as_bytes().as_slice(),
            key.as_bytes().as_slice(),
            key.fingerprint().as_slice(),
        ],
    )?;
    if node_state != 2 {
        repository.database.connection_mut().execute(
            "UPDATE nodes SET state = ?1 WHERE node_id = ?2",
            rusqlite::params![node_state, node_id.as_bytes().as_slice()],
        )?;
    }
    Ok(key)
}

fn insert_node(
    repository: &mut AuthoritativeRepository,
    seed: u8,
    role_code: i64,
    node_state: i64,
) -> Result<NodeId, Box<dyn std::error::Error>> {
    let host_id = HostId::from_bytes([seed; 16])?;
    let node_id = NodeId::from_bytes([seed.wrapping_add(1); 16])?;
    repository.database.connection_mut().execute(
        "INSERT INTO hosts(
            host_id, display_name, canonical_name, state, created_at, retired_at, revision
         ) VALUES (?1, ?2, ?2, 1, 1, NULL, 1)",
        rusqlite::params![host_id.as_bytes().as_slice(), format!("host-{seed}")],
    )?;
    repository.database.connection_mut().execute(
        "INSERT INTO nodes(
            node_id, host_id, display_name, canonical_name, state, current_incarnation,
            admitted_at, activated_at, retired_at, revision
         ) VALUES (?1, ?2, ?3, ?3, ?4, 1, 1, 1, NULL, 1)",
        rusqlite::params![
            node_id.as_bytes().as_slice(),
            host_id.as_bytes().as_slice(),
            format!("node-{seed}"),
            node_state,
        ],
    )?;
    repository.database.connection_mut().execute(
        "INSERT INTO node_roles(node_id, role_code, revision) VALUES (?1, ?2, 1)",
        rusqlite::params![node_id.as_bytes().as_slice(), role_code],
    )?;
    Ok(node_id)
}
