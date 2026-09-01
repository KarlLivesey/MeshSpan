// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    AuditEventId, ComponentInstanceId, HostId, MeshId, NodeId, OperationId, PrincipalId, TargetId,
    UnixMicros,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

use crate::{
    AuthoritativeCommand, CreateComponent, LocalDatabase, LocalTargetDisposition, LocalTargetError,
    LocalTargetState, NewLocalTarget, RecordName, RegisterStorageTarget, StorageUsageLimit,
};

#[test]
fn target_registration_journal_resumes_every_exact_transition_after_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("local.sqlite3");
    let node_id = NodeId::from_bytes([1; 16])?;
    let mut database = LocalDatabase::open(&file_path, node_id, UnixMicros::new(1))?;
    let intent = target_intent(node_id)?;
    assert_eq!(
        database.prepare_local_target(&intent)?,
        LocalTargetDisposition::Applied
    );
    assert_eq!(
        database.prepare_local_target(&intent)?,
        LocalTargetDisposition::Replayed
    );
    assert_eq!(
        database
            .local_target_by_path(&intent.canonical_path)?
            .ok_or("prepared target path was not found")?
            .intent,
        intent
    );
    assert_eq!(
        database.record_local_target_marker(intent.target_id, [20; 32], UnixMicros::new(11))?,
        LocalTargetDisposition::Applied
    );
    assert_eq!(
        database.record_local_target_marker(intent.target_id, [20; 32], UnixMicros::new(12))?,
        LocalTargetDisposition::Replayed
    );
    let marker_record = database
        .local_target(intent.target_id)?
        .ok_or("prepared target was not found")?;
    let (context, command) = marker_record.authority_input()?;
    assert_eq!(context.operation_id, intent.registration_operation_id);
    let AuthoritativeCommand::RegisterStorageTarget(RegisterStorageTarget {
        target_id,
        marker_fingerprint,
        provider,
        usage_limit,
        ..
    }) = command
    else {
        return Err("target journal reconstructed another command".into());
    };
    assert_eq!(target_id, intent.target_id);
    assert_eq!(marker_fingerprint, [20; 32]);
    assert_eq!(provider, intent.provider);
    assert_eq!(usage_limit, intent.usage_limit);

    assert_eq!(
        database.record_local_target_authority_commit(
            intent.target_id,
            [21; 32],
            UnixMicros::new(12),
        )?,
        LocalTargetDisposition::Applied
    );
    drop(database);

    let mut database = LocalDatabase::open_existing(&file_path, UnixMicros::new(13))?;
    let committed = database
        .local_target(intent.target_id)?
        .ok_or("committed target was not found")?;
    assert_eq!(committed.state, LocalTargetState::AuthorityCommitted);
    assert_eq!(committed.revision, 3);
    assert_eq!(committed.authority_result_digest, Some([21; 32]));
    assert_eq!(
        database.activate_local_target(intent.target_id, UnixMicros::new(13))?,
        LocalTargetDisposition::Applied
    );
    assert_eq!(
        database.activate_local_target(intent.target_id, UnixMicros::new(14))?,
        LocalTargetDisposition::Replayed
    );
    let active = database
        .local_target(intent.target_id)?
        .ok_or("active target was not found")?;
    assert_eq!(active.state, LocalTargetState::Active);
    assert_eq!(active.revision, 4);
    Ok(())
}

#[test]
fn target_registration_rejects_changed_replays_out_of_order_work_and_corruption()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("local.sqlite3");
    let node_id = NodeId::from_bytes([1; 16])?;
    let mut database = LocalDatabase::open(&file_path, node_id, UnixMicros::new(1))?;
    let intent = target_intent(node_id)?;
    database.prepare_local_target(&intent)?;

    let mut changed = intent.clone();
    changed.usage_limit = StorageUsageLimit::Percent(90);
    assert_eq!(
        database.prepare_local_target(&changed),
        Err(LocalTargetError::Conflict)
    );
    let mut wrong_node = intent.clone();
    wrong_node.target_id = TargetId::from_bytes([30; 16])?;
    wrong_node.registration_operation_id = OperationId::from_bytes([31; 16])?;
    wrong_node.provider.instance_id = ComponentInstanceId::from_bytes([32; 16])?;
    wrong_node.canonical_path = b"/storage/b".to_vec();
    wrong_node.node_id = NodeId::from_bytes([33; 16])?;
    assert_eq!(
        database.prepare_local_target(&wrong_node),
        Err(LocalTargetError::Invalid)
    );
    assert_eq!(
        database.record_local_target_authority_commit(
            intent.target_id,
            [40; 32],
            UnixMicros::new(11),
        ),
        Err(LocalTargetError::Conflict)
    );
    assert_eq!(
        database.activate_local_target(intent.target_id, UnixMicros::new(11)),
        Err(LocalTargetError::Conflict)
    );
    database.record_local_target_marker(intent.target_id, [20; 32], UnixMicros::new(11))?;
    assert_eq!(
        database.record_local_target_marker(intent.target_id, [22; 32], UnixMicros::new(12)),
        Err(LocalTargetError::Conflict)
    );
    database.connection_mut().execute(
        "UPDATE local_targets SET marker_fingerprint = ?1 WHERE target_id = ?2",
        rusqlite::params![
            [0_u8; 32].as_slice(),
            intent.target_id.as_bytes().as_slice()
        ],
    )?;
    assert_eq!(
        database.local_target(intent.target_id),
        Err(LocalTargetError::Invalid)
    );
    assert_eq!(
        database.local_target_by_path(b""),
        Err(LocalTargetError::Invalid)
    );
    Ok(())
}

fn target_intent(node_id: NodeId) -> Result<NewLocalTarget, Box<dyn std::error::Error>> {
    let configuration = b"{\"provider\":\"folder\"}".to_vec();
    Ok(NewLocalTarget {
        target_id: TargetId::from_bytes([2; 16])?,
        registration_operation_id: OperationId::from_bytes([3; 16])?,
        mesh_id: MeshId::from_bytes([4; 16])?,
        node_id,
        host_id: HostId::from_bytes([5; 16])?,
        actor_principal_id: PrincipalId::from_bytes([6; 16])?,
        audit_event_id: AuditEventId::from_bytes([7; 16])?,
        provider: CreateComponent {
            instance_id: ComponentInstanceId::from_bytes([8; 16])?,
            component_kind: 1,
            name: RecordName::new("Folder provider")?,
            implementation_id: "meshspan-folder".to_owned(),
            contract_major: 1,
            contract_minor: 0,
            schema_version: 1,
            configuration_digest: Sha256::digest(&configuration).into(),
            canonical_configuration: configuration,
        },
        target_name: RecordName::new("Storage folder")?,
        canonical_path: b"/storage/a".to_vec(),
        generation: 1,
        usage_limit: StorageUsageLimit::Percent(95),
        prepared_at: UnixMicros::new(10),
    })
}
