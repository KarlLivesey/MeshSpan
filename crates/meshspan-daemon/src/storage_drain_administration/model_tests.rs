// SPDX-License-Identifier: GPL-2.0-only

use meshspan_api_contract::{BeginStorageDrainRequest, StorageDrainScope};
use meshspan_domain::{PrincipalId, UnixMicros};
use meshspan_metadata::AuthoritativeCommand;
use meshspan_work::{DrainScope, WorkSubject};

use super::model::request_command;
use crate::IdentityAdministrator;

#[test]
fn public_target_drain_becomes_one_generation_fenced_urgent_job()
-> Result<(), Box<dyn std::error::Error>> {
    let request = request(StorageDrainScope::Target {
        target_id: "223e4567-e89b-42d3-a456-426614174000".to_owned(),
        generation: "9".to_owned(),
    })?;
    let (operation_id, drain_id, context, command) = request_command(administrator()?, &request)?;
    assert_eq!(operation_id.as_bytes(), drain_id.as_bytes());
    assert_eq!(context.operation_id, operation_id);
    let AuthoritativeCommand::BeginStorageTargetDrain(command) = command else {
        return Err("target request produced the wrong command".into());
    };
    assert_eq!(command.work.work_id, drain_id);
    assert_eq!(command.work.next_attempt_at, administrator()?.now);
    assert_eq!(command.work.demand.in_flight_bytes, 1);
    assert_eq!(
        command.work.subject,
        WorkSubject::Drain(DrainScope::Target {
            target_id: meshspan_domain::TargetId::from_bytes(uuid(0x22))?,
            target_generation: 9,
        })
    );
    assert!(command.allow_temporary_degraded);
    assert!(!command.cleanup_requested);
    Ok(())
}

#[test]
fn public_node_and_fault_group_drains_keep_their_exact_scope()
-> Result<(), Box<dyn std::error::Error>> {
    let node = request(StorageDrainScope::Node {
        node_id: "223e4567-e89b-42d3-a456-426614174000".to_owned(),
        incarnation: "7".to_owned(),
    })?;
    let (_, _, _, AuthoritativeCommand::BeginStorageScopeDrain(node)) =
        request_command(administrator()?, &node)?
    else {
        return Err("node request produced the wrong command".into());
    };
    assert_eq!(
        node.scope,
        DrainScope::Node {
            node_id: meshspan_domain::NodeId::from_bytes(uuid(0x22))?,
            node_incarnation: 7,
        }
    );

    let group = request(StorageDrainScope::FaultGroup {
        fault_group_id: "323e4567-e89b-42d3-a456-426614174000".to_owned(),
    })?;
    let (_, _, _, AuthoritativeCommand::BeginStorageScopeDrain(group)) =
        request_command(administrator()?, &group)?
    else {
        return Err("fault-group request produced the wrong command".into());
    };
    assert_eq!(
        group.scope,
        DrainScope::FaultGroup {
            fault_group_id: meshspan_domain::FaultGroupId::from_bytes(uuid(0x32))?,
        }
    );
    Ok(())
}

fn request(
    scope: StorageDrainScope,
) -> Result<BeginStorageDrainRequest, Box<dyn std::error::Error>> {
    Ok(BeginStorageDrainRequest {
        operation_id: serde_json::from_str("\"123e4567-e89b-42d3-a456-426614174000\"")?,
        scope,
        allow_temporary_degraded: true,
        cleanup_requested: false,
    })
}

fn administrator() -> Result<IdentityAdministrator, Box<dyn std::error::Error>> {
    Ok(IdentityAdministrator {
        principal_id: PrincipalId::from_bytes([7; 16])?,
        now: UnixMicros::new(123_456),
    })
}

fn uuid(first_byte: u8) -> [u8; 16] {
    [
        first_byte, 0x3e, 0x45, 0x67, 0xe8, 0x9b, 0x42, 0xd3, 0xa4, 0x56, 0x42, 0x66, 0x14, 0x17,
        0x40, 0x00,
    ]
}
