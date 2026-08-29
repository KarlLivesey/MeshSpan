// SPDX-License-Identifier: GPL-2.0-only

//! Root-to-child metadata delegation wire invariants.

use meshspan_protocol::v1::control_envelope::Message;
use meshspan_protocol::v1::metadata_key_range::Range;
use meshspan_protocol::v1::{
    BeginScopeHandoff, BoundedMetadataKeyRange, ControlEnvelope, MetadataKeyRange,
    MetadataOperationFamily, ProtocolVersion, RequestHeader, ScopeRoute,
};
use meshspan_protocol::{WireContractError, WireLimits, encode_control_frame};

#[test]
fn route_binds_permanent_root_family_range_and_epochs() -> Result<(), Box<dyn std::error::Error>> {
    let route = ScopeRoute {
        scope_id: vec![1; 16],
        partition_id: vec![2; 16],
        routing_epoch: 3,
        owner_node_id: vec![4; 16],
        signature: vec![5; 64],
        root_partition_id: vec![6; 16],
        ownership_epoch: 7,
        operation_family: MetadataOperationFamily::Authentication.into(),
        key_range: Some(all_keys()),
    };
    assert!(encode_control_frame(&envelope(Message::ScopeRoute(route.clone())), limits()?).is_ok());

    let mut missing_root = route;
    missing_root.root_partition_id.clear();
    assert_eq!(
        encode_control_frame(&envelope(Message::ScopeRoute(missing_root)), limits()?),
        Err(WireContractError::InvalidMessage)
    );
    Ok(())
}

#[test]
fn handoff_requires_capacity_relative_admission_evidence() -> Result<(), Box<dyn std::error::Error>>
{
    let handoff = BeginScopeHandoff {
        scope_id: vec![10; 16],
        source_partition_id: vec![11; 16],
        destination_partition_id: vec![12; 16],
        routing_epoch: 2,
        root_partition_id: vec![11; 16],
        operation_family: MetadataOperationFamily::Namespace.into(),
        key_range: Some(MetadataKeyRange {
            range: Some(Range::Bounded(BoundedMetadataKeyRange {
                start_inclusive: vec![0; 16],
                end_exclusive: vec![128; 16],
            })),
        }),
        eligible_member_count: 3,
        planned_voter_count: 3,
        quorum_plan_digest: vec![13; 32],
        load_evidence_digest: vec![14; 32],
        measured_at_unix_micros: 1_000,
    };
    assert!(
        encode_control_frame(
            &envelope(Message::BeginScopeHandoff(handoff.clone())),
            limits()?
        )
        .is_ok()
    );

    let mut insufficient = handoff;
    insufficient.eligible_member_count = 2;
    assert_eq!(
        encode_control_frame(
            &envelope(Message::BeginScopeHandoff(insufficient)),
            limits()?
        ),
        Err(WireContractError::InvalidMessage)
    );
    Ok(())
}

fn all_keys() -> MetadataKeyRange {
    MetadataKeyRange {
        range: Some(Range::All(true)),
    }
}

fn envelope(message: Message) -> ControlEnvelope {
    ControlEnvelope {
        header: Some(RequestHeader {
            version: Some(ProtocolVersion { major: 1, minor: 0 }),
            mesh_id: vec![21; 16],
            partition_id: vec![22; 16],
            routing_epoch: 1,
            sender_node_id: vec![23; 16],
            sender_incarnation: 1,
            request_id: vec![24; 16],
            operation_id: vec![25; 16],
            deadline_unix_micros: 2_000_000,
            trace_id: vec![26; 16],
        }),
        message: Some(message),
    }
}

fn limits() -> Result<WireLimits, WireContractError> {
    WireLimits::new(4 * 1_024 * 1_024, 1_024 * 1_024, 4_096, 4_096)
}
