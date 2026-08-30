// SPDX-License-Identifier: GPL-2.0-only

//! Committed canonical-byte and hostile-frame compatibility vectors.

use meshspan_protocol::v1::control_envelope::Message;
use meshspan_protocol::v1::data_control_envelope::Message as DataMessage;
use meshspan_protocol::v1::{
    ComponentSupport, ControlEnvelope, DataControlEnvelope, DataFrame, DeleteShardRequest,
    DeleteShardResult, NodeHello, NodeRole, OperationOutcome, OperationResult, Ping,
    ProtocolVersion, PublishPresence, PutShardBegin, ReclaimShardRequest, ReclaimShardResult,
    RequestHeader, ShardIdentity, VersionedPayload, VoteRequest, VoteResponse,
};
use meshspan_protocol::{
    WireContractError, WireLimits, decode_control_frame, decode_data_control_frame,
    decode_data_frame, encode_control_frame, encode_data_control_frame, encode_data_frame,
};
use serde::Deserialize;

const FIXTURE: &str = include_str!("../../../contracts/protobuf/v1/node-hello.json");

#[derive(Debug, Deserialize)]
struct HelloFixture {
    name: String,
    protocol_major: u32,
    protocol_minor: u32,
    mesh_id_hex: String,
    node_id_hex: String,
    incarnation: u64,
    roles: Vec<i32>,
    feature_bits: Vec<u32>,
    component_contract_kind: u32,
    component_implementation_id: String,
    maximum_control_bytes: u64,
    maximum_data_frame_bytes: u64,
    maximum_items: u32,
    maximum_concurrency: u32,
    maximum_streams: u32,
    expected_frame_hex: String,
}

#[test]
fn committed_node_hello_bytes_are_canonical_and_round_trip()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture: HelloFixture = serde_json::from_str(FIXTURE)?;
    assert_eq!(fixture.name, "node-hello-v1.0");
    let envelope = hello_envelope(&fixture)?;
    let encoded = encode_control_frame(&envelope, limits()?)?;
    assert_eq!(bytes_to_hex(&encoded), fixture.expected_frame_hex);
    assert_eq!(
        decode_control_frame(&encoded, limits()?)?.into_inner(),
        envelope
    );
    Ok(())
}

#[test]
fn unknown_minor_field_is_ignored_without_changing_known_semantics()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture: HelloFixture = serde_json::from_str(FIXTURE)?;
    let envelope = hello_envelope(&fixture)?;
    let mut encoded = encode_control_frame(&envelope, limits()?)?;
    encoded.extend_from_slice(&[0xf8, 0x07, 0x01]);
    rewrite_length_prefix(&mut encoded)?;
    assert_eq!(
        decode_control_frame(&encoded, limits()?)?.into_inner(),
        envelope
    );
    Ok(())
}

#[test]
fn framing_rejects_excess_truncation_and_length_lies_before_decode()
-> Result<(), Box<dyn std::error::Error>> {
    let wire_limits = limits()?;
    assert_eq!(
        decode_control_frame(&[0, 64, 0, 1], wire_limits),
        Err(WireContractError::FrameTooLarge)
    );
    assert_eq!(
        decode_control_frame(&[0, 0, 0], wire_limits),
        Err(WireContractError::Truncated)
    );
    assert_eq!(
        decode_control_frame(&[0, 0, 0, 2, 1], wire_limits),
        Err(WireContractError::LengthMismatch)
    );
    Ok(())
}

#[test]
fn semantic_validation_rejects_missing_authority_and_excessive_repetition()
-> Result<(), Box<dyn std::error::Error>> {
    let wire_limits = WireLimits::new(4_096, 1_024, 2, 64)?;
    let no_header = ControlEnvelope {
        header: None,
        message: Some(Message::Ping(Ping {
            nonce: 9,
            sent_monotonic_micros: 1,
        })),
    };
    assert!(encode_control_frame(&no_header, wire_limits).is_ok());

    let mut fixture: HelloFixture = serde_json::from_str(FIXTURE)?;
    fixture.feature_bits = vec![1, 2, 3];
    assert_eq!(
        encode_control_frame(&hello_envelope(&fixture)?, wire_limits),
        Err(WireContractError::InvalidMessage)
    );

    let authority_message = ControlEnvelope {
        header: None,
        message: Some(Message::VoteRequest(VoteRequest::default())),
    };
    assert_eq!(
        encode_control_frame(&authority_message, wire_limits),
        Err(WireContractError::InvalidMessage)
    );
    Ok(())
}

#[test]
fn presence_requires_a_monotonic_sequence_and_valid_lease_interval()
-> Result<(), Box<dyn std::error::Error>> {
    let envelope = |presence: PublishPresence| ControlEnvelope {
        header: Some(valid_header()),
        message: Some(Message::PublishPresence(presence)),
    };
    let valid = PublishPresence {
        node_id: vec![3; 16],
        incarnation: 2,
        roles: vec![NodeRole::Storage.into()],
        private_addresses: vec!["127.0.0.1:7443".to_owned()],
        lease_expires_unix_micros: 2_000,
        health: Some(VersionedPayload {
            format_version: 1,
            canonical_bytes: Vec::new(),
        }),
        presence_sequence: 7,
        observed_mesh_time: 1_000,
    };
    assert!(encode_control_frame(&envelope(valid.clone()), limits()?).is_ok());

    let mut missing_sequence = valid.clone();
    missing_sequence.presence_sequence = 0;
    assert_eq!(
        encode_control_frame(&envelope(missing_sequence), limits()?),
        Err(WireContractError::InvalidMessage)
    );

    let mut reversed_lease = valid;
    reversed_lease.lease_expires_unix_micros = 999;
    assert_eq!(
        encode_control_frame(&envelope(reversed_lease), limits()?),
        Err(WireContractError::InvalidMessage)
    );
    Ok(())
}

#[test]
fn consensus_responses_are_bound_to_an_exact_quorum_plan() -> Result<(), Box<dyn std::error::Error>>
{
    let mut response = VoteResponse {
        term: 4,
        granted: true,
        membership_epoch: 3,
        rejection: None,
        quorum_plan_digest: vec![9; 32],
    };
    let envelope = |response: VoteResponse| ControlEnvelope {
        header: Some(valid_header()),
        message: Some(Message::VoteResponse(response)),
    };
    assert!(encode_control_frame(&envelope(response.clone()), limits()?).is_ok());
    response.quorum_plan_digest.clear();
    assert_eq!(
        encode_control_frame(&envelope(response), limits()?),
        Err(WireContractError::InvalidMessage)
    );
    Ok(())
}

#[test]
fn bulk_frames_have_independent_payload_bounds() -> Result<(), Box<dyn std::error::Error>> {
    let wire_limits = WireLimits::new(4_096, 4, 8, 64)?;
    let accepted = DataFrame {
        offset: 10,
        bytes: vec![1, 2, 3, 4],
    };
    let encoded = encode_data_frame(&accepted, wire_limits)?;
    assert_eq!(
        decode_data_frame(&encoded, wire_limits)?.into_inner(),
        accepted
    );
    assert_eq!(
        encode_data_frame(
            &DataFrame {
                offset: 0,
                bytes: vec![0; 5],
            },
            wire_limits
        ),
        Err(WireContractError::InvalidMessage)
    );
    Ok(())
}

#[test]
fn shard_control_requires_bound_authority_and_round_trips() -> Result<(), Box<dyn std::error::Error>>
{
    let wire_limits = limits()?;
    let accepted = DataControlEnvelope {
        message: Some(DataMessage::PutShardBegin(PutShardBegin {
            header: Some(valid_header()),
            target_id: vec![7; 16],
            target_generation: 2,
            shard: Some(valid_shard()),
            declared_length: 4,
            declared_digest: vec![8; 32],
            write_capability: vec![9; 32],
            federation_capability_digest: Vec::new(),
        })),
    };
    let encoded = encode_data_control_frame(&accepted, wire_limits)?;
    assert_eq!(
        decode_data_control_frame(&encoded, wire_limits)?.into_inner(),
        accepted
    );

    let missing_permit = DataControlEnvelope {
        message: Some(DataMessage::DeleteShardRequest(DeleteShardRequest {
            header: Some(valid_header()),
            target_id: vec![7; 16],
            target_generation: 2,
            shard: Some(valid_shard()),
            removal_permit: None,
            federation_capability_digest: Vec::new(),
        })),
    };
    assert_eq!(
        encode_data_control_frame(&missing_permit, wire_limits),
        Err(WireContractError::InvalidMessage)
    );

    for accepted in [
        DataControlEnvelope {
            message: Some(DataMessage::DeleteShardResult(DeleteShardResult {
                result: Some(durable_result()),
                receipt: Some(versioned_payload()),
            })),
        },
        DataControlEnvelope {
            message: Some(DataMessage::ReclaimShardRequest(ReclaimShardRequest {
                header: Some(valid_header()),
                target_id: vec![7; 16],
                target_generation: 2,
                shard: Some(valid_shard()),
                tombstone_receipt: Some(versioned_payload()),
                federation_capability_digest: Vec::new(),
            })),
        },
        DataControlEnvelope {
            message: Some(DataMessage::ReclaimShardResult(ReclaimShardResult {
                result: Some(durable_result()),
                receipt: Some(versioned_payload()),
            })),
        },
    ] {
        let encoded = encode_data_control_frame(&accepted, wire_limits)?;
        assert_eq!(
            decode_data_control_frame(&encoded, wire_limits)?.into_inner(),
            accepted
        );
    }
    Ok(())
}

fn durable_result() -> OperationResult {
    OperationResult {
        outcome: OperationOutcome::Durable.into(),
        committed_revision: None,
        error: None,
        result: None,
        result_digest: Vec::new(),
    }
}

fn versioned_payload() -> VersionedPayload {
    VersionedPayload {
        format_version: 1,
        canonical_bytes: vec![1],
    }
}

fn hello_envelope(fixture: &HelloFixture) -> Result<ControlEnvelope, Box<dyn std::error::Error>> {
    let version = ProtocolVersion {
        major: fixture.protocol_major,
        minor: fixture.protocol_minor,
    };
    let component = ComponentSupport {
        contract_kind: fixture.component_contract_kind,
        implementation_id: fixture.component_implementation_id.clone(),
        versions: vec![version],
        maximum_control_bytes: fixture.maximum_control_bytes,
        maximum_items: fixture.maximum_items,
        maximum_concurrency: fixture.maximum_concurrency,
    };
    Ok(ControlEnvelope {
        header: None,
        message: Some(Message::NodeHello(NodeHello {
            versions: vec![version],
            mesh_id: hex_to_bytes(&fixture.mesh_id_hex)?,
            node_id: hex_to_bytes(&fixture.node_id_hex)?,
            incarnation: fixture.incarnation,
            roles: fixture.roles.clone(),
            components: vec![component],
            feature_bits: fixture.feature_bits.clone(),
            maximum_control_bytes: fixture.maximum_control_bytes,
            maximum_data_frame_bytes: fixture.maximum_data_frame_bytes,
            maximum_streams: fixture.maximum_streams,
        })),
    })
}

fn limits() -> Result<WireLimits, WireContractError> {
    WireLimits::new(4 * 1_024 * 1_024, 1_024 * 1_024, 4_096, 4_096)
}

fn rewrite_length_prefix(frame: &mut [u8]) -> Result<(), Box<dyn std::error::Error>> {
    let payload_length = frame.len().checked_sub(4).ok_or("missing frame prefix")?;
    let prefix = u32::try_from(payload_length)?.to_be_bytes();
    frame[..4].copy_from_slice(&prefix);
    Ok(())
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn hex_to_bytes(value: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if !value.len().is_multiple_of(2) {
        return Err("hex value has an odd length".into());
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let pair = std::str::from_utf8(pair)?;
            Ok(u8::from_str_radix(pair, 16)?)
        })
        .collect()
}

fn valid_header() -> RequestHeader {
    RequestHeader {
        version: Some(ProtocolVersion { major: 1, minor: 0 }),
        mesh_id: vec![1; 16],
        partition_id: vec![2; 16],
        routing_epoch: 1,
        sender_node_id: vec![3; 16],
        sender_incarnation: 1,
        request_id: vec![4; 16],
        operation_id: vec![5; 16],
        deadline_unix_micros: 1,
        trace_id: vec![6; 16],
    }
}

fn valid_shard() -> ShardIdentity {
    ShardIdentity {
        manifest_digest: vec![10; 32],
        stripe_index: 0,
        shard_index: 0,
        generation: 1,
    }
}
