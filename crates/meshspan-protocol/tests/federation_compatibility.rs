// SPDX-License-Identifier: GPL-2.0-only

//! Canonical cross-swarm federation bytes and hostile semantic vectors.

use meshspan_protocol::v1::federation_envelope::Message;
use meshspan_protocol::v1::{
    ErrorCode, FederatedBranchResult, FederatedStorageCapability, FederationAuthorityPage,
    FederationEnvelope, FederationHeader, FederationHello, ProposeFederatedBranch, ProtocolVersion,
    RemoteShardAction, RequestFederatedStorageCapability, ShardIdentity, VersionedPayload,
    WireError,
};
use meshspan_protocol::{
    WireContractError, WireLimits, decode_federation_frame, encode_federation_frame,
};
use serde::Deserialize;

const FIXTURE: &str = include_str!("../../../contracts/protobuf/v1/federation-hello.json");

#[derive(Debug, Deserialize)]
struct FederationHelloFixture {
    name: String,
    relationship_id_hex: String,
    sender_mesh_id_hex: String,
    recipient_mesh_id_hex: String,
    request_id_hex: String,
    operation_id_hex: String,
    trace_id_hex: String,
    authority_epoch: u64,
    deadline_unix_micros: i64,
    identity_generation: u64,
    maximum_control_bytes: u64,
    maximum_data_frame_bytes: u64,
    maximum_streams: u32,
    expected_frame_hex: String,
}

#[test]
fn committed_federation_hello_is_canonical() -> Result<(), Box<dyn std::error::Error>> {
    let fixture: FederationHelloFixture = serde_json::from_str(FIXTURE)?;
    assert_eq!(fixture.name, "federation-hello-v1.0");
    let envelope = hello_envelope(&fixture)?;
    let frame = encode_federation_frame(&envelope, limits()?)?;
    assert_eq!(bytes_to_hex(&frame), fixture.expected_frame_hex);
    assert_eq!(
        decode_federation_frame(&frame, limits()?)?.into_inner(),
        envelope
    );
    Ok(())
}

#[test]
fn header_rejects_self_federation_and_missing_replay_binding()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture: FederationHelloFixture = serde_json::from_str(FIXTURE)?;
    let mut envelope = hello_envelope(&fixture)?;
    let header = envelope.header.as_mut().ok_or("missing header")?;
    header.recipient_mesh_id.clone_from(&header.sender_mesh_id);
    assert_eq!(
        encode_federation_frame(&envelope, limits()?),
        Err(WireContractError::InvalidMessage)
    );

    let mut envelope = hello_envelope(&fixture)?;
    envelope
        .header
        .as_mut()
        .ok_or("missing header")?
        .replay_nonce
        .clear();
    assert_eq!(
        encode_federation_frame(&envelope, limits()?),
        Err(WireContractError::InvalidMessage)
    );
    Ok(())
}

#[test]
fn branch_result_cannot_collapse_distinct_durability_states()
-> Result<(), Box<dyn std::error::Error>> {
    use meshspan_protocol::v1::{OperationOutcome, OperationResult};

    let valid = |outcome: OperationOutcome,
                 owner_history_revision: Option<u64>,
                 protection_receipt: Option<VersionedPayload>,
                 quarantine_id: Option<Vec<u8>>| {
        federation_envelope(Message::BranchResult(FederatedBranchResult {
            result: Some(OperationResult {
                outcome: outcome.into(),
                committed_revision: None,
                error: matches!(outcome, OperationOutcome::Rejected).then_some(WireError {
                    code: ErrorCode::Unauthorised.into(),
                    diagnostic_code: 1,
                    retry_after_micros: None,
                }),
                result: None,
                result_digest: Vec::new(),
            }),
            accepting_swarm_receipt: Some(payload()),
            owner_history_revision,
            protection_receipt,
            quarantine_id,
            alternative_head_digests: vec![vec![14; 32]],
            signature: vec![15; 64],
        }))
    };

    for envelope in [
        valid(OperationOutcome::BranchCommitted, None, None, None),
        valid(OperationOutcome::GloballyConverged, Some(8), None, None),
        valid(
            OperationOutcome::PolicyCommitted,
            Some(8),
            Some(payload()),
            None,
        ),
        valid(OperationOutcome::Rejected, None, None, Some(vec![16; 16])),
    ] {
        assert!(encode_federation_frame(&envelope, limits()?).is_ok());
    }

    assert_eq!(
        encode_federation_frame(
            &valid(OperationOutcome::GloballyConverged, None, None, None),
            limits()?
        ),
        Err(WireContractError::InvalidMessage)
    );
    assert_eq!(
        encode_federation_frame(
            &valid(OperationOutcome::BranchCommitted, Some(8), None, None),
            limits()?
        ),
        Err(WireContractError::InvalidMessage)
    );
    Ok(())
}

#[test]
fn federation_pages_obey_negotiated_item_bounds() -> Result<(), Box<dyn std::error::Error>> {
    let page = |records: Vec<VersionedPayload>| {
        federation_envelope(Message::AuthorityPage(FederationAuthorityPage {
            authority_revision: 2,
            records,
            next_cursor: vec![1],
            page_digest: vec![2; 32],
            signature: vec![3; 64],
        }))
    };
    let small_limits = WireLimits::new(4_096, 1_024, 2, 64)?;
    assert!(encode_federation_frame(&page(vec![payload(), payload()]), small_limits).is_ok());
    assert_eq!(
        encode_federation_frame(&page(vec![payload(), payload(), payload()]), small_limits),
        Err(WireContractError::InvalidMessage)
    );
    Ok(())
}

#[test]
fn branch_exchange_binds_grant_scope_heads_and_signature() -> Result<(), Box<dyn std::error::Error>>
{
    let mut proposal = ProposeFederatedBranch {
        grant_id: vec![20; 16],
        resource_scope: Some(payload()),
        grant_use_evidence: Some(payload()),
        branch_head_digests: vec![vec![21; 32]],
        expected_owner_head_digest: vec![22; 32],
        signature: vec![23; 64],
    };
    assert!(
        encode_federation_frame(
            &federation_envelope(Message::ProposeBranch(proposal.clone())),
            limits()?
        )
        .is_ok()
    );
    proposal.branch_head_digests.clear();
    assert_eq!(
        encode_federation_frame(
            &federation_envelope(Message::ProposeBranch(proposal)),
            limits()?
        ),
        Err(WireContractError::InvalidMessage)
    );
    Ok(())
}

#[test]
fn storage_capability_is_exactly_bound_and_bounded() -> Result<(), Box<dyn std::error::Error>> {
    let request = RequestFederatedStorageCapability {
        grant_id: vec![30; 16],
        target_id: vec![31; 16],
        target_generation: 2,
        shard: Some(shard()),
        action: RemoteShardAction::Put.into(),
        maximum_bytes: 1_024,
        scope_digest: vec![32; 32],
    };
    assert!(
        encode_federation_frame(
            &federation_envelope(Message::RequestStorageCapability(request.clone())),
            limits()?
        )
        .is_ok()
    );

    let mut missing_action = request;
    missing_action.action = RemoteShardAction::Unspecified.into();
    assert_eq!(
        encode_federation_frame(
            &federation_envelope(Message::RequestStorageCapability(missing_action)),
            limits()?
        ),
        Err(WireContractError::InvalidMessage)
    );

    let capability = FederatedStorageCapability {
        grant_id: vec![30; 16],
        target_id: vec![31; 16],
        target_generation: 2,
        shard: Some(shard()),
        action: RemoteShardAction::Get.into(),
        maximum_bytes: 1_024,
        valid_until_unix_micros: 3_000_000,
        capability_nonce: vec![33; 32],
        canonical_capability: vec![34; 128],
        signature: vec![35; 64],
    };
    assert!(
        encode_federation_frame(
            &federation_envelope(Message::StorageCapability(capability)),
            limits()?
        )
        .is_ok()
    );
    Ok(())
}

fn hello_envelope(
    fixture: &FederationHelloFixture,
) -> Result<FederationEnvelope, Box<dyn std::error::Error>> {
    Ok(FederationEnvelope {
        header: Some(FederationHeader {
            version: Some(ProtocolVersion { major: 1, minor: 0 }),
            relationship_id: hex_to_bytes(&fixture.relationship_id_hex)?,
            sender_mesh_id: hex_to_bytes(&fixture.sender_mesh_id_hex)?,
            recipient_mesh_id: hex_to_bytes(&fixture.recipient_mesh_id_hex)?,
            request_id: hex_to_bytes(&fixture.request_id_hex)?,
            operation_id: hex_to_bytes(&fixture.operation_id_hex)?,
            authority_epoch: fixture.authority_epoch,
            deadline_unix_micros: fixture.deadline_unix_micros,
            trace_id: hex_to_bytes(&fixture.trace_id_hex)?,
            replay_nonce: vec![9; 32],
        }),
        message: Some(Message::Hello(FederationHello {
            versions: vec![ProtocolVersion { major: 1, minor: 0 }],
            identity_generation: fixture.identity_generation,
            public_identity_chain: vec![10; 48],
            challenge_nonce: vec![11; 32],
            feature_bits: vec![2, 8],
            maximum_control_bytes: fixture.maximum_control_bytes,
            maximum_data_frame_bytes: fixture.maximum_data_frame_bytes,
            maximum_streams: fixture.maximum_streams,
            signature: vec![12; 64],
        })),
    })
}

fn federation_envelope(message: Message) -> FederationEnvelope {
    FederationEnvelope {
        header: Some(FederationHeader {
            version: Some(ProtocolVersion { major: 1, minor: 0 }),
            relationship_id: vec![1; 16],
            sender_mesh_id: vec![2; 16],
            recipient_mesh_id: vec![3; 16],
            request_id: vec![4; 16],
            operation_id: vec![5; 16],
            authority_epoch: 1,
            deadline_unix_micros: 2_000_000,
            trace_id: vec![6; 16],
            replay_nonce: vec![7; 32],
        }),
        message: Some(message),
    }
}

fn payload() -> VersionedPayload {
    VersionedPayload {
        format_version: 1,
        canonical_bytes: vec![1],
    }
}

fn shard() -> ShardIdentity {
    ShardIdentity {
        manifest_digest: vec![40; 32],
        stripe_index: 1,
        shard_index: 2,
        generation: 3,
    }
}

fn limits() -> Result<WireLimits, WireContractError> {
    WireLimits::new(4 * 1_024 * 1_024, 1_024 * 1_024, 4_096, 4_096)
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
