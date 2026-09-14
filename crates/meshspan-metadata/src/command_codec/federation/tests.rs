// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::BoundedItems;
use meshspan_domain::{AuditEventId, OperationId, PrincipalId, UnixMicros};

use super::*;
use crate::{
    CommandContext, FederationGovernanceEdge, FederationGovernanceProof, FederationTrustIdentity,
    decode_authoritative_command, encode_authoritative_command,
};

mod lifecycle;

#[test]
fn federation_pairing_commands_preserve_evidence_and_reject_truncated_wire()
-> Result<(), Box<dyn std::error::Error>> {
    let invitation = crate::IssueFederationPairingInvitation {
        relationship_id: FederationRelationshipId::from_bytes([4; 16])?,
        issuing_node_id: meshspan_domain::NodeId::from_bytes([5; 16])?,
        issuance_key_generation: 3,
        material_verifier: [6; 32],
        endpoint: "https://files.example.test:8443".into(),
        certificate_fingerprint: [7; 32],
        expires_at: UnixMicros::new(900_000_100),
    };
    let commands = [
        AuthoritativeCommand::IssueFederationPairingInvitation(invitation.clone()),
        AuthoritativeCommand::CancelFederationPairingInvitation(
            crate::CancelFederationPairingInvitation {
                relationship_id: invitation.relationship_id,
                expected_invitation_revision: meshspan_domain::Revision::new(5),
                reason: "Withdraw connection".into(),
            },
        ),
    ];
    for (command, kind) in commands.iter().zip([116_u16, 117]) {
        assert_round_trip_and_bounds(context()?, command)?;
        let encoded = encode_authoritative_command(context()?, command)?;
        assert_eq!(encoded.get(61..63), Some(kind.to_be_bytes().as_slice()));
    }
    Ok(())
}

#[test]
fn federation_proposal_has_exact_wire_layout_and_rejects_unknown_tags()
-> Result<(), Box<dyn std::error::Error>> {
    let command =
        AuthoritativeCommand::ProposeFederationRelationship(ProposeFederationRelationship {
            relationship_id: FederationRelationshipId::from_bytes([4; 16])?,
            remote_mesh_id: MeshId::from_bytes([5; 16])?,
            remote_name: RecordName::new("Office")?,
            kind: FederationRelationshipKind::Horizontal,
            governance_direction: FederationGovernanceDirection::None,
        });
    let context = context()?;
    let encoded = encode_authoritative_command(context, &command)?;
    let mut expected = b"MSC\x04".to_vec();
    for identifier in [[1; 16], [2; 16], [3; 16]] {
        expected.extend(identifier);
    }
    expected.extend(100_i64.to_be_bytes());
    expected.push(0); // No expected revision.
    expected.extend(91_u16.to_be_bytes());
    expected.extend([4; 16]);
    expected.extend([5; 16]);
    expected.extend(6_u32.to_be_bytes());
    expected.extend(b"Office");
    expected.extend([1, 0]); // Horizontal, no governance direction.
    assert_eq!(encoded, expected);
    assert_round_trip_and_bounds(context, &command)?;
    for position in [encoded.len() - 1, encoded.len() - 2] {
        let mut malformed = encoded.clone();
        malformed[position] = 9;
        assert!(matches!(
            decode_authoritative_command(&malformed),
            Err(MetadataCommandCodecError::Invalid)
        ));
    }
    Ok(())
}

#[test]
fn federation_approval_preserves_signed_ancestry_and_bounds_it_before_encoding()
-> Result<(), Box<dyn std::error::Error>> {
    let edge = FederationGovernanceEdge {
        parent_mesh_id: MeshId::from_bytes([5; 16])?,
        child_mesh_id: MeshId::from_bytes([6; 16])?,
    };
    let mut value = ApproveFederationRelationship {
        relationship_id: FederationRelationshipId::from_bytes([4; 16])?,
        expected_authority_epoch: 1,
        local_identity: identity(7),
        remote_identity: identity(8),
        governance_proof: Some(FederationGovernanceProof {
            remote_authority_epoch: 9,
            ancestry: BoundedItems::new(vec![edge], 1)?,
            signer_generation: 10,
            signature: [11; 64],
        }),
    };
    assert_round_trip_and_bounds(
        context()?,
        &AuthoritativeCommand::ApproveFederationRelationship(value.clone()),
    )?;
    value.governance_proof.as_mut().ok_or("proof")?.ancestry =
        BoundedItems::new(vec![edge; 4097], 4097)?;
    assert!(matches!(
        encode_authoritative_command(
            context()?,
            &AuthoritativeCommand::ApproveFederationRelationship(value)
        ),
        Err(MetadataCommandCodecError::CapacityExceeded)
    ));
    Ok(())
}

#[test]
fn federation_transitions_reject_invalid_epoch_and_reason() -> Result<(), Box<dyn std::error::Error>>
{
    let mut value = RevokeFederationRelationship {
        relationship_id: FederationRelationshipId::from_bytes([4; 16])?,
        expected_authority_epoch: 2,
        authority_epoch: 3,
        reason: "End sharing".into(),
    };
    assert_round_trip_and_bounds(
        context()?,
        &AuthoritativeCommand::RevokeFederationRelationship(value.clone()),
    )?;
    for reason in [" ".to_owned(), "unsafe\nreason".to_owned(), "x".repeat(513)] {
        value.reason = reason;
        assert!(
            encode_authoritative_command(
                context()?,
                &AuthoritativeCommand::RevokeFederationRelationship(value.clone())
            )
            .is_err()
        );
    }
    value.reason = "End sharing".into();
    value.authority_epoch = 2;
    assert!(matches!(
        encode_authoritative_command(
            context()?,
            &AuthoritativeCommand::RevokeFederationRelationship(value)
        ),
        Err(MetadataCommandCodecError::Invalid)
    ));
    Ok(())
}

fn assert_round_trip_and_bounds(
    context: CommandContext,
    command: &AuthoritativeCommand,
) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = encode_authoritative_command(context, command)?;
    let decoded = decode_authoritative_command(&bytes)?;
    assert_eq!(decoded.context, context);
    assert_eq!(decoded.command, *command);
    assert_eq!(
        encode_authoritative_command(decoded.context, &decoded.command)?,
        bytes
    );
    for end in 0..bytes.len() {
        assert!(decode_authoritative_command(&bytes[..end]).is_err());
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(matches!(
        decode_authoritative_command(&trailing),
        Err(MetadataCommandCodecError::Invalid)
    ));
    Ok(())
}

fn context() -> Result<CommandContext, meshspan_domain::IdentifierError> {
    Ok(CommandContext {
        operation_id: OperationId::from_bytes([1; 16])?,
        actor_principal_id: PrincipalId::from_bytes([2; 16])?,
        audit_event_id: AuditEventId::from_bytes([3; 16])?,
        occurred_at: UnixMicros::new(100),
        expected_revision: None,
    })
}

fn identity(marker: u8) -> FederationTrustIdentity {
    FederationTrustIdentity {
        generation: 1,
        certificate_fingerprint: [marker; 32],
        verifying_key: [marker; 32],
        valid_from: UnixMicros::new(1),
        valid_until: UnixMicros::new(1000),
    }
}
