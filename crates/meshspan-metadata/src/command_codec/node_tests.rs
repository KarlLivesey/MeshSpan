// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::{
    AuthoritativeCommandContext, NodeCapabilityPrior, NodeCommandContext, RefreshNodeCapabilities,
    RevokeUserEnrollment,
};
use meshspan_domain::NodeId;

#[test]
fn metadata_versions_preserve_18_principals_and_reject_new_opcodes()
-> Result<(), Box<dyn std::error::Error>> {
    let (context, command) = tests::fixture()?;
    let bytes = encode_authoritative_command(context, &command)?;
    assert_eq!(bytes.get(..4), Some(b"MSC\x04".as_slice()));
    for version in [18, 19] {
        let decoded = decode_authoritative_entry_for_version(version, &bytes)?;
        assert_eq!(
            decoded.context,
            AuthoritativeCommandContext::Principal(context)
        );
        assert_eq!(decoded.command, command);
        assert_eq!(
            decoded.context.request_digest(&decoded.command),
            command.request_digest(context)
        );
    }
    for version in [0, 1, 17, 20, u16::MAX] {
        assert!(!is_supported_metadata_command_version(version));
        assert_eq!(
            decode_authoritative_entry_for_version(version, &bytes),
            Err(MetadataCommandCodecError::Unsupported)
        );
    }
    let command = AuthoritativeCommand::RevokeUserEnrollment(RevokeUserEnrollment {
        enrollment_operation_id: context.operation_id,
        expected_revision: Revision::new(1),
    });
    let bytes = encode_authoritative_command(context, &command)?;
    assert_eq!(
        decode_authoritative_entry_for_version(18, &bytes),
        Err(MetadataCommandCodecError::Unsupported)
    );
    assert_eq!(
        decode_authoritative_entry_for_version(19, &bytes)?.command,
        command
    );
    Ok(())
}

#[test]
fn node_envelope_has_distinct_actor_digest_and_rejects_principal_or_historical_use()
-> Result<(), Box<dyn std::error::Error>> {
    let (principal, _) = tests::fixture()?;
    let node = NodeId::from_bytes([42; 16])?;
    let context = NodeCommandContext {
        operation_id: principal.operation_id,
        actor_node_id: node,
        audit_event_id: principal.audit_event_id,
        occurred_at: principal.occurred_at,
        expected_revision: None,
    };
    let command = AuthoritativeCommand::RefreshNodeCapabilities(RefreshNodeCapabilities {
        node_id: node,
        incarnation: 1,
        certificate_generation: 2,
        certificate_fingerprint: [3; 32],
        capability_digest: [4; 32],
        prior: NodeCapabilityPrior::InitialAdmittedCertificate {
            revision: Revision::new(7),
            generation: 2,
            certificate_fingerprint: [3; 32],
        },
    });
    let bytes = encode_authoritative_node_command(context, &command)?;
    assert_eq!(bytes.get(..4), Some(b"MSN\x01".as_slice()));
    assert_eq!(
        decode_authoritative_entry_for_version(19, &bytes)?,
        DecodedAuthoritativeEntry {
            context: AuthoritativeCommandContext::Node(context),
            command: command.clone()
        }
    );
    assert_eq!(
        decode_authoritative_entry_for_version(18, &bytes),
        Err(MetadataCommandCodecError::Unsupported)
    );
    assert!(encode_authoritative_command(principal, &command).is_err());
    assert!(decode_authoritative_command(&bytes).is_err());
    assert_ne!(
        command.request_digest(principal),
        AuthoritativeCommandContext::Node(context).request_digest(&command)
    );
    for length in 0..bytes.len() {
        assert!(decode_authoritative_entry_for_version(19, &bytes[..length]).is_err());
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(decode_authoritative_entry_for_version(19, &trailing).is_err());
    let mut wrong_actor = context;
    wrong_actor.actor_node_id = NodeId::from_bytes([43; 16])?;
    assert!(encode_authoritative_node_command(wrong_actor, &command).is_err());
    Ok(())
}
