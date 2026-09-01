// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    ApiKeyId, AuditEventId, AuthenticationMethodId, HostId, MeshId, NodeId, OperationId,
    PrincipalId, Revision, RoleId, UnixMicros,
};

use super::*;
use crate::{
    BootstrapAppliance, BootstrapMesh, CreateAuthenticationMethod, NewAuthenticationCredential,
    RecordName,
};

#[test]
fn bootstrap_appliance_round_trips_canonically() -> Result<(), Box<dyn std::error::Error>> {
    let (context, command) = fixture()?;
    let first = encode_authoritative_command(context, &command)?;
    let decoded = decode_authoritative_command(&first)?;
    let second = encode_authoritative_command(decoded.context, &decoded.command)?;
    assert_eq!(decoded, DecodedAuthoritativeCommand { context, command });
    assert_eq!(first, second);
    Ok(())
}

#[test]
fn decoder_rejects_truncation_trailing_bytes_and_noncanonical_flags()
-> Result<(), Box<dyn std::error::Error>> {
    let (context, command) = fixture()?;
    let bytes = encode_authoritative_command(context, &command)?;
    for length in 0..bytes.len() {
        assert!(decode_authoritative_command(&bytes[..length]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        decode_authoritative_command(&trailing),
        Err(MetadataCommandCodecError::Invalid)
    );
    let mut invalid_optional_revision = bytes;
    invalid_optional_revision[60] = 2;
    assert_eq!(
        decode_authoritative_command(&invalid_optional_revision),
        Err(MetadataCommandCodecError::Invalid)
    );
    Ok(())
}

#[test]
fn unsupported_command_never_produces_partial_wire_bytes() -> Result<(), Box<dyn std::error::Error>>
{
    let (context, _) = fixture()?;
    let command = AuthoritativeCommand::CreateUser(crate::CreateUser {
        principal_id: PrincipalId::from_bytes([91; 16])?,
        name: RecordName::new("Not encoded yet")?,
    });
    assert_eq!(
        encode_authoritative_command(context, &command),
        Err(MetadataCommandCodecError::Unsupported)
    );
    Ok(())
}

fn fixture() -> Result<(CommandContext, AuthoritativeCommand), Box<dyn std::error::Error>> {
    let context = CommandContext {
        operation_id: OperationId::from_bytes([1; 16])?,
        actor_principal_id: PrincipalId::from_bytes([2; 16])?,
        audit_event_id: AuditEventId::from_bytes([3; 16])?,
        occurred_at: UnixMicros::new(-12),
        expected_revision: Some(Revision::new(4)),
    };
    let command = AuthoritativeCommand::BootstrapAppliance(BootstrapAppliance {
        mesh: BootstrapMesh {
            mesh_id: MeshId::from_bytes([5; 16])?,
            mesh_name: RecordName::new("Mesh")?,
            administrator_id: context.actor_principal_id,
            administrator_name: RecordName::new("Administrator")?,
            administrator_role_id: RoleId::from_bytes([6; 16])?,
            host_id: HostId::from_bytes([7; 16])?,
            host_name: RecordName::new("Host")?,
            node_id: NodeId::from_bytes([8; 16])?,
            node_name: RecordName::new("Node")?,
            partition_name: RecordName::new("Root authority")?,
        },
        authentication: CreateAuthenticationMethod {
            method_id: AuthenticationMethodId::from_bytes([9; 16])?,
            principal_id: context.actor_principal_id,
            label: "Initial API key".to_owned(),
            service_scope: 7,
            expires_at: None,
            credential: NewAuthenticationCredential::ApiKey {
                key_id: ApiKeyId::from_bytes([10; 16])?,
                key_digest: [11; 32],
                scopes: 1,
                valid_from: context.occurred_at,
            },
        },
    });
    Ok((context, command))
}
