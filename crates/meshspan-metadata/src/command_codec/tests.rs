// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    ActivationPolicyId, ApiKeyId, AuditEventId, AuthenticationMethodId, GroupId, HostId, MeshId,
    NodeId, OperationId, PrincipalId, RecoveryCodeId, Revision, RoleId, UnixMicros,
};

use super::*;
use crate::{
    AddGroupMember, BootstrapAppliance, BootstrapMesh, CreateAuthenticationMethod, CreateGroup,
    CreateUser, NewAuthenticationCredential, NewRecoveryCode, RecordName, RemoveGroupMember,
    TotpAlgorithm,
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
    let (context, bootstrap) = fixture()?;
    let AuthoritativeCommand::BootstrapAppliance(bootstrap) = bootstrap else {
        return Err("fixture command changed".into());
    };
    let command = AuthoritativeCommand::BootstrapMesh(bootstrap.mesh);
    assert_eq!(
        encode_authoritative_command(context, &command),
        Err(MetadataCommandCodecError::Unsupported)
    );
    Ok(())
}

#[test]
fn identity_commands_round_trip_without_losing_optional_intent()
-> Result<(), Box<dyn std::error::Error>> {
    let (context, _) = fixture()?;
    let group = GroupId::from_bytes([41; 16])?;
    let principal = PrincipalId::from_bytes([42; 16])?;
    for command in [
        AuthoritativeCommand::CreateUser(CreateUser {
            principal_id: principal,
            name: RecordName::new("User")?,
        }),
        AuthoritativeCommand::CreateGroup(CreateGroup {
            group_id: group,
            name: RecordName::new("Group")?,
            activation_policy_id: Some(ActivationPolicyId::from_bytes([43; 16])?),
        }),
        AuthoritativeCommand::AddGroupMember(AddGroupMember {
            containing_group_id: group,
            member_principal_id: principal,
            valid_from: None,
            valid_until: Some(UnixMicros::new(99)),
            activation_required: true,
        }),
        AuthoritativeCommand::RemoveGroupMember(RemoveGroupMember {
            containing_group_id: group,
            member_principal_id: principal,
            reason: "Access ended".to_owned(),
        }),
    ] {
        assert_round_trip(context, command)?;
    }
    Ok(())
}

#[test]
fn every_authentication_credential_family_round_trips() -> Result<(), Box<dyn std::error::Error>> {
    let (context, _) = fixture()?;
    let credentials = [
        NewAuthenticationCredential::Passkey {
            credential_id: vec![1, 2, 3],
            public_key_algorithm: -7,
            public_key: vec![4, 5, 6],
            signature_counter: 7,
            authenticator_guid: Some([8; 16]),
            transports: 3,
            backup_eligible: true,
            backup_state: false,
        },
        NewAuthenticationCredential::Totp {
            secret_ciphertext: vec![9, 10],
            algorithm: TotpAlgorithm::Sha512,
            digits: 8,
            period_seconds: 30,
            accepted_step_window: 1,
        },
        NewAuthenticationCredential::RecoveryCodes {
            codes: BoundedItems::new(
                vec![NewRecoveryCode {
                    code_id: RecoveryCodeId::from_bytes([44; 16])?,
                    code_digest: [45; 32],
                }],
                1,
            )?,
        },
        NewAuthenticationCredential::ApiKey {
            key_id: ApiKeyId::from_bytes([46; 16])?,
            key_digest: [47; 32],
            scopes: 3,
            valid_from: UnixMicros::new(-1),
        },
    ];
    for (index, credential) in credentials.into_iter().enumerate() {
        let method_marker = 50_u8
            .checked_add(u8::try_from(index)?)
            .ok_or("method fixture marker overflowed")?;
        assert_round_trip(
            context,
            AuthoritativeCommand::CreateAuthenticationMethod(CreateAuthenticationMethod {
                method_id: AuthenticationMethodId::from_bytes([method_marker; 16])?,
                principal_id: context.actor_principal_id,
                label: format!("Method {index}"),
                service_scope: 7,
                expires_at: Some(UnixMicros::new(1_000)),
                credential,
            }),
        )?;
    }
    Ok(())
}

fn assert_round_trip(
    context: CommandContext,
    command: AuthoritativeCommand,
) -> Result<(), MetadataCommandCodecError> {
    let bytes = encode_authoritative_command(context, &command)?;
    assert_eq!(
        decode_authoritative_command(&bytes)?,
        DecodedAuthoritativeCommand { context, command }
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
