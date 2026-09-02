// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    ActivationPolicyId, ApiKeyId, AssuranceLevel, AuditEventId, AuthenticationMethodId,
    AuthenticationService, AvailabilityCellId, ComponentInstanceId, DurationMicros, EntropyError,
    FailureScenario, FailureTerm, FaultGroupClassId, FaultGroupId, GrantId, GroupId, HostId,
    MeshId, NodeId, ObjectId, OperationId, OwnerSetId, PrincipalId, ProtectionPolicyId,
    ProtectionScenarioId, RandomSource, RecoveryCodeId, Revision, Rights, RoleId, SessionId,
    SmbExportId, TargetId, UnixMicros, VolumeId,
};
use meshspan_secret_envelope::{
    SecretContext, WrappingPrivateKey, WrappingPublicKey, encrypt_secret,
};
use sha2::{Digest, Sha256};

use super::*;
use crate::{
    AddGroupMember, AssignVolumeProtectionPolicy, BootstrapMesh, BootstrapRecoveryIdentity,
    CommitSecretGeneration, CreateActivationPolicy, CreateAuthenticationMethod,
    CreateAvailabilityCell, CreateComponent, CreateFaultGroup, CreateGroup, CreateProtectionPolicy,
    CreateUser, CreateVolume, GrantInheritance, GrantPermission, GrantPermissionWithActivation,
    IssueAuthenticationSession, NewAuthenticationCredential, NewRecoveryCode, PermissionScope,
    ProtectionScenarioConfiguration, PublishSmbExport, RecordName, RegisterNodeWrappingKey,
    RegisterStorageTarget, RemoveGroupMember, RevokeAuthenticationMethod,
    RevokeAuthenticationSession, SessionAuthenticationFactor, SessionClientLabel,
    SetHostAvailabilityCellMembership, SetHostFaultGroupMembership,
    SetTargetAvailabilityCellMembership, SmbExportGatewaySelection, StepUpAuthenticationSession,
    StorageUsageLimit, TotpAlgorithm, VOLUME_CONTENT_KEY_SECRET_KIND, WithdrawSmbExport,
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
fn topology_commands_round_trip_canonically() -> Result<(), Box<dyn std::error::Error>> {
    let (context, _) = fixture()?;
    let group_id = FaultGroupId::from_bytes([91; 16])?;
    for command in [
        AuthoritativeCommand::CreateFaultGroup(CreateFaultGroup {
            class_id: FaultGroupClassId::from_bytes([90; 16])?,
            class_name: RecordName::new("Power source")?,
            group_id,
            group_name: RecordName::new("UPS A")?,
        }),
        AuthoritativeCommand::SetHostFaultGroupMembership(SetHostFaultGroupMembership {
            group_id,
            host_id: HostId::from_bytes([92; 16])?,
            present: true,
        }),
        AuthoritativeCommand::CreateAvailabilityCell(CreateAvailabilityCell {
            cell_id: AvailabilityCellId::from_bytes([103; 16])?,
            name: RecordName::new("Building A")?,
            parent_cell_id: Some(AvailabilityCellId::from_bytes([104; 16])?),
        }),
        AuthoritativeCommand::SetHostAvailabilityCellMembership(
            SetHostAvailabilityCellMembership {
                cell_id: AvailabilityCellId::from_bytes([103; 16])?,
                host_id: HostId::from_bytes([105; 16])?,
                present: true,
            },
        ),
        AuthoritativeCommand::SetTargetAvailabilityCellMembership(
            SetTargetAvailabilityCellMembership {
                cell_id: AvailabilityCellId::from_bytes([103; 16])?,
                target_id: TargetId::from_bytes([106; 16])?,
                present: false,
            },
        ),
    ] {
        assert_round_trip(context, command)?;
    }
    Ok(())
}

#[test]
fn protection_policy_commands_round_trip_complete_failure_promises()
-> Result<(), Box<dyn std::error::Error>> {
    let (context, _) = fixture()?;
    let policy_id = ProtectionPolicyId::from_bytes([98; 16])?;
    for command in [
        AuthoritativeCommand::CreateProtectionPolicy(CreateProtectionPolicy {
            policy_id,
            name: RecordName::new("Two machines and three devices")?,
            scenarios: BoundedItems::new(
                vec![ProtectionScenarioConfiguration {
                    scenario_id: ProtectionScenarioId::from_bytes([99; 16])?,
                    name: RecordName::new("Combined machine and device loss")?,
                    scenario: FailureScenario::new(vec![
                        FailureTerm {
                            class_id: FaultGroupClassId::from_bytes([100; 16])?,
                            failure_count: 2,
                        },
                        FailureTerm {
                            class_id: FaultGroupClassId::from_bytes([101; 16])?,
                            failure_count: 3,
                        },
                    ])?,
                }],
                16,
            )?,
        }),
        AuthoritativeCommand::AssignVolumeProtectionPolicy(AssignVolumeProtectionPolicy {
            volume_id: VolumeId::from_bytes([102; 16])?,
            policy_id,
        }),
    ] {
        assert_round_trip(context, command)?;
    }
    Ok(())
}

#[test]
fn smb_export_commands_round_trip_gateway_selection_and_audit_reason()
-> Result<(), Box<dyn std::error::Error>> {
    let (context, _) = fixture()?;
    let export_id = SmbExportId::from_bytes([93; 16])?;
    for command in [
        AuthoritativeCommand::PublishSmbExport(PublishSmbExport {
            export_id,
            volume_id: VolumeId::from_bytes([94; 16])?,
            root_object_id: ObjectId::from_bytes([95; 16])?,
            share_name: RecordName::new("Finance")?,
            gateways: SmbExportGatewaySelection::Selected(BoundedItems::new(
                vec![NodeId::from_bytes([96; 16])?, NodeId::from_bytes([97; 16])?],
                1_024,
            )?),
            encryption_required: true,
        }),
        AuthoritativeCommand::WithdrawSmbExport(WithdrawSmbExport {
            export_id,
            reason: "No longer published".to_owned(),
        }),
    ] {
        assert_round_trip(context, command)?;
    }
    Ok(())
}

#[test]
fn activation_policy_and_grant_round_trip_as_one_atomic_command()
-> Result<(), Box<dyn std::error::Error>> {
    let (context, _) = fixture()?;
    let policy_id = ActivationPolicyId::from_bytes([44; 16])?;
    assert_round_trip(
        context,
        AuthoritativeCommand::GrantPermissionWithActivation(GrantPermissionWithActivation {
            policy: CreateActivationPolicy {
                policy_id,
                maximum_duration: DurationMicros::new(3_600_000_000),
                reason_required: true,
                minimum_assurance: AssuranceLevel::SingleFactor,
                valid_from: None,
                valid_until: Some(UnixMicros::new(900)),
            },
            grant: GrantPermission {
                grant_id: GrantId::from_bytes([45; 16])?,
                subject_principal_id: PrincipalId::from_bytes([46; 16])?,
                scope: PermissionScope::Volume(VolumeId::from_bytes([47; 16])?),
                rights: Rights::READ_DATA.union(Rights::WRITE_DATA),
                inheritance: GrantInheritance::ObjectAndDescendants,
                valid_from: Some(UnixMicros::new(100)),
                valid_until: Some(UnixMicros::new(800)),
                activation_policy_id: Some(policy_id),
            },
        }),
    )?;
    Ok(())
}

#[test]
fn volume_creation_round_trips_every_identity_and_owner() -> Result<(), Box<dyn std::error::Error>>
{
    let (context, _) = fixture()?;
    assert_round_trip(
        context,
        AuthoritativeCommand::CreateVolume(CreateVolume {
            volume_id: VolumeId::from_bytes([61; 16])?,
            name: RecordName::new("Shared files")?,
            root_object_id: ObjectId::from_bytes([62; 16])?,
            owner_set_id: OwnerSetId::from_bytes([63; 16])?,
            owners: BoundedItems::new(
                vec![
                    PrincipalId::from_bytes([64; 16])?,
                    PrincipalId::from_bytes([65; 16])?,
                ],
                1_024,
            )?,
            key_generation: codec_volume_key(VolumeId::from_bytes([61; 16])?)?,
        }),
    )?;
    Ok(())
}

#[test]
fn storage_target_registration_round_trips_topology_and_optional_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let (context, _) = fixture()?;
    for (offset, backing_device_fingerprint, filesystem_fingerprint, usage_limit) in [
        (
            0_u8,
            Some([20; 32]),
            Some([21; 32]),
            StorageUsageLimit::Percent(95),
        ),
        (1, None, None, StorageUsageLimit::Bytes(1_000_000)),
    ] {
        assert_round_trip(
            context,
            AuthoritativeCommand::RegisterStorageTarget(RegisterStorageTarget {
                target_id: TargetId::from_bytes([30 + offset; 16])?,
                node_id: NodeId::from_bytes([31 + offset; 16])?,
                host_id: HostId::from_bytes([32 + offset; 16])?,
                provider: storage_provider(33 + offset)?,
                name: RecordName::new(&format!("Storage {offset}"))?,
                generation: u64::from(offset) + 1,
                marker_fingerprint: [34 + offset; 32],
                backing_device_fingerprint,
                filesystem_fingerprint,
                usage_limit,
            }),
        )?;
    }
    Ok(())
}

#[test]
fn storage_target_codec_rejects_invalid_limits_and_fingerprints()
-> Result<(), Box<dyn std::error::Error>> {
    let (context, _) = fixture()?;
    let valid = RegisterStorageTarget {
        target_id: TargetId::from_bytes([30; 16])?,
        node_id: NodeId::from_bytes([31; 16])?,
        host_id: HostId::from_bytes([32; 16])?,
        provider: storage_provider(33)?,
        name: RecordName::new("Storage")?,
        generation: 1,
        marker_fingerprint: [34; 32],
        backing_device_fingerprint: None,
        filesystem_fingerprint: None,
        usage_limit: StorageUsageLimit::Percent(95),
    };
    for invalid in [
        RegisterStorageTarget {
            generation: 0,
            ..valid.clone()
        },
        RegisterStorageTarget {
            marker_fingerprint: [0; 32],
            ..valid.clone()
        },
        RegisterStorageTarget {
            usage_limit: StorageUsageLimit::Percent(101),
            ..valid
        },
    ] {
        assert_eq!(
            encode_authoritative_command(
                context,
                &AuthoritativeCommand::RegisterStorageTarget(invalid),
            ),
            Err(MetadataCommandCodecError::Invalid)
        );
    }
    Ok(())
}

#[test]
fn node_wrapping_key_round_trips_and_rejects_substitution() -> Result<(), Box<dyn std::error::Error>>
{
    let (context, _) = fixture()?;
    let public_key = WrappingPrivateKey::from_bytes([44; 32])?.public_key();
    let valid = RegisterNodeWrappingKey {
        node_id: NodeId::from_bytes([45; 16])?,
        generation: 1,
        public_key: public_key.as_bytes(),
        key_fingerprint: public_key.fingerprint(),
    };
    assert_round_trip(
        context,
        AuthoritativeCommand::RegisterNodeWrappingKey(valid),
    )?;
    for invalid in [
        RegisterNodeWrappingKey {
            generation: 0,
            ..valid
        },
        RegisterNodeWrappingKey {
            key_fingerprint: [0; 32],
            ..valid
        },
    ] {
        assert_eq!(
            encode_authoritative_command(
                context,
                &AuthoritativeCommand::RegisterNodeWrappingKey(invalid),
            ),
            Err(MetadataCommandCodecError::Invalid)
        );
    }
    Ok(())
}

#[test]
fn encrypted_secret_generation_round_trips_only_in_canonical_recipient_order()
-> Result<(), Box<dyn std::error::Error>> {
    let (command_context, _) = fixture()?;
    let first = WrappingPrivateKey::from_bytes([61; 32])?.public_key();
    let second = WrappingPrivateKey::from_bytes([62; 32])?.public_key();
    let (secret, recipients) = encrypt_secret(
        SecretContext::new(1, [63; 16], 1)?,
        b"volume content key",
        &[second, first],
        &mut SecretRandom(70),
    )?;
    let valid = CommitSecretGeneration {
        secret: secret.parts(),
        recipients: recipients
            .iter()
            .map(meshspan_secret_envelope::RecipientKeyEnvelope::parts)
            .collect(),
    };
    assert_round_trip(
        command_context,
        AuthoritativeCommand::CommitSecretGeneration(valid.clone()),
    )?;

    let mut reversed = valid.clone();
    reversed.recipients.reverse();
    assert_eq!(
        encode_authoritative_command(
            command_context,
            &AuthoritativeCommand::CommitSecretGeneration(reversed),
        ),
        Err(MetadataCommandCodecError::Invalid)
    );
    let mut tampered = valid;
    tampered.secret.digest[0] ^= 1;
    assert_eq!(
        encode_authoritative_command(
            command_context,
            &AuthoritativeCommand::CommitSecretGeneration(tampered),
        ),
        Err(MetadataCommandCodecError::Invalid)
    );
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
            smb_verifier_ciphertext: Some(vec![48; 65]),
            scopes: 7,
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

#[test]
fn session_lifecycle_commands_round_trip_every_factor_and_null_state()
-> Result<(), Box<dyn std::error::Error>> {
    let (context, _) = fixture()?;
    let principal_id = context.actor_principal_id;
    let factors = vec![
        SessionAuthenticationFactor::Passkey {
            method_id: AuthenticationMethodId::from_bytes([61; 16])?,
            credential_generation: 2,
            method_revision: Revision::new(3),
            credential_id: vec![4, 5],
            signature_counter: 6,
            backup_state: true,
        },
        SessionAuthenticationFactor::Totp {
            method_id: AuthenticationMethodId::from_bytes([62; 16])?,
            credential_generation: 7,
            method_revision: Revision::new(8),
            accepted_step: 9,
        },
        SessionAuthenticationFactor::RecoveryCode {
            method_id: AuthenticationMethodId::from_bytes([63; 16])?,
            credential_generation: 10,
            method_revision: Revision::new(11),
            code_id: RecoveryCodeId::from_bytes([64; 16])?,
        },
        SessionAuthenticationFactor::ApiKey {
            method_id: AuthenticationMethodId::from_bytes([65; 16])?,
            credential_generation: 12,
            method_revision: Revision::new(13),
            key_id: ApiKeyId::from_bytes([66; 16])?,
        },
    ];
    assert_round_trip(
        context,
        AuthoritativeCommand::IssueAuthenticationSession(IssueAuthenticationSession {
            session_id: SessionId::from_bytes([67; 16])?,
            principal_id,
            token_digest: [68; 32],
            csrf_digest: [69; 32],
            client_label: SessionClientLabel::Null,
            persistent_cookie: true,
            service: AuthenticationService::Https,
            factors: BoundedItems::new(factors, 8)?,
            expires_at: UnixMicros::new(500),
        }),
    )?;
    assert_round_trip(
        context,
        AuthoritativeCommand::StepUpAuthenticationSession(StepUpAuthenticationSession {
            source_session_id: SessionId::from_bytes([70; 16])?,
            replacement_session_id: SessionId::from_bytes([71; 16])?,
            principal_id,
            token_digest: [72; 32],
            csrf_digest: [73; 32],
            additional_factor: SessionAuthenticationFactor::Totp {
                method_id: AuthenticationMethodId::from_bytes([74; 16])?,
                credential_generation: 1,
                method_revision: Revision::new(2),
                accepted_step: 3,
            },
            expires_at: UnixMicros::new(600),
        }),
    )?;
    assert_round_trip(
        context,
        AuthoritativeCommand::RevokeAuthenticationSession(RevokeAuthenticationSession {
            session_id: SessionId::from_bytes([75; 16])?,
            principal_id,
        }),
    )?;
    assert_round_trip(
        context,
        AuthoritativeCommand::RevokeAuthenticationMethod(RevokeAuthenticationMethod {
            method_id: AuthenticationMethodId::from_bytes([76; 16])?,
            principal_id,
            reason: "Rotated".to_owned(),
        }),
    )?;
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

fn storage_provider(marker: u8) -> Result<CreateComponent, Box<dyn std::error::Error>> {
    let configuration = b"{\"provider\":\"folder\"}".to_vec();
    Ok(CreateComponent {
        instance_id: ComponentInstanceId::from_bytes([marker; 16])?,
        component_kind: 1,
        name: RecordName::new(&format!("Folder provider {marker}"))?,
        implementation_id: "meshspan-folder".to_owned(),
        contract_major: 1,
        contract_minor: 0,
        schema_version: 1,
        configuration_digest: Sha256::digest(&configuration).into(),
        canonical_configuration: configuration,
    })
}

fn fixture() -> Result<(CommandContext, AuthoritativeCommand), Box<dyn std::error::Error>> {
    let context = CommandContext {
        operation_id: OperationId::from_bytes([1; 16])?,
        actor_principal_id: PrincipalId::from_bytes([2; 16])?,
        audit_event_id: AuditEventId::from_bytes([3; 16])?,
        occurred_at: UnixMicros::new(-12),
        expected_revision: Some(Revision::new(4)),
    };
    let command = AuthoritativeCommand::BootstrapAppliance(Box::new(
        crate::test_support::bootstrap_appliance(
            BootstrapMesh {
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
            CreateAuthenticationMethod {
                method_id: AuthenticationMethodId::from_bytes([9; 16])?,
                principal_id: context.actor_principal_id,
                label: "Initial API key".to_owned(),
                service_scope: 7,
                expires_at: None,
                credential: NewAuthenticationCredential::ApiKey {
                    key_id: ApiKeyId::from_bytes([10; 16])?,
                    key_digest: [11; 32],
                    smb_verifier_ciphertext: Some(vec![12; 65]),
                    scopes: 7,
                    valid_from: context.occurred_at,
                },
            },
            Box::new(recovery_identity()?),
        )?,
    ));
    Ok((context, command))
}

fn recovery_identity() -> Result<BootstrapRecoveryIdentity, Box<dyn std::error::Error>> {
    let public_key = WrappingPublicKey::from_bytes([12; 32])?;
    let certificate = vec![13; 64];
    Ok(BootstrapRecoveryIdentity {
        public_wrapping_key: public_key.as_bytes(),
        key_fingerprint: public_key.fingerprint(),
        online_authority_certificate_digest: Sha256::digest(&certificate).into(),
        online_authority_certificate_der: certificate.clone(),
        root_certificate_digest: Sha256::digest(&certificate).into(),
        root_certificate_der: certificate,
        bundle_digest: [14; 32],
        save_challenge_commitment: [15; 32],
    })
}

fn codec_volume_key(
    volume_id: VolumeId,
) -> Result<Box<CommitSecretGeneration>, Box<dyn std::error::Error>> {
    let recipient = WrappingPublicKey::from_bytes([12; 32])?;
    let (secret, recipients) = encrypt_secret(
        SecretContext::new(VOLUME_CONTENT_KEY_SECRET_KIND, volume_id.as_bytes(), 1)?,
        &[16; 32],
        &[recipient],
        &mut SecretRandom(17),
    )?;
    Ok(Box::new(CommitSecretGeneration {
        secret: secret.parts(),
        recipients: recipients
            .into_iter()
            .map(|recipient| recipient.parts())
            .collect(),
    }))
}

struct SecretRandom(u8);

impl RandomSource for SecretRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        for byte in destination {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1).max(1);
        }
        Ok(())
    }
}
